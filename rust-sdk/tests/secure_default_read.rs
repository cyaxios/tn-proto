//! Secure-default read behavior of the Rust SDK surface.
//!
//! Covers the `ReadOptions` secure defaults, the raise-on-first-rejection
//! automatic mode, receiver-local trust loading through
//! `ConfigReadTrustProvider` (config `trust.writers`, verified-publisher
//! records, and the local device), per-`Tn` provider injection, and the
//! one-warning-plus-one-audit observability contract for every explicit
//! weakening.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, ThreadId};

use serde_json::{json, Value};
use tn_core::runtime::{CursorKind, ReadContext, VerifyMode};
use tn_proto::read_trust::{
    ConfigReadTrustProvider, InMemoryReadTrustProvider, ReadTrustProvider, TrustSource,
};
use tn_proto::{ReadOptions, ReadPolicyOptions, Tn, TnProjectOptions};

// ---------------------------------------------------------------------------
// log-warning capture
//
// `log::set_logger` is process-global, so the recorder is installed once and
// each test filters captured records down to its own thread. The SDK emits
// the structured weakening warning on the caller's thread, which makes the
// per-thread view an exact per-test count even with the default parallel
// test harness.
// ---------------------------------------------------------------------------

static RECORDS: Mutex<Vec<(ThreadId, String, String)>> = Mutex::new(Vec::new());

struct RecordingLogger;

impl log::Log for RecordingLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        RECORDS.lock().expect("log records lock").push((
            thread::current().id(),
            record.target().to_string(),
            record.args().to_string(),
        ));
    }

    fn flush(&self) {}
}

fn install_recorder() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        log::set_logger(&RecordingLogger).expect("install recording logger");
        log::set_max_level(log::LevelFilter::Warn);
    });
}

/// Security warnings captured on this test's thread so far.
fn my_security_warnings() -> Vec<String> {
    let me = thread::current().id();
    RECORDS
        .lock()
        .expect("log records lock")
        .iter()
        .filter(|(thread_id, target, _)| *thread_id == me && target == "tn.security")
        .map(|(_, _, message)| message.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn probe_context(local_device_did: &str) -> ReadContext {
    ReadContext {
        active: true,
        local_log: true,
        detached: false,
        writable: true,
        profile_sign: Some(true),
        profile_chain: Some(true),
        local_device_did: Some(local_device_did.to_string()),
        required_group: None,
    }
}

fn all_runs() -> ReadOptions {
    ReadOptions {
        all_runs: true,
        ..ReadOptions::default()
    }
}

/// Count `tn.security.unsafe_operation` rows the runtime attested this run.
fn audit_events(tn: &Tn) -> tn_proto::Result<Vec<tn_proto::Entry>> {
    Ok(tn
        .read(ReadOptions::default())?
        .into_iter()
        .filter(|entry| entry.event_type() == Some("tn.security.unsafe_operation"))
        .collect())
}

/// Last raw log line whose envelope carries `event_type`.
fn raw_line_for(log_path: &Path, event_type: &str) -> String {
    let text = fs::read_to_string(log_path).expect("read log");
    text.lines()
        .filter(|line| line.contains(&format!("\"{event_type}\"")))
        .next_back()
        .unwrap_or_else(|| panic!("no {event_type} row in {}", log_path.display()))
        .to_string()
}

/// Create a project ceremony under `workspace` and return its yaml path.
fn project_yaml(workspace: &Path, project: &str) -> tn_proto::Result<PathBuf> {
    let tn = Tn::init_project_with_options(
        project,
        TnProjectOptions {
            project_dir: Some(workspace.to_path_buf()),
            ..TnProjectOptions::default()
        },
    )?;
    let yaml_path = tn.yaml_path().to_path_buf();
    tn.close()?;
    Ok(yaml_path)
}

fn append_trust_writers(yaml_path: &Path, writers: &[&str]) {
    let mut yaml = fs::read_to_string(yaml_path).expect("read yaml");
    yaml.push_str("trust:\n  writers:\n");
    for writer in writers {
        yaml.push_str(&format!("    - \"{writer}\"\n"));
    }
    fs::write(yaml_path, yaml).expect("write yaml");
}

// ---------------------------------------------------------------------------
// secure defaults
// ---------------------------------------------------------------------------

#[test]
fn read_options_default_is_secure_auto() {
    let options = ReadOptions::default();
    assert!(options.verify);
    assert!(!options.all_runs);
    let policy = ReadPolicyOptions::default();
    assert_eq!(policy.verify, VerifyMode::Auto);
    assert_eq!(policy.require_signature, None);
    assert_eq!(policy.allow_unauthenticated, None);
    assert_eq!(policy.trusted_writers, None);
    assert!(!policy.allow_unknown_writers);
}

#[test]
fn auto_read_raises_on_first_rejection_without_leaking_plaintext() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("secure.ok", json!({ "marker": "fine" }))?;
    tn.info("secure.bad", json!({ "secret": "never-return-this" }))?;

    let log_path = tn.log_path().to_path_buf();
    let text = fs::read_to_string(&log_path)?;
    let mut lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("envelope json"))
        .collect();
    lines
        .last_mut()
        .expect("at least one row")
        .as_object_mut()
        .expect("envelope object")
        .insert(
            "signature".into(),
            Value::String("invalid-signature".into()),
        );
    let rewritten = lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&log_path, rewritten)?;

    // The secure automatic default raises on the first rejected row.
    let error = tn.read(all_runs()).expect_err("auto must raise");
    let message = error.to_string();
    assert!(message.contains("signature_invalid"), "{message}");
    assert!(!message.contains("never-return-this"), "{message}");

    // The run filter never bypasses the security gate: the default
    // current-run read scans (and rejects) the same tampered row.
    let error = tn
        .read(ReadOptions::default())
        .expect_err("default read must raise too");
    assert!(error.to_string().contains("signature_invalid"), "{error}");

    // verify="skip" keeps verified continuity and reports the rejection.
    let report = tn.read_with_policy_options(&ReadPolicyOptions {
        all_runs: true,
        verify: VerifyMode::Skip,
        ..ReadPolicyOptions::default()
    })?;
    assert!(report.skipped >= 1, "skipped={}", report.skipped);
    assert_eq!(report.yielded, report.entries.len());
    assert!(report.scanned > report.yielded);
    assert!(report
        .entries
        .iter()
        .all(|entry| entry.event_type() != Some("secure.bad")));
    Ok(())
}

#[test]
fn read_report_carries_counts_and_byte_offset_cursor() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("report.one", json!({ "n": 1 }))?;
    tn.info("report.two", json!({ "n": 2 }))?;

    let log_len = fs::metadata(tn.log_path())?.len();
    let report = tn.read_with_options(&all_runs())?;

    assert_eq!(report.yielded, report.entries.len());
    assert!(report.yielded >= 2);
    assert_eq!(report.skipped, 0);
    assert!(report.scanned >= report.yielded);

    assert_eq!(report.cursor.version, 1);
    assert_eq!(report.cursor.sources.len(), 1);
    let expected_id =
        tn_core::runtime::canonical_file_source_id(tn.log_path().to_str().expect("utf-8 log path"));
    let source = report
        .cursor
        .sources
        .get(&expected_id)
        .expect("cursor keyed by the canonical file source id");
    assert_eq!(source.kind, CursorKind::ByteOffset);
    assert_eq!(source.value, log_len.to_string());
    Ok(())
}

#[test]
fn public_cursor_read_resumes_without_replaying_prior_rows() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("resume.before", json!({ "n": 1 }))?;
    let options = ReadPolicyOptions {
        all_runs: true,
        ..ReadPolicyOptions::default()
    };
    let first = tn.read_with_policy_options(&options)?;

    tn.info("resume.after", json!({ "n": 2 }))?;
    let resumed = tn.read_from_cursor(&options, &first.cursor)?;

    assert_eq!(resumed.scanned, 1);
    assert_eq!(resumed.yielded, 1);
    assert_eq!(resumed.entries[0].event_type(), Some("resume.after"));
    Ok(())
}

// ---------------------------------------------------------------------------
// receiver-local trust
// ---------------------------------------------------------------------------

#[test]
fn unknown_writers_are_rejected_by_default() -> tn_proto::Result<()> {
    let foreign = Tn::ephemeral()?;
    foreign.info("foreign.event", json!({}))?;
    let foreign_line = raw_line_for(foreign.log_path(), "foreign.event");

    let tn = Tn::ephemeral()?;
    tn.info("local.anchor", json!({}))?;
    let mut log = fs::read_to_string(tn.log_path())?;
    log.push_str(&foreign_line);
    log.push('\n');
    fs::write(tn.log_path(), log)?;

    let error = tn
        .read(all_runs())
        .expect_err("a cryptographically valid but unknown writer is rejected");
    assert!(error.to_string().contains("writer_untrusted"), "{error}");
    Ok(())
}

#[test]
fn config_trust_writers_authorize_an_exact_foreign_did() -> tn_proto::Result<()> {
    let foreign = Tn::ephemeral()?;
    foreign.info("foreign.event", json!({}))?;
    let foreign_did = foreign.did().to_string();
    let foreign_line = raw_line_for(foreign.log_path(), "foreign.event");

    let workspace = tempfile::tempdir().expect("tempdir");
    let yaml_path = project_yaml(workspace.path(), "trusting")?;
    append_trust_writers(&yaml_path, &[&foreign_did]);

    let tn = Tn::init(&yaml_path)?;
    tn.info("local.anchor", json!({}))?;
    let mut log = fs::read_to_string(tn.log_path())?;
    log.push_str(&foreign_line);
    log.push('\n');
    fs::write(tn.log_path(), log)?;

    let entries = tn.read(all_runs())?;
    let entry = common::find_event(&entries, "foreign.event");
    let valid = entry
        .get("_valid")
        .and_then(Value::as_object)
        .expect("_valid block");
    assert_eq!(valid.get("writer_authenticated"), Some(&Value::Bool(true)));
    assert_eq!(valid.get("writer_authorized"), Some(&Value::Bool(true)));

    // The provider itself reports exact-DID entries and their sources.
    let provider = ConfigReadTrustProvider::load(&yaml_path)?;
    let trusted = provider.trusted_writer_dids(&probe_context(tn.did()));
    assert!(trusted.contains(&foreign_did));
    assert!(trusted.contains(tn.did()));
    assert_eq!(
        provider.source_for(&foreign_did),
        Some(TrustSource::ExplicitConfig)
    );
    assert_eq!(
        provider.source_for(tn.did()),
        Some(TrustSource::LocalDevice)
    );
    assert_eq!(provider.source_for("did:key:zUnknown"), None);
    Ok(())
}

#[test]
fn config_provider_loads_verified_publisher_records() -> tn_proto::Result<()> {
    let workspace = tempfile::tempdir().expect("tempdir");
    let yaml_path = project_yaml(workspace.path(), "publishers")?;

    let publisher_did = tn_core::DeviceKey::generate().did().to_string();
    let overlapping_did = tn_core::DeviceKey::generate().did().to_string();
    append_trust_writers(&yaml_path, &[&overlapping_did]);

    let trust_dir = yaml_path
        .parent()
        .expect("yaml parent")
        .join("keys")
        .join("trust");
    fs::create_dir_all(&trust_dir)?;
    let mut publishers = serde_json::Map::new();
    publishers.insert(
        publisher_did.clone(),
        json!({ "version": 1, "ceremony_id": "cer_x", "group": "default" }),
    );
    publishers.insert(
        overlapping_did.clone(),
        json!({ "version": 1, "ceremony_id": "cer_y", "group": "default" }),
    );
    fs::write(
        trust_dir.join("verified_publishers.v1.json"),
        serde_json::to_string(&json!({ "version": 1, "publishers": publishers }))?,
    )?;

    let provider = ConfigReadTrustProvider::load(&yaml_path)?;
    assert_eq!(
        provider.source_for(&publisher_did),
        Some(TrustSource::VerifiedPackage)
    );
    // A verified package record outranks an explicit config entry, and the
    // local device outranks both.
    assert_eq!(
        provider.source_for(&overlapping_did),
        Some(TrustSource::VerifiedPackage)
    );

    // A malformed record file fails closed instead of loading partially.
    fs::write(
        trust_dir.join("verified_publishers.v1.json"),
        "{\"publishers\": []}",
    )?;
    assert!(ConfigReadTrustProvider::load(&yaml_path).is_err());
    Ok(())
}

#[test]
fn injected_provider_overrides_config_trust_per_tn() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;
    tn.info("own.row", json!({ "marker": "mine" }))?;
    assert!(!tn.read(all_runs())?.is_empty());

    // A provider that does not trust the local device rejects its own rows.
    let stranger = tn_core::DeviceKey::generate().did().to_string();
    tn.set_read_trust_provider(Arc::new(InMemoryReadTrustProvider::new([(
        stranger,
        TrustSource::ExplicitConfig,
    )])?));
    let error = tn.read(all_runs()).expect_err("injected provider wins");
    assert!(error.to_string().contains("writer_untrusted"), "{error}");

    // Trusting the local device again restores acceptance.
    tn.set_read_trust_provider(Arc::new(InMemoryReadTrustProvider::new([(
        tn.did().to_string(),
        TrustSource::ExplicitConfig,
    )])?));
    assert!(!tn.read(all_runs())?.is_empty());

    // Injection is scoped to one handle: a fresh Tn keeps its own defaults.
    let other = Tn::ephemeral()?;
    other.info("other.row", json!({}))?;
    assert!(!other.read(all_runs())?.is_empty());
    Ok(())
}

#[test]
fn explicit_trusted_writers_replace_the_call_allowlist() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    tn.info("allow.row", json!({}))?;

    // Excluding the local writer rejects local rows for that call only.
    let stranger = tn_core::DeviceKey::generate().did().to_string();
    let error = tn
        .read_with_policy(ReadPolicyOptions {
            all_runs: true,
            trusted_writers: Some(BTreeSet::from([stranger])),
            ..ReadPolicyOptions::default()
        })
        .expect_err("explicit allowlist replaces the default");
    assert!(error.to_string().contains("writer_untrusted"), "{error}");
    assert!(!tn.read(all_runs())?.is_empty());

    // verify=Disabled cannot claim authorization from an explicit allowlist.
    let error = tn
        .read_with_policy(ReadPolicyOptions {
            all_runs: true,
            verify: VerifyMode::Disabled,
            trusted_writers: Some(BTreeSet::from([tn.did().to_string()])),
            ..ReadPolicyOptions::default()
        })
        .expect_err("verify=Disabled with trusted_writers is a parameter error");
    assert!(error.to_string().contains("trusted_writers"), "{error}");
    Ok(())
}

#[test]
fn in_memory_provider_rejects_non_canonical_dids() {
    let error = InMemoryReadTrustProvider::new([(
        "did:web:example.com".to_string(),
        TrustSource::ExplicitConfig,
    )])
    .expect_err("only canonical Ed25519 did:key entries are trusted");
    assert!(
        error.to_string().contains("canonical Ed25519"),
        "got {error}"
    );
}

// ---------------------------------------------------------------------------
// trust.writers config schema validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_trust_config_is_rejected_at_init() -> tn_proto::Result<()> {
    let workspace = tempfile::tempdir().expect("tempdir");
    let yaml_path = project_yaml(workspace.path(), "badtrust")?;
    let clean_yaml = fs::read_to_string(&yaml_path)?;

    // Non-list writers value.
    fs::write(
        &yaml_path,
        format!("{clean_yaml}trust:\n  writers: did:key:zNotAList\n"),
    )?;
    assert!(Tn::init(&yaml_path).is_err(), "non-list writers must fail");

    // Well-shaped string that is not a canonical Ed25519 did:key.
    fs::write(&yaml_path, clean_yaml.clone())?;
    append_trust_writers(&yaml_path, &["did:web:example.com"]);
    let error = Tn::init(&yaml_path).expect_err("invalid DID must fail");
    assert!(
        error.to_string().contains("canonical Ed25519"),
        "got {error}"
    );

    // Duplicate entries after exact-string comparison.
    let did = tn_core::DeviceKey::generate().did().to_string();
    fs::write(&yaml_path, clean_yaml)?;
    append_trust_writers(&yaml_path, &[&did, &did]);
    let error = Tn::init(&yaml_path).expect_err("duplicate DID must fail");
    assert!(error.to_string().contains("duplicate"), "got {error}");
    Ok(())
}

// ---------------------------------------------------------------------------
// weakening observability: one warning + one audit event per weakening
// ---------------------------------------------------------------------------

#[test]
fn weakened_read_warns_once_and_audits_once_per_weakening() -> tn_proto::Result<()> {
    install_recorder();
    let tn = Tn::ephemeral()?;
    tn.info("weaken.row", json!({}))?;

    // Secure defaults emit nothing.
    let baseline = my_security_warnings().len();
    tn.read(all_runs())?;
    assert_eq!(my_security_warnings().len(), baseline);
    assert_eq!(audit_events(&tn)?.len(), 0);

    // First weakening: exactly one warning and one audit event.
    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
        ..ReadOptions::default()
    })?;
    assert!(!entries.is_empty());
    let warnings = my_security_warnings();
    assert_eq!(warnings.len(), baseline + 1, "{warnings:?}");
    let message = warnings.last().expect("one warning");
    assert!(message.contains("\"operation\":\"read\""), "{message}");
    assert!(message.contains("verification_disabled"), "{message}");

    let audits = audit_events(&tn)?;
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].get("operation").and_then(Value::as_str),
        Some("read")
    );
    assert_eq!(
        audits[0].get("relaxations"),
        Some(&json!(["verification_disabled"]))
    );
    assert_eq!(audits[0].get("group"), Some(&Value::Null));
    assert_eq!(audits[0].get("subject_did"), Some(&Value::Null));
    assert_eq!(audits[0].get("artifact_digest"), Some(&Value::Null));

    // Each weakening emits its own pair.
    tn.read(ReadOptions {
        all_runs: true,
        verify: false,
        ..ReadOptions::default()
    })?;
    assert_eq!(my_security_warnings().len(), baseline + 2);
    assert_eq!(audit_events(&tn)?.len(), 2);
    Ok(())
}

#[test]
fn combined_relaxations_are_sorted_and_deduplicated() -> tn_proto::Result<()> {
    install_recorder();
    let tn = Tn::ephemeral()?;
    tn.info("relax.row", json!({}))?;

    let baseline = my_security_warnings().len();
    tn.read_with_policy(ReadPolicyOptions {
        all_runs: true,
        require_signature: Some(false),
        allow_unauthenticated: Some(true),
        allow_unknown_writers: true,
        ..ReadPolicyOptions::default()
    })?;

    let warnings = my_security_warnings();
    assert_eq!(warnings.len(), baseline + 1, "{warnings:?}");
    let audits = audit_events(&tn)?;
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].get("relaxations"),
        Some(&json!([
            "signature_not_required",
            "unauthenticated_allowed",
            "unknown_writer_allowed",
        ]))
    );
    Ok(())
}

#[test]
fn weakened_watch_warns_once_at_construction_not_per_poll() -> tn_proto::Result<()> {
    install_recorder();
    let tn = Tn::ephemeral()?;
    tn.info("watch.seed", json!({}))?;

    let baseline = my_security_warnings().len();
    let mut watch = tn.watch(tn_proto::WatchOptions {
        read: ReadOptions {
            all_runs: true,
            verify: false,
        },
        ..tn_proto::WatchOptions::default()
    })?;

    let warnings = my_security_warnings();
    assert_eq!(warnings.len(), baseline + 1, "{warnings:?}");
    assert!(
        warnings
            .last()
            .expect("one warning")
            .contains("\"operation\":\"watch\""),
        "{warnings:?}"
    );
    assert_eq!(audit_events(&tn)?.len(), 1);
    assert_eq!(
        audit_events(&tn)?[0]
            .get("operation")
            .and_then(Value::as_str),
        Some("watch")
    );

    tn.info("watch.one", json!({}))?;
    watch.poll()?;
    tn.info("watch.two", json!({}))?;
    watch.poll()?;

    assert_eq!(my_security_warnings().len(), baseline + 1);
    assert_eq!(audit_events(&tn)?.len(), 1);
    Ok(())
}
