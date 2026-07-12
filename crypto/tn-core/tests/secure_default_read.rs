//! Secure-default read policy, report, and cursor contract tests.

#![cfg(feature = "fs")]

mod common;

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::runtime::{
    canonical_file_source_id, canonical_source_id, CursorKind, ReadContext, ReadCursorV1,
    ReadRecordState, ReadRejectReason, ReadTrustPolicy, SourceCursorV1, VerifyMode,
};
use tn_core::storage::{FsStorage, Storage, StorageReadSnapshot};
use tn_core::{Error, OnInvalid, Runtime, SecureReadOptions};

#[derive(Default)]
struct SnapshotProbeStorage {
    inner: FsStorage,
    target: std::sync::Mutex<Option<std::path::PathBuf>>,
    armed: std::sync::atomic::AtomicBool,
    whole_reads: std::sync::atomic::AtomicUsize,
    snapshot_opens: std::sync::atomic::AtomicUsize,
}

impl SnapshotProbeStorage {
    fn arm_for(&self, path: &std::path::Path) {
        *self.target.lock().unwrap() = Some(path.to_owned());
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_armed_target(&self, path: &std::path::Path) -> bool {
        self.armed.load(std::sync::atomic::Ordering::SeqCst)
            && self.target.lock().unwrap().as_deref() == Some(path)
    }
}

impl Storage for SnapshotProbeStorage {
    fn read_bytes(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        if self.is_armed_target(path) {
            self.whole_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(std::io::Error::other(
                "whole-source reads are forbidden for the armed path",
            ));
        }
        self.inner.read_bytes(path)
    }

    fn open_read_snapshot(
        &self,
        path: &std::path::Path,
    ) -> std::io::Result<Option<StorageReadSnapshot>> {
        if self.is_armed_target(path) {
            self.snapshot_opens
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.open_read_snapshot(path)
    }

    fn write_bytes(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(path, data)
    }

    fn append_bytes(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        self.inner.append_bytes(path, data)
    }

    fn exists(&self, path: &std::path::Path) -> bool {
        self.inner.exists(path)
    }

    fn list(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        self.inner.list(path)
    }

    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        self.inner.rename(from, to)
    }

    fn remove(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.inner.remove(path)
    }

    fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn cas_write(
        &self,
        path: &std::path::Path,
        prior: Option<&[u8]>,
        new: &[u8],
    ) -> std::io::Result<()> {
        self.inner.cas_write(path, prior, new)
    }
}

fn fixture(name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/trust/v1")
        .join(name);
    serde_json::from_slice(&std::fs::read(root).unwrap()).unwrap()
}

fn bool_field(value: &Value, name: &str) -> bool {
    value[name].as_bool().unwrap_or_else(|| panic!("{name}"))
}

fn optional_bool(value: &Value, name: &str) -> Option<bool> {
    value.get(name).and_then(Value::as_bool)
}

fn context_for(case: &Value) -> ReadContext {
    let value = &case["input"]["context"];
    ReadContext {
        active: bool_field(value, "active"),
        local_log: bool_field(value, "local_log"),
        detached: bool_field(value, "detached"),
        writable: bool_field(value, "writable"),
        profile_sign: optional_bool(value, "profile_sign"),
        profile_chain: optional_bool(value, "profile_chain"),
        local_device_did: value["local_device_did"].as_str().map(str::to_owned),
        required_group: value["required_group"].as_str().map(str::to_owned),
    }
}

fn policy_for(case: &Value) -> std::result::Result<ReadTrustPolicy, &'static str> {
    let input = &case["input"];
    let value = &input["policy"];
    let verify = match &value["verify"] {
        Value::Bool(true) => VerifyMode::Raise,
        Value::Bool(false) => VerifyMode::Disabled,
        Value::String(mode) if mode == "auto" => VerifyMode::Auto,
        Value::String(mode) if mode == "raise" => VerifyMode::Raise,
        Value::String(mode) if mode == "skip" => VerifyMode::Skip,
        _ => return Err("verify public parameter"),
    };
    let explicit = value["trusted_writers"].as_array();
    let trusted_values = explicit.unwrap_or_else(|| {
        input["context"]["trusted_writer_dids"]
            .as_array()
            .expect("trusted_writer_dids")
    });
    let trusted_writers = trusted_values
        .iter()
        .map(|did| did.as_str().unwrap().to_owned())
        .collect();
    Ok(ReadTrustPolicy {
        verify,
        require_signature: optional_bool(value, "require_signature"),
        allow_unauthenticated: optional_bool(value, "allow_unauthenticated"),
        trusted_writers,
        trusted_writers_supplied: explicit.is_some(),
        allow_unknown_writers: bool_field(value, "allow_unknown_writers"),
    })
}

fn record_for(case: &Value) -> ReadRecordState {
    let value = &case["input"]["record"];
    ReadRecordState {
        record_valid: bool_field(value, "record_valid"),
        row_hash_present: bool_field(value, "row_hash_present"),
        row_hash_valid: bool_field(value, "row_hash_valid"),
        chain_valid: bool_field(value, "chain_valid"),
        signature_present: bool_field(value, "signature_present"),
        signature_valid: bool_field(value, "signature_valid"),
        writer_did: value["writer_did"].as_str().map(str::to_owned),
        aad_valid: bool_field(value, "aad_valid"),
        recipient_groups: value["recipient_groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group.as_str().unwrap().to_owned())
            .collect(),
    }
}

fn reasons(value: &Value) -> Vec<ReadRejectReason> {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn accepted_read_policy_matrix_matches_exactly() {
    let document = fixture("read_policy_matrix.json");
    assert_eq!(document["schema"], "tn.trust-fixtures/v1");
    assert_eq!(document["fixture"], "read_policy_matrix");

    for case in document["cases"].as_array().unwrap() {
        let expected = &case["expected"];
        let dynamic_policy = policy_for(case);
        if expected["parameter_error"].as_bool() == Some(true) {
            if let Ok(policy) = dynamic_policy {
                assert!(
                    policy.resolve(&context_for(case)).is_err(),
                    "{} should be rejected",
                    case["id"]
                );
            }
            continue;
        }

        let context = context_for(case);
        let policy = dynamic_policy.unwrap().resolve(&context).unwrap();
        let decision = policy.evaluate(&record_for(case), &context);
        let resolved_mode: VerifyMode =
            serde_json::from_value(expected["resolved_mode"].clone()).unwrap();
        assert_eq!(policy.verify, resolved_mode, "{} mode", case["id"]);
        assert_eq!(
            decision.accepted,
            bool_field(expected, "accepted"),
            "{} accepted",
            case["id"]
        );
        assert_eq!(
            decision.reasons,
            reasons(&expected["reasons"]),
            "{} reasons",
            case["id"]
        );
        assert_eq!(
            decision.writer_authenticated,
            bool_field(expected, "writer_authenticated"),
            "{} authenticated",
            case["id"]
        );
        assert_eq!(
            decision.writer_authorized,
            bool_field(expected, "writer_authorized"),
            "{} authorized",
            case["id"]
        );
    }
}

#[test]
fn reasons_are_stable_ordered_and_deduplicated() {
    let document = fixture("read_policy_matrix.json");
    let baseline = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "auto_local_signed")
        .unwrap();
    let mut context = context_for(baseline);
    context.required_group = Some("default".into());
    let policy = policy_for(baseline).unwrap().resolve(&context).unwrap();
    let decision = policy.evaluate(
        &ReadRecordState {
            record_valid: true,
            row_hash_present: true,
            row_hash_valid: false,
            chain_valid: false,
            signature_present: true,
            signature_valid: false,
            writer_did: Some("did:key:z6Mkf1YtL1qR91LXM63W4mSmU18wCqFJCEGBWayXn7ykPuZ3".into()),
            aad_valid: false,
            recipient_groups: BTreeSet::new(),
        },
        &context,
    );
    assert_eq!(
        decision.reasons,
        [
            ReadRejectReason::RowHashInvalid,
            ReadRejectReason::ChainInvalid,
            ReadRejectReason::SignatureInvalid,
            ReadRejectReason::WriterUntrusted,
            ReadRejectReason::AadInvalid,
            ReadRejectReason::NotARecipient,
        ]
    );
    assert_eq!(
        decision.first_reason(),
        Some(ReadRejectReason::RowHashInvalid)
    );
    let unique: BTreeSet<_> = decision.reasons.iter().copied().collect();
    assert_eq!(unique.len(), decision.reasons.len());
}

#[test]
fn absent_signature_can_be_allowed_but_present_invalid_signature_cannot() {
    let document = fixture("read_policy_matrix.json");
    let case = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "explicit_foreign_unsigned")
        .unwrap();
    let context = context_for(case);
    let policy = policy_for(case).unwrap().resolve(&context).unwrap();
    let mut record = record_for(case);
    assert!(policy.evaluate(&record, &context).accepted);
    record.signature_present = true;
    record.signature_valid = false;
    let decision = policy.evaluate(&record, &context);
    assert!(!decision.accepted);
    assert_eq!(decision.reasons, [ReadRejectReason::SignatureInvalid]);
    assert!(!decision.writer_authenticated);
    assert!(!decision.writer_authorized);
}

#[test]
fn local_unsigned_profile_is_inferred_only_for_active_attached_local_log() {
    let document = fixture("read_policy_matrix.json");
    let case = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "auto_local_profile_unsigned")
        .unwrap();
    let local = context_for(case);
    let inferred = policy_for(case).unwrap().resolve(&local).unwrap();
    assert_eq!(inferred.require_signature, Some(false));

    let mut foreign = context_for(case);
    foreign.local_log = false;
    let resolved = policy_for(case).unwrap().resolve(&foreign).unwrap();
    assert_eq!(resolved.require_signature, Some(true));
    let mut detached = context_for(case);
    detached.detached = true;
    assert_eq!(
        policy_for(case)
            .unwrap()
            .resolve(&detached)
            .unwrap()
            .require_signature,
        Some(true)
    );
    let mut inactive = context_for(case);
    inactive.active = false;
    assert_eq!(
        policy_for(case)
            .unwrap()
            .resolve(&inactive)
            .unwrap()
            .require_signature,
        Some(true)
    );
}

fn local_policy(rt: &Runtime, verify: VerifyMode) -> ReadTrustPolicy {
    ReadTrustPolicy {
        verify,
        require_signature: None,
        allow_unauthenticated: None,
        trusted_writers: BTreeSet::from([rt.did().to_owned()]),
        trusted_writers_supplied: false,
        allow_unknown_writers: false,
    }
}

fn local_context(rt: &Runtime) -> ReadContext {
    ReadContext {
        active: true,
        local_log: true,
        detached: false,
        writable: true,
        profile_sign: Some(true),
        profile_chain: Some(true),
        local_device_did: Some(rt.did().to_owned()),
        required_group: None,
    }
}

fn prepend_oversized_whitespace_line(rt: &Runtime) -> usize {
    let valid_tail = std::fs::read(rt.log_path()).unwrap();
    let mut bytes = vec![b' '; 8 * 1024 * 1024 + 1];
    bytes.push(b'\n');
    bytes.extend_from_slice(&valid_tail);
    std::fs::write(rt.log_path(), &bytes).unwrap();
    bytes.len()
}

#[test]
fn missing_validity_is_rejected_and_skip_storage_is_bounded() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    let valid_tail = std::fs::read_to_string(rt.log_path()).unwrap();
    let malformed = std::iter::repeat_n("{}\n", 512).collect::<String>() + &valid_tail;
    std::fs::write(rt.log_path(), malformed.as_bytes()).unwrap();

    let mut context = local_context(&rt);
    context.writable = false;
    let report = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Skip),
            &context,
            None,
        )
        .unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.scanned, 513);
    assert_eq!(report.yielded, 1);
    assert_eq!(report.skipped, 512);
    assert_eq!(report.cursor.version, 1);
    let source = report.cursor.sources.values().next().unwrap();
    assert_eq!(source.kind, CursorKind::ByteOffset);
    assert_eq!(source.value, malformed.len().to_string());
}

#[test]
fn oversized_whitespace_line_is_counted_and_skipped() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    let source_len = prepend_oversized_whitespace_line(&rt);
    let mut context = local_context(&rt);
    context.writable = false;

    let report = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Skip),
            &context,
            None,
        )
        .unwrap();

    assert_eq!(report.scanned, 2);
    assert_eq!(report.yielded, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(
        report.cursor.sources.values().next().unwrap().value,
        source_len.to_string()
    );
}

#[test]
fn oversized_whitespace_line_raises_record_invalid() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    prepend_oversized_whitespace_line(&rt);

    let error = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Raise),
            &local_context(&rt),
            None,
        )
        .unwrap_err();

    assert!(error.to_string().contains("record_invalid"), "{error}");
}

#[test]
fn policy_rejection_happens_before_plaintext_is_returned() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info(
        "secret.event",
        serde_json::Map::from_iter([("secret".into(), json!("never-return-this"))]),
    )
    .unwrap();

    let log_path = rt.log_path().to_owned();
    let text = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines.last_mut().unwrap()["signature"] = Value::String("invalid-signature".into());
    let rewritten = lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&log_path, rewritten).unwrap();

    let error = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Raise),
            &local_context(&rt),
            None,
        )
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("signature_invalid"), "{message}");
    assert!(!message.contains("never-return-this"), "{message}");
}

#[test]
fn disabled_read_never_defaults_missing_validity_to_true() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info("missing.validity", serde_json::Map::new()).unwrap();

    let log_path = rt.log_path().to_owned();
    let text = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let last = lines.last_mut().unwrap().as_object_mut().unwrap();
    last.remove("row_hash");
    last.remove("signature");
    let rewritten = lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&log_path, rewritten).unwrap();

    let report = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Disabled),
            &local_context(&rt),
            None,
        )
        .unwrap();
    let entry = report
        .entries
        .iter()
        .find(|entry| entry["event_type"] == "missing.validity")
        .unwrap();
    assert_eq!(entry["_valid"]["row_hash"], Value::Bool(false));
    assert_eq!(entry["_valid"]["signature"], Value::Bool(false));
    assert_eq!(
        entry["_valid"]["reasons"],
        json!(["row_hash_invalid", "signature_required"])
    );
}

#[test]
fn accepted_cursor_vectors_preserve_sorted_ids_and_lossless_values() {
    let document = fixture("read_cursor_vectors.json");
    assert_eq!(document["schema"], "tn.trust-fixtures/v1");
    assert_eq!(document["fixture"], "read_cursor_vectors");

    for case in document["cases"].as_array().unwrap() {
        let expected = &case["expected"]["cursor"];
        let cursor: ReadCursorV1 = serde_json::from_value(expected.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&cursor).unwrap(),
            *expected,
            "{}",
            case["id"]
        );
        let keys: Vec<_> = cursor.sources.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "{}", case["id"]);
        for source in cursor.sources.values() {
            assert_eq!(
                source.value,
                expected["sources"]
                    .as_object()
                    .unwrap()
                    .values()
                    .find(|value| value["value"] == source.value)
                    .unwrap()["value"]
            );
        }

        if let (Some(descriptor), Some(source_id)) = (
            case["expected"]["descriptor_b64"].as_str(),
            case["expected"]["source_id"].as_str(),
        ) {
            assert_eq!(
                canonical_source_id(&STANDARD.decode(descriptor).unwrap()),
                source_id
            );
        }
        if case["source_kind"] == "file-posix" || case["source_kind"] == "file-windows" {
            let separator = if case["input"]["platform"] == "windows" {
                "\\"
            } else {
                "/"
            };
            let joined = format!(
                "{}{}{}",
                case["input"]["base_directory"].as_str().unwrap(),
                separator,
                case["input"]["path"].as_str().unwrap()
            );
            assert_eq!(
                canonical_file_source_id(&joined),
                case["expected"]["source_id"]
            );
        }
    }
}

#[test]
fn report_cursor_resumes_after_skips_and_preserves_other_sources() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info("cursor.first", serde_json::Map::new()).unwrap();
    let context = local_context(&rt);
    let policy = local_policy(&rt, VerifyMode::Skip);
    let options = SecureReadOptions::default();

    let first = rt
        .read_with_policy(&options, &policy, &context, None)
        .unwrap();
    assert!(first.yielded >= 2);
    let mut cursor = first.cursor;
    let unrelated_id = format!("source:sha256:{}", "0".repeat(64));
    let unrelated = SourceCursorV1 {
        kind: CursorKind::Opaque,
        value: "opaque:page/7?token=A%2FB".into(),
    };
    cursor
        .sources
        .insert(unrelated_id.clone(), unrelated.clone());

    rt.info("cursor.second", serde_json::Map::new()).unwrap();
    let second = rt
        .read_with_policy(&options, &policy, &context, Some(&cursor))
        .unwrap();
    assert_eq!(second.scanned, 1);
    assert_eq!(second.yielded, 1);
    assert_eq!(second.skipped, 0);
    assert_eq!(second.entries[0]["event_type"], "cursor.second");
    assert_eq!(second.cursor.sources[&unrelated_id], unrelated);
    let keys: Vec<_> = second.cursor.sources.keys().cloned().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn relative_option_path_and_source_id_are_anchored_at_yaml_directory() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info("relative.source", serde_json::Map::new()).unwrap();

    let relative = std::path::PathBuf::from("detached/read.tnlog");
    let absolute = td.path().join(&relative);
    std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
    std::fs::copy(rt.log_path(), &absolute).unwrap();
    let options = SecureReadOptions {
        log_path: Some(relative),
        ..SecureReadOptions::default()
    };
    let mut context = local_context(&rt);
    context.local_log = false;
    context.writable = false;

    let report = rt
        .read_with_policy(
            &options,
            &local_policy(&rt, VerifyMode::Raise),
            &context,
            None,
        )
        .unwrap();
    assert!(report
        .entries
        .iter()
        .any(|entry| entry["event_type"] == "relative.source"));

    let mut rendered = absolute.to_string_lossy().replace('\\', "/");
    if rendered.as_bytes().get(1) == Some(&b':') {
        let drive = rendered[..1].to_ascii_lowercase();
        rendered.replace_range(..1, &drive);
    }
    let expected_id = canonical_source_id(format!("file\0{rendered}").as_bytes());
    assert!(report.cursor.sources.contains_key(&expected_id));
}

#[test]
fn local_chain_disabled_rows_report_effective_chain_validity() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let yaml = std::fs::read_to_string(&ceremony.yaml_path)
        .unwrap()
        .replace(
            "protocol_events_location: main_log}",
            "protocol_events_location: main_log, chain: false}",
        );
    std::fs::write(&ceremony.yaml_path, yaml).unwrap();
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info("unchained.same", serde_json::Map::new()).unwrap();
    rt.info("unchained.same", serde_json::Map::new()).unwrap();
    let mut context = local_context(&rt);
    context.profile_chain = Some(false);

    let report = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Raise),
            &context,
            None,
        )
        .unwrap();
    let rows: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry["event_type"] == "unchained.same")
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|entry| entry["_valid"]["chain"] == Value::Bool(true)));
}

#[test]
fn explicit_file_source_cannot_spoof_local_unsigned_context() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let yaml = std::fs::read_to_string(&ceremony.yaml_path)
        .unwrap()
        .replace(
            "protocol_events_location: main_log}",
            "protocol_events_location: main_log, sign: false}",
        );
    std::fs::write(&ceremony.yaml_path, yaml).unwrap();
    let rt = Runtime::init(&ceremony.yaml_path).unwrap();
    rt.info("unsigned.foreign", serde_json::Map::new()).unwrap();

    let relative = std::path::PathBuf::from("foreign/unsigned.tnlog");
    let absolute = td.path().join(&relative);
    std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
    std::fs::copy(rt.log_path(), absolute).unwrap();
    let options = SecureReadOptions {
        log_path: Some(relative),
        ..SecureReadOptions::default()
    };
    let mut spoofed = local_context(&rt);
    spoofed.profile_sign = Some(false);
    spoofed.local_log = true;

    let error = rt
        .read_with_policy(
            &options,
            &local_policy(&rt, VerifyMode::Auto),
            &spoofed,
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("signature_required"), "{error}");
}

#[test]
fn policy_scan_uses_snapshot_reader_without_whole_source_read() {
    let td = tempfile::tempdir().unwrap();
    let ceremony = common::setup_minimal_btn_ceremony(td.path());
    let probe = std::sync::Arc::new(SnapshotProbeStorage::default());
    let storage: std::sync::Arc<dyn Storage> = probe.clone();
    let rt = Runtime::init_with_storage(&ceremony.yaml_path, storage).unwrap();
    rt.info("snapshot.streamed", serde_json::Map::new())
        .unwrap();
    probe.arm_for(rt.log_path());

    let report = rt
        .read_with_policy(
            &SecureReadOptions::default(),
            &local_policy(&rt, VerifyMode::Raise),
            &local_context(&rt),
            None,
        )
        .unwrap();
    assert!(report
        .entries
        .iter()
        .any(|entry| entry["event_type"] == "snapshot.streamed"));
    assert_eq!(
        probe
            .snapshot_opens
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        probe.whole_reads.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn foreign_peek_uses_snapshot_reader_without_whole_source_read() {
    let local_dir = tempfile::tempdir().unwrap();
    let foreign_dir = tempfile::tempdir().unwrap();
    let local_ceremony = common::setup_minimal_btn_ceremony(local_dir.path());
    let foreign_ceremony = common::setup_minimal_btn_ceremony(foreign_dir.path());
    let foreign = Runtime::init(&foreign_ceremony.yaml_path).unwrap();
    foreign
        .info("snapshot.foreign", serde_json::Map::new())
        .unwrap();
    let foreign_log = foreign.log_path().to_owned();

    let probe = std::sync::Arc::new(SnapshotProbeStorage::default());
    let storage: std::sync::Arc<dyn Storage> = probe.clone();
    let local = Runtime::init_with_storage(&local_ceremony.yaml_path, storage).unwrap();
    probe.arm_for(&foreign_log);
    let error = local
        .secure_read(SecureReadOptions {
            on_invalid: OnInvalid::Raise,
            log_path: Some(foreign_log),
        })
        .unwrap_err();

    assert!(matches!(error, Error::NotImplemented(_)), "{error}");
    assert_eq!(
        probe
            .snapshot_opens
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        probe.whole_reads.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}
