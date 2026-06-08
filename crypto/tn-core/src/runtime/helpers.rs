//! Miscellaneous runtime free helpers: UTC timestamp formatting,
//! event-type validation, cross-platform path resolution, and the
//! fresh-btn-ceremony minter used by `Runtime::ephemeral`.
//!
//! Split out of `runtime.rs` (file-size refactor). Behavior unchanged;
//! `use super::*` re-imports everything these helpers need from the parent.

use super::*;

pub(crate) fn current_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    // "2026-04-21T12:00:00.000000Z": microseconds, Z suffix. Matches Python.
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    );
    now.format(&fmt).expect("formatting infallible")
}

/// RFC-3339 timestamp matching Python's `datetime.now(tz.utc).isoformat()`
/// shape with offset suffix `+00:00`. Used by vault_link / vault_unlink so
/// the canonical row matches the Python emitter.
pub(crate) fn current_timestamp_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]+00:00"
    );
    now.format(&fmt).expect("formatting infallible")
}

pub(crate) fn validate_event_type(et: &str) -> Result<()> {
    if et.is_empty() {
        return Err(Error::InvalidConfig("event_type empty".into()));
    }
    if !et
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(Error::InvalidConfig(format!(
            "event_type has invalid chars: {et:?}"
        )));
    }
    Ok(())
}

pub(crate) fn resolve(base: &Path, p: &Path) -> PathBuf {
    if is_absolute_xplat_path(p) {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Cross-platform absolute-path test. Mirrors
/// `config::is_absolute_xplat` but works on `&Path` so callers in the
/// runtime don't have to round-trip through a string. Required for
/// wasm32 hosts on Windows where `Path::is_absolute()` follows Unix
/// rules and would mis-classify `C:\…` as relative, causing
/// `extends:`-resolved paths to double-join.
pub(crate) fn is_absolute_xplat_path(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    let s = p.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() >= 3 {
        let drive = bytes[0];
        if drive.is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\') {
            return true;
        }
    }
    false
}

/// Resolve the protocol-events-location template without a Runtime instance.
///
/// Only expands `{event_class}` to `"ceremony"` (the class of `tn.ceremony.init`),
/// plus `{yaml_dir}`, `{ceremony_id}`, and `{did}`. `{event_type}` becomes
/// `"tn.ceremony.init"`. `{date}` is not required for fresh-detection purposes;
/// the file either exists or it doesn't regardless of date.
pub(crate) fn resolve_pel_static(tmpl: &str, yaml_dir: &Path, ceremony_id: &str, did: &str) -> PathBuf {
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date = OffsetDateTime::now_utc()
        .format(&date_fmt)
        .unwrap_or_else(|_| "1970-01-01".to_string());
    let yaml_dir_s = yaml_dir.to_string_lossy().into_owned();
    // `{event_class}` is the first dotted segment of `tn.ceremony.init`
    // = `tn` (matches Python/PathTemplate, not the prior `nth(1)`
    // shorthand which would yield `ceremony`). The init-time fresh-
    // detection scan and the emit-time write must agree on the
    // rendered path, otherwise restart re-emits `tn.ceremony.init`.
    let filled = tmpl
        .replace("{event_type}", "tn.ceremony.init")
        .replace("{event_class}", "tn")
        .replace("{date}", &date)
        .replace("{yaml_dir}", &yaml_dir_s)
        .replace("{ceremony_id}", ceremony_id)
        .replace("{did}", did);
    // Anchor relative templates at the yaml dir — same fix as
    // ``Runtime::resolve_pel``. Without it, fresh-detection scans the
    // wrong file (process cwd) and we end up emitting tn.ceremony.init
    // twice on a re-init.
    let p = PathBuf::from(filled);
    if is_absolute_xplat_path(&p) {
        p
    } else {
        yaml_dir.join(p)
    }
}

/// Mint a fresh btn ceremony at `root`. Layout matches the test helper
/// in `tests/common/mod.rs::setup_minimal_btn_ceremony`:
///
/// ```text
/// <root>/
///   .tn/
///     keys/
///       local.private        — 32-byte Ed25519 seed
///       index_master.key     — 32 random bytes
///       default.btn.state    — serialized PublisherState
///       default.btn.mykit    — minted ReaderKit
///       tn.agents.btn.state  — serialized PublisherState (reserved policy group)
///       tn.agents.btn.mykit  — minted ReaderKit (reserved policy group)
///   tn.yaml
/// ```
///
/// Used by [`Runtime::ephemeral`]. Lives in the public crate so
/// downstream tests + benches don't have to duplicate it.
///
/// Auto-injects the reserved `tn.agents` group per the 2026-04-25
/// read-ergonomics spec §2.3. Pure-logging users pay nothing — the
/// group's plaintext stays empty when no policy file exists.
pub(crate) fn write_fresh_btn_ceremony(root: &Path) -> std::io::Result<()> {
    use crate::keystore_backend::atomic_write_bytes;
    use rand_core::{OsRng, RngCore};

    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore)?;

    // Every write below uses atomic_write_bytes (tmp + fsync +
    // rename) so a crash mid-mint never leaves a half-formed
    // keystore on disk — partial state files would fail to parse on
    // next load and burn the ceremony silently. No CAS here because
    // this is fresh-ceremony init: by construction nobody else is
    // writing to this keystore yet.

    // Device key — 32-byte Ed25519 seed.
    let dk = crate::DeviceKey::generate();
    atomic_write_bytes(&keystore.join("local.private"), &dk.private_bytes())?;

    // Master index key — 32 random bytes from the OS.
    let mut master = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    atomic_write_bytes(&keystore.join("index_master.key"), &master)?;

    // default group: btn publisher state + self-reader kit.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed).map_err(|e| {
            std::io::Error::other(format!("btn setup failed: {e:?}"))
        })?;
    let kit = pub_state.mint().map_err(|e| {
        std::io::Error::other(format!("btn mint failed: {e:?}"))
    })?;
    atomic_write_bytes(&keystore.join("default.btn.state"), &pub_state.to_bytes())?;
    atomic_write_bytes(&keystore.join("default.btn.mykit"), &kit.to_bytes())?;

    // tn.agents reserved group: btn publisher state + self-reader kit.
    let mut agents_seed = [0u8; 32];
    OsRng.fill_bytes(&mut agents_seed);
    let mut agents_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, agents_seed).map_err(|e| {
            std::io::Error::other(format!("btn setup (tn.agents) failed: {e:?}"))
        })?;
    let agents_kit = agents_state
        .mint()
        .map_err(|e| std::io::Error::other(format!("btn mint (tn.agents) failed: {e:?}")))?;
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.state"),
        &agents_state.to_bytes(),
    )?;
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.mykit"),
        &agents_kit.to_bytes(),
    )?;

    let did = dk.did().to_string();
    let id = format!("cer_eph_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let yaml = format!(
        "ceremony: {{id: {id}, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    crate::keystore_backend::atomic_write_bytes(&root.join("tn.yaml"), yaml.as_bytes())?;
    Ok(())
}
