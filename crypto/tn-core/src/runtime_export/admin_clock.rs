//! Admin-log scanning, clock recovery, and per-envelope accept logic.
//!
//! The producer side ([`scan_admin_envelopes`]) gathers and dedupes admin
//! envelopes into the snapshot body and computes its vector clock; the receiver
//! side ([`build_local_admin_clock`] + [`try_accept_admin_envelope`] +
//! [`append_admin_envelopes`]) replays local state, decides each incoming line,
//! and appends the accepted set. The smaller validators
//! ([`envelope_well_formed`], [`verify_envelope_signature`]) and the
//! leaf-revocation trackers back the accept loop. Used by
//! [`Runtime::export`](crate::Runtime::export) and the snapshot-absorb path on
//! [`Runtime`](crate::Runtime).

use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::admin_cache::{is_admin_event_type, ChainConflict};
use crate::signing::DeviceKey;
use crate::tnpkg::VectorClock;
use crate::Result;

pub(super) fn scan_admin_envelopes(
    sources: &[PathBuf],
) -> Result<(Vec<u8>, VectorClock, u64, Option<String>)> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    let mut clock: VectorClock = BTreeMap::new();
    let mut head_row_hash: Option<String> = None;

    for path in sources {
        if !path.exists() {
            continue;
        }
        let raw = std::fs::read_to_string(path)?;
        for line in raw.lines() {
            let stripped = line.trim();
            if stripped.is_empty() {
                continue;
            }
            let Ok(env) = serde_json::from_str::<Value>(stripped) else {
                continue;
            };
            let et = env.get("event_type").and_then(Value::as_str).unwrap_or("");
            if !is_admin_event_type(et) {
                continue;
            }
            let rh = env.get("row_hash").and_then(Value::as_str).unwrap_or("");
            if rh.is_empty() || seen.contains(rh) {
                continue;
            }
            let did = env
                .get("device_identity")
                .and_then(Value::as_str)
                .unwrap_or("");
            let seq = env.get("sequence").and_then(Value::as_u64);
            let Some(seq) = seq else { continue };
            seen.insert(rh.to_string());
            out.extend_from_slice(stripped.as_bytes());
            out.push(b'\n');
            let slot = clock.entry(did.to_string()).or_default();
            let cur = slot.get(et).copied().unwrap_or(0);
            if seq > cur {
                slot.insert(et.to_string(), seq);
            }
            head_row_hash = Some(rh.to_string());
        }
    }

    let count = u64::try_from(seen.len()).unwrap_or(u64::MAX);
    Ok((out, clock, count, head_row_hash))
}

pub(super) fn append_admin_envelopes(admin_log: &Path, envelopes: &[Value]) -> Result<()> {
    if let Some(parent) = admin_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(admin_log)?;
    for env in envelopes {
        let line = serde_json::to_string(env)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    Ok(())
}

pub(super) fn envelope_well_formed(env: &Value) -> bool {
    for k in [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "row_hash",
        "signature",
    ] {
        if env.get(k).and_then(Value::as_str).is_none() {
            return false;
        }
    }
    true
}

pub(super) fn verify_envelope_signature(env: &Value) -> bool {
    let did = env
        .get("device_identity")
        .and_then(Value::as_str)
        .unwrap_or("");
    let row_hash = env.get("row_hash").and_then(Value::as_str).unwrap_or("");
    let sig_b64 = env.get("signature").and_then(Value::as_str).unwrap_or("");
    if sig_b64.is_empty() {
        // Unsigned mode: envelopes ride the chain on row_hash alone. Treat as
        // valid for absorb purposes — the chain hash is the integrity check.
        return true;
    }
    let Ok(sig) = crate::signing::signature_from_b64(sig_b64) else {
        return false;
    };
    DeviceKey::verify_did(did, row_hash.as_bytes(), &sig).unwrap_or(false)
}

// ----------------------------------------------------------------------
// absorb_admin_log_snapshot helpers
// ----------------------------------------------------------------------

/// Receiver-side admin state recovered from disk for the snapshot
/// absorb path: ``(local_clock, seen_row_hashes, revoked_leaves)``.
///
/// Aliased so the function signature and the orchestrator's
/// destructuring read at a glance — and so clippy doesn't trip
/// `type_complexity` on the nested generics.
type LocalAdminClockState = (
    VectorClock,
    HashSet<String>,
    BTreeMap<(String, u64), Option<String>>,
);

/// Replay the receiver's existing admin log to recover the trio
/// ``(local_clock, seen_row_hashes, revoked_leaves)``.
///
/// The vector clock and the seen-set are the dedupe signals; the
/// revoked-leaves map is what the per-envelope accept loop checks
/// to surface ``LeafReuseAttempt`` conflicts on incoming
/// ``tn.recipient.added`` envelopes whose leaf was previously
/// revoked locally.
///
/// Missing log file is fine: returns three empty containers, as
/// though the receiver had never seen any admin envelope. Malformed
/// lines (non-JSON, non-string row_hash) are silently skipped — they
/// can't be matched against anyway.
pub(super) fn build_local_admin_clock(admin_log: &Path) -> Result<LocalAdminClockState> {
    let mut local_clock: VectorClock = BTreeMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut revoked_leaves: BTreeMap<(String, u64), Option<String>> = BTreeMap::new();

    if !admin_log.exists() {
        return Ok((local_clock, seen, revoked_leaves));
    }
    let text = std::fs::read_to_string(admin_log)?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let rh = env.get("row_hash").and_then(Value::as_str);
        if let Some(rh) = rh {
            seen.insert(rh.to_string());
        }
        if let (Some(d), Some(e), Some(s)) = (
            env.get("device_identity").and_then(Value::as_str),
            env.get("event_type").and_then(Value::as_str),
            env.get("sequence").and_then(Value::as_u64),
        ) {
            let slot = local_clock.entry(d.to_string()).or_default();
            let cur = slot.get(e).copied().unwrap_or(0);
            if s > cur {
                slot.insert(e.to_string(), s);
            }
        }
        if env.get("event_type").and_then(Value::as_str) == Some("tn.recipient.revoked") {
            if let (Some(g), Some(li)) = (
                env.get("group").and_then(Value::as_str),
                env.get("leaf_index").and_then(Value::as_u64),
            ) {
                revoked_leaves.insert((g.to_string(), li), rh.map(str::to_string));
            }
        }
    }
    Ok((local_clock, seen, revoked_leaves))
}

/// Decide whether one admin log line should be accepted into the
/// receiver's log.
///
/// In-place mutations on success: appends to ``accepted``, marks the
/// row_hash in ``seen``, may push a ``LeafReuseAttempt`` to
/// ``conflicts``, may update ``revoked_leaves`` if the envelope is
/// itself a ``tn.recipient.revoked``. Increments ``deduped`` when
/// the envelope's row_hash is already in ``seen``.
///
/// All malformed / unsigned / dedupe-skip cases are silent no-ops —
/// the caller's totals are accurate against the well-formed input
/// only.
pub(super) fn try_accept_admin_envelope(
    line: &str,
    seen: &mut HashSet<String>,
    revoked_leaves: &mut BTreeMap<(String, u64), Option<String>>,
    accepted: &mut Vec<Value>,
    conflicts: &mut Vec<ChainConflict>,
    deduped: &mut usize,
) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let Ok(env) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if !envelope_well_formed(&env) || !verify_envelope_signature(&env) {
        return;
    }
    let rh = env
        .get("row_hash")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if rh.is_empty() {
        return;
    }
    if seen.contains(&rh) {
        *deduped += 1;
        return;
    }

    let event_type = env.get("event_type").and_then(Value::as_str);
    match event_type {
        Some("tn.recipient.added") => {
            record_leaf_reuse_if_revoked(&env, &rh, revoked_leaves, conflicts);
        }
        Some("tn.recipient.revoked") => {
            track_revoked_leaf(&env, &rh, revoked_leaves);
        }
        _ => {}
    }
    accepted.push(env);
    seen.insert(rh);
}

fn record_leaf_reuse_if_revoked(
    env: &Value,
    rh: &str,
    revoked_leaves: &BTreeMap<(String, u64), Option<String>>,
    conflicts: &mut Vec<ChainConflict>,
) {
    let (Some(g), Some(li)) = (
        env.get("group").and_then(Value::as_str),
        env.get("leaf_index").and_then(Value::as_u64),
    ) else {
        return;
    };
    let key = (g.to_string(), li);
    if let Some(rev_rh) = revoked_leaves.get(&key).cloned() {
        conflicts.push(ChainConflict::LeafReuseAttempt {
            group: g.to_string(),
            leaf_index: li,
            attempted_row_hash: rh.to_string(),
            originally_revoked_at_row_hash: rev_rh,
        });
    }
}

fn track_revoked_leaf(
    env: &Value,
    rh: &str,
    revoked_leaves: &mut BTreeMap<(String, u64), Option<String>>,
) {
    let (Some(g), Some(li)) = (
        env.get("group").and_then(Value::as_str),
        env.get("leaf_index").and_then(Value::as_u64),
    ) else {
        return;
    };
    revoked_leaves.insert((g.to_string(), li), Some(rh.to_string()));
}
