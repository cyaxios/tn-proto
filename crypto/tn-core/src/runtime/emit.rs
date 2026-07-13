//! The write path: build, seal, sign, chain, and append an attested
//! event, then fan it out to handlers.
//!
//! Holds the public write family ([`Runtime::log`] / [`Runtime::info`] /
//! [`Runtime::warning`] / [`Runtime::error`] / [`Runtime::debug`] and the
//! lower-level `emit*` variants), the single canonical
//! `emit_inner` builder, handler registration / fan-out, the `tn.agents`
//! policy splice, and the protocol-event-location resolver. The read-back
//! side lives in the `read` submodule.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    admin_catalog,
    canonical::canonical_bytes,
    chain::{chain_tip_from_log_tail_reverse, compute_row_hash, GroupInput, RowHashInput},
    classifier::classify,
    envelope::{build_envelope, EnvelopeInput, GroupPayload},
    indexing::index_token_with_template,
    signing::signature_b64,
    Error, Result,
};

use super::util::{current_timestamp, validate_event_type};

/// Effective AAD marker for a group: its configured default overlaid by the
/// per-emit marker (per-emit wins per key). Returns an empty map when both
/// are empty so the caller seals with no binding.
fn merge_aad(default: &Map<String, Value>, per_emit: &Map<String, Value>) -> Map<String, Value> {
    if default.is_empty() && per_emit.is_empty() {
        return Map::new();
    }
    let mut out = default.clone();
    for (k, v) in per_emit {
        out.insert(k.clone(), v.clone());
    }
    out
}
use super::{level_value, Runtime, LOG_LEVEL_THRESHOLD};

/// Borrowed inputs [`Runtime::build_and_write`] needs to hash, sign,
/// serialize, and append one row. Bundles the per-emit locals so the three
/// write branches in `emit_inner` (locked / chained-per-event / unchained)
/// each pass a single reference instead of a long argument list.
struct EmitWriteCtx<'a> {
    ts: &'a str,
    eid: &'a str,
    event_type: &'a str,
    level_norm: &'a str,
    need_row_hash: bool,
    sign: Option<bool>,
    pel_routed: bool,
    public_out: &'a Map<String, Value>,
    group_inputs: &'a BTreeMap<String, GroupInput>,
    group_payloads: &'a BTreeMap<String, String>,
}

impl Runtime {
    /// Write one attested event at `level` with the current timestamp
    /// and a fresh time-sortable event_id.
    ///
    /// This is the general write primitive behind the level shortcuts
    /// ([`Runtime::info`], [`Runtime::warning`], …). `level` is one of
    /// `"debug"` / `"info"` / `"warning"` / `"error"` (case-insensitive)
    /// or `""` for a severity-less fact; an event whose level is below
    /// the active [`Runtime::set_level`] threshold is dropped (and `Ok`
    /// is returned). `fields` are classified per the yaml: each routes to
    /// its group's encrypted block or to the public envelope; a
    /// per-runtime `run_id` is auto-injected so [`Runtime::read`] can
    /// default-filter to the current run.
    ///
    /// The entry is sealed, hash-chained, optionally signed (per the
    /// ceremony's `sign` flag — override with
    /// [`Runtime::emit_override_sign`]), appended to the log, and fanned
    /// out to every attached handler.
    ///
    /// Returns `Result<()>` for cross-language parity (Python `tn.log`
    /// returns `None`, TS `tn.log` returns `void`). Internal callers that
    /// need the row_hash / event_id / sequence drop down to `emit_inner`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) if
    /// `event_type` is empty or has illegal characters, or a field has no
    /// group route and no `default` group to absorb it.
    /// [`Error::Malformed`](crate::Error::Malformed) if a known `tn.*`
    /// admin event fails its catalog schema. [`Error::Io`](crate::Error::Io)
    /// if the log can't be written, plus cipher / JSON errors from
    /// sealing the payload. Handler fan-out failures are logged and
    /// swallowed, never returned.
    ///
    /// # Panics
    ///
    /// Panics if an internal log-writer or group-state lock is poisoned.
    pub fn emit(&self, level: &str, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit_inner(level, event_type, fields, None, None, None, &Map::new())
            .map(|_| ())
    }

    /// Write an attested event with an explicit `timestamp` and
    /// `event_id`; used by deterministic tests and replay.
    ///
    /// Signing follows the ceremony's `sign` config flag. Use
    /// [`Runtime::emit_override_sign`] or [`Runtime::emit_with_override_sign`]
    /// when the caller wants to flip signing for one entry.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    ///
    /// # Panics
    ///
    /// Panics if the internal log-writer mutex is poisoned.
    pub fn emit_with(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<()> {
        self.emit_inner(
            level,
            event_type,
            fields,
            timestamp,
            event_id,
            None,
            &Map::new(),
        )
        .map(|_| ())
    }

    /// Write an attested event with an explicit `sign` override, current
    /// timestamp, and a fresh event_id.
    ///
    /// `Some(true)` forces a signature regardless of yaml config;
    /// `Some(false)` skips the signature; `None` uses the ceremony default.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn emit_override_sign(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        sign: Option<bool>,
    ) -> Result<()> {
        self.emit_inner(level, event_type, fields, None, None, sign, &Map::new())
            .map(|_| ())
    }

    /// Write an attested event with full control: explicit timestamp,
    /// event_id, and sign override.
    ///
    /// `sign=None` uses the ceremony default; `Some(true)` forces signing;
    /// `Some(false)` skips signing.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn emit_with_override_sign(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<()> {
        self.emit_inner(
            level,
            event_type,
            fields,
            timestamp,
            event_id,
            sign,
            &Map::new(),
        )
        .map(|_| ())
    }

    /// Same as [`Runtime::emit_with_override_sign`] but returns the canonical
    /// envelope NDJSON line (newline-terminated) so the host can fan out to
    /// its own handlers without re-deriving it. `Ok(None)` means the emit
    /// was filtered by the log-level threshold and produced no envelope.
    ///
    /// Used by the Python `DispatchRuntime` to run user-registered Python
    /// handlers (kafka, S3, vault.sync, etc.) after the Rust runtime has
    /// already written the entry, signed it, advanced the chain, and fanned
    /// out to its own native handlers (file, stdout). Mirrors what TS does
    /// natively in-process — Python pays the JSON-parse cost once on the
    /// returned line rather than re-encrypting + re-signing in pure Python.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn emit_with_override_sign_returning_line(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<Option<String>> {
        self.emit_inner(
            level,
            event_type,
            fields,
            timestamp,
            event_id,
            sign,
            &Map::new(),
        )
    }

    /// Same as [`emit_with_override_sign_returning_line`] but binds an AAD
    /// marker map (per-emit, overlaid onto each group's configured default)
    /// into the sealed bodies and echoes it under the public `tn_aad` field.
    ///
    /// [`emit_with_override_sign_returning_line`]: Self::emit_with_override_sign_returning_line
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn emit_with_aad_returning_line(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
        aad: &Map<String, Value>,
    ) -> Result<Option<String>> {
        self.emit_inner(level, event_type, fields, timestamp, event_id, sign, aad)
    }

    /// Write a severity-less attested event. Backs `tn.log()`.
    ///
    /// Use when the event isn't fundamentally debug/info/warning/error —
    /// it's a fact to attest. The envelope carries `level: ""`, which
    /// always passes the [`Runtime::set_level`] threshold (a fact's
    /// semantics shouldn't depend on the filter).
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn log(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("", event_type, fields)
    }

    /// Write a DEBUG-level attested event. Backs `tn.debug()`.
    ///
    /// Dropped when the active threshold is above DEBUG — see
    /// [`Runtime::set_level`].
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn debug(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("debug", event_type, fields)
    }

    /// Write an INFO-level attested event. Backs `tn.info()`.
    ///
    /// Dropped when the active threshold is above INFO — see
    /// [`Runtime::set_level`].
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::Runtime;
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::ephemeral()?;
    /// let mut fields = serde_json::Map::new();
    /// fields.insert("order_id".into(), serde_json::json!("ord_123"));
    /// rt.info("order.placed", fields)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn info(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("info", event_type, fields)
    }

    /// Write a WARNING-level attested event. Backs `tn.warning()`.
    ///
    /// Dropped when the active threshold is above WARNING — see
    /// [`Runtime::set_level`].
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn warning(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("warning", event_type, fields)
    }

    /// Write an ERROR-level attested event. Backs `tn.error()`.
    ///
    /// The highest standard level — always passes any standard threshold.
    /// See [`Runtime::set_level`].
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn error(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("error", event_type, fields)
    }

    /// Route each field to the public envelope or to its encrypted
    /// group(s). Step 1 of [`Runtime::emit`]'s pipeline.
    ///
    /// Multi-group routing: a field declared under N groups in yaml
    /// (`groups[<g>].fields: [...]`) is encrypted into all N groups'
    /// payloads. The `field_to_groups` table is precomputed at
    /// `Runtime::init` (0.4.2a7 — was rebuilt every emit) and sorted
    /// alphabetically per field at load time so envelope encoding stays
    /// canonical across SDK implementations.
    ///
    /// A field lands in the public map when ANY of these hold: it is
    /// listed in top-level `public_fields`, or it routes to a group whose
    /// policy is `"public"`. Everything else goes through the per-group
    /// encrypt path. Multi-group fan-out clones the field into each target.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) when a field
    /// has no declared route, the classifier guess is not a known group,
    /// and there is no `default` group to absorb it.
    ///
    /// `pub(crate)`: also the classification step of `Runtime::seal`
    /// (runtime/seal.rs), which calls it directly — without the emit
    /// prelude's run_id injection or agent-policy splice.
    pub(crate) fn classify_fields(
        &self,
        fields: Map<String, Value>,
    ) -> Result<(Map<String, Value>, BTreeMap<String, Map<String, Value>>)> {
        let field_to_groups = &self.field_to_groups;
        let public_set = &self.public_set;
        let public_groups = &self.public_groups;
        let t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let mut public_out: Map<String, Value> = Map::new();
        let mut per_group: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for (k, v) in fields {
            if public_set.contains(&k) {
                public_out.insert(k, v);
                continue;
            }
            if let Some(routed) = field_to_groups.get(&k) {
                if routed.len() == 1 {
                    // Single-group: most common case. Avoid the
                    // v.clone() that the multi-group path needs
                    // on the last iteration.
                    let gname = &routed[0];
                    if public_groups.contains(gname) {
                        public_out.insert(k, v);
                    } else {
                        per_group.entry(gname.clone()).or_default().insert(k, v);
                    }
                } else {
                    for gname in routed {
                        if public_groups.contains(gname) {
                            public_out.insert(k.clone(), v.clone());
                        } else {
                            per_group
                                .entry(gname.clone())
                                .or_default()
                                .insert(k.clone(), v.clone());
                        }
                    }
                }
            } else {
                // Field has no declared route. Try the legacy
                // classifier (returns a single name today,
                // "default" by stub). If that lands in a known
                // group, use it; otherwise fall back to the
                // "default" group when present. Last resort:
                // raise.
                let guess = classify(&self.cfg, &k);
                let target = if self.cfg.groups.contains_key(guess) {
                    guess.to_string()
                } else if self.cfg.groups.contains_key("default") {
                    "default".to_string()
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "field {k:?} has no group route and is not in \
                         public_fields. Add it to `groups[<g>].fields` in \
                         tn.yaml, list it under public_fields, or define a \
                         `default` group to absorb unknowns."
                    )));
                };
                if public_groups.contains(&target) {
                    public_out.insert(k, v);
                } else {
                    per_group.entry(target).or_default().insert(k, v);
                }
            }
        }
        if let Some(t0) = t0 {
            crate::perf::record_ns("emit:field_classify", t0.elapsed().as_nanos() as u64);
        }
        Ok((public_out, per_group))
    }

    /// Index, canonicalize, and encrypt each per-group field set into the
    /// `(group_inputs_for_hash, group_payloads)` the envelope build
    /// consumes. Steps 2–3 of [`Runtime::emit`]'s pipeline.
    ///
    /// `group_inputs_for_hash` is only built when `need_row_hash` is true
    /// (chain or sign consumes it); in pure-log mode (chain=F sign=F) the
    /// clones are skipped. `group_payloads` carries the pre-rendered JSON
    /// snippet per group so `build_envelope` splices it verbatim. A cipher's
    /// `NotAPublisher` error is propagated so routed private fields cannot be
    /// silently omitted.
    ///
    /// # Errors
    ///
    /// Cipher / index-token / canonical-bytes / JSON errors from sealing a
    /// group's payload.
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state `RwLock` is poisoned.
    ///
    /// `pub(crate)`: also the encrypt step of `Runtime::seal`
    /// (runtime/seal.rs), which reuses the per-group sort / index-token
    /// / AAD-merge / encrypt pipeline for standalone objects.
    pub(crate) fn encrypt_groups(
        &self,
        per_group: BTreeMap<String, Map<String, Value>>,
        aad: &Map<String, Value>,
        need_row_hash: bool,
    ) -> Result<(
        BTreeMap<String, GroupInput>,
        BTreeMap<String, String>,
        Map<String, Value>,
    )> {
        let mut group_inputs_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
        // Per-group effective markers actually bound, echoed as `tn_aad`.
        let mut aad_echo: Map<String, Value> = Map::new();
        // group_payloads (0.4.2a7): pre-rendered JSON snippets rather
        // than serde_json::Value trees. envelope_build splices the
        // raw snippet in verbatim, skipping a `to_value` tree alloc
        // here AND a re-walk inside envelope_build.
        let mut group_payloads: BTreeMap<String, String> = BTreeMap::new();

        let _group_encrypt_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };

        for (gname, plain) in per_group {
            let Some(gstate_arc) = self.groups.get(&gname) else {
                // Field routed to a group we don't know; skip silently, matching
                // Python's fall-through to "default".
                continue;
            };
            let gstate = gstate_arc.read().expect("group state RwLock poisoned");
            let (maybe_input, payload_json, effective_aad) =
                Self::seal_one_group(&gstate, plain, aad, need_row_hash)?;
            if let Some(input) = maybe_input {
                group_inputs_for_hash.insert(gname.clone(), input);
            }
            if !effective_aad.is_empty() {
                aad_echo.insert(gname.clone(), Value::Object(effective_aad));
            }
            group_payloads.insert(gname, payload_json);
        }

        if let Some(t0) = _group_encrypt_t0 {
            crate::perf::record_ns("emit:group_encrypt", t0.elapsed().as_nanos() as u64);
        }

        Ok((group_inputs_for_hash, group_payloads, aad_echo))
    }

    /// Index, canonicalize, encrypt, and render one group's field set.
    /// The per-group body of [`Runtime::encrypt_groups`].
    ///
    /// Returns the rendered payload JSON plus, when `need_row_hash` is set,
    /// the `GroupInput` the row-hash compute consumes (skipped in pure-log
    /// mode to avoid the clones).
    ///
    /// # Errors
    ///
    /// Index-token, canonical-bytes, cipher, or JSON-render errors.
    fn seal_one_group(
        gstate: &super::GroupState,
        plain: Map<String, Value>,
        per_emit_aad: &Map<String, Value>,
        need_row_hash: bool,
    ) -> Result<(Option<GroupInput>, String, Map<String, Value>)> {
        // Sub-stage timing inside group_encrypt. emit:group_encrypt
        // (outer) is still the total; these four sum to it.
        let _sort_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let sorted: BTreeMap<String, Value> = plain.into_iter().collect();
        if let Some(t0) = _sort_t0 {
            crate::perf::record_ns("emit:group_encrypt.sort", t0.elapsed().as_nanos() as u64);
        }

        let _idx_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &sorted {
            field_hashes.insert(
                k.clone(),
                index_token_with_template(&gstate.hmac_template, k, v)?,
            );
        }
        if let Some(t0) = _idx_t0 {
            crate::perf::record_ns(
                "emit:group_encrypt.index_token",
                t0.elapsed().as_nanos() as u64,
            );
        }

        let _canon_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let plaintext_bytes = canonical_bytes(&Value::Object(sorted.into_iter().collect()))?;
        if let Some(t0) = _canon_t0 {
            crate::perf::record_ns(
                "emit:group_encrypt.canonical_bytes",
                t0.elapsed().as_nanos() as u64,
            );
        }

        let _enc_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        // Effective marker = group default overlaid by the per-emit marker
        // (per-emit wins per key). When non-empty it is canonicalized and
        // bound into the body AEAD; empty binds nothing (byte-identical to a
        // plain seal). The effective map is returned so the caller echoes it.
        let effective_aad = merge_aad(&gstate.aad_default, per_emit_aad);
        let ct = if effective_aad.is_empty() {
            gstate.cipher.encrypt(&plaintext_bytes)?
        } else {
            let aad_bytes =
                crate::canonical::canonical_bytes(&Value::Object(effective_aad.clone()))?;
            gstate
                .cipher
                .encrypt_with_aad(&plaintext_bytes, &aad_bytes)?
        };
        if let Some(t0) = _enc_t0 {
            crate::perf::record_ns("emit:group_encrypt.cipher", t0.elapsed().as_nanos() as u64);
        }

        let _build_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        // group_inputs_for_hash only feeds compute_row_hash; skip
        // the clones when no row_hash will be computed (chain=F
        // sign=F pure-log mode).
        let maybe_input = if need_row_hash {
            Some(GroupInput {
                ciphertext: ct.clone(),
                field_hashes: field_hashes.clone(),
            })
        } else {
            None
        };
        // Render GroupPayload to a JSON snippet directly via
        // serde_json::to_string. Skips the prior `to_value`
        // intermediate that envelope_build then had to re-walk.
        let payload = GroupPayload {
            ciphertext: ct,
            field_hashes,
        };
        let payload_json = serde_json::to_string(&payload)?;
        if let Some(t0) = _build_t0 {
            crate::perf::record_ns(
                "emit:group_encrypt.payload_build",
                t0.elapsed().as_nanos() as u64,
            );
        }
        Ok((maybe_input, payload_json, effective_aad))
    }

    /// Refresh the in-memory chain tip for `event_type` from on-disk truth
    /// while the cross-process advisory lock is held. The tail-scan body of
    /// [`Runtime::emit`]'s chained write path.
    ///
    /// If another process appended rows since our last emit, this is where
    /// we discover the latest `(seq, prev_hash)` for our event_type and
    /// overwrite the local `ChainState` entry. A writer-pool failure is
    /// parked in `deferred_err` and surfaced as an io error so the caller
    /// re-raises the original error after releasing the lock; a read-tail
    /// failure maps straight to an io error.
    ///
    /// Reverse-scans only the tail window (0.4.2a7 perf fix): we care about
    /// one event_type's tip, not the full tips map, so stopping at the
    /// first matching row keeps the hot path O(scan-window) rather than the
    /// prior O(filesize) forward scan. See
    /// `chain.rs::chain_tip_from_log_tail_reverse` and the S11 stress
    /// regression that surfaced the issue.
    ///
    /// # Panics
    ///
    /// Panics if the log-writer mutex is poisoned.
    fn refresh_chain_tip_under_lock(
        &self,
        pel_routed: bool,
        event_type: &str,
        eid: &str,
        deferred_err: &mut Option<Error>,
    ) -> std::io::Result<()> {
        let _tip_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        // Tail-byte windowing (0.4.2a7 perf fix). The chain
        // tip is always near the end of the log — the row we
        // just emitted last time is right before whatever
        // someone else may have appended since. Reading the
        // whole file every emit (which the prior version
        // did) cost ~10 ms on a 1 MB log; reading 64 KB of
        // tail through a PINNED read handle costs ~50 µs.
        //
        // The pinned read handle (`log_writer.read_tail`) is
        // what makes this fast on Windows: opening a fresh
        // read handle while our own writer holds an append
        // handle to the same file costs ~9 ms on NTFS
        // (share-mode reconciliation / AV scan). The pinned
        // handle skips that cost — `seek + read` on an
        // already-open file is ~50 µs.
        //
        // For chain=T emits targeting a PEL admin path (rare:
        // only fires when admin events are chained AND the
        // PEL is not "main_log"), we fall back to
        // `storage.read_bytes_tail` which opens a fresh
        // handle. That path pays the ~9 ms once per
        // admin emit but admin emits are rare so the
        // amortized cost is negligible.
        //
        // Cold path (no match in window): the in-memory
        // chain state is already seeded from a whole-file
        // scan at `Runtime::init`, so missing the tip in the
        // tail just leaves the existing in-memory tip in
        // place. This is a known, accepted trade-off.
        const TIP_REFRESH_TAIL_WINDOW: usize = 64 * 1024;
        // Pinned-read fast path with single-writer skip
        // (0.4.2a7). `read_tail_if_grown` returns None when
        // the file's current size matches what we wrote
        // ourselves — no other process appended,
        // in-memory chain tip is current, no read needed.
        // In multi-writer setups this falls through to a
        // full tail read.
        //
        // PEL admin emits use the same pinned-writer pool
        // (0.4.2a8 PEL pinned-writer fix), so the tip
        // refresh for `pel_routed=true` consults
        // `pel_writer` and gets the same machinery.
        //
        // The file-not-yet-created case (very first emit
        // before any append) yields NotFound from the lazy
        // reader open; treat as "no prior rows, leave
        // in-memory tip alone".
        let writers = if pel_routed {
            &self.pel_writer
        } else {
            &self.log_writer
        };
        let writer_arc = match writers.writer_for(event_type, eid) {
            Ok(a) => a,
            Err(e) => {
                *deferred_err = Some(e);
                return Err(std::io::Error::other("writer_for failed (deferred)"));
            }
        };
        let bytes_opt: Option<Vec<u8>> = {
            let w = writer_arc.lock().expect("log writer mutex poisoned");
            match w.read_tail_if_grown(TIP_REFRESH_TAIL_WINDOW) {
                Ok(opt) => opt,
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(e).map_err(|err| std::io::Error::other(format!("read_tail: {err}")))
                }
            }
        };
        if let Some(bytes) = bytes_opt {
            if let Some((tip_seq, tip_hash)) = chain_tip_from_log_tail_reverse(&bytes, event_type) {
                let mut single: HashMap<String, (u64, String)> = HashMap::new();
                single.insert(event_type.to_string(), (tip_seq, tip_hash));
                self.chain.seed(single);
            }
        }
        if let Some(t0) = _tip_t0 {
            crate::perf::record_ns("emit:tip_refresh", t0.elapsed().as_nanos() as u64);
        }
        Ok(())
    }

    /// Hash, sign, serialize, and append one row, returning
    /// `(row_hash, line)`. Steps 5–8 of [`Runtime::emit`]'s pipeline,
    /// shared by all three write branches in `emit_inner` (locked,
    /// chained-per-event, unchained).
    ///
    /// The caller supplies `seq` + `prev_hash` (the chain-advance output)
    /// and the borrowed [`EmitWriteCtx`]; on error the caller parks the
    /// returned [`Error`] in its `deferred_err` slot and re-raises it after
    /// releasing the advisory lock. Pure-log mode (chain=F sign=F) ships
    /// the empty `row_hash` / `signature` sentinels.
    ///
    /// # Errors
    ///
    /// Envelope-build, writer-pool, append, or flush failures.
    ///
    /// # Panics
    ///
    /// Panics if the log-writer mutex is poisoned.
    fn build_and_write(
        &self,
        seq: u64,
        prev_hash: &str,
        ctx: &EmitWriteCtx<'_>,
    ) -> Result<(String, String)> {
        // 5. Row hash — skipped when neither chain nor sign
        //    consumes it (chain=F sign=F pure-log mode).
        let _rh_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let row_hash = if ctx.need_row_hash {
            let public_bmap: BTreeMap<String, Value> = ctx.public_out.clone().into_iter().collect();
            compute_row_hash(&RowHashInput {
                device_identity: self.device.did(),
                timestamp: ctx.ts,
                event_id: ctx.eid,
                event_type: ctx.event_type,
                level: ctx.level_norm,
                prev_hash,
                public_fields: &public_bmap,
                groups: ctx.group_inputs,
            })
        } else {
            // Pure-log mode (chain=F sign=F): no consumer.
            // Envelope ships ``row_hash: ""`` as the
            // documented unchained-and-unsigned sentinel,
            // matching prev_hash="" and signature="".
            String::new()
        };
        if let Some(t0) = _rh_t0 {
            crate::perf::record_ns("emit:row_hash", t0.elapsed().as_nanos() as u64);
        }

        // 6. Sign: respects per-call override, then ceremony default.
        let _sign_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let should_sign = ctx.sign.unwrap_or(self.cfg.ceremony.sign);
        let sig_b64 = if should_sign {
            let sig = self.device.sign(row_hash.as_bytes());
            signature_b64(&sig)
        } else {
            String::new()
        };
        if let Some(t0) = _sign_t0 {
            crate::perf::record_ns("emit:sign", t0.elapsed().as_nanos() as u64);
        }

        // 7. Envelope serialize.
        let _env_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let line = build_envelope(EnvelopeInput {
            device_identity: self.device.did(),
            timestamp: ctx.ts,
            event_id: ctx.eid,
            event_type: ctx.event_type,
            level: ctx.level_norm,
            sequence: seq,
            prev_hash,
            row_hash: &row_hash,
            signature_b64: &sig_b64,
            public_fields: ctx.public_out.clone(),
            group_payloads: ctx.group_payloads.clone(),
        })?;
        if let Some(t0) = _env_t0 {
            crate::perf::record_ns("emit:envelope_build", t0.elapsed().as_nanos() as u64);
        }

        // 8. Append to log file (or the resolved pel for tn.* events).
        let _wr_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        // Get-or-create the writer for this event_type's
        // rendered path. PEL admin emits route through
        // `pel_writer`; everything else through `log_writer`.
        // Both fields are pinned-writer pools so the syscall
        // floor matches whether we're writing to the main log
        // or a split admin log.
        let writers = if ctx.pel_routed {
            &self.pel_writer
        } else {
            &self.log_writer
        };
        let writer_arc = writers.writer_for(ctx.event_type, ctx.eid)?;
        let mut w = writer_arc.lock().expect("log writer mutex poisoned");
        w.append_line(&line)?;
        w.flush()?;
        if let Some(t0) = _wr_t0 {
            crate::perf::record_ns("emit:file_write", t0.elapsed().as_nanos() as u64);
        }

        Ok((row_hash, line))
    }

    /// Advance the per-event_type chain, build + write the row, and commit
    /// the row_hash back into the chain — returning `(row_hash, line)`.
    /// Steps 4–9 of [`Runtime::emit`]'s pipeline, with the cross-process
    /// serialization that steps 4–9 require.
    ///
    /// Three branches:
    /// - **chained + shared file** (the default audit profile): bookend
    ///   advance → write → commit with an advisory file lock, refreshing
    ///   the chain tip from disk truth under the lock so concurrent
    ///   publishers don't branch the chain. A non-io error is parked in a
    ///   local `deferred_err` and re-raised after the lock releases.
    /// - **chained + `{event_id}` per-event file**: one unique file per
    ///   emit, so there is nothing to coordinate cross-process — advance →
    ///   write → commit without the lock.
    /// - **unchained** (`ceremony.chain: false`): no lock, no commit; the
    ///   append-only syscall is the only ordering primitive.
    ///
    /// # Errors
    ///
    /// Propagates the [`build_and_write`](Self::build_and_write) /
    /// chain-tip-refresh error set, plus an advisory-lock acquisition
    /// failure.
    ///
    /// # Panics
    ///
    /// Panics if the lock helper returns `Ok` without populating the row
    /// outputs (an internal invariant violation).
    fn advance_and_write(
        &self,
        per_event: bool,
        lock_path: &Path,
        ctx: &EmitWriteCtx<'_>,
    ) -> Result<(String, String)> {
        let event_type = ctx.event_type;
        let pel_routed = ctx.pel_routed;

        // Capture the row's outputs from inside the closure so the
        // outer scope can return them. The lock helper returns
        // io::Result<()>; non-io errors get parked here and re-raised
        // after the lock releases.
        let mut row_hash_out: Option<String> = None;
        let mut line_out: Option<String> = None;
        let mut deferred_err: Option<Error> = None;

        // Chain gating (0.4.2a7): `ceremony.chain: false` skips the
        // cross-process advisory lock and the per-emit tail-scan.
        // Used by the `telemetry` and `secure_log` profiles where
        // per-row prev_hash linkage isn't part of the audit story
        // and the per-emit lock cost would dominate hot paths.
        //
        // 0.4.2a9: the unchained path still increments a per-
        // event_type `sequence` counter (no lock, in-memory only —
        // resets to 1 on restart). `prev_hash` stays empty as the
        // "no linkage claim" sentinel. Readers that check chain
        // integrity see `ceremony.chain == false` and skip the
        // per-row prev_hash compare; sequence remains useful for
        // ordering inside a single run.
        let chain_enabled = self.cfg.ceremony.chain;

        if chain_enabled && !per_event {
            let storage_for_lock = Arc::clone(&self.storage);
            let _lock_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else {
                None
            };
            storage_for_lock.with_advisory_lock(lock_path, &mut || {
                if let Some(t0) = _lock_t0 {
                    crate::perf::record_ns("emit:lock_acquire", t0.elapsed().as_nanos() as u64);
                }
                // Under the lock: refresh in-memory chain tip from
                // disk truth before advancing. Factored into
                // `refresh_chain_tip_under_lock`; a writer-pool failure is
                // parked in `deferred_err` and re-raised after the lock
                // releases.
                self.refresh_chain_tip_under_lock(
                    pel_routed,
                    event_type,
                    ctx.eid,
                    &mut deferred_err,
                )?;

                // 4. Chain advance (now reflects disk truth).
                let _adv_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                let (seq, prev_hash) = self.chain.advance(event_type);
                if let Some(t0) = _adv_t0 {
                    crate::perf::record_ns("emit:chain_advance", t0.elapsed().as_nanos() as u64);
                }

                let (row_hash, line) = match self.build_and_write(seq, &prev_hash, ctx) {
                    Ok(v) => v,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other("build_and_write failed (deferred)"));
                    }
                };

                // 9. Commit row_hash into the chain.
                let _cm_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                self.chain.commit(event_type, &row_hash);
                if let Some(t0) = _cm_t0 {
                    crate::perf::record_ns("emit:chain_commit", t0.elapsed().as_nanos() as u64);
                }

                row_hash_out = Some(row_hash);
                line_out = Some(line);
                Ok(())
            })?;
        } else if chain_enabled {
            // Chained `{event_id}` template: one unique file per emit,
            // so there is no shared file to coordinate and no point
            // acquiring the advisory lock or tail-scanning the
            // just-created (empty) file. The in-memory ChainState is
            // the authoritative tip within this process — it already
            // carries the previous emit's row_hash — and `Runtime::init`
            // re-seeds it by globbing every rendered file across a
            // restart. So advance + write + commit without the lock.
            let (seq, prev_hash) = self.chain.advance(event_type);
            let result: std::io::Result<()> = (|| {
                let (row_hash, line) = match self.build_and_write(seq, &prev_hash, ctx) {
                    Ok(v) => v,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other("build_and_write failed (deferred)"));
                    }
                };
                self.chain.commit(event_type, &row_hash);
                row_hash_out = Some(row_hash);
                line_out = Some(line);
                Ok(())
            })();
            result?;
        } else {
            // Lockless emit for unchained profiles. No advisory
            // lock means no `.emit.lock` artifact on disk, no
            // tail-scan, no chain prev_hash linkage. The append-only
            // syscall is the only ordering primitive — interleaving
            // across processes is acceptable because there's no
            // chain to break.
            //
            // 0.4.2a9: even unchained profiles increment a per-
            // event_type sequence counter. `prev_hash` stays empty
            // (sentinel pattern; the verifier knows to skip the
            // linkage check when `ceremony.chain == false`), but
            // `sequence` grows monotonically within a single
            // process. Across restart the counter resets to 1 —
            // there's no seed scan for unchained profiles, by
            // design (would defeat the perf-first promise). Users
            // that need cross-restart sequence continuity should
            // pick `audit` or `transaction`.
            let (seq, _prev_unused) = self.chain.advance(event_type);
            let result: std::io::Result<()> = (|| {
                let (row_hash, line) = match self.build_and_write(seq, "", ctx) {
                    Ok(v) => v,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other("build_and_write failed (deferred)"));
                    }
                };
                row_hash_out = Some(row_hash);
                line_out = Some(line);
                Ok(())
            })();
            result?;
        }

        if let Some(e) = deferred_err {
            return Err(e);
        }
        let row_hash = row_hash_out.expect("with_advisory_lock returned Ok but row_hash unset");
        let line = line_out.expect("with_advisory_lock returned Ok but line unset");
        Ok((row_hash, line))
    }

    // emit_inner is the single canonical path for building + signing an
    // envelope: prelude (level filter, run_id, policy splice, catalog
    // check), then field classification (`classify_fields`), per-group
    // encryption (`encrypt_groups`), and the chain-advance/write/commit
    // core (`advance_and_write`). The orchestration is still long enough to
    // warrant the line-count allow.
    #[allow(clippy::too_many_lines)]
    fn emit_inner(
        &self,
        level: &str,
        event_type: &str,
        mut fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
        aad: &Map<String, Value>,
    ) -> Result<Option<String>> {
        // Outer perf wrapper — measures total emit_inner time so we
        // can confirm the per-stage breakdown sums correctly.
        // `TN_PERF_TRACE` env var gates the instrumentation; when
        // off this is one atomic-bool load per emit.
        let _emit_total_start = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };

        // Log-level filter (AVL J3.2). Drop emits whose level is below
        // the active threshold before any work happens. Severity-less
        // ("") always passes — it's an explicit "this is a fact"
        // primitive whose semantics shouldn't depend on the filter.
        if !level.is_empty() {
            let lv = level_value(level);
            if lv >= 0 && lv < LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) {
                return Ok(None);
            }
        }

        let _prelude_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        validate_event_type(event_type)?;

        // Auto-inject run_id. Caller can override by
        // passing `run_id` explicitly in fields.
        if !fields.contains_key("run_id") {
            fields.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        }

        // Splice the `tn.agents` policy text into `fields` for this
        // event_type, if a template is loaded. setdefault semantics — the
        // caller can override individual fields per-emit. Per 2026-04-25
        // spec §2.6.
        self.splice_agent_policy(event_type, &mut fields);

        // Catalog check: any tn.* event that's in the catalog must pass schema
        // validation before we sign it. This prevents the publisher from
        // accidentally signing an envelope that the reducer would later reject.
        // Unknown tn.* events (not in the catalog) pass through unchecked --
        // forward-compat for event kinds added in newer publishers.
        if event_type.starts_with("tn.") {
            if let Some(_kind) = admin_catalog::kind_for(event_type) {
                admin_catalog::validate_emit(event_type, &fields).map_err(|e| {
                    Error::Malformed {
                        kind: "admin event",
                        reason: format!("admin event {event_type} failed schema: {e}"),
                    }
                })?;
            }
        }
        if let Some(t0) = _prelude_t0 {
            crate::perf::record_ns("emit:prelude", t0.elapsed().as_nanos() as u64);
        }

        let (ts, eid, level_norm) = crate::perf::time_stage("emit:header", || {
            (
                timestamp.map_or_else(current_timestamp, str::to_string),
                // UUID v7 (0.4.2a7): time-sortable event_id with a
                // 48-bit ms timestamp in the high bits. Sorting log
                // entries by event_id now puts them in chronological
                // order — drop-in friendly for DB indexes and binary
                // tree scans. Older event_ids passed in via the
                // ``event_id`` override (replay, deterministic test
                // fixtures) still take precedence verbatim, so the
                // change is transparent to callers who supply their
                // own ids.
                event_id.map_or_else(|| Uuid::now_v7().to_string(), str::to_string),
                level.to_ascii_lowercase(),
            )
        });

        // 1. Classify fields: public vs per-group.
        let (mut public_out, per_group) = self.classify_fields(fields)?;

        // row_hash gating (0.4.2a7): hoisted up here from below so the
        // per-group encrypt loop can skip building `group_inputs_for_hash`
        // when no consumer will read it. The structure only feeds into
        // `compute_row_hash`; when chain=F sign=F (pure-log mode), the
        // row_hash compute is skipped and the structure is dead. The
        // per-call sign override (`sign=true` passed explicitly) also
        // pulls it back in since the signature is over row_hash bytes.
        let chain_enabled_for_row_hash = self.cfg.ceremony.chain;
        let need_row_hash =
            chain_enabled_for_row_hash || self.cfg.ceremony.sign || sign.unwrap_or(false);

        // 2. Index tokens + 3. Encrypt per group (binding each group's
        //    effective AAD marker into its body).
        let (group_inputs_for_hash, group_payloads, aad_echo) =
            self.encrypt_groups(per_group, aad, need_row_hash)?;

        // Echo the effective markers into the public `tn_aad` field as the
        // canonical JSON string of the {group: marker} map, so a reader
        // reconstructs byte-identical AAD. It rides in `public_out`, so it
        // feeds row_hash and the signature (an authenticated echo). Absent
        // when no group bound a marker, keeping such records byte-identical
        // to the pre-AAD wire shape. A STRING (not an object) so row_hash
        // matches the pure pipeline and every implementation.
        if !aad_echo.is_empty() {
            let bytes = crate::canonical::canonical_bytes(&Value::Object(aad_echo))?;
            let s = String::from_utf8(bytes)
                .map_err(|_| Error::Internal("tn_aad canonical bytes not utf-8".into()))?;
            public_out.insert("tn_aad".to_string(), Value::String(s));
        }

        // DX review 0.4.2a3: cross-process emit serialization.
        //
        // Steps 4–9 (chain advance through chain commit) MUST execute
        // atomically across processes. Otherwise, two workers writing
        // to the same log race on per-process ChainState: both compute
        // (seq, prev_hash) from a stale local view, both write rows
        // referencing the same parent, and the chain branches —
        // ``tn.read(verify=True)`` then rejects every branch except
        // the first.
        //
        // The fix bookends 4–9 with an advisory file lock on a
        // sentinel adjacent to the write target (main log OR pel for
        // protocol events). Under the lock we refresh ChainState from
        // disk truth for this event_type before advance, then proceed.
        // The lock is released as soon as the row is on disk + chain
        // committed; handler fan-out runs unlocked because the row is
        // already durable.
        //
        // The wasm code path inherits the trait's no-op lock impl
        // (single-threaded, single-process — no race to coordinate).
        let _path_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let is_protocol = event_type.starts_with("tn.");
        let pel_routed = is_protocol && self.cfg.ceremony.protocol_events_location != "main_log";
        // Derive the on-disk path from the writer pool's template so
        // the advisory-lock file always sits next to the file we're
        // actually appending to. Going through `pel_writer.path_for`
        // also keeps the `{event_class}` semantics consistent with
        // PathTemplate / Python (first dotted segment) — the prior
        // `self.resolve_pel(event_type)` used `nth(1)` and would
        // disagree with the writer pool when the PEL template
        // contains `{event_class}`.
        let target_path: PathBuf = if pel_routed {
            self.pel_writer.path_for(event_type, &eid)
        } else {
            self.log_writer.path_for(event_type, &eid)
        };
        // `{event_id}` templates render a unique file per emit, so the
        // file is never shared with another row and there is nothing to
        // coordinate cross-process. Skip the advisory lock + tail-scan
        // (which would otherwise litter one `.emit.lock` per event and
        // always read an empty just-created file) but keep the in-memory
        // chain advance/commit so prev_hash linkage is preserved within
        // a process and re-seeded from the glob at init across restarts.
        let per_event = if pel_routed {
            self.pel_writer.is_per_event()
        } else {
            self.log_writer.is_per_event()
        };
        let lock_path = {
            let mut s = target_path.as_os_str().to_os_string();
            s.push(".emit.lock");
            PathBuf::from(s)
        };
        // Parent-directory creation moved into `LogFileWriter::open`
        // (0.4.2a8 PEL pinned-writer fix). Each rendered path opens
        // its writer lazily on first emit; `LogFileWriter::open`
        // already calls `storage.create_dir_all(parent)` then.
        // Subsequent emits to the same rendered path reuse the pinned
        // handle and skip the parent-create syscall entirely.
        if let Some(t0) = _path_t0 {
            crate::perf::record_ns("emit:path_setup", t0.elapsed().as_nanos() as u64);
        }

        // Pre-clone the inputs the write branches consume by reference so
        // the borrow checker is happy with the `with_advisory_lock` FnMut
        // signature; bundle them into the shared `EmitWriteCtx`.
        let public_out_for_lock = public_out;
        let group_inputs_for_lock = group_inputs_for_hash;
        let group_payloads_for_lock = group_payloads;
        let ctx = EmitWriteCtx {
            ts: &ts,
            eid: &eid,
            event_type,
            level_norm: &level_norm,
            need_row_hash,
            sign,
            pel_routed,
            public_out: &public_out_for_lock,
            group_inputs: &group_inputs_for_lock,
            group_payloads: &group_payloads_for_lock,
        };

        // 4–9. Chain advance + build + write + commit. The cross-process
        // serialization (advisory lock for chained, shared-file ceremonies)
        // lives in `advance_and_write`.
        let (row_hash, line) = self.advance_and_write(per_event, &lock_path, &ctx)?;

        // 10. Fan out to handlers. Mirrors Python `tn/logger.py:343` and
        //     TS `node_runtime.ts:376`. A handler whose filter rejects
        //     the envelope is skipped; a handler whose `emit` panics or
        //     errors is logged + swallowed so the publish call still
        //     succeeds for the caller.
        let _fan_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        self.fan_out_to_handlers(line.as_bytes(), event_type, &eid);
        if let Some(t0) = _fan_t0 {
            crate::perf::record_ns("emit:fan_out", t0.elapsed().as_nanos() as u64);
        }
        if let Some(t0) = _emit_total_start {
            crate::perf::record_ns("emit:_TOTAL", t0.elapsed().as_nanos() as u64);
        }

        // event_id, row_hash, and sequence are not surfaced through the
        // public emit*() facades (which discard the line and return
        // Result<()> for cross-language parity with Python None / TS void).
        // The on-disk envelope carries them. The `_returning_line` variant
        // hands the canonical NDJSON back so a host runtime (PyO3) can fan
        // out to its own handlers without re-deriving it.
        //
        // ``seq`` lives inside the cross-process lock closure after the
        // 0.4.2a3 emit-locking refactor; the envelope itself still
        // carries it on disk, so this sink only needs the two values
        // we have in this scope.
        let _ = (eid, row_hash);
        Ok(Some(line))
    }

    /// Register a handler to receive every subsequent emit fan-out.
    /// Mirrors Python's `extra_handlers` constructor parameter and TS
    /// `NodeRuntime.addHandler`.
    ///
    /// The handler's `accepts()` is consulted per-envelope; only
    /// matching events reach `emit()`. Errors raised inside `emit()` are
    /// logged via `log::warn!` and swallowed — the publish call must
    /// not fail because a downstream handler had a bad day.
    ///
    /// # Panics
    /// Panics if the internal handlers mutex is poisoned.
    pub fn add_handler(&self, handler: Arc<dyn crate::handlers::TnHandler>) {
        self.handlers
            .lock()
            .expect("handlers mutex poisoned")
            .push(handler);
    }

    /// Number of currently-attached handlers. Mainly for tests.
    ///
    /// # Panics
    /// Panics if the internal handlers mutex is poisoned.
    pub fn handler_count(&self) -> usize {
        self.handlers.lock().expect("handlers mutex poisoned").len()
    }

    fn fan_out_to_handlers(&self, raw_line: &[u8], event_type: &str, event_id: &str) {
        // Snapshot the handler list under the lock, then release it
        // before invoking handlers. A handler that re-enters emit (e.g.
        // to log a derived event) would otherwise deadlock the mutex.
        let handlers: Vec<Arc<dyn crate::handlers::TnHandler>> = {
            let guard = self.handlers.lock().expect("handlers mutex poisoned");
            if guard.is_empty() {
                return;
            }
            guard.iter().map(Arc::clone).collect()
        };

        // Re-parse the just-written line into an envelope Value. The
        // line is freshly produced by `build_envelope` so this is
        // infallible in practice; if it ever fails we log and skip
        // fan-out rather than corrupt the caller's emit.
        let envelope: Value = match serde_json::from_slice(raw_line) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "handler fan-out: failed to parse envelope JSON for {event_type}/{event_id}: {e}"
                );
                return;
            }
        };

        for h in &handlers {
            if !h.accepts(&envelope) {
                continue;
            }
            // The TnHandler trait's `emit` returns `()` — handlers are
            // expected to swallow their own errors and log internally
            // (see vault_push.rs:308). We additionally wrap the call
            // in catch_unwind so a panicking handler does not poison
            // the publish path. Panics are rare; log + continue.
            let h_for_call = Arc::clone(h);
            let env_ref = &envelope;
            let raw_ref = raw_line;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                h_for_call.emit(env_ref, raw_ref);
            }));
            if let Err(payload) = result {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                log::warn!(
                    "handler {:?} panicked on {event_type}/{event_id}; entry already sealed: {msg}",
                    h.name()
                );
            }
        }
    }
}
