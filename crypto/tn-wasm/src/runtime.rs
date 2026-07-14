//! `WasmRuntime` — wasm-bindgen wrapper around `tn_core::Runtime`.
//!
//! Core surface:
//!   - `init(yaml_path)` static factory
//!   - `ephemeral()` static factory (tmpdir-backed)
//!   - `did()` / `logPath()` / `groupNames()` metadata
//!   - `emit(level, eventType, fields)` -> basic emit
//!   - `read()` -> flat-entry default shape
//!   - `close()` -> explicit flush (no-op on drop is also fine)
//!
//! Read variants:
//!   - `readAllRuns()` -> like `read()` minus the `$TN_RUN_ID` filter
//!   - `readWithVerify()` -> `read()` + `_valid: {signature, row_hash, chain}` block
//!   - `readRaw()` -> audit-grade `{envelope, plaintext}` shape
//!   - `secureRead(onInvalid)` -> verified read with skip/raise/forensic modes
//!
//! Emit variants (emitWith / overrideSign / log/debug/info/...), admin
//! verbs, handler registration + log-level statics, vault + readFrom,
//! and the browser Storage adapter are all wired further down this file.
//!
//! The PyO3 binding at `crypto/tn-core-py/src/lib.rs` is the
//! reference: same `Arc<Runtime>` ownership shape, same flatten path
//! (`tn_core::runtime::flatten_raw_entry`), same error-to-message
//! mapping. Conversions of JS values go through `JSON.stringify`/
//! `JSON.parse` (mirroring `lib.rs::js_to_json` / `json_to_js`) so that
//! `Option::None`s in the envelope round-trip as JS `null` rather than
//! collapsing to `undefined`.

use std::path::Path;
use std::sync::Arc;

use wasm_bindgen::prelude::*;

use ::tn_core::{OnInvalid, Runtime, RuntimeInitOptions, SecureReadOptions};

use crate::storage::JsStorageAdapter;
use crate::{js_to_json, json_to_js};

mod seal;

/// JS-side wrapper around a single `tn-core` `Runtime` instance.
///
/// Owns an `Arc<Runtime>` so the JS handle can be cloned-by-reference
/// in the future without forcing a `Runtime` copy. `Drop` releases the
/// shared reference; `close()` exists for callers that want an explicit
/// flush + a `Result` they can await on.
#[wasm_bindgen]
pub struct WasmRuntime {
    inner: Arc<Runtime>,
}

#[wasm_bindgen]
impl WasmRuntime {
    /// Load a ceremony from `yamlPath` using a JS-supplied storage
    /// callbacks object.
    ///
    /// The `storage` argument must be a JS object with the property
    /// shape documented in `crypto/tn-wasm/src/storage.rs` - `read`,
    /// `write`, `append`, `exists`, `list`, `rename`, `remove`,
    /// `createDirAll`, `casWrite` (synchronous function values).
    /// Node consumers wrap `fs.*Sync` methods; future browser
    /// consumers wrap an IndexedDB shim.
    ///
    /// Internally constructs a [`JsStorageAdapter`] around the
    /// callbacks and hands it to `Runtime::init_with_storage`. Every
    /// file read during init (yaml, device key, master index key,
    /// per-group cipher state + kits, agents.md) goes through the
    /// adapter. Subsequent emit / read / admin call sites still talk
    /// to `std::fs::*` directly; finishing that migration is tracked in
    /// the storage abstraction's `Storage` trait comment.
    ///
    /// Errors surface as `JsError` with the Rust `Display` message.
    #[wasm_bindgen(js_name = "init")]
    pub fn init_js(yaml_path: &str, storage: JsValue) -> Result<WasmRuntime, JsError> {
        // wasm32-unknown-unknown's `std::path` is Unix-only: `\` is not a
        // separator. A caller passing a Windows-native path like
        // `C:\Users\foo\tn.yaml` would collapse to a single filename, so
        // `yaml_path.parent()` falls back to `"."` and `Runtime::init`
        // hunts for `./.tn/...` keystore files in the wrong directory.
        // Normalizing to forward slashes server-side means callers don't
        // have to know about the wasm-path quirk. The host filesystem
        // (Node fs) accepts forward slashes on Windows, so the
        // normalized paths still resolve when handed to the storage
        // adapter's callbacks.
        let normalized = yaml_path.replace('\\', "/");
        let storage = JsStorageAdapter::from_js(storage)?;
        let rt = Runtime::init_with_storage(Path::new(&normalized), storage)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmRuntime {
            inner: Arc::new(rt),
        })
    }

    /// Like `init` but takes an `opts` object with extra knobs that
    /// SDK wrappers need.
    ///
    /// Recognised keys on `opts`:
    /// * `skipCeremonyInitEmit`: bool — when true, suppress the
    ///   auto-emit of `tn.ceremony.init` even when the ceremony looks
    ///   fresh. Used by the TS `NodeRuntime` so the lazy `attachWasm()`
    ///   hop doesn't double-attest a ceremony the TS path has already
    ///   wired up.
    ///
    /// Returns a fully-constructed [`WasmRuntime`]. Errors surface as
    /// [`JsError`] with the Rust `Display` message.
    #[wasm_bindgen(js_name = "initWith")]
    pub fn init_with_js(
        yaml_path: &str,
        storage: JsValue,
        opts: JsValue,
    ) -> Result<WasmRuntime, JsError> {
        let normalized = yaml_path.replace('\\', "/");
        let storage = JsStorageAdapter::from_js(storage)?;
        let skip_ceremony_init_emit =
            js_sys::Reflect::get(&opts, &JsValue::from_str("skipCeremonyInitEmit"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        let skip_policy_published_emit =
            js_sys::Reflect::get(&opts, &JsValue::from_str("skipPolicyPublishedEmit"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        let init_opts = RuntimeInitOptions {
            skip_ceremony_init_emit,
            skip_policy_published_emit,
        };
        let rt = Runtime::init_with_options(Path::new(&normalized), storage, init_opts)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmRuntime {
            inner: Arc::new(rt),
        })
    }

    /// Build an ephemeral btn-cipher runtime backed by a fresh tmpdir.
    ///
    /// Gated to **non-wasm builds only**. `Runtime::ephemeral` calls
    /// `tempfile::TempDir` and then runs the `std::fs`-backed
    /// `Runtime::init`; on `wasm32-unknown-unknown` both surfaces are
    /// stubbed to return errors, so the function would compile but
    /// throw at every call. Exposing it on wasm would be a footgun.
    ///
    /// On wasm, callers can set up a fresh ceremony in their own
    /// storage adapter (Node-side tmpdir, in-memory map, IndexedDB)
    /// and call `init(yamlPath, storage)` instead. A future
    /// `Runtime::ephemeral_with_storage` could fold that pattern back
    /// into one call; today it'd just be a thin wrapper.
    #[cfg(not(target_arch = "wasm32"))]
    #[wasm_bindgen(js_name = "ephemeral")]
    pub fn ephemeral_js() -> Result<WasmRuntime, JsError> {
        let rt = Runtime::ephemeral().map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmRuntime {
            inner: Arc::new(rt),
        })
    }

    /// This runtime's publisher DID (`did:key:z…`).
    #[wasm_bindgen(js_name = "did")]
    pub fn did_js(&self) -> String {
        self.inner.did().to_string()
    }

    /// Absolute path of the main ndjson log this runtime writes to.
    #[wasm_bindgen(js_name = "logPath")]
    pub fn log_path_js(&self) -> String {
        self.inner.log_path().display().to_string()
    }

    /// Names of every group declared in the active ceremony yaml, in
    /// `BTreeMap` (alphabetical) order — matches what
    /// `Runtime::group_names` returns.
    #[wasm_bindgen(js_name = "groupNames")]
    pub fn group_names_js(&self) -> Vec<JsValue> {
        self.inner
            .group_names()
            .into_iter()
            .map(|s| JsValue::from_str(&s))
            .collect()
    }

    /// Emit one envelope at `level` for `eventType` with `fields`.
    ///
    /// `fields` must be a JS object that maps to a JSON object - keys
    /// are strings, values are anything `JSON.stringify` accepts. The
    /// envelope is signed (or not) per the ceremony yaml; use
    /// `emitOverrideSign` for per-call control.
    ///
    /// Returns `undefined` on success; throws on schema violations,
    /// I/O failures, or a non-object `fields` value. (The richer
    /// "returns the envelope ndjson line on success, `None` if the
    /// log-level threshold filtered it" shape that the PyO3 binding
    /// exposes is provided by the other emit variants below.)
    #[wasm_bindgen(js_name = "emit")]
    pub fn emit_js(&self, level: &str, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let value = js_to_json(fields)?;
        let map = match value {
            serde_json::Value::Object(m) => m,
            _ => return Err(JsError::new("emit: fields must be a JSON object")),
        };
        self.inner
            .emit(level, event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Read every entry from the main log as flat JS objects.
    ///
    /// Matches the PyO3 `Runtime.read()` default shape: six envelope
    /// basics (`timestamp`, `event_type`, `level`, `did`, `sequence`,
    /// `event_id`) plus every readable group's decrypted fields
    /// hoisted to the top level. Filtered to the current process's
    /// `run_id` by default - to span every run use `readAllRuns`.
    ///
    /// Returns `Entry[]` (a JS array of plain objects).
    #[wasm_bindgen(js_name = "read")]
    pub fn read_js(&self) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .read()
            .map_err(|e| JsError::new(&e.to_string()))?;
        // FlatEntry is `Map<String, Value>`, so serializing the Vec
        // directly produces a JS `Array<object>` after the JSON.parse
        // round-trip. Going through the `json_to_js` helper keeps null
        // values intact (see lib.rs comment).
        let arr: Vec<serde_json::Value> =
            entries.into_iter().map(serde_json::Value::Object).collect();
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Like `read()` but returns entries from every run on disk (not
    /// just the current process's `$TN_RUN_ID`). Use for audit /
    /// compliance reports that span the whole log lifetime.
    ///
    /// Mirrors the PyO3 `Runtime.read_all_runs()` shape: same flat dicts
    /// as `read()`, just unfiltered.
    #[wasm_bindgen(js_name = "readAllRuns")]
    pub fn read_all_runs_js(&self) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .read_all_runs()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let arr: Vec<serde_json::Value> =
            entries.into_iter().map(serde_json::Value::Object).collect();
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Like `read()` but adds a `_valid: {signature, row_hash, chain}`
    /// block to each flat entry so callers can inspect verification
    /// status without raising. Mirrors PyO3 `Runtime.read_with_verify()`.
    #[wasm_bindgen(js_name = "readWithVerify")]
    pub fn read_with_verify_js(&self) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .read_with_verify()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let arr: Vec<serde_json::Value> =
            entries.into_iter().map(serde_json::Value::Object).collect();
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Audit-grade read: returns one object per entry with the full
    /// on-disk `envelope` (including `prev_hash` / `row_hash` /
    /// `signature` / `groups`) plus a `plaintext` map of per-group
    /// decrypted values. Mirrors PyO3 `Runtime.read_raw()` — key name is
    /// `plaintext` (not the Rust field name `plaintext_per_group`) so
    /// the JS surface matches Python.
    #[wasm_bindgen(js_name = "readRaw")]
    pub fn read_raw_js(&self) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .read_raw()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let mut arr: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
        for e in entries {
            let mut obj = serde_json::Map::new();
            obj.insert("envelope".to_string(), e.envelope);
            // `BTreeMap<String, Value>` -> `Object` so the JS side sees
            // `{ groupName: <decrypted plaintext>, ... }`. Iteration over
            // BTreeMap is already sorted; serde_json::Map preserves
            // insertion order, which gives the JS object the same
            // group-name ordering as Python.
            let mut pt = serde_json::Map::new();
            for (g, v) in e.plaintext_per_group {
                pt.insert(g, v);
            }
            obj.insert("plaintext".to_string(), serde_json::Value::Object(pt));
            arr.push(serde_json::Value::Object(obj));
        }
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Verified read (sig + row_hash + chain). On failure, behavior
    /// follows `onInvalid`:
    ///   - `"skip"` — drop the bad row, append a
    ///     `tn.read.tampered_row_skipped` admin event (default).
    ///   - `"raise"` — throw a JS error.
    ///   - `"forensic"` — keep the row, attach `_valid` and
    ///     `_invalid_reasons` markers.
    ///
    /// Each returned entry is a flat dict shaped like `read()`, plus an
    /// optional `instructions` block when the caller holds the
    /// `tn.agents` kit (mirroring PyO3 `Runtime.secure_read()`).
    /// `_hidden_groups` / `_decrypt_errors` are surfaced as arrays when
    /// non-empty.
    #[wasm_bindgen(js_name = "secureRead")]
    pub fn secure_read_js(&self, on_invalid: &str) -> Result<JsValue, JsError> {
        let mode = match on_invalid {
            "skip" => OnInvalid::Skip,
            "raise" => OnInvalid::Raise,
            "forensic" => OnInvalid::Forensic,
            other => {
                return Err(JsError::new(&format!(
                    "secureRead: unknown on_invalid={other:?}; expected 'skip' | 'raise' | 'forensic'"
                )));
            }
        };
        let opts = SecureReadOptions {
            on_invalid: mode,
            log_path: None,
        };
        let entries = self
            .inner
            .secure_read(opts)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let mut arr: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut flat = entry.fields;
            if let Some(instr) = entry.instructions {
                let mut id = serde_json::Map::new();
                id.insert(
                    "instruction".into(),
                    serde_json::Value::String(instr.instruction),
                );
                id.insert("use_for".into(), serde_json::Value::String(instr.use_for));
                id.insert(
                    "do_not_use_for".into(),
                    serde_json::Value::String(instr.do_not_use_for),
                );
                id.insert(
                    "consequences".into(),
                    serde_json::Value::String(instr.consequences),
                );
                id.insert(
                    "on_violation_or_error".into(),
                    serde_json::Value::String(instr.on_violation_or_error),
                );
                id.insert("policy".into(), serde_json::Value::String(instr.policy));
                flat.insert("instructions".into(), serde_json::Value::Object(id));
            }
            if !entry.hidden_groups.is_empty() {
                flat.insert(
                    "_hidden_groups".into(),
                    serde_json::Value::Array(
                        entry
                            .hidden_groups
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            if !entry.decrypt_errors.is_empty() {
                flat.insert(
                    "_decrypt_errors".into(),
                    serde_json::Value::Array(
                        entry
                            .decrypt_errors
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            arr.push(serde_json::Value::Object(flat));
        }
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Explicit flush + close.
    ///
    /// Consumes `self`. Optional — the `Runtime`'s own `Drop` impl
    /// flushes OS file buffers via `File::Drop`. Use `close()` when
    /// you want to surface a flush error to JS rather than let it slip
    /// past.
    ///
    /// Implementation note: we can only call `Runtime::close(self)`
    /// when we hold the unique owner of the `Arc`. If JS code clones
    /// the handle (it can't today, but it might in a later phase),
    /// the unwrap falls back to a best-effort drop without surfacing
    /// flush errors.
    #[wasm_bindgen(js_name = "close")]
    pub fn close_js(self) -> Result<(), JsError> {
        match Arc::try_unwrap(self.inner) {
            Ok(rt) => rt.close().map_err(|e| JsError::new(&e.to_string())),
            Err(_arc) => {
                // Some other handle is still alive; let `Drop` flush
                // on its own when the last refcount goes away.
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------
    // Emit variants
    //
    // Mirrors the `Runtime::emit_with{,_override_sign}` / `log` / `debug`
    // / `info` / `warning` / `error` surface that PyO3 exposes via a
    // single variadic wrapper. wasm-bindgen can't collapse them into one
    // method with optional args at the JS callsite as cleanly as PyO3
    // does, so we publish each verb as its own export. The conversion
    // path (`js_to_json` → require a JSON object, else reject) matches
    // `emit_js`; the `fields_object` helper at the bottom of this file
    // centralizes the "fields must be a JSON object" error message.
    // -----------------------------------------------------------------

    /// Emit with explicit `timestamp` / `event_id` overrides.
    ///
    /// `null`/`undefined` for either argument falls back to the
    /// runtime's defaults (`OffsetDateTime::now_utc()` and a fresh
    /// UUID). Signing follows the ceremony's yaml `sign` flag — use
    /// `emitWithOverrideSign` for per-call signing control.
    #[wasm_bindgen(js_name = "emitWith")]
    pub fn emit_with_js(
        &self,
        level: &str,
        event_type: &str,
        fields: JsValue,
        timestamp: Option<String>,
        event_id: Option<String>,
    ) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .emit_with(
                level,
                event_type,
                map,
                timestamp.as_deref(),
                event_id.as_deref(),
            )
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Emit with an explicit `sign` override.
    ///
    /// `None` (JS `null`/`undefined`) keeps the ceremony default;
    /// `Some(true)` forces a signature; `Some(false)` skips it.
    #[wasm_bindgen(js_name = "emitOverrideSign")]
    pub fn emit_override_sign_js(
        &self,
        level: &str,
        event_type: &str,
        fields: JsValue,
        sign: Option<bool>,
    ) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .emit_override_sign(level, event_type, map, sign)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Full-control emit: explicit timestamp, event_id, and sign override.
    #[wasm_bindgen(js_name = "emitWithOverrideSign")]
    pub fn emit_with_override_sign_js(
        &self,
        level: &str,
        event_type: &str,
        fields: JsValue,
        timestamp: Option<String>,
        event_id: Option<String>,
        sign: Option<bool>,
    ) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .emit_with_override_sign(
                level,
                event_type,
                map,
                timestamp.as_deref(),
                event_id.as_deref(),
                sign,
            )
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Full-control emit that returns the canonical envelope NDJSON line
    /// (or `undefined` when the log-level threshold filtered the emit).
    ///
    /// Mirrors the PyO3 binding's line-returning emit. The host (TS
    /// `NodeRuntime`) parses the returned line to synthesize the
    /// `EmitReceipt` directly, instead of reading the row back off the
    /// log. That read-back breaks for templated `logs.path` (e.g.
    /// `./logs/{event_id}.ndjson`) where the just-written row lives in a
    /// per-event file, not the single main log — the line is the source
    /// of truth regardless of where it was written.
    #[wasm_bindgen(js_name = "emitReturningLine")]
    pub fn emit_returning_line_js(
        &self,
        level: &str,
        event_type: &str,
        fields: JsValue,
        timestamp: Option<String>,
        event_id: Option<String>,
        sign: Option<bool>,
        aad: JsValue,
    ) -> Result<Option<String>, JsError> {
        let map = fields_object(fields)?;
        // `aad` is an optional marker object (undefined/null -> no marker).
        let aad_map = if aad.is_undefined() || aad.is_null() {
            serde_json::Map::new()
        } else {
            fields_object(aad)?
        };
        self.inner
            .emit_with_aad_returning_line(
                level,
                event_type,
                map,
                timestamp.as_deref(),
                event_id.as_deref(),
                sign,
                &aad_map,
            )
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Severity-less attested event (envelope carries `level: ""`).
    ///
    /// Bypasses the log-level threshold filter by design — this is the
    /// "this is a fact" primitive whose semantics shouldn't depend on
    /// the active level.
    #[wasm_bindgen(js_name = "log")]
    pub fn log_js(&self, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .log(event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// DEBUG-level attested event.
    #[wasm_bindgen(js_name = "debug")]
    pub fn debug_js(&self, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .debug(event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// INFO-level attested event.
    #[wasm_bindgen(js_name = "info")]
    pub fn info_js(&self, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .info(event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// WARNING-level attested event.
    #[wasm_bindgen(js_name = "warning")]
    pub fn warning_js(&self, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .warning(event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// ERROR-level attested event.
    #[wasm_bindgen(js_name = "error")]
    pub fn error_js(&self, event_type: &str, fields: JsValue) -> Result<(), JsError> {
        let map = fields_object(fields)?;
        self.inner
            .error(event_type, map)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    // -----------------------------------------------------------------
    // Admin verbs
    //
    // Mirrors the PyO3 `add_recipient` / `revoke_recipient` /
    // `revoked_count` / `recipients` / `admin_state` /
    // `admin_add_agent_runtime` / `bundle_for_recipient` block at
    // `crypto/tn-core-py/src/lib.rs:269..504`.
    //
    // Every persistence path (publisher state file, kit file, label
    // sidecar) is routed through the runtime's `Storage` handle, so
    // admin verbs work against the same `JsStorageAdapter` the rest of
    // `WasmRuntime` uses. Routing them anywhere else would short-circuit
    // the storage abstraction and call stubbed `std::fs::*` on wasm.
    //
    // Each method maps `tn-core` types straight to JS via
    // `serde_json::to_value` + `json_to_js`. The lifecycle types
    // (`RecipientEntry`, `AdminState`, …) already derive `Serialize`
    // so the conversion is mechanical.
    // -----------------------------------------------------------------

    /// Mint a fresh btn reader kit for `group`, write it to
    /// `outPath`, persist the updated publisher state, and return the
    /// new recipient's leaf index.
    ///
    /// Optional `recipientDid` (`did:key:…`) attaches identity to the
    /// `tn.recipient.added` attested event the publisher emits as a
    /// side-effect. Mirrors PyO3 `add_recipient`.
    #[wasm_bindgen(js_name = "adminAddRecipient")]
    pub fn admin_add_recipient_js(
        &self,
        group: &str,
        out_path: &str,
        recipient_did: Option<String>,
    ) -> Result<u32, JsError> {
        // The PyO3 binding returns u64 to match Rust core's leaf-index
        // type; wasm-bindgen cannot express u64 over the JS boundary
        // (BigInt vs Number ambiguity bites every consumer). The
        // protocol guarantees leaf indices fit in u32 — the btn tree
        // is depth-bounded — so a downcast is safe. Reject obviously
        // out-of-range values so a future tree-depth bump can't
        // silently wrap.
        let leaf = self
            .inner
            .admin_add_recipient(
                group,
                std::path::Path::new(out_path),
                recipient_did.as_deref(),
            )
            .map_err(|e| JsError::new(&e.to_string()))?;
        u32::try_from(leaf).map_err(|_| {
            JsError::new(&format!(
                "adminAddRecipient: leaf index {leaf} exceeds u32 range; bump the JS surface to BigInt"
            ))
        })
    }

    /// Revoke the recipient at `leafIndex` in `group`. Persists the
    /// updated state and emits `tn.recipient.revoked`. Mirrors PyO3
    /// `revoke_recipient`. Accepts the leaf index as a JS `number`
    /// (we widen to `u64` for `tn-core`).
    #[wasm_bindgen(js_name = "adminRevokeRecipient")]
    pub fn admin_revoke_recipient_js(&self, group: &str, leaf_index: u32) -> Result<(), JsError> {
        self.inner
            .admin_revoke_recipient(group, u64::from(leaf_index))
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Number of recipients currently marked revoked in `group`'s
    /// publisher state. Mirrors PyO3 `revoked_count`. Returned as a
    /// JS `number`.
    #[wasm_bindgen(js_name = "adminRevokedCount")]
    pub fn admin_revoked_count_js(&self, group: &str) -> Result<u32, JsError> {
        let count = self
            .inner
            .admin_revoked_count(group)
            .map_err(|e| JsError::new(&e.to_string()))?;
        u32::try_from(count).map_err(|_| {
            JsError::new(&format!(
                "adminRevokedCount: count {count} exceeds u32 range"
            ))
        })
    }

    /// Replay the log through the admin reducer and return the full
    /// `AdminState` as a plain JS object. `group` is optional — pass
    /// `null` for the all-groups view, a string to scope to one
    /// group's rows. Mirrors PyO3 `admin_state`.
    #[wasm_bindgen(js_name = "adminState")]
    pub fn admin_state_js(&self, group: Option<String>) -> Result<JsValue, JsError> {
        let state = self
            .inner
            .admin_state(group.as_deref())
            .map_err(|e| JsError::new(&e.to_string()))?;
        let value = serde_json::to_value(&state)
            .map_err(|e| JsError::new(&format!("adminState: serialize: {e}")))?;
        json_to_js(&value)
    }

    /// Return the current recipient roster for `group` by replaying
    /// the log. When `includeRevoked` is true, revoked recipients are
    /// appended after the active ones. Mirrors PyO3 `recipients`.
    /// Returns a JS array of plain objects (`{leafIndex, recipientDid,
    /// mintedAt, kitSha256, revoked, revokedAt}`); the snake_case
    /// field names from `RecipientEntry` survive intact through the
    /// serde roundtrip.
    #[wasm_bindgen(js_name = "recipients")]
    pub fn recipients_js(&self, group: &str, include_revoked: bool) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .recipients(group, include_revoked)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let value = serde_json::to_value(&entries)
            .map_err(|e| JsError::new(&format!("recipients: serialize: {e}")))?;
        json_to_js(&value)
    }

    /// Mint kits for `runtimeDid` across the requested groups + the
    /// reserved `tn.agents` group, then export a `kit_bundle` `.tnpkg`
    /// at `outPath`. Optional `label` writes a sidecar `.label` file
    /// next to the bundle (best-effort).
    ///
    /// `groups` is a JS array of strings; entries that aren't strings
    /// are silently dropped. Returns the absolute bundle path.
    /// Mirrors PyO3 `admin_add_agent_runtime`.
    #[wasm_bindgen(js_name = "adminAddAgentRuntime")]
    pub fn admin_add_agent_runtime_js(
        &self,
        runtime_did: &str,
        groups: Vec<JsValue>,
        out_path: &str,
        label: Option<String>,
    ) -> Result<String, JsError> {
        // wasm-bindgen accepts `Vec<JsValue>` for variadic-string
        // inputs; extract real strings out of it. Non-string entries
        // drop on the floor so a caller's transient `undefined` doesn't
        // tank the whole call. Cap at 64 — every real ceremony has a
        // handful of groups, and an unbounded loop here would be a DoS
        // vector for misbehaving JS.
        let group_strs: Vec<String> = groups
            .into_iter()
            .filter_map(|v| v.as_string())
            .take(64)
            .collect();
        let group_refs: Vec<&str> = group_strs.iter().map(String::as_str).collect();
        let p = self
            .inner
            .admin_add_agent_runtime(
                runtime_did,
                &group_refs,
                std::path::Path::new(out_path),
                label.as_deref(),
            )
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(p.display().to_string())
    }

    /// Mint a fresh kit for `recipientDid` across one or more groups
    /// and bundle them into a single `.tnpkg` at `outPath`. `groups`
    /// is optional — pass `null`/`undefined` to bundle every non-
    /// internal group declared in the active ceremony.
    ///
    /// Cipher behavior comes from tn-core: BTN groups mint `.btn.mykit`
    /// reader kits; native HIBE builds mint `.hibe.mpk/.idpath/.sk`
    /// material; JWE groups return an explicit unsupported error because
    /// JWE lives in the TypeScript pure-JS JOSE pipeline.
    ///
    /// Mirrors PyO3 `bundle_for_recipient` and Python
    /// `tn.bundle_for_recipient`. Returns the absolute bundle path.
    #[wasm_bindgen(js_name = "bundleForRecipient")]
    pub fn bundle_for_recipient_js(
        &self,
        recipient_did: &str,
        out_path: &str,
        groups: Option<Vec<JsValue>>,
    ) -> Result<String, JsError> {
        let group_strs: Option<Vec<String>> = groups.map(|gs| {
            gs.into_iter()
                .filter_map(|v| v.as_string())
                .take(64)
                .collect()
        });
        let group_refs: Option<Vec<&str>> = group_strs
            .as_ref()
            .map(|gs| gs.iter().map(String::as_str).collect());
        let p = self
            .inner
            .bundle_for_recipient(
                recipient_did,
                std::path::Path::new(out_path),
                group_refs.as_deref(),
            )
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(p.display().to_string())
    }

    // -----------------------------------------------------------------
    // Vault verbs + read-from-path variants
    //
    // Mirrors PyO3 `vault_link` / `vault_unlink` at
    // `crypto/tn-core-py/src/lib.rs:506,514` and the optional `log_path`
    // variants on `read()` / `read_with_verify()` / `read_raw()` from
    // the same module. Appended at the end of `impl WasmRuntime` to
    // avoid stomping on the handler / log-level methods further down.
    // -----------------------------------------------------------------

    /// Emit a signed `tn.vault.linked` admin event recording that this
    /// ceremony is paired with `vaultDid`'s `projectId`. Idempotent —
    /// an active link to the same `(vault_did, project_id)` is a no-op.
    /// Mirrors PyO3 `vault_link` and Python `tn.vault_link`.
    #[wasm_bindgen(js_name = "vaultLink")]
    pub fn vault_link_js(&self, vault_did: &str, project_id: &str) -> Result<(), JsError> {
        self.inner
            .vault_link(vault_did, project_id)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Emit a signed `tn.vault.unlinked` admin event recording that the
    /// pairing between this ceremony and `vaultDid`'s `projectId` has
    /// been severed. `reason` is an optional free-form string; pass
    /// `null`/`undefined` to omit (the event will carry `reason: null`).
    /// Mirrors PyO3 `vault_unlink` and Python `tn.vault_unlink`.
    #[wasm_bindgen(js_name = "vaultUnlink")]
    pub fn vault_unlink_js(
        &self,
        vault_did: &str,
        project_id: &str,
        reason: Option<String>,
    ) -> Result<(), JsError> {
        self.inner
            .vault_unlink(vault_did, project_id, reason.as_deref())
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Read all entries from an explicit `logPath` as `{envelope,
    /// plaintext}` records (audit-grade shape). Mirrors PyO3
    /// `read_raw(log_path=…)` / Python `tn.read_raw(log_path=…)` —
    /// useful for cross-publisher reads where the caller absorbed a
    /// foreign kit and wants to decrypt that party's log.
    ///
    /// Returns the same `{envelope, plaintext}` shape that `readRaw()`
    /// produces; consumers who want the flat hoisted shape can post-
    /// process or call `readWithVerify` once it grows a path arg.
    ///
    /// For this wasm runtime build, configured BTN logs are supported.
    /// Foreign BTN recipient-kit reads are supported when BTN kits are in
    /// the keystore. Foreign HIBE/JWE recipient-kit dispatch returns a
    /// clear unsupported error instead of using BTN assumptions; HIBE is
    /// exposed separately through the standalone `hibe*` primitives and
    /// JWE through the TS pure-JS JOSE path.
    #[wasm_bindgen(js_name = "readFrom")]
    pub fn read_from_js(&self, log_path: &str) -> Result<JsValue, JsError> {
        let normalized = log_path.replace('\\', "/");
        let entries = self
            .inner
            .read_from(std::path::Path::new(&normalized))
            .map_err(|e| JsError::new(&e.to_string()))?;
        let mut arr: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
        for e in entries {
            let mut obj = serde_json::Map::new();
            obj.insert("envelope".to_string(), e.envelope);
            let mut pt = serde_json::Map::new();
            for (g, v) in e.plaintext_per_group {
                pt.insert(g, v);
            }
            obj.insert("plaintext".to_string(), serde_json::Value::Object(pt));
            arr.push(serde_json::Value::Object(obj));
        }
        json_to_js(&serde_json::Value::Array(arr))
    }

    /// Audit-grade read against the runtime's own log with explicit
    /// per-row validity flags. Returns one object per entry:
    /// `{envelope, plaintext, valid: {signature, row_hash, chain}}`.
    /// Mirrors PyO3's `(ReadEntry, ValidFlags)` tuple — flattened into
    /// a single dict for the JS surface so consumers don't need a
    /// tuple shim. Mirrors Python `tn.read_raw_with_validity()`.
    #[wasm_bindgen(js_name = "readRawWithValidity")]
    pub fn read_raw_with_validity_js(&self) -> Result<JsValue, JsError> {
        let entries = self
            .inner
            .read_raw_with_validity()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let value = read_with_validity_to_json(entries);
        json_to_js(&value)
    }

    /// As [`Self::read_raw_with_validity_js`] but reads from an
    /// explicit `logPath`. Mirrors Python
    /// `tn.read_raw_with_validity(log_path=…)`.
    ///
    /// The explicit-path validity path handles configured-runtime reads.
    /// Foreign recipient-kit reads with validity fail clearly today rather
    /// than reporting BTN-shaped validity for HIBE/JWE material.
    #[wasm_bindgen(js_name = "readFromWithValidity")]
    pub fn read_from_with_validity_js(&self, log_path: &str) -> Result<JsValue, JsError> {
        let normalized = log_path.replace('\\', "/");
        let entries = self
            .inner
            .read_from_with_validity(std::path::Path::new(&normalized))
            .map_err(|e| JsError::new(&e.to_string()))?;
        let value = read_with_validity_to_json(entries);
        json_to_js(&value)
    }

    // -----------------------------------------------------------------
    // Handler registration
    //
    // Mirrors `Runtime::add_handler` / Python's `extra_handlers` /
    // `NodeRuntime.addHandler`. The JS-side callback object is wrapped
    // in a `JsHandler` that implements the `TnHandler` trait, and the
    // resulting `Arc<dyn TnHandler>` is pushed into the runtime's
    // handler list. Subsequent emits fan out through it like every
    // other handler kind.
    // -----------------------------------------------------------------

    /// Register a JS-supplied handler. Subsequent emits fan out
    /// through it (subject to its `accepts` filter, if any).
    ///
    /// `callbacks` is a JS object: `{ name: string, emit: fn,
    /// accepts?: fn, close?: fn }`. See `JsHandler::from_js` for the
    /// full contract.
    #[wasm_bindgen(js_name = "addHandler")]
    pub fn add_handler_js(&self, callbacks: JsValue) -> Result<(), JsError> {
        let handler = crate::handlers::JsHandler::from_js(callbacks)?;
        self.inner.add_handler(Arc::new(handler));
        Ok(())
    }
}

// -----------------------------------------------------------------
// Log-level control (static methods)
//
// These mirror Python's `tn.set_level` / `tn.get_level` /
// `tn.is_enabled_for` and TS's `TNClient.setLevel`. They're static
// because the threshold is process-wide (a single atomic in
// `tn_core::runtime`), not per-runtime - matching the Rust core's
// `Runtime::set_level` / `get_level` / `is_enabled_for` surface.
// Statics live in their own `impl` block so wasm-bindgen doesn't
// try to inject a `&self` translation.
// -----------------------------------------------------------------
#[wasm_bindgen]
impl WasmRuntime {
    /// Set the process-wide log-level threshold by name. Accepts
    /// "debug" / "info" / "warning" / "error" (case-insensitive,
    /// "warn" aliases "warning"). Throws on unknown names.
    #[wasm_bindgen(js_name = "setLevel")]
    pub fn set_level_js(level: &str) -> Result<(), JsError> {
        Runtime::set_level(level).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Set the process-wide threshold from a numeric value (10/20/
    /// 30/40 etc.). Lets callers plug in custom severities without
    /// the string map.
    #[wasm_bindgen(js_name = "setLevelValue")]
    pub fn set_level_value_js(level: i32) {
        Runtime::set_level_value(level);
    }

    /// The active threshold as a level name (or the numeric stringified
    /// value when it doesn't match one of the four standard names).
    #[wasm_bindgen(js_name = "getLevel")]
    pub fn get_level_js() -> String {
        Runtime::get_level()
    }

    /// True iff `level` would currently emit. Use as a guard for
    /// expensive log-arg construction (mirrors Python's
    /// `Logger.isEnabledFor`).
    #[wasm_bindgen(js_name = "isEnabledFor")]
    pub fn is_enabled_for_js(level: &str) -> bool {
        Runtime::is_enabled_for(level)
    }
}

/// Flatten Rust's `Vec<(ReadEntry, ValidFlags)>` tuple into the JS dict
/// shape: each tuple becomes `{envelope, plaintext, valid: {…}}`. Shared
/// between the runtime-log and explicit-path variants so the on-wire
/// shape stays in lockstep.
fn read_with_validity_to_json(
    entries: Vec<(::tn_core::ReadEntry, ::tn_core::ValidFlags)>,
) -> serde_json::Value {
    let mut arr: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for (entry, valid) in entries {
        let mut obj = serde_json::Map::new();
        obj.insert("envelope".to_string(), entry.envelope);
        let mut pt = serde_json::Map::new();
        for (g, v) in entry.plaintext_per_group {
            pt.insert(g, v);
        }
        obj.insert("plaintext".to_string(), serde_json::Value::Object(pt));
        let mut vmap = serde_json::Map::new();
        vmap.insert(
            "signature".to_string(),
            serde_json::Value::Bool(valid.signature),
        );
        vmap.insert(
            "row_hash".to_string(),
            serde_json::Value::Bool(valid.row_hash),
        );
        vmap.insert("chain".to_string(), serde_json::Value::Bool(valid.chain));
        obj.insert("valid".to_string(), serde_json::Value::Object(vmap));
        arr.push(serde_json::Value::Object(obj));
    }
    serde_json::Value::Array(arr)
}

/// Shared helper: validate that `fields` round-trips into a JSON object
/// and return the `serde_json::Map` `Runtime` wants. Centralizes the
/// "fields must be a JSON object" error message so every emit verb
/// reports the same failure mode.
fn fields_object(fields: JsValue) -> Result<serde_json::Map<String, serde_json::Value>, JsError> {
    let value = js_to_json(fields)?;
    match value {
        serde_json::Value::Object(m) => Ok(m),
        _ => Err(JsError::new("emit: fields must be a JSON object")),
    }
}
