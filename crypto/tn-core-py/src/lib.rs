//! PyO3 wrapper for tn_core::Runtime.

// Migrated to the pyo3 0.24 bound API: the 0.21-era `*_bound` constructors and
// the `IntoPy`/`ToPyObject` conversions are gone in favor of the plain
// `Bound`-returning constructors and the fallible `IntoPyObject` trait. (The
// 0.24 bump itself cleared RUSTSEC-2025-0020, the PyString::from_object buffer
// overflow.)

mod admin;

use pyo3::exceptions::{PyException, PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use pyo3::{create_exception, intern, wrap_pyfunction, IntoPyObjectExt};
use std::path::Path;
use std::sync::Arc;

use ::tn_core::admin_cache::ChainConflict;
use ::tn_core::tnpkg::{
    read_tnpkg, verify_manifest, write_tnpkg, BodyContents, Manifest, ManifestKind, TnpkgSource,
};
use ::tn_core::{AbsorbSource, AdminStateCache, Error as TnError, ExportOptions, Runtime};

create_exception!(_core, TnRuntimeError, PyException);
create_exception!(_core, NotEntitled, PyException);
create_exception!(_core, NotAPublisher, PyException);

fn err_to_py(e: TnError) -> PyErr {
    match e {
        TnError::Io(e) => PyIOError::new_err(e.to_string()),
        TnError::NotEntitled { group } => NotEntitled::new_err(group),
        TnError::NotAPublisher { group, reason } => {
            NotAPublisher::new_err(format!("{group}: {reason}"))
        }
        TnError::InvalidConfig(s) => PyValueError::new_err(s),
        TnError::Yaml(s) => PyValueError::new_err(s),
        // Env-var substitution surfaces as ValueError on the Python side
        // for parity with `tn.config._substitute_env_vars` raising
        // `ValueError` from the pure-Python loader.
        e @ TnError::ConfigEnvVarMissing { .. } => PyValueError::new_err(e.to_string()),
        e @ TnError::ConfigEnvVarMalformed { .. } => PyValueError::new_err(e.to_string()),
        TnError::Malformed { kind, reason } => {
            PyValueError::new_err(format!("malformed {kind}: {reason}"))
        }
        e @ TnError::ReservedGroupName { .. } => PyValueError::new_err(e.to_string()),
        other => TnRuntimeError::new_err(other.to_string()),
    }
}

/// Run a binding entry point, converting any Rust panic escaping the core into
/// a catchable `TnRuntimeError` instead of letting it cross the FFI boundary as
/// a pyo3 `PanicException` (which subclasses `BaseException` and so slips past
/// an ordinary `except Exception:`). Normal `Err(PyErr)` results pass through
/// unchanged; only an actual panic is remapped. The SDK must never surface an
/// exception the caller did not request — a panic is a last-resort bug signal,
/// so it is contained here and re-raised as a TN-typed, catchable error.
pub(crate) fn guard<T>(f: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    match ::tn_core::catch_panic(f) {
        Ok(result) => result,
        Err(msg) => Err(TnRuntimeError::new_err(format!(
            "internal error (panic): {msg}"
        ))),
    }
}

#[pyclass(module = "tn_core._core", name = "Runtime")]
pub struct PyRuntime {
    inner: Arc<Runtime>,
}

#[pymethods]
impl PyRuntime {
    #[staticmethod]
    fn init(yaml_path: &str) -> PyResult<Self> {
        guard(|| {
            let rt = Runtime::init(Path::new(yaml_path)).map_err(err_to_py)?;
            Ok(Self {
                inner: Arc::new(rt),
            })
        })
    }

    fn did(&self) -> &str {
        self.inner.did()
    }

    fn log_path(&self) -> String {
        self.inner.log_path().display().to_string()
    }

    /// Emit an event. `fields` is a Python dict.
    ///
    /// Returns the canonical envelope NDJSON line (newline-terminated bytes)
    /// so the Python `DispatchRuntime` can fan out to user-registered Python
    /// handlers (kafka, S3, vault.sync, etc.) without re-deriving it. Returns
    /// `None` when the emit was filtered by the log-level threshold and no
    /// envelope was produced.
    ///
    /// Note: this is a 0.0.x API change from the previous `-> None` return.
    /// Callers that don't need the line just discard the result.
    ///
    /// `sign` overrides the ceremony's yaml `ceremony.sign` default for this
    /// single call. `None` uses the configured default (typically `True`).
    // Argument count matches the Python-visible signature; PyO3 methods
    // surface individual args to keep the Python callsite ergonomic.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (level, event_type, fields, timestamp=None, event_id=None, sign=None, aad=None))]
    fn emit<'py>(
        &self,
        py: Python<'py>,
        level: &str,
        event_type: &str,
        fields: &Bound<'_, PyDict>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
        aad: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        guard(|| {
            // PyO3-layer perf hooks. Same env-gating as the in-runtime
            // markers — one AtomicBool::load(Relaxed) per stage on the
            // disabled path. Together with emit:_TOTAL we get the full
            // Python→Rust crossing accounted for.
            let _py_t0 = if tn_core::perf::enabled() {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let fields_json = pydict_to_json(fields)?;
            let aad_json = match aad {
                Some(d) => pydict_to_json(d)?,
                None => serde_json::Map::new(),
            };
            if let Some(t0) = _py_t0 {
                tn_core::perf::record_ns("emit:py_dict_marshal", t0.elapsed().as_nanos() as u64);
            }
            let _wrap_t0 = if tn_core::perf::enabled() {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let line = self
                .inner
                .emit_with_aad_returning_line(
                    level,
                    event_type,
                    fields_json,
                    timestamp,
                    event_id,
                    sign,
                    &aad_json,
                )
                .map_err(err_to_py)?;
            let result = Ok(line.map(|s| PyBytes::new(py, s.as_bytes())));
            if let Some(t0) = _wrap_t0 {
                // Includes both Runtime::emit_inner (which has its own
                // emit:_TOTAL marker) AND the return-wrap into PyBytes.
                // Subtract emit:_TOTAL to isolate the wrap-back cost.
                tn_core::perf::record_ns("emit:py_call_and_wrap", t0.elapsed().as_nanos() as u64);
            }
            result
        })
    }

    /// Rebuild a group's cipher from the current on-disk keystore material.
    ///
    /// Call after a Python-side admin mutation that rewrote a group's key
    /// files outside this runtime's own native admin verbs — notably the
    /// hibe admin verbs (grant/rotate/revoke), which change
    /// `<group>.hibe.{idpath,sk,idpath.history,...}`. Without it, the cached
    /// native cipher would keep sealing to the pre-mutation identity path.
    fn reload_group_cipher(&self, group: &str) -> PyResult<()> {
        guard(|| self.inner.reload_group_cipher(group).map_err(err_to_py))
    }

    /// Read all entries as flat dicts (the default 2026-04-25 shape).
    ///
    /// Six envelope basics (`timestamp`, `event_type`, `level`, `did`,
    /// `sequence`, `event_id`) plus every readable group's decrypted
    /// fields land at the top level. `_hidden_groups` /
    /// `_decrypt_errors` markers surface only when non-empty.
    #[pyo3(signature = (log_path=None))]
    fn read<'py>(&self, py: Python<'py>, log_path: Option<&str>) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            let raw = match log_path {
                Some(p) => self
                    .inner
                    .read_from(std::path::Path::new(p))
                    .map_err(err_to_py)?,
                None => self.inner.read_raw().map_err(err_to_py)?,
            };
            let list = PyList::empty(py);
            for r in &raw {
                let flat = ::tn_core::runtime::flatten_raw_entry(r, false);
                list.append(json_to_py(py, &serde_json::Value::Object(flat))?)?;
            }
            Ok(list)
        })
    }

    /// Read all entries as flat dicts plus a `_valid: {signature,
    /// row_hash, chain}` block per spec §1.3.
    ///
    /// Mirrors the optional `log_path` parameter on `read()` and
    /// `read_raw()`: when supplied, verification runs against the named
    /// log file; otherwise it runs against the runtime's own log.
    #[pyo3(signature = (log_path=None))]
    fn read_with_verify<'py>(
        &self,
        py: Python<'py>,
        log_path: Option<&str>,
    ) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            use serde_json::{Map, Value};
            let raw_with_valid = match log_path {
                Some(p) => self
                    .inner
                    .read_from_with_validity(std::path::Path::new(p))
                    .map_err(err_to_py)?,
                None => self.inner.read_raw_with_validity().map_err(err_to_py)?,
            };
            let list = PyList::empty(py);
            for (entry, valid) in raw_with_valid {
                let mut flat = ::tn_core::runtime::flatten_raw_entry(&entry, false);
                let mut v = Map::new();
                v.insert("signature".into(), Value::Bool(valid.signature));
                v.insert("row_hash".into(), Value::Bool(valid.row_hash));
                v.insert("chain".into(), Value::Bool(valid.chain));
                flat.insert("_valid".into(), Value::Object(v));
                list.append(json_to_py(py, &Value::Object(flat))?)?;
            }
            Ok(list)
        })
    }

    /// Read all entries as the audit-grade `{envelope, plaintext}`
    /// shape (today's pre-2026-04-25 default).
    #[pyo3(signature = (log_path=None))]
    fn read_raw<'py>(
        &self,
        py: Python<'py>,
        log_path: Option<&str>,
    ) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            let entries = match log_path {
                Some(p) => self
                    .inner
                    .read_from(std::path::Path::new(p))
                    .map_err(err_to_py)?,
                None => self.inner.read_raw().map_err(err_to_py)?,
            };
            let list = PyList::empty(py);
            for e in entries {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "envelope"), json_to_py(py, &e.envelope)?)?;
                let pt = PyDict::new(py);
                for (g, v) in e.plaintext_per_group {
                    pt.set_item(g, json_to_py(py, &v)?)?;
                }
                d.set_item(intern!(py, "plaintext"), pt)?;
                list.append(d)?;
            }
            Ok(list)
        })
    }

    /// Iterate verified entries (sig + row_hash + chain). Returns flat
    /// dicts like `read()` plus an optional `instructions` block when
    /// the caller holds the `tn.agents` kit. Per spec §3.
    ///
    /// `on_invalid` is one of "skip" (default), "raise", "forensic".
    #[pyo3(signature = (on_invalid="skip"))]
    fn secure_read<'py>(&self, py: Python<'py>, on_invalid: &str) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            use ::tn_core::OnInvalid;
            let mode = match on_invalid {
            "skip" => OnInvalid::Skip,
            "raise" => OnInvalid::Raise,
            "forensic" => OnInvalid::Forensic,
            other => {
                return Err(PyValueError::new_err(format!(
                    "tn.secure_read: unknown on_invalid={other:?}; expected 'skip' | 'raise' | 'forensic'"
                )))
            }
        };
            let opts = ::tn_core::SecureReadOptions {
                on_invalid: mode,
                log_path: None,
            };
            let entries = self.inner.secure_read(opts).map_err(err_to_py)?;
            let list = PyList::empty(py);
            for entry in entries {
                // Build the flat dict. Then attach `instructions` when present.
                let dict = json_to_py(py, &serde_json::Value::Object(entry.fields))?;
                let dict_obj: Bound<'_, PyDict> = dict.downcast_into::<PyDict>()?;
                if let Some(instr) = entry.instructions {
                    let id = PyDict::new(py);
                    id.set_item(intern!(py, "instruction"), instr.instruction)?;
                    id.set_item(intern!(py, "use_for"), instr.use_for)?;
                    id.set_item(intern!(py, "do_not_use_for"), instr.do_not_use_for)?;
                    id.set_item(intern!(py, "consequences"), instr.consequences)?;
                    id.set_item(
                        intern!(py, "on_violation_or_error"),
                        instr.on_violation_or_error,
                    )?;
                    id.set_item(intern!(py, "policy"), instr.policy)?;
                    dict_obj.set_item(intern!(py, "instructions"), id)?;
                }
                // hidden_groups / decrypt_errors (rebuild — flatten removed them
                // when attach_instructions was called).
                if !entry.hidden_groups.is_empty() {
                    let arr = PyList::empty(py);
                    for g in entry.hidden_groups {
                        arr.append(g)?;
                    }
                    dict_obj.set_item(intern!(py, "_hidden_groups"), arr)?;
                }
                if !entry.decrypt_errors.is_empty() {
                    let arr = PyList::empty(py);
                    for g in entry.decrypt_errors {
                        arr.append(g)?;
                    }
                    dict_obj.set_item(intern!(py, "_decrypt_errors"), arr)?;
                }
                list.append(dict_obj)?;
            }
            Ok(list)
        })
    }

    /// Mint kits for `runtime_did` across all named groups + tn.agents,
    /// then write a `kit_bundle` `.tnpkg` at `out_path`. Per spec §2.8.
    #[pyo3(signature = (runtime_did, groups, out_path, label=None))]
    fn admin_add_agent_runtime(
        &self,
        runtime_did: &str,
        groups: Vec<String>,
        out_path: &str,
        label: Option<&str>,
    ) -> PyResult<String> {
        guard(|| {
            let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();
            let p = self
                .inner
                .admin_add_agent_runtime(runtime_did, &group_refs, Path::new(out_path), label)
                .map_err(err_to_py)?;
            Ok(p.display().to_string())
        })
    }

    fn close(&self) -> PyResult<()> {
        guard(|| {
            // Arc<Runtime> — dropping PyRuntime decrements refcount; close is implicit.
            Ok(())
        })
    }

    // ------------------------------------------------------------------
    // Admin verbs (Task 39)
    // ------------------------------------------------------------------

    /// Mint a new btn reader kit for `group`, write it to `out_path`, and
    /// return the leaf index (`u64`) of the new reader.
    ///
    /// When `recipient_did` is provided, a `tn.recipient.added` attested
    /// event is appended to the log carrying the leaf index + DID + kit
    /// SHA-256. Readers can replay these events to reconstruct the current
    /// recipient map.
    #[pyo3(signature = (group, out_path, recipient_did=None))]
    fn add_recipient(
        &self,
        group: &str,
        out_path: &str,
        recipient_did: Option<&str>,
    ) -> PyResult<u64> {
        guard(|| {
            self.inner
                .admin_add_recipient(group, Path::new(out_path), recipient_did)
                .map_err(err_to_py)
        })
    }

    /// Revoke the btn reader at `leaf_index` in `group`.
    fn revoke_recipient(&self, group: &str, leaf_index: u64) -> PyResult<()> {
        guard(|| {
            self.inner
                .admin_revoke_recipient(group, leaf_index)
                .map_err(err_to_py)
        })
    }

    /// Return how many recipients are currently revoked in `group`'s btn state.
    fn revoked_count(&self, group: &str) -> PyResult<usize> {
        guard(|| self.inner.admin_revoked_count(group).map_err(err_to_py))
    }

    /// Return the current recipient roster for `group` by replaying the log.
    ///
    /// Returns a list of dicts with keys: `leaf_index`, `recipient_did`,
    /// `minted_at`, `kit_sha256`, `revoked`, `revoked_at`. Mirrors Python
    /// `tn.recipients(group, include_revoked=…)`.
    #[pyo3(signature = (group, include_revoked=false))]
    fn recipients<'py>(
        &self,
        py: Python<'py>,
        group: &str,
        include_revoked: bool,
    ) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            let entries = self
                .inner
                .recipients(group, include_revoked)
                .map_err(err_to_py)?;
            let list = PyList::empty(py);
            for r in entries {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "leaf_index"), r.leaf_index)?;
                d.set_item(intern!(py, "recipient_identity"), r.recipient_identity)?;
                d.set_item(intern!(py, "minted_at"), r.minted_at)?;
                d.set_item(intern!(py, "kit_sha256"), r.kit_sha256)?;
                d.set_item(intern!(py, "revoked"), r.revoked)?;
                d.set_item(intern!(py, "revoked_at"), r.revoked_at)?;
                list.append(d)?;
            }
            Ok(list)
        })
    }

    /// Return the full local admin state by replaying the log.
    ///
    /// Shape mirrors Python `tn.admin_state(group=…)`:
    /// `{ceremony, groups, recipients, rotations, coupons, enrolments, vault_links}`.
    #[pyo3(signature = (group=None))]
    fn admin_state<'py>(
        &self,
        py: Python<'py>,
        group: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        guard(|| {
            let state = self.inner.admin_state(group).map_err(err_to_py)?;
            let out = PyDict::new(py);

            // ceremony
            let ceremony_v: Bound<'py, PyAny> = match state.ceremony {
                Some(c) => {
                    let d = PyDict::new(py);
                    d.set_item(intern!(py, "ceremony_id"), c.ceremony_id)?;
                    d.set_item(intern!(py, "cipher"), c.cipher)?;
                    d.set_item(intern!(py, "device_identity"), c.device_identity)?;
                    d.set_item(intern!(py, "created_at"), c.created_at)?;
                    d.into_any()
                }
                None => py.None().into_bound(py),
            };
            out.set_item(intern!(py, "ceremony"), ceremony_v)?;

            // groups
            let groups = PyList::empty(py);
            for g in state.groups {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "group"), g.group)?;
                d.set_item(intern!(py, "cipher"), g.cipher)?;
                d.set_item(intern!(py, "publisher_identity"), g.publisher_identity)?;
                d.set_item(intern!(py, "added_at"), g.added_at)?;
                groups.append(d)?;
            }
            out.set_item(intern!(py, "groups"), groups)?;

            // recipients
            let recipients = PyList::empty(py);
            for r in state.recipients {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "group"), r.group)?;
                d.set_item(intern!(py, "leaf_index"), r.leaf_index)?;
                d.set_item(intern!(py, "recipient_identity"), r.recipient_identity)?;
                d.set_item(intern!(py, "kit_sha256"), r.kit_sha256)?;
                d.set_item(intern!(py, "minted_at"), r.minted_at)?;
                d.set_item(intern!(py, "active_status"), r.active_status)?;
                d.set_item(intern!(py, "revoked_at"), r.revoked_at)?;
                d.set_item(intern!(py, "retired_at"), r.retired_at)?;
                recipients.append(d)?;
            }
            out.set_item(intern!(py, "recipients"), recipients)?;

            // rotations
            let rotations = PyList::empty(py);
            for r in state.rotations {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "group"), r.group)?;
                d.set_item(intern!(py, "cipher"), r.cipher)?;
                d.set_item(intern!(py, "generation"), r.generation)?;
                d.set_item(intern!(py, "previous_kit_sha256"), r.previous_kit_sha256)?;
                d.set_item(intern!(py, "rotated_at"), r.rotated_at)?;
                rotations.append(d)?;
            }
            out.set_item(intern!(py, "rotations"), rotations)?;

            // coupons
            let coupons = PyList::empty(py);
            for c in state.coupons {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "group"), c.group)?;
                d.set_item(intern!(py, "slot"), c.slot)?;
                d.set_item(intern!(py, "recipient_identity"), c.recipient_identity)?;
                d.set_item(intern!(py, "issued_to"), c.issued_to)?;
                d.set_item(intern!(py, "issued_at"), c.issued_at)?;
                coupons.append(d)?;
            }
            out.set_item(intern!(py, "coupons"), coupons)?;

            // enrolments
            let enrolments = PyList::empty(py);
            for e in state.enrolments {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "group"), e.group)?;
                d.set_item(intern!(py, "peer_identity"), e.peer_identity)?;
                d.set_item(intern!(py, "package_sha256"), e.package_sha256)?;
                d.set_item(intern!(py, "status"), e.status)?;
                d.set_item(intern!(py, "compiled_at"), e.compiled_at)?;
                d.set_item(intern!(py, "absorbed_at"), e.absorbed_at)?;
                enrolments.append(d)?;
            }
            out.set_item(intern!(py, "enrolments"), enrolments)?;

            // vault_links
            let vault_links = PyList::empty(py);
            for v in state.vault_links {
                let d = PyDict::new(py);
                d.set_item(intern!(py, "vault_identity"), v.vault_identity)?;
                d.set_item(intern!(py, "project_id"), v.project_id)?;
                d.set_item(intern!(py, "linked_at"), v.linked_at)?;
                d.set_item(intern!(py, "unlinked_at"), v.unlinked_at)?;
                vault_links.append(d)?;
            }
            out.set_item(intern!(py, "vault_links"), vault_links)?;

            Ok(out)
        })
    }

    /// Emit a signed `tn.vault.linked` event. Idempotent: returns `None`
    /// either way (matches Python `tn.vault_link`).
    fn vault_link(&self, vault_did: &str, project_id: &str) -> PyResult<()> {
        guard(|| {
            self.inner
                .vault_link(vault_did, project_id)
                .map_err(err_to_py)
        })
    }

    /// Emit a signed `tn.vault.unlinked` event. Returns `None`
    /// (matches Python `tn.vault_unlink`).
    #[pyo3(signature = (vault_did, project_id, reason=None))]
    fn vault_unlink(
        &self,
        vault_did: &str,
        project_id: &str,
        reason: Option<&str>,
    ) -> PyResult<()> {
        guard(|| {
            self.inner
                .vault_unlink(vault_did, project_id, reason)
                .map_err(err_to_py)
        })
    }

    // ------------------------------------------------------------------
    // export / absorb (Section 3.2 of 2026-04-24 admin log architecture)
    // ------------------------------------------------------------------

    /// Pack a `.tnpkg` from local ceremony state.
    #[pyo3(signature = (
        out_path,
        kind,
        to_did=None,
        scope=None,
        confirm_includes_secrets=false,
        groups=None,
        package_body=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn export(
        &self,
        out_path: &str,
        kind: &str,
        to_did: Option<String>,
        scope: Option<String>,
        confirm_includes_secrets: bool,
        groups: Option<Vec<String>>,
        package_body: Option<Vec<u8>>,
    ) -> PyResult<String> {
        guard(|| {
            let mk = ManifestKind::from_wire(kind)
                .ok_or_else(|| PyValueError::new_err(format!("unknown manifest kind: {kind:?}")))?;
            let opts = ExportOptions {
                kind: Some(mk),
                to_did,
                scope,
                confirm_includes_secrets,
                groups,
                keystore: None,
                encrypt_body_with: None,
                seal_for_recipients: Vec::new(),
                package_body,
            };
            let p = self
                .inner
                .export(Path::new(out_path), opts)
                .map_err(err_to_py)?;
            Ok(p.display().to_string())
        })
    }

    /// Apply a `.tnpkg` to local state. `source` may be a path string or bytes.
    fn absorb<'py>(
        &self,
        py: Python<'py>,
        source: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
        guard(|| {
            let receipt = if let Ok(b) = source.extract::<Vec<u8>>() {
                self.inner
                    .absorb(AbsorbSource::Bytes(&b))
                    .map_err(err_to_py)?
            } else if let Ok(s) = source.extract::<String>() {
                self.inner
                    .absorb(AbsorbSource::Path(Path::new(&s)))
                    .map_err(err_to_py)?
            } else {
                return Err(PyValueError::new_err(
                    "absorb: source must be bytes or a path string",
                ));
            };
            let d = PyDict::new(py);
            d.set_item(intern!(py, "kind"), receipt.kind)?;
            d.set_item(intern!(py, "accepted_count"), receipt.accepted_count)?;
            d.set_item(intern!(py, "deduped_count"), receipt.deduped_count)?;
            d.set_item(intern!(py, "noop"), receipt.noop)?;
            let derived_state: Bound<'py, PyAny> = match receipt.derived_state {
                Some(s) => {
                    let v = serde_json::to_value(s).map_err(|e| {
                        PyValueError::new_err(format!("absorb: derived_state -> json: {e}"))
                    })?;
                    json_to_py(py, &v)?
                }
                None => py.None().into_bound(py),
            };
            d.set_item(intern!(py, "derived_state"), derived_state)?;
            let conflicts = PyList::empty(py);
            for c in &receipt.conflicts {
                conflicts.append(conflict_to_py(py, c)?)?;
            }
            d.set_item(intern!(py, "conflicts"), conflicts)?;
            d.set_item(intern!(py, "legacy_status"), receipt.legacy_status)?;
            d.set_item(intern!(py, "legacy_reason"), receipt.legacy_reason)?;
            Ok(d)
        })
    }

    /// Construct an `AdminStateCache` backed by this runtime.
    fn admin_cache(&self) -> PyResult<PyAdminStateCache> {
        guard(|| {
            let cache = AdminStateCache::from_runtime_arc(&self.inner).map_err(err_to_py)?;
            Ok(PyAdminStateCache {
                inner: std::sync::Mutex::new(cache),
            })
        })
    }
}

#[pyclass(module = "tn_core._core", name = "AdminStateCache")]
pub struct PyAdminStateCache {
    inner: std::sync::Mutex<AdminStateCache>,
}

#[pymethods]
impl PyAdminStateCache {
    #[getter]
    fn at_offset(&self) -> usize {
        self.inner
            .lock()
            .expect("AdminStateCache mutex poisoned")
            .at_offset()
    }

    #[getter]
    fn head_row_hash(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("AdminStateCache mutex poisoned")
            .head_row_hash()
            .map(str::to_string)
    }

    #[getter]
    fn head_conflicts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            let g = self.inner.lock().expect("AdminStateCache mutex poisoned");
            let list = PyList::empty(py);
            for c in g.head_conflicts() {
                list.append(conflict_to_py(py, c)?)?;
            }
            Ok(list)
        })
    }

    fn diverged(&self) -> bool {
        self.inner
            .lock()
            .expect("AdminStateCache mutex poisoned")
            .diverged()
    }

    fn refresh(&self) -> PyResult<usize> {
        guard(|| {
            let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
            g.refresh().map_err(err_to_py)
        })
    }

    fn state<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
            let v = g.state().map_err(err_to_py)?.clone();
            json_to_py(py, &v)
        })
    }

    #[pyo3(signature = (group, include_revoked=false))]
    fn recipients<'py>(
        &self,
        py: Python<'py>,
        group: &str,
        include_revoked: bool,
    ) -> PyResult<Bound<'py, PyList>> {
        guard(|| {
            let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
            let recs = g.recipients(group, include_revoked).map_err(err_to_py)?;
            let list = PyList::empty(py);
            for r in &recs {
                list.append(json_to_py(py, r)?)?;
            }
            Ok(list)
        })
    }
}

fn conflict_to_py<'py>(py: Python<'py>, c: &ChainConflict) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    match c {
        ChainConflict::LeafReuseAttempt {
            group,
            leaf_index,
            attempted_row_hash,
            originally_revoked_at_row_hash,
        } => {
            d.set_item(intern!(py, "kind"), "leaf_reuse_attempt")?;
            d.set_item(intern!(py, "group"), group)?;
            d.set_item(intern!(py, "leaf_index"), leaf_index)?;
            d.set_item(intern!(py, "attempted_row_hash"), attempted_row_hash)?;
            d.set_item(
                intern!(py, "originally_revoked_at_row_hash"),
                originally_revoked_at_row_hash.as_deref(),
            )?;
        }
        ChainConflict::SameCoordinateFork {
            did,
            event_type,
            sequence,
            row_hash_a,
            row_hash_b,
        } => {
            d.set_item(intern!(py, "kind"), "same_coordinate_fork")?;
            d.set_item(intern!(py, "did"), did)?;
            d.set_item(intern!(py, "event_type"), event_type)?;
            d.set_item(intern!(py, "sequence"), sequence)?;
            d.set_item(intern!(py, "row_hash_a"), row_hash_a)?;
            d.set_item(intern!(py, "row_hash_b"), row_hash_b)?;
        }
        ChainConflict::RotationConflict {
            group,
            generation,
            previous_kit_sha256_a,
            previous_kit_sha256_b,
        } => {
            d.set_item(intern!(py, "kind"), "rotation_conflict")?;
            d.set_item(intern!(py, "group"), group)?;
            d.set_item(intern!(py, "generation"), generation)?;
            d.set_item(intern!(py, "previous_kit_sha256_a"), previous_kit_sha256_a)?;
            d.set_item(intern!(py, "previous_kit_sha256_b"), previous_kit_sha256_b)?;
        }
    }
    Ok(d)
}

pub(crate) fn pydict_to_json(
    d: &Bound<'_, PyDict>,
) -> PyResult<serde_json::Map<String, serde_json::Value>> {
    let mut out = serde_json::Map::new();
    for (k, v) in d.iter() {
        let k: String = k.extract()?;
        out.insert(k, py_to_json(&v)?);
    }
    Ok(out)
}

pub(crate) fn py_to_json(v: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    use serde_json::Value;
    if v.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = v.extract::<bool>() {
        return Ok(Value::Bool(b));
    }
    if let Ok(i) = v.extract::<i64>() {
        return Ok(Value::Number(i.into()));
    }
    if let Ok(f) = v.extract::<f64>() {
        return serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err("NaN/inf not JSON-serializable"));
    }
    if let Ok(s) = v.extract::<String>() {
        return Ok(Value::String(s));
    }
    if let Ok(list) = v.downcast::<PyList>() {
        let mut arr = Vec::with_capacity(list.len());
        for item in list.iter() {
            arr.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(arr));
    }
    if let Ok(dict) = v.downcast::<PyDict>() {
        let mut m = serde_json::Map::with_capacity(dict.len());
        for (k, vv) in dict.iter() {
            let k: String = k.extract()?;
            m.insert(k, py_to_json(&vv)?);
        }
        return Ok(Value::Object(m));
    }
    if let Ok(bytes) = v.extract::<Vec<u8>>() {
        // `{"$b64": "..."}` sentinel matches Rust canonical's wrap_bytes.
        use base64::Engine as _;
        let mut m = serde_json::Map::new();
        m.insert(
            "$b64".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        );
        return Ok(Value::Object(m));
    }
    Err(PyValueError::new_err(format!(
        "unsupported Python type for TN field: {}",
        v.get_type().name()?
    )))
}

pub(crate) fn json_to_py<'py>(
    py: Python<'py>,
    v: &serde_json::Value,
) -> PyResult<Bound<'py, PyAny>> {
    use serde_json::Value;
    Ok(match v {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => (*b).into_bound_py_any(py)?,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_bound_py_any(py)?
            } else if let Some(f) = n.as_f64() {
                f.into_bound_py_any(py)?
            } else {
                n.to_string().into_bound_py_any(py)?
            }
        }
        Value::String(s) => s.as_str().into_bound_py_any(py)?,
        Value::Array(xs) => {
            let list = PyList::empty(py);
            for x in xs {
                list.append(json_to_py(py, x)?)?;
            }
            list.into_any()
        }
        Value::Object(m) => {
            let d = PyDict::new(py);
            for (k, vv) in m {
                d.set_item(k, json_to_py(py, vv)?)?;
            }
            d.into_any()
        }
    })
}

/// Snapshot the runtime's per-stage perf counters as a list of
/// `(stage, count, total_ns)` tuples. Empty when `TN_PERF_TRACE` is
/// unset (no recording happened) — set the env var BEFORE calling
/// `Runtime.init` to enable.
#[pyfunction]
fn perf_snapshot(py: Python<'_>) -> PyResult<PyObject> {
    guard(|| {
        let snap = tn_core::perf::snapshot();
        let list = PyList::empty(py);
        for (stage, stats) in snap {
            let tup = (stage, stats.count, stats.total_ns).into_pyobject(py)?;
            list.append(tup)?;
        }
        Ok(list.into())
    })
}

/// Reset all perf counters to zero. Use to drop warmup costs before
/// a measurement window.
#[pyfunction]
fn perf_reset() {
    tn_core::perf::reset();
}

/// List the manifest kinds recognized by the Rust core (the single source
/// of truth for the cross-implementation kind catalog).
#[pyfunction]
fn manifest_known_kinds<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
    guard(|| {
        let list = PyList::empty(py);
        for kind in [
            ManifestKind::AdminLogSnapshot,
            ManifestKind::Offer,
            ManifestKind::Enrolment,
            ManifestKind::RecipientInvite,
            ManifestKind::KitBundle,
            ManifestKind::FullKeystore,
            ManifestKind::ContactUpdate,
            ManifestKind::IdentitySeed,
            ManifestKind::ProjectSeed,
            ManifestKind::GroupKeys,
        ] {
            list.append(kind.as_str())?;
        }
        Ok(list)
    })
}

/// Normalize a manifest wire dictionary through the Rust manifest parser.
#[pyfunction]
fn manifest_to_dict<'py>(
    py: Python<'py>,
    manifest_doc: &Bound<'_, PyDict>,
) -> PyResult<Bound<'py, PyAny>> {
    guard(|| {
        let manifest = manifest_from_pydict(manifest_doc)?;
        json_to_py(py, &manifest.to_json())
    })
}

/// Canonical signing bytes for a manifest, with `manifest_signature_b64`
/// stripped by the Rust core.
#[pyfunction]
fn manifest_signing_bytes<'py>(
    py: Python<'py>,
    manifest_doc: &Bound<'_, PyDict>,
) -> PyResult<Bound<'py, PyBytes>> {
    guard(|| {
        let manifest = manifest_from_pydict(manifest_doc)?;
        let bytes = manifest.signing_bytes().map_err(err_to_py)?;
        Ok(PyBytes::new(py, &bytes))
    })
}

/// Return True iff the manifest signature verifies against
/// `publisher_identity`.
#[pyfunction]
fn manifest_verify_signature(manifest_doc: &Bound<'_, PyDict>) -> PyResult<bool> {
    guard(|| {
        let manifest = manifest_from_pydict(manifest_doc)?;
        Ok(verify_manifest(&manifest).is_ok())
    })
}

/// Read a `.tnpkg` (path string or bytes) and return `(manifest_dict, body_dict)`.
#[pyfunction]
fn tnpkg_read<'py>(py: Python<'py>, source: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyTuple>> {
    guard(|| {
        let (manifest, body) = if let Ok(b) = source.extract::<Vec<u8>>() {
            read_tnpkg(TnpkgSource::Bytes(&b)).map_err(err_to_py)?
        } else if let Ok(s) = source.extract::<String>() {
            read_tnpkg(TnpkgSource::Path(Path::new(&s))).map_err(err_to_py)?
        } else {
            return Err(PyValueError::new_err(
                "tnpkg_read: source must be bytes or a path string",
            ));
        };

        let manifest_py = json_to_py(py, &manifest.to_json())?;
        let body_py = PyDict::new(py);
        for (name, data) in body {
            body_py.set_item(name, PyBytes::new(py, &data))?;
        }
        PyTuple::new(py, [manifest_py, body_py.into_any()])
    })
}

/// Write a `.tnpkg` at `out_path` from a manifest wire dict + body file map.
#[pyfunction]
fn tnpkg_write(
    out_path: &str,
    manifest_doc: &Bound<'_, PyDict>,
    body_files: &Bound<'_, PyDict>,
) -> PyResult<String> {
    guard(|| {
        let manifest = manifest_from_pydict(manifest_doc)?;
        let mut body = BodyContents::new();
        for (k, v) in body_files.iter() {
            let name: String = k.extract()?;
            let data: Vec<u8> = v.extract()?;
            body.insert(name, data);
        }
        let path = Path::new(out_path);
        write_tnpkg(path, &manifest, &body).map_err(err_to_py)?;
        Ok(path.display().to_string())
    })
}

/// Load `tn.yaml` through the Rust control-plane loader and return the
/// normalized summary dict (ceremony, paths, groups, vault block).
#[pyfunction]
fn config_load_summary<'py>(py: Python<'py>, yaml_path: &str) -> PyResult<Bound<'py, PyDict>> {
    guard(|| {
        let cfg = tn_core::config::load(Path::new(yaml_path)).map_err(err_to_py)?;
        let vault = cfg.normalized_vault();
        let field_to_groups = cfg.field_to_groups().map_err(err_to_py)?;

        let out = PyDict::new(py);
        out.set_item(intern!(py, "ceremony_id"), cfg.ceremony.id)?;
        out.set_item(intern!(py, "cipher"), cfg.ceremony.cipher)?;
        out.set_item(intern!(py, "mode"), cfg.ceremony.mode)?;
        out.set_item(intern!(py, "sign"), cfg.ceremony.sign)?;
        out.set_item(intern!(py, "chain"), cfg.ceremony.chain)?;
        out.set_item(intern!(py, "log_path"), cfg.logs.path)?;
        out.set_item(
            intern!(py, "admin_log_location"),
            cfg.ceremony.protocol_events_location,
        )?;
        out.set_item(intern!(py, "keystore_path"), cfg.keystore.path)?;
        out.set_item(intern!(py, "device_identity"), cfg.device.device_identity)?;
        out.set_item(
            intern!(py, "groups"),
            json_to_py(
                py,
                &serde_json::Value::Array(
                    cfg.groups
                        .keys()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            )?,
        )?;
        out.set_item(
            intern!(py, "field_to_groups"),
            json_to_py(
                py,
                &serde_json::to_value(field_to_groups)
                    .map_err(|e| PyValueError::new_err(format!("config_load_summary: {e}")))?,
            )?,
        )?;

        let vault_py = PyDict::new(py);
        vault_py.set_item(intern!(py, "enabled"), vault.enabled)?;
        let url_py: Bound<'_, PyAny> = match vault.url {
            Some(s) => s.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        };
        vault_py.set_item(intern!(py, "url"), url_py)?;
        let linked_project_id_py: Bound<'_, PyAny> = match vault.linked_project_id {
            Some(s) => s.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        };
        vault_py.set_item(intern!(py, "linked_project_id"), linked_project_id_py)?;
        vault_py.set_item(intern!(py, "autosync"), vault.autosync)?;
        vault_py.set_item(
            intern!(py, "sync_interval_seconds"),
            vault.sync_interval_seconds,
        )?;
        vault_py.set_item(intern!(py, "declared"), cfg.vault_declared)?;
        out.set_item(intern!(py, "vault"), vault_py)?;

        Ok(out)
    })
}

fn manifest_from_pydict(d: &Bound<'_, PyDict>) -> PyResult<Manifest> {
    let value = serde_json::Value::Object(pydict_to_json(d)?);
    Manifest::from_json(&value).map_err(err_to_py)
}

/// Register all tn-core classes/functions (including the `admin`
/// submodule) into `m`. Shared entry point for the merged
/// `tn._native.core` submodule (the one-package tn-proto wheel). The
/// caller registers the `admin` submodule in sys.modules under its final
/// dotted path — PyO3 only wires attribute access, so explicit
/// `import ....admin` needs the sys.modules entry.
pub fn populate(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRuntime>()?;
    m.add_class::<PyAdminStateCache>()?;
    m.add("TnRuntimeError", py.get_type::<TnRuntimeError>())?;
    m.add("NotEntitled", py.get_type::<NotEntitled>())?;
    m.add("NotAPublisher", py.get_type::<NotAPublisher>())?;
    m.add_function(wrap_pyfunction!(perf_snapshot, m)?)?;
    m.add_function(wrap_pyfunction!(perf_reset, m)?)?;
    m.add_function(wrap_pyfunction!(manifest_known_kinds, m)?)?;
    m.add_function(wrap_pyfunction!(manifest_to_dict, m)?)?;
    m.add_function(wrap_pyfunction!(manifest_signing_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(manifest_verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(tnpkg_read, m)?)?;
    m.add_function(wrap_pyfunction!(tnpkg_write, m)?)?;
    m.add_function(wrap_pyfunction!(config_load_summary, m)?)?;
    crate::admin::register(m)?;
    Ok(())
}
