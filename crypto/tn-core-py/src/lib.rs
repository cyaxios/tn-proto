//! PyO3 wrapper for tn_core::Runtime.

// pyo3 0.22 macros expand to code that references a non-existent `gil-refs`
// cargo feature and insert `.into()` conversions that clippy flags as
// useless. Both are pyo3-side artifacts — suppressed here until we bump to
// pyo3 0.23+ (tracked in the remediation plan).
#![allow(unexpected_cfgs)]
#![allow(clippy::useless_conversion)]

mod admin;

use pyo3::exceptions::{PyException, PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::{create_exception, intern};
use std::path::Path;
use std::sync::Arc;

use ::tn_core::admin_cache::ChainConflict;
use ::tn_core::tnpkg::ManifestKind;
use ::tn_core::{
    AbsorbSource, AdminStateCache, Error as TnError, ExportOptions, Runtime,
};

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

#[pyclass(module = "tn_core._core", name = "Runtime")]
pub struct PyRuntime {
    inner: Arc<Runtime>,
}

#[pymethods]
impl PyRuntime {
    #[staticmethod]
    fn init(yaml_path: &str) -> PyResult<Self> {
        let rt = Runtime::init(Path::new(yaml_path)).map_err(err_to_py)?;
        Ok(Self {
            inner: Arc::new(rt),
        })
    }

    fn did(&self) -> &str {
        self.inner.did()
    }

    fn log_path(&self) -> String {
        self.inner.log_path().display().to_string()
    }

    /// Emit an event. `fields` is a Python dict; returns `None` for
    /// cross-language parity with Python `tn.log` (returns `None`) and
    /// TS `tn.log` (returns `void`).
    ///
    /// `sign` overrides the ceremony's yaml `ceremony.sign` default for this
    /// single call. `None` uses the configured default (typically `True`).
    // Argument count matches the Python-visible signature; PyO3 methods
    // surface individual args to keep the Python callsite ergonomic.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (level, event_type, fields, timestamp=None, event_id=None, sign=None))]
    fn emit(
        &self,
        level: &str,
        event_type: &str,
        fields: &Bound<'_, PyDict>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> PyResult<()> {
        let fields_json = pydict_to_json(fields)?;
        self.inner
            .emit_with_override_sign(level, event_type, fields_json, timestamp, event_id, sign)
            .map_err(err_to_py)
    }

    /// Read all entries as flat dicts (the default 2026-04-25 shape).
    ///
    /// Six envelope basics (`timestamp`, `event_type`, `level`, `did`,
    /// `sequence`, `event_id`) plus every readable group's decrypted
    /// fields land at the top level. `_hidden_groups` /
    /// `_decrypt_errors` markers surface only when non-empty.
    #[pyo3(signature = (log_path=None))]
    fn read<'py>(&self, py: Python<'py>, log_path: Option<&str>) -> PyResult<Bound<'py, PyList>> {
        let raw = match log_path {
            Some(p) => self
                .inner
                .read_from(std::path::Path::new(p))
                .map_err(err_to_py)?,
            None => self.inner.read_raw().map_err(err_to_py)?,
        };
        let list = PyList::empty_bound(py);
        for r in &raw {
            let flat = ::tn_core::runtime::flatten_raw_entry(r, false);
            list.append(json_to_py(py, &serde_json::Value::Object(flat))?)?;
        }
        Ok(list)
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
        use serde_json::{Map, Value};
        let raw_with_valid = match log_path {
            Some(p) => self
                .inner
                .read_from_with_validity(std::path::Path::new(p))
                .map_err(err_to_py)?,
            None => self.inner.read_raw_with_validity().map_err(err_to_py)?,
        };
        let list = PyList::empty_bound(py);
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
    }

    /// Read all entries as the audit-grade `{envelope, plaintext}`
    /// shape (today's pre-2026-04-25 default).
    #[pyo3(signature = (log_path=None))]
    fn read_raw<'py>(
        &self,
        py: Python<'py>,
        log_path: Option<&str>,
    ) -> PyResult<Bound<'py, PyList>> {
        let entries = match log_path {
            Some(p) => self
                .inner
                .read_from(std::path::Path::new(p))
                .map_err(err_to_py)?,
            None => self.inner.read_raw().map_err(err_to_py)?,
        };
        let list = PyList::empty_bound(py);
        for e in entries {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "envelope"), json_to_py(py, &e.envelope)?)?;
            let pt = PyDict::new_bound(py);
            for (g, v) in e.plaintext_per_group {
                pt.set_item(g, json_to_py(py, &v)?)?;
            }
            d.set_item(intern!(py, "plaintext"), pt)?;
            list.append(d)?;
        }
        Ok(list)
    }

    /// Iterate verified entries (sig + row_hash + chain). Returns flat
    /// dicts like `read()` plus an optional `instructions` block when
    /// the caller holds the `tn.agents` kit. Per spec §3.
    ///
    /// `on_invalid` is one of "skip" (default), "raise", "forensic".
    #[pyo3(signature = (on_invalid="skip"))]
    fn secure_read<'py>(
        &self,
        py: Python<'py>,
        on_invalid: &str,
    ) -> PyResult<Bound<'py, PyList>> {
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
        let list = PyList::empty_bound(py);
        for entry in entries {
            // Build the flat dict. Then attach `instructions` when present.
            let dict = json_to_py(py, &serde_json::Value::Object(entry.fields))?;
            let dict_obj: Bound<'_, PyDict> = dict.downcast_into::<PyDict>()?;
            if let Some(instr) = entry.instructions {
                let id = PyDict::new_bound(py);
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
                let arr = PyList::empty_bound(py);
                for g in entry.hidden_groups {
                    arr.append(g)?;
                }
                dict_obj.set_item(intern!(py, "_hidden_groups"), arr)?;
            }
            if !entry.decrypt_errors.is_empty() {
                let arr = PyList::empty_bound(py);
                for g in entry.decrypt_errors {
                    arr.append(g)?;
                }
                dict_obj.set_item(intern!(py, "_decrypt_errors"), arr)?;
            }
            list.append(dict_obj)?;
        }
        Ok(list)
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
        let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();
        let p = self
            .inner
            .admin_add_agent_runtime(runtime_did, &group_refs, Path::new(out_path), label)
            .map_err(err_to_py)?;
        Ok(p.display().to_string())
    }

    fn close(&self) -> PyResult<()> {
        // Arc<Runtime> — dropping PyRuntime decrements refcount; close is implicit.
        Ok(())
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
        self.inner
            .admin_add_recipient(group, Path::new(out_path), recipient_did)
            .map_err(err_to_py)
    }

    /// Revoke the btn reader at `leaf_index` in `group`.
    fn revoke_recipient(&self, group: &str, leaf_index: u64) -> PyResult<()> {
        self.inner
            .admin_revoke_recipient(group, leaf_index)
            .map_err(err_to_py)
    }

    /// Return how many recipients are currently revoked in `group`'s btn state.
    fn revoked_count(&self, group: &str) -> PyResult<usize> {
        self.inner.admin_revoked_count(group).map_err(err_to_py)
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
        let entries = self
            .inner
            .recipients(group, include_revoked)
            .map_err(err_to_py)?;
        let list = PyList::empty_bound(py);
        for r in entries {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "leaf_index"), r.leaf_index)?;
            d.set_item(
                intern!(py, "recipient_did"),
                r.recipient_did.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(
                intern!(py, "minted_at"),
                r.minted_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(
                intern!(py, "kit_sha256"),
                r.kit_sha256.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(intern!(py, "revoked"), r.revoked)?;
            d.set_item(
                intern!(py, "revoked_at"),
                r.revoked_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            list.append(d)?;
        }
        Ok(list)
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
        let state = self.inner.admin_state(group).map_err(err_to_py)?;
        let out = PyDict::new_bound(py);

        // ceremony
        let ceremony_v: Bound<'py, PyAny> = match state.ceremony {
            Some(c) => {
                let d = PyDict::new_bound(py);
                d.set_item(intern!(py, "ceremony_id"), c.ceremony_id)?;
                d.set_item(intern!(py, "cipher"), c.cipher)?;
                d.set_item(intern!(py, "device_did"), c.device_did)?;
                d.set_item(
                    intern!(py, "created_at"),
                    c.created_at.map_or_else(|| py.None(), |s| s.into_py(py)),
                )?;
                d.into_any()
            }
            None => py.None().into_bound(py),
        };
        out.set_item(intern!(py, "ceremony"), ceremony_v)?;

        // groups
        let groups = PyList::empty_bound(py);
        for g in state.groups {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "group"), g.group)?;
            d.set_item(intern!(py, "cipher"), g.cipher)?;
            d.set_item(intern!(py, "publisher_did"), g.publisher_did)?;
            d.set_item(intern!(py, "added_at"), g.added_at)?;
            groups.append(d)?;
        }
        out.set_item(intern!(py, "groups"), groups)?;

        // recipients
        let recipients = PyList::empty_bound(py);
        for r in state.recipients {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "group"), r.group)?;
            d.set_item(intern!(py, "leaf_index"), r.leaf_index)?;
            d.set_item(
                intern!(py, "recipient_did"),
                r.recipient_did.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(intern!(py, "kit_sha256"), r.kit_sha256)?;
            d.set_item(
                intern!(py, "minted_at"),
                r.minted_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(intern!(py, "active_status"), r.active_status)?;
            d.set_item(
                intern!(py, "revoked_at"),
                r.revoked_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(
                intern!(py, "retired_at"),
                r.retired_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            recipients.append(d)?;
        }
        out.set_item(intern!(py, "recipients"), recipients)?;

        // rotations
        let rotations = PyList::empty_bound(py);
        for r in state.rotations {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "group"), r.group)?;
            d.set_item(intern!(py, "cipher"), r.cipher)?;
            d.set_item(intern!(py, "generation"), r.generation)?;
            d.set_item(intern!(py, "previous_kit_sha256"), r.previous_kit_sha256)?;
            d.set_item(intern!(py, "rotated_at"), r.rotated_at)?;
            rotations.append(d)?;
        }
        out.set_item(intern!(py, "rotations"), rotations)?;

        // coupons
        let coupons = PyList::empty_bound(py);
        for c in state.coupons {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "group"), c.group)?;
            d.set_item(intern!(py, "slot"), c.slot)?;
            d.set_item(intern!(py, "to_did"), c.to_did)?;
            d.set_item(intern!(py, "issued_to"), c.issued_to)?;
            d.set_item(
                intern!(py, "issued_at"),
                c.issued_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            coupons.append(d)?;
        }
        out.set_item(intern!(py, "coupons"), coupons)?;

        // enrolments
        let enrolments = PyList::empty_bound(py);
        for e in state.enrolments {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "group"), e.group)?;
            d.set_item(intern!(py, "peer_did"), e.peer_did)?;
            d.set_item(intern!(py, "package_sha256"), e.package_sha256)?;
            d.set_item(intern!(py, "status"), e.status)?;
            d.set_item(
                intern!(py, "compiled_at"),
                e.compiled_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            d.set_item(
                intern!(py, "absorbed_at"),
                e.absorbed_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            enrolments.append(d)?;
        }
        out.set_item(intern!(py, "enrolments"), enrolments)?;

        // vault_links
        let vault_links = PyList::empty_bound(py);
        for v in state.vault_links {
            let d = PyDict::new_bound(py);
            d.set_item(intern!(py, "vault_did"), v.vault_did)?;
            d.set_item(intern!(py, "project_id"), v.project_id)?;
            d.set_item(intern!(py, "linked_at"), v.linked_at)?;
            d.set_item(
                intern!(py, "unlinked_at"),
                v.unlinked_at.map_or_else(|| py.None(), |s| s.into_py(py)),
            )?;
            vault_links.append(d)?;
        }
        out.set_item(intern!(py, "vault_links"), vault_links)?;

        Ok(out)
    }

    /// Emit a signed `tn.vault.linked` event. Idempotent: returns `None`
    /// either way (matches Python `tn.vault_link`).
    fn vault_link(&self, vault_did: &str, project_id: &str) -> PyResult<()> {
        self.inner
            .vault_link(vault_did, project_id)
            .map_err(err_to_py)
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
        self.inner
            .vault_unlink(vault_did, project_id, reason)
            .map_err(err_to_py)
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
        let mk = ManifestKind::from_wire(kind)
            .ok_or_else(|| PyValueError::new_err(format!("unknown manifest kind: {kind:?}")))?;
        let opts = ExportOptions {
            kind: Some(mk),
            to_did,
            scope,
            confirm_includes_secrets,
            groups,
            package_body,
        };
        let p = self
            .inner
            .export(Path::new(out_path), opts)
            .map_err(err_to_py)?;
        Ok(p.display().to_string())
    }

    /// Apply a `.tnpkg` to local state. `source` may be a path string or bytes.
    fn absorb<'py>(
        &self,
        py: Python<'py>,
        source: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
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
        let d = PyDict::new_bound(py);
        d.set_item(intern!(py, "kind"), receipt.kind)?;
        d.set_item(intern!(py, "accepted_count"), receipt.accepted_count)?;
        d.set_item(intern!(py, "deduped_count"), receipt.deduped_count)?;
        d.set_item(intern!(py, "noop"), receipt.noop)?;
        d.set_item(
            intern!(py, "derived_state"),
            receipt
                .derived_state
                .map_or_else(|| py.None(), |s| {
                    serde_json::to_value(s)
                        .ok()
                        .and_then(|v| json_to_py(py, &v).ok().map(|b| b.unbind()))
                        .map_or_else(|| py.None(), |o| o.into_py(py))
                }),
        )?;
        let conflicts = PyList::empty_bound(py);
        for c in &receipt.conflicts {
            conflicts.append(conflict_to_py(py, c)?)?;
        }
        d.set_item(intern!(py, "conflicts"), conflicts)?;
        d.set_item(intern!(py, "legacy_status"), receipt.legacy_status)?;
        d.set_item(intern!(py, "legacy_reason"), receipt.legacy_reason)?;
        Ok(d)
    }

    /// Construct an `AdminStateCache` backed by this runtime.
    fn admin_cache(&self) -> PyResult<PyAdminStateCache> {
        let cache = AdminStateCache::from_runtime_arc(&self.inner).map_err(err_to_py)?;
        Ok(PyAdminStateCache {
            inner: std::sync::Mutex::new(cache),
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
        let g = self.inner.lock().expect("AdminStateCache mutex poisoned");
        let list = PyList::empty_bound(py);
        for c in g.head_conflicts() {
            list.append(conflict_to_py(py, c)?)?;
        }
        Ok(list)
    }

    fn diverged(&self) -> bool {
        self.inner
            .lock()
            .expect("AdminStateCache mutex poisoned")
            .diverged()
    }

    fn refresh(&self) -> PyResult<usize> {
        let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
        g.refresh().map_err(err_to_py)
    }

    fn state<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
        let v = g.state().map_err(err_to_py)?.clone();
        json_to_py(py, &v)
    }

    #[pyo3(signature = (group, include_revoked=false))]
    fn recipients<'py>(
        &self,
        py: Python<'py>,
        group: &str,
        include_revoked: bool,
    ) -> PyResult<Bound<'py, PyList>> {
        let mut g = self.inner.lock().expect("AdminStateCache mutex poisoned");
        let recs = g.recipients(group, include_revoked).map_err(err_to_py)?;
        let list = PyList::empty_bound(py);
        for r in &recs {
            list.append(json_to_py(py, r)?)?;
        }
        Ok(list)
    }
}

fn conflict_to_py<'py>(py: Python<'py>, c: &ChainConflict) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
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
                originally_revoked_at_row_hash
                    .as_ref()
                    .map_or_else(|| py.None(), |s| s.clone().into_py(py)),
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
        Value::Bool(b) => b.into_py(py).into_bound(py),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py).into_bound(py)
            } else if let Some(f) = n.as_f64() {
                f.into_py(py).into_bound(py)
            } else {
                n.to_string().into_py(py).into_bound(py)
            }
        }
        Value::String(s) => s.clone().into_py(py).into_bound(py),
        Value::Array(xs) => {
            let list = PyList::empty_bound(py);
            for x in xs {
                list.append(json_to_py(py, x)?)?;
            }
            list.into_any()
        }
        Value::Object(m) => {
            let d = PyDict::new_bound(py);
            for (k, vv) in m {
                d.set_item(k, json_to_py(py, vv)?)?;
            }
            d.into_any()
        }
    })
}

#[pymodule]
#[pyo3(name = "_core")]
fn tn_core_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRuntime>()?;
    m.add_class::<PyAdminStateCache>()?;
    m.add("TnRuntimeError", py.get_type_bound::<TnRuntimeError>())?;
    m.add("NotEntitled", py.get_type_bound::<NotEntitled>())?;
    m.add("NotAPublisher", py.get_type_bound::<NotAPublisher>())?;
    crate::admin::register(m)?;
    // Make `import tn_core._core.admin` (and thus `from tn_core.admin import …`)
    // work. PyO3 submodules are not automatically registered in sys.modules;
    // without this only attribute access (tn_core._core.admin.kinds()) works,
    // and explicit imports fail with ModuleNotFoundError.
    let admin_mod = m.getattr("admin")?;
    let py = m.py();
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("tn_core._core.admin", &admin_mod)?;
    Ok(())
}
