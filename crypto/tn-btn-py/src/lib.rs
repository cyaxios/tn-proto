//! Python bindings for the `btn` broadcast-transaction encryption library.
//!
//! The API surface is deliberately narrow — bytes in, bytes out. Reader
//! kits and ciphertexts are exchanged as `bytes` objects (the underlying
//! wire format from `btn::wire`), so Python callers never touch any
//! Rust struct directly.
//!
//! ## Usage
//!
//! ```python
//! import btn
//!
//! # Publisher
//! state = btn.PublisherState()                   # random seed
//! alice_kit = state.mint()                       # bytes (~2.8 KB at h=10)
//! bob_kit = state.mint()
//! ct = state.encrypt(b"hello everyone")           # bytes (~300 B)
//!
//! # Any reader with a kit
//! pt = btn.decrypt(alice_kit, ct)
//! assert pt == b"hello everyone"
//!
//! # Revocation
//! state.revoke_kit(bob_kit)
//! ct2 = state.encrypt(b"not for bob")
//! btn.decrypt(alice_kit, ct2)                    # b"not for bob"
//! btn.decrypt(bob_kit, ct2)                       # raises btn.NotEntitled
//! ```

// On pyo3 0.24 (bumped to clear RUSTSEC-2025-0020, the PyString::from_object
// buffer overflow). The 0.21-era bound-API names (`*_bound`) have been
// migrated to the plain `Bound`-returning constructors.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// We alias the underlying Rust crate so we can keep `fn btn` as the
// PyO3 module entry point (the pymodule function name must match the
// Python module name, which is `tn_btn`).
extern crate tn_btn as btn_lib;
use btn_lib::{
    Ciphertext, Config as BtnConfig, Error as BtnLibError, LeafIndex,
    PublisherState as RustPubState, ReaderKit, RetiredPublisherState as RustRetired,
    RotationOutcome as RustOutcome,
};

mod pipeline;

create_exception!(_core, NotEntitled, PyException);
create_exception!(_core, BtnRuntimeError, PyException);

pub(crate) fn err_to_py(e: BtnLibError) -> PyErr {
    match e {
        BtnLibError::NotEntitled => NotEntitled::new_err("reader not entitled"),
        _ => BtnRuntimeError::new_err(format!("{e}")),
    }
}

/// Common message for any method called on a PyPublisherState whose
/// inner has been consumed by `rotate()`. Returned as a PyRuntimeError.
fn consumed_err() -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(
        "PublisherState has been consumed by rotate(); use the new active state \
         returned in RotationOutcome.active.",
    )
}

/// Publisher-side state.
///
/// Owns the master seed, the eagerly-populated node-key cache, and the
/// bookkeeping for issued and revoked readers. Loss = cannot encrypt
/// further ciphertexts from this publisher. Leak = catastrophic.
#[pyclass(module = "btn._core", name = "PublisherState")]
pub(crate) struct PyPublisherState {
    /// `Option` so `rotate(self)` can `take()` the inner state and
    /// hand ownership to `tn_btn::PublisherState::rotate(self)`. Once
    /// rotated, this wrapper is "consumed" — every subsequent method
    /// call surfaces a RuntimeError pointing at `RotationOutcome.active`.
    pub(crate) inner: Option<RustPubState>,
}

impl PyPublisherState {
    pub(crate) fn require_inner(&self) -> PyResult<&RustPubState> {
        self.inner.as_ref().ok_or_else(consumed_err)
    }
    pub(crate) fn require_inner_mut(&mut self) -> PyResult<&mut RustPubState> {
        self.inner.as_mut().ok_or_else(consumed_err)
    }

    /// Internal encrypt helper for the pipeline module; bypasses the
    /// Python bytes conversion.
    pub(crate) fn encrypt_internal(&self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        let inner = self.require_inner()?;
        inner
            .encrypt(plaintext)
            .map(|ct| ct.to_bytes())
            .map_err(err_to_py)
    }
}

#[pymethods]
impl PyPublisherState {
    /// Create a publisher. If `seed` is supplied (as 32 bytes), the
    /// publisher is deterministic. Otherwise a random seed is generated
    /// via the OS CSPRNG.
    #[new]
    #[pyo3(signature = (seed = None))]
    fn new(seed: Option<&[u8]>) -> PyResult<Self> {
        let inner = match seed {
            Some(s) => {
                if s.len() != 32 {
                    return Err(PyValueError::new_err(format!(
                        "seed must be exactly 32 bytes, got {}",
                        s.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(s);
                RustPubState::setup_with_seed(BtnConfig, arr).map_err(err_to_py)?
            }
            None => RustPubState::setup(BtnConfig).map_err(err_to_py)?,
        };
        Ok(Self { inner: Some(inner) })
    }

    /// 32-byte publisher identifier. Stable for the lifetime of the
    /// publisher (derived from the master seed).
    #[getter]
    fn publisher_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.require_inner()?;
        Ok(PyBytes::new(py, &inner.publisher_id()))
    }

    /// Current epoch counter. Starts at 0; increments on every
    /// successful `rotate()`.
    #[getter]
    fn epoch(&self) -> PyResult<u32> {
        Ok(self.require_inner()?.epoch())
    }

    /// Number of currently-active reader kits.
    #[getter]
    fn issued_count(&self) -> PyResult<usize> {
        Ok(self.require_inner()?.issued_count())
    }

    /// Number of revoked reader kits.
    #[getter]
    fn revoked_count(&self) -> PyResult<usize> {
        Ok(self.require_inner()?.revoked_count())
    }

    /// Tree height for this configuration (always TREE_HEIGHT).
    #[getter]
    fn tree_height(&self) -> u8 {
        btn_lib::config::TREE_HEIGHT
    }

    /// Maximum readers this publisher can ever mint.
    #[getter]
    fn max_leaves(&self) -> u64 {
        btn_lib::config::MAX_LEAVES
    }

    /// Mint a fresh reader kit. Returns serialized `.tnpkg` bytes.
    fn mint<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.require_inner_mut()?;
        let kit = inner.mint().map_err(err_to_py)?;
        Ok(PyBytes::new(py, &kit.to_bytes()))
    }

    /// Revoke a reader by their kit bytes. Idempotent.
    fn revoke_kit(&mut self, kit_bytes: &[u8]) -> PyResult<()> {
        let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
        let inner = self.require_inner_mut()?;
        inner.revoke(&kit).map_err(err_to_py)
    }

    /// Revoke a reader by leaf index directly. Idempotent.
    fn revoke_by_leaf(&mut self, leaf: u64) -> PyResult<()> {
        let inner = self.require_inner_mut()?;
        inner.revoke_by_leaf(LeafIndex(leaf)).map_err(err_to_py)
    }

    /// Encrypt `plaintext` for all currently-active readers. Returns
    /// serialized ciphertext bytes.
    fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.require_inner()?;
        let ct = inner.encrypt(plaintext).map_err(err_to_py)?;
        Ok(PyBytes::new(py, &ct.to_bytes()))
    }

    /// Serialize this publisher state for persistence. Treat as secret.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.require_inner()?;
        Ok(PyBytes::new(py, &inner.to_bytes()))
    }

    /// Restore a publisher state from bytes previously produced by
    /// [`Self::to_bytes`]. Rebuilds the internal cache in ~500 µs.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner = RustPubState::from_bytes(bytes).map_err(err_to_py)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Rotate this publisher state. Consumes the underlying Rust state;
    /// subsequent method calls on this wrapper raise RuntimeError until
    /// `RotationOutcome.active` is moved into a fresh PublisherState.
    ///
    /// Returns a `RotationOutcome` with two attributes:
    ///   .active   — fresh PublisherState (new master_seed, new
    ///               publisher_id, epoch = prior + 1, empty leaf
    ///               bookkeeping)
    ///   .retired  — RetiredPublisherState snapshot of the prior state
    ///               (master_seed + publisher_id + epoch + retired_at_unix_secs;
    ///               kept for keywalk on historical ciphertexts)
    fn rotate(&mut self) -> PyResult<PyRotationOutcome> {
        let inner = self.inner.take().ok_or_else(consumed_err)?;
        let outcome = inner.rotate().map_err(err_to_py)?;
        Ok(convert_outcome(outcome))
    }

    fn __repr__(&self) -> String {
        match self.inner.as_ref() {
            None => "PublisherState(<consumed by rotate()>)".to_string(),
            Some(inner) => {
                let id = inner.publisher_id();
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "PublisherState(publisher_id={hex}, epoch={}, issued={}, revoked={})",
                    inner.epoch(),
                    inner.issued_count(),
                    inner.revoked_count(),
                )
            }
        }
    }
}

// -----------------------------------------------------------------------
// RotationOutcome + RetiredPublisherState (phase A spec section 3.1)
// -----------------------------------------------------------------------

/// Frozen snapshot of a publisher state that has been retired by a
/// rotation. Carries enough material to decrypt historical ciphertexts
/// minted under it (via the existing reader-kit path) and to identify
/// it on disk (publisher_id + epoch).
#[pyclass(module = "btn._core", name = "RetiredPublisherState")]
pub(crate) struct PyRetiredPublisherState {
    pub(crate) inner: RustRetired,
}

#[pymethods]
impl PyRetiredPublisherState {
    /// 32-byte publisher_id this state served under.
    #[getter]
    fn publisher_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.publisher_id())
    }

    /// Epoch this state was active under (0, 1, 2, ...).
    #[getter]
    fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    /// Wall-clock UTC seconds at which this state was retired.
    #[getter]
    fn retired_at_unix_secs(&self) -> u64 {
        self.inner.retired_at_unix_secs()
    }

    /// Serialize for on-disk persistence. Treat as secret.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// Restore from bytes previously produced by `to_bytes()`.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner = RustRetired::from_bytes(bytes).map_err(err_to_py)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        let id = self.inner.publisher_id();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "RetiredPublisherState(publisher_id={hex}, epoch={}, retired_at_unix_secs={})",
            self.inner.epoch(),
            self.inner.retired_at_unix_secs(),
        )
    }
}

/// Result of `PublisherState.rotate()`. Has two `Option`-backed
/// attributes that yield ownership of their inner once each (getter
/// `take()` semantics). Re-accessing after the first read raises
/// RuntimeError — this prevents accidental aliasing of the active
/// state across two Python references.
#[pyclass(module = "btn._core", name = "RotationOutcome")]
pub(crate) struct PyRotationOutcome {
    pub(crate) active: Option<PyPublisherState>,
    pub(crate) retired: Option<PyRetiredPublisherState>,
}

#[pymethods]
impl PyRotationOutcome {
    /// Pull the new active state out of the outcome. Single-use.
    #[getter]
    fn active(&mut self) -> PyResult<PyPublisherState> {
        self.active.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "rotation outcome's active state has already been consumed",
            )
        })
    }

    /// Pull the retired state snapshot out of the outcome. Single-use.
    #[getter]
    fn retired(&mut self) -> PyResult<PyRetiredPublisherState> {
        self.retired.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "rotation outcome's retired state has already been consumed",
            )
        })
    }
}

fn convert_outcome(outcome: RustOutcome) -> PyRotationOutcome {
    PyRotationOutcome {
        active: Some(PyPublisherState {
            inner: Some(outcome.active),
        }),
        retired: Some(PyRetiredPublisherState {
            inner: outcome.retired,
        }),
    }
}

/// Decrypt `ct_bytes` with `kit_bytes`. Returns plaintext bytes.
///
/// Raises `btn.NotEntitled` if the reader is not entitled to decrypt
/// (revoked, or ciphertext from a different publisher / epoch). Raises
/// `btn.BtnRuntimeError` for malformed input.
#[pyfunction]
fn decrypt<'py>(
    py: Python<'py>,
    kit_bytes: &[u8],
    ct_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
    let ct = Ciphertext::from_bytes(ct_bytes).map_err(err_to_py)?;
    let pt = kit.decrypt(&ct).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &pt))
}

/// Extract the 32-byte publisher_id from a ciphertext without
/// decrypting. Useful for routing: "which publisher produced this?"
#[pyfunction]
fn ciphertext_publisher_id<'py>(py: Python<'py>, ct_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let ct = Ciphertext::from_bytes(ct_bytes).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &ct.publisher_id))
}

/// Extract the 32-byte publisher_id from a reader kit.
#[pyfunction]
fn kit_publisher_id<'py>(py: Python<'py>, kit_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &kit.publisher_id()))
}

/// Extract the leaf index (u64) from a reader kit.
#[pyfunction]
fn kit_leaf(kit_bytes: &[u8]) -> PyResult<u64> {
    let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
    Ok(kit.leaf().0)
}

/// Current hard-coded tree height for this build.
#[pyfunction]
fn tree_height() -> u8 {
    btn_lib::config::TREE_HEIGHT
}

/// Maximum number of leaves this build supports.
#[pyfunction]
fn max_leaves() -> u64 {
    btn_lib::config::MAX_LEAVES
}

/// Register all tn-btn classes/functions into `m`. Shared entry point for
/// the merged `tn._native.btn` submodule (the one-package tn-proto wheel).
pub fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPublisherState>()?;
    m.add_class::<PyRetiredPublisherState>()?;
    m.add_class::<PyRotationOutcome>()?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ciphertext_publisher_id, m)?)?;
    m.add_function(wrap_pyfunction!(kit_publisher_id, m)?)?;
    m.add_function(wrap_pyfunction!(kit_leaf, m)?)?;
    m.add_function(wrap_pyfunction!(tree_height, m)?)?;
    m.add_function(wrap_pyfunction!(max_leaves, m)?)?;
    m.add_function(wrap_pyfunction!(pipeline::build_envelope_line, m)?)?;
    m.add("NotEntitled", m.py().get_type::<NotEntitled>())?;
    m.add("BtnRuntimeError", m.py().get_type::<BtnRuntimeError>())?;
    Ok(())
}
