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

// pyo3 0.22 macros expand to code that references a non-existent `gil-refs`
// cargo feature and insert `.into()` conversions that clippy flags as
// useless. Both are pyo3-side artifacts — suppressed here until we bump to
// pyo3 0.23+ (tracked in the remediation plan).
#![allow(unexpected_cfgs)]
#![allow(clippy::useless_conversion)]

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
    PublisherState as RustPubState, ReaderKit,
};

mod pipeline;

create_exception!(_core, NotEntitled, PyException);
create_exception!(_core, BtnRuntimeError, PyException);

fn err_to_py(e: BtnLibError) -> PyErr {
    match e {
        BtnLibError::NotEntitled => NotEntitled::new_err("reader not entitled"),
        _ => BtnRuntimeError::new_err(format!("{e}")),
    }
}

/// Publisher-side state.
///
/// Owns the master seed, the eagerly-populated node-key cache, and the
/// bookkeeping for issued and revoked readers. Loss = cannot encrypt
/// further ciphertexts from this publisher. Leak = catastrophic.
#[pyclass(module = "btn._core", name = "PublisherState")]
pub(crate) struct PyPublisherState {
    pub(crate) inner: RustPubState,
}

impl PyPublisherState {
    /// Internal encrypt helper for the pipeline module; bypasses the
    /// Python bytes conversion.
    pub(crate) fn encrypt_internal(&self, plaintext: &[u8]) -> btn_lib::Result<Vec<u8>> {
        self.inner.encrypt(plaintext).map(|ct| ct.to_bytes())
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
        Ok(Self { inner })
    }

    /// 32-byte publisher identifier. Stable for the lifetime of the
    /// publisher (derived from the master seed).
    #[getter]
    fn publisher_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.publisher_id())
    }

    /// Current epoch counter. Starts at 0; reserved for rotation.
    #[getter]
    fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    /// Number of currently-active reader kits.
    #[getter]
    fn issued_count(&self) -> usize {
        self.inner.issued_count()
    }

    /// Number of revoked reader kits.
    #[getter]
    fn revoked_count(&self) -> usize {
        self.inner.revoked_count()
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
        let kit = self.inner.mint().map_err(err_to_py)?;
        Ok(PyBytes::new_bound(py, &kit.to_bytes()))
    }

    /// Revoke a reader by their kit bytes. Idempotent.
    fn revoke_kit(&mut self, kit_bytes: &[u8]) -> PyResult<()> {
        let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
        self.inner.revoke(&kit).map_err(err_to_py)
    }

    /// Revoke a reader by leaf index directly. Idempotent.
    fn revoke_by_leaf(&mut self, leaf: u64) -> PyResult<()> {
        self.inner
            .revoke_by_leaf(LeafIndex(leaf))
            .map_err(err_to_py)
    }

    /// Encrypt `plaintext` for all currently-active readers. Returns
    /// serialized ciphertext bytes.
    fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self.inner.encrypt(plaintext).map_err(err_to_py)?;
        Ok(PyBytes::new_bound(py, &ct.to_bytes()))
    }

    /// Serialize this publisher state for persistence. Treat as secret.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.to_bytes())
    }

    /// Restore a publisher state from bytes previously produced by
    /// [`Self::to_bytes`]. Rebuilds the internal cache in ~500 µs.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner = RustPubState::from_bytes(bytes).map_err(err_to_py)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        let id = self.inner.publisher_id();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "PublisherState(publisher_id={hex}, epoch={}, issued={}, revoked={})",
            self.inner.epoch(),
            self.inner.issued_count(),
            self.inner.revoked_count(),
        )
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
    Ok(PyBytes::new_bound(py, &pt))
}

/// Extract the 32-byte publisher_id from a ciphertext without
/// decrypting. Useful for routing: "which publisher produced this?"
#[pyfunction]
fn ciphertext_publisher_id<'py>(py: Python<'py>, ct_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let ct = Ciphertext::from_bytes(ct_bytes).map_err(err_to_py)?;
    Ok(PyBytes::new_bound(py, &ct.publisher_id))
}

/// Extract the 32-byte publisher_id from a reader kit.
#[pyfunction]
fn kit_publisher_id<'py>(py: Python<'py>, kit_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let kit = ReaderKit::from_bytes(kit_bytes).map_err(err_to_py)?;
    Ok(PyBytes::new_bound(py, &kit.publisher_id()))
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

#[pymodule]
#[pyo3(name = "_core")]
fn btn_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPublisherState>()?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ciphertext_publisher_id, m)?)?;
    m.add_function(wrap_pyfunction!(kit_publisher_id, m)?)?;
    m.add_function(wrap_pyfunction!(kit_leaf, m)?)?;
    m.add_function(wrap_pyfunction!(tree_height, m)?)?;
    m.add_function(wrap_pyfunction!(max_leaves, m)?)?;
    m.add_function(wrap_pyfunction!(pipeline::build_envelope_line, m)?)?;
    m.add("NotEntitled", m.py().get_type_bound::<NotEntitled>())?;
    m.add(
        "BtnRuntimeError",
        m.py().get_type_bound::<BtnRuntimeError>(),
    )?;
    Ok(())
}
