//! Python bindings for the `tn-hibe` BBG HIBE cipher core.
//!
//! Bytes in, bytes out, mirroring the tn-btn binding posture: Python never
//! touches a Rust struct. Every argument and return value uses the canonical
//! tn-hibe encodings (`PublicParams`/`MasterKey`/`PrivateKey` bytes, wrapped
//! CEKs, sealed blobs), so what Python holds in the keystore is exactly what
//! the golden vectors pin.
//!
//! Exposed as the `hibe` submodule of `tn._native`.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::OsRng;

use tn_hibe::{HibeError, Identity, MasterKey, PrivateKey, PublicParams};

create_exception!(_core, HibeCryptoError, PyException);

fn err_to_py(e: HibeError) -> PyErr {
    match e {
        // Wrong key or tampered bytes: a domain error the cipher layer maps
        // to NotARecipientError. Everything else is a caller/programming
        // error and surfaces as ValueError.
        HibeError::Unwrap => HibeCryptoError::new_err(format!("{e}")),
        other => PyValueError::new_err(format!("{other}")),
    }
}

fn parse_pp(mpk: &[u8]) -> PyResult<PublicParams> {
    PublicParams::from_bytes(mpk).map_err(err_to_py)
}

fn parse_sk(sk: &[u8]) -> PyResult<PrivateKey> {
    PrivateKey::from_bytes(sk).map_err(err_to_py)
}

/// Run BBG Setup for a fresh authority. Returns `(mpk_bytes, msk_bytes)`.
#[pyfunction]
fn setup(py: Python<'_>, max_depth: usize) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (pp, msk) = tn_hibe::setup(max_depth, OsRng).map_err(err_to_py)?;
    Ok((
        PyBytes::new(py, &pp.to_bytes()).into(),
        PyBytes::new(py, &msk.to_bytes()).into(),
    ))
}

/// Generate the private key for `id_path` (slash-separated) from the msk.
#[pyfunction]
fn keygen(py: Python<'_>, mpk: &[u8], msk: &[u8], id_path: &str) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let msk = MasterKey::from_bytes(msk).map_err(err_to_py)?;
    let id = Identity::from_str_path(id_path);
    let sk = tn_hibe::keygen(&pp, &msk, &id, OsRng).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &sk.to_bytes()).into())
}

/// Derive the key for `parent_sk`'s child labelled `child_label` — no msk.
#[pyfunction]
fn delegate(py: Python<'_>, mpk: &[u8], parent_sk: &[u8], child_label: &str) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let parent = parse_sk(parent_sk)?;
    let sk = tn_hibe::delegate(&pp, &parent, child_label.as_bytes(), OsRng).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &sk.to_bytes()).into())
}

/// The slash-separated identity path a private key opens.
#[pyfunction]
fn key_id_path(sk: &[u8]) -> PyResult<String> {
    let sk = parse_sk(sk)?;
    let labels: Vec<String> = sk
        .identity()
        .labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    Ok(labels.join("/"))
}

/// Wrap a 32-byte CEK to `id_path` under the authority's mpk.
#[pyfunction]
fn kem_wrap(py: Python<'_>, mpk: &[u8], id_path: &str, cek: &[u8]) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let cek: [u8; 32] = cek
        .try_into()
        .map_err(|_| PyValueError::new_err("cek must be exactly 32 bytes"))?;
    let id = Identity::from_str_path(id_path);
    let wrapped = tn_hibe::kem_wrap(&pp, &id, &cek, OsRng).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &wrapped).into())
}

/// Unwrap a wrapped CEK with a key on its identity path.
#[pyfunction]
fn kem_unwrap(py: Python<'_>, mpk: &[u8], sk: &[u8], wrapped: &[u8]) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let sk = parse_sk(sk)?;
    let cek = tn_hibe::kem_unwrap(&pp, &sk, wrapped).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &cek).into())
}

/// Seal a full group body to `id_path`: the blob a hibe group stores as its
/// `ciphertext` (fresh CEK + KEM wrap + AES-256-GCM body, single encoding
/// owned by Rust so Python/wasm can never fork the layout).
///
/// `aad` (optional) binds additional authenticated data into the body tag:
/// authenticated, not encrypted, not stored. The reader must supply the
/// identical `aad` to open. Omitting it (or passing empty) yields a blob
/// byte-identical to a plain seal.
#[pyfunction]
#[pyo3(signature = (mpk, id_path, plaintext, aad=None))]
fn seal(
    py: Python<'_>,
    mpk: &[u8],
    id_path: &str,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let id = Identity::from_str_path(id_path);
    let blob = tn_hibe::seal_with_aad(&pp, &id, plaintext, aad.unwrap_or(&[]), OsRng)
        .map_err(err_to_py)?;
    Ok(PyBytes::new(py, &blob).into())
}

/// Open a sealed group blob with a key on its identity path. If the blob was
/// sealed with `aad`, the same `aad` MUST be supplied here or the open fails.
#[pyfunction]
#[pyo3(signature = (mpk, sk, blob, aad=None))]
fn open(
    py: Python<'_>,
    mpk: &[u8],
    sk: &[u8],
    blob: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    let sk = parse_sk(sk)?;
    let body = tn_hibe::open_with_aad(&pp, &sk, blob, aad.unwrap_or(&[])).map_err(err_to_py)?;
    Ok(PyBytes::new(py, &body).into())
}

/// SHA-256 fingerprint of an authority's mpk (the manifest `mpk_fp`).
#[pyfunction]
fn mpk_fingerprint(py: Python<'_>, mpk: &[u8]) -> PyResult<Py<PyBytes>> {
    let pp = parse_pp(mpk)?;
    Ok(PyBytes::new(py, &tn_hibe::mpk_fingerprint(&pp)).into())
}

/// The maximum identity-path depth an authority's mpk supports. Doubles as
/// a parse check: raises ValueError on malformed mpk bytes.
#[pyfunction]
fn mpk_max_depth(mpk: &[u8]) -> PyResult<usize> {
    Ok(parse_pp(mpk)?.max_depth())
}

/// Register all tn-hibe functions into `m`. Shared entry point for the
/// merged `tn._native.hibe` submodule (the one-package tn-proto wheel).
pub fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(setup, m)?)?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(delegate, m)?)?;
    m.add_function(wrap_pyfunction!(key_id_path, m)?)?;
    m.add_function(wrap_pyfunction!(kem_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(kem_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(seal, m)?)?;
    m.add_function(wrap_pyfunction!(open, m)?)?;
    m.add_function(wrap_pyfunction!(mpk_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(mpk_max_depth, m)?)?;
    m.add("HibeCryptoError", m.py().get_type::<HibeCryptoError>())?;
    Ok(())
}
