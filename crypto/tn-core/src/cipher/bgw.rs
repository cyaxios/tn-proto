//! BGW cipher stub (feature-gated). A concrete cipher backing
//! [`crate::Runtime`]; selected by group cipher policy. Internal primitive —
//! most readers want the high-level API instead (`tn.info()` / `tn read`);
//! reach here directly only to inspect the Rust-side BGW stub.
//!
//! BGW uses the existing C library at `tn-protocol/crypto/src/bgw.cpp` via
//! FFI, which is not wired in tn-core: any BGW operation here returns
//! `NotImplemented` (BGW groups run through the Python runtime instead).
//! Enable the `bgw` feature to compile this module at all.

use crate::{Error, Result};

/// Sentinel BGW publisher cipher — FFI not yet wired.
pub struct BgwPublisherCipher;

/// Sentinel BGW reader cipher — FFI not yet wired.
pub struct BgwReaderCipher;

impl super::GroupCipher for BgwPublisherCipher {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "BGW encrypt — libtncrypto FFI not yet wired (use Python runtime for BGW groups)",
        ))
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "BGW decrypt — libtncrypto FFI not yet wired",
        ))
    }
    fn kind(&self) -> &'static str {
        "bgw"
    }
}

impl super::GroupCipher for BgwReaderCipher {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("BGW encrypt"))
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("BGW decrypt"))
    }
    fn kind(&self) -> &'static str {
        "bgw"
    }
}
