//! BBG HIBE on BLS12-381 — our own Apache-2.0/MIT reimplementation.
//!
//! This crate is the BBG scheme behind `tn-hibe`. It replaced the
//! previously-vendored LGPL `hohibe` crate (now deleted), implementing the
//! same construction (Boneh-Boyen-Goh 2005, "Hierarchical Identity Based
//! Encryption with Constant Size Ciphertext", eprint 2005/015) on the same
//! curve (BLS12-381 via `bls12_381_plus`), with the same element placement,
//! the same identity mapping (`I_i = SHA-256(label) mod p`), and the same
//! canonical byte encodings and KEM wire format. Result: the on-wire bytes
//! are unchanged — the swap carried zero wire difference (proven by the
//! interop gate in `tests/interop.rs`, which opens the frozen golden
//! vectors that were generated under hohibe).
//!
//! `tn-hibe` is now a thin re-export of this crate's high-level HIBE surface,
//! so its consumers (tn-hibe-py, tn-wasm, tn-core) are unchanged.
//!
//! # Provenance / licensing
//!
//! The algorithm is derived from the BBG05 paper and, for structure only, from
//! `samkumar/hibe` (Go, BSD-2-Clause — safe to derive from). It targets
//! BLS12-381, NOT bn256. No LGPL `hohibe` source was read or copied; hohibe is
//! used strictly as a black-box correctness oracle via its frozen golden
//! vectors. This crate therefore carries no LGPL obligation: `MIT OR
//! Apache-2.0`.
//!
//! # Element placement (matches the tn-proto HIBE spec + the frozen goldens)
//!
//! - `PublicParams { max_depth, g:G1, g1:G1, g2:G2, g3:G2, hs:[G2] }`
//! - `MasterKey { g2^alpha : G2 }`
//! - `PrivateKey { a0:G2, a1:G1, bs:Vec<G2>, id }`
//! - `raw::Ciphertext { a:GT, b:G1, c:G2 }` (constant 3 elements)
//!
//! # Security status
//!
//! The `tn-bbg` scheme implementation and `bls12_381_plus` pairing library are
//! unaudited. External cryptographic review is required before production use.
//!
//! # Key lifecycle
//!
//! BBG delegated keys are permanent: there is no forward revocation of an
//! admitted reader.

mod codec;
mod encrypt;
mod error;
mod identity;
mod kem;
mod key;
mod params;
mod seal;

/// Raw BBG primitives over GT.
///
/// The normal HIBE wire surface is [`kem_wrap`]/[`kem_unwrap`] and
/// [`seal`]/[`open`]. Direct GT encryption and GT byte codecs are kept here
/// for golden-vector fixtures and advanced interop checks.
pub mod raw {
    pub use crate::codec::{gt_from_bytes, gt_to_bytes};
    pub use crate::encrypt::{decrypt, encrypt, Ciphertext};
}

pub use codec::mpk_fingerprint;
pub use error::BbgError;
pub use identity::Identity;
pub use kem::{kem_unwrap, kem_wrap, WRAPPED_CEK_LEN};
pub use key::{delegate, keygen, PrivateKey};
pub use params::{setup, MasterKey, PublicParams};
pub use seal::{open, open_with_aad, seal, seal_with_aad};

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn sys(max_depth: usize) -> (PublicParams, MasterKey, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (pp, msk) = setup(max_depth, &mut rng).unwrap();
        (pp, msk, rng)
    }

    fn id(path: &str) -> Identity {
        Identity::try_from_str_path(path).unwrap()
    }

    #[test]
    fn roundtrip_depths_1_2_3() {
        for path in ["a", "a/b", "a/b/c"] {
            let (pp, msk, mut rng) = sys(3);
            let id = id(path);
            let sk = keygen(&pp, &msk, &id, &mut rng).unwrap();
            let cek = [7u8; 32];
            let wrapped = kem_wrap(&pp, &id, &cek, &mut rng).unwrap();
            assert_eq!(kem_unwrap(&pp, &sk, &wrapped).unwrap(), cek, "{path}");
        }
    }

    #[test]
    fn ciphertext_is_three_elements_any_depth() {
        for path in ["a", "a/b", "a/b/c"] {
            let (pp, msk, mut rng) = sys(3);
            let id = id(path);
            let sk = keygen(&pp, &msk, &id, &mut rng).unwrap();
            let m = {
                use bls12_381_plus::group::Group;
                bls12_381_plus::Gt::random(&mut rng)
            };
            let ct = raw::encrypt(&pp, &id, &m, &mut rng).unwrap();
            // Exactly a:GT + b:G1 + c:G2, independent of depth.
            assert_eq!(ct.to_bytes().len(), 1 + 576 + 48 + 96);
            assert_eq!(raw::decrypt(&pp, &sk, &ct).unwrap(), m, "{path}");
        }
    }

    #[test]
    fn delegate_then_decrypt() {
        let (pp, msk, mut rng) = sys(3);
        let parent = keygen(&pp, &msk, &id("a"), &mut rng).unwrap();
        let child = delegate(&pp, &parent, b"b", &mut rng).unwrap();
        assert_eq!(child.identity(), &id("a/b"));
        let cek = [9u8; 32];
        let wrapped = kem_wrap(&pp, &id("a/b"), &cek, &mut rng).unwrap();
        assert_eq!(kem_unwrap(&pp, &child, &wrapped).unwrap(), cek);
        // Two-level delegation.
        let grand = delegate(&pp, &child, b"c", &mut rng).unwrap();
        let wrapped2 = kem_wrap(&pp, &id("a/b/c"), &cek, &mut rng).unwrap();
        assert_eq!(kem_unwrap(&pp, &grand, &wrapped2).unwrap(), cek);
    }

    #[test]
    fn wrong_identity_fails() {
        let (pp, msk, mut rng) = sys(3);
        let alice = keygen(&pp, &msk, &id("alice"), &mut rng).unwrap();
        let cek = [3u8; 32];
        let wrapped = kem_wrap(&pp, &id("bob"), &cek, &mut rng).unwrap();
        // A key on a different path must not recover the CEK (AEAD tag fails).
        assert!(kem_unwrap(&pp, &alice, &wrapped).is_err());
    }

    #[test]
    fn encoding_roundtrips() {
        let (pp, msk, mut rng) = sys(2);
        assert_eq!(PublicParams::from_bytes(&pp.to_bytes()).unwrap(), pp);
        let sk = keygen(&pp, &msk, &id("x"), &mut rng).unwrap();
        assert_eq!(PrivateKey::from_bytes(&sk.to_bytes()).unwrap(), sk);
        let msk2 = MasterKey::from_bytes(&msk.to_bytes()).unwrap();
        assert_eq!(msk2.to_bytes(), msk.to_bytes());
    }
}
