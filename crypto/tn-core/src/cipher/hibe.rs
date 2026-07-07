//! HIBE cipher for the native runtime.
//!
//! Selected by `cipher: hibe`. When the `hibe` feature is on (default), the
//! native runtime seals and opens hibe groups directly through the `tn-hibe`
//! crate — the same BBG scheme, encodings, and CEK KEM the Python and wasm
//! surfaces use — so a hibe ceremony runs the whole assembly line (classify,
//! index, chain, row_hash, sign) in Rust at full speed. When the feature is
//! off (an Apache-only `tn-core` without the LGPL scheme), a hibe group
//! yields a clear `NotImplemented` from the runtime.
//!
//! Wire compatibility: the group `ciphertext` blob and the candidate-key
//! decrypt order match `tn/cipher.py::HibeGroupCipher` byte-for-byte, so a
//! record written by the native runtime is identical to one written by the
//! pure Python pipeline and vice versa.

use crate::{Error, Result};

/// Sentinel used when the `hibe` feature is off: a hibe group yields a clear
/// `NotImplemented` from the Rust runtime rather than a build error.
pub struct HibePlaceholder;

impl super::GroupCipher for HibePlaceholder {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "HIBE support is not built into this tn-core (the `hibe` feature is off)",
        ))
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "HIBE support is not built into this tn-core (the `hibe` feature is off)",
        ))
    }
    fn kind(&self) -> &'static str {
        "hibe"
    }
}

#[cfg(feature = "hibe")]
pub use real::HibeCipher;

#[cfg(feature = "hibe")]
mod real {
    use std::collections::HashSet;

    use rand_core::OsRng;
    use tn_hibe::{
        delegate, keygen, open_with_aad, seal_with_aad, HibeError, Identity, MasterKey, PrivateKey,
        PublicParams,
    };

    use crate::{Error, Result};

    fn hibe_err(e: HibeError) -> Error {
        Error::Cipher(format!("hibe: {e}"))
    }

    /// One hibe group's key material, loaded from the keystore.
    ///
    /// Mirrors `HibeGroupCipher`: the authority master public key, this
    /// group's identity path, an optional held reader key, an optional
    /// master secret (present only in the authority's own keystore), the
    /// prior sealing paths from rotations, and superseded reader keys kept
    /// so a survivor still opens pre-rotation entries. Secret bytes are
    /// parsed lazily on decrypt.
    pub struct HibeCipher {
        pp: PublicParams,
        id_path: String,
        sk: Option<Vec<u8>>,
        msk: Option<Vec<u8>>,
        prior_paths: Vec<String>,
        prior_sks: Vec<Vec<u8>>,
    }

    impl HibeCipher {
        /// Build from raw keystore bytes. `mpk` and `id_path` are required;
        /// everything else is optional (a write-only party holds neither
        /// `sk` nor `msk`).
        pub fn new(
            mpk: &[u8],
            id_path: &str,
            sk: Option<Vec<u8>>,
            msk: Option<Vec<u8>>,
            prior_paths: Vec<String>,
            prior_sks: Vec<Vec<u8>>,
        ) -> Result<Self> {
            let pp = PublicParams::from_bytes(mpk).map_err(hibe_err)?;
            Ok(Self {
                pp,
                id_path: id_path.to_string(),
                sk,
                msk,
                prior_paths,
                prior_sks,
            })
        }

        /// Decryption-key candidates, most likely first, without minting the
        /// same path twice. Byte-for-byte the order of
        /// `HibeGroupCipher._candidate_keys`.
        fn candidate_keys(&self) -> Result<Vec<PrivateKey>> {
            let mut out: Vec<PrivateKey> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();

            if let Some(sk_bytes) = &self.sk {
                let sk = PrivateKey::from_bytes(sk_bytes).map_err(hibe_err)?;
                seen.insert(path_of(&sk));
                out.push(sk.clone());
                if let Some(derived) = derive_from_held(&self.pp, &sk, &self.id_path)? {
                    if seen.insert(self.id_path.clone()) {
                        out.push(derived);
                    }
                }
            }

            for old in &self.prior_sks {
                let sk = PrivateKey::from_bytes(old).map_err(hibe_err)?;
                if seen.insert(path_of(&sk)) {
                    out.push(sk);
                }
            }

            if let Some(msk_bytes) = &self.msk {
                let msk = MasterKey::from_bytes(msk_bytes).map_err(hibe_err)?;
                let mut paths = vec![self.id_path.clone()];
                paths.extend(self.prior_paths.iter().cloned());
                for p in paths {
                    if seen.insert(p.clone()) {
                        let id = Identity::from_str_path(&p);
                        out.push(keygen(&self.pp, &msk, &id, OsRng).map_err(hibe_err)?);
                    }
                }
            }

            Ok(out)
        }
    }

    impl crate::cipher::GroupCipher for HibeCipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.encrypt_with_aad(plaintext, &[])
        }

        fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            let id = Identity::from_str_path(&self.id_path);
            seal_with_aad(&self.pp, &id, plaintext, aad, OsRng).map_err(hibe_err)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            self.decrypt_with_aad(ciphertext, &[])
        }

        fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            let candidates = self.candidate_keys()?;
            if candidates.is_empty() {
                return Err(Error::NotEntitled {
                    group: "hibe".into(),
                });
            }
            for sk in &candidates {
                match open_with_aad(&self.pp, sk, ciphertext, aad) {
                    Ok(pt) => return Ok(pt),
                    Err(HibeError::Unwrap) => continue,
                    Err(e) => return Err(hibe_err(e)),
                }
            }
            Err(Error::NotEntitled {
                group: "hibe".into(),
            })
        }

        fn kind(&self) -> &'static str {
            "hibe"
        }
    }

    /// The slash-joined identity path a key opens.
    fn path_of(sk: &PrivateKey) -> String {
        sk.identity()
            .labels()
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The held key if it sits on `target_path`, derived down from an
    /// ancestor when needed (BBG opens only with an exact-path key). Mirrors
    /// `HibeGroupCipher._derive_from_held`.
    fn derive_from_held(
        pp: &PublicParams,
        sk: &PrivateKey,
        target_path: &str,
    ) -> Result<Option<PrivateKey>> {
        let held = sk.identity();
        let target = Identity::from_str_path(target_path);
        if held == &target {
            return Ok(Some(sk.clone()));
        }
        if !held.is_parent_of(&target) {
            return Ok(None);
        }
        let mut cur = sk.clone();
        for label in &target.labels()[held.depth()..] {
            cur = delegate(pp, &cur, label, OsRng).map_err(hibe_err)?;
        }
        Ok(Some(cur))
    }
}

#[cfg(all(test, feature = "hibe"))]
mod test {
    use super::HibeCipher;
    use crate::cipher::GroupCipher;
    use rand_core::OsRng;
    use tn_hibe::{keygen, setup, Identity};

    #[test]
    fn native_round_trip_aad_and_candidate_keys() {
        let (pp, msk) = setup(2, OsRng).unwrap();
        let mpk = pp.to_bytes();
        let reader_sk = keygen(&pp, &msk, &Identity::from_str_path("reader/policy"), OsRng)
            .unwrap()
            .to_bytes();

        // Reader-only cipher: mpk + idpath + sk, no master secret.
        let reader = HibeCipher::new(&mpk, "reader/policy", Some(reader_sk), None, vec![], vec![])
            .unwrap();
        let blob = reader.encrypt(b"body").unwrap();
        assert_eq!(reader.decrypt(&blob).unwrap(), b"body");

        // AAD bind + gate + no-aad back-compat.
        let sealed = reader.encrypt_with_aad(b"governed", b"policy=finra").unwrap();
        assert_eq!(reader.decrypt_with_aad(&sealed, b"policy=finra").unwrap(), b"governed");
        assert!(reader.decrypt_with_aad(&sealed, b"policy=other").is_err());
        assert!(reader.decrypt(&sealed).is_err());

        // Authority cipher (holds msk, not the exact sk) opens by minting the
        // path key on demand — exercises the msk-minted candidate branch.
        let authority =
            HibeCipher::new(&mpk, "reader/policy", None, Some(msk.to_bytes()), vec![], vec![])
                .unwrap();
        assert_eq!(authority.decrypt(&blob).unwrap(), b"body");

        // An ancestor-path key opens by deriving down (derive_from_held).
        let dept_sk = keygen(&pp, &msk, &Identity::from_str_path("reader"), OsRng)
            .unwrap()
            .to_bytes();
        let dept = HibeCipher::new(&mpk, "reader/policy", Some(dept_sk), None, vec![], vec![])
            .unwrap();
        assert_eq!(dept.decrypt(&blob).unwrap(), b"body");

        // A stranger's key cannot open.
        let stranger_sk = keygen(&pp, &msk, &Identity::from_str_path("other/policy"), OsRng)
            .unwrap()
            .to_bytes();
        let stranger =
            HibeCipher::new(&mpk, "reader/policy", Some(stranger_sk), None, vec![], vec![]).unwrap();
        assert!(stranger.decrypt(&blob).is_err());
    }
}
