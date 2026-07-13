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
//! Wire compatibility: the group `ciphertext` blob format and the
//! candidate-key decrypt order match `tn/cipher.py::HibeGroupCipher`, so
//! records written by the native runtime and Python pipeline are mutually
//! readable. Ciphertext bytes are randomized and are not expected to match
//! for the same plaintext.

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
pub(crate) use real::{
    decode_hibe_history_line, encode_hibe_history_path, identity_to_path, normalize_hibe_path,
    validate_identity_path,
};

#[cfg(feature = "hibe")]
mod real {
    use std::collections::HashSet;
    use std::str;

    use rand_core::OsRng;
    use tn_hibe::{
        delegate, keygen, open_with_aad, seal_with_aad, HibeError, Identity, MasterKey, PrivateKey,
        PublicParams,
    };

    use crate::{Error, Result};

    fn hibe_err(e: HibeError) -> Error {
        Error::Cipher(format!("hibe: {e}"))
    }

    pub(crate) fn validate_identity_path(path: &str) -> Result<Identity> {
        Identity::try_from_str_path(path).map_err(hibe_err)
    }

    pub(crate) fn identity_to_path(id: &Identity) -> Result<String> {
        let label_refs: Vec<&[u8]> = id.labels().iter().map(Vec::as_slice).collect();
        Identity::try_from_path(&label_refs).map_err(hibe_err)?;
        let mut out = Vec::with_capacity(id.labels().len());
        for label in id.labels() {
            let s = str::from_utf8(label).map_err(|_| {
                Error::Cipher("hibe: identity label is not valid UTF-8".to_string())
            })?;
            out.push(s.to_string());
        }
        Ok(out.join("/"))
    }

    /// Sentinel line the idpath history file uses for a prior ROOT path —
    /// the tab prefix cannot appear in a validated path, so the line is
    /// unambiguous. Wire contract with Python's
    /// `tn/cipher.py::_HIBE_HISTORY_ROOT_SENTINEL`.
    const HIBE_HISTORY_ROOT_SENTINEL: &str = "\troot";

    /// Validate one non-root HIBE label without lossy normalization.
    /// Message-for-message mirror of `tn/cipher.py::_validate_hibe_label`
    /// (the TN boundary rejects rather than trims — a silently "fixed"
    /// path would be a different authorization path).
    fn validate_hibe_label(label: &str, what: &str) -> Result<()> {
        if label.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not be empty"
            )));
        }
        if label.contains('/') {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must be one path segment, not contain '/'"
            )));
        }
        if label != label.trim() {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not have leading or trailing whitespace"
            )));
        }
        if label.contains('\r') || label.contains('\n') {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not contain line breaks"
            )));
        }
        Ok(())
    }

    /// Return a canonical slash-separated HIBE path or an error.
    ///
    /// Check-for-check mirror of `tn/cipher.py::_normalize_hibe_path`: no
    /// trimming, no slash collapsing, no blank-segment skipping — those
    /// transformations create ambiguous authorization paths. The HIBE root
    /// path is the empty string and is accepted only when `allow_root` is
    /// explicitly true (the error text names the Python-normative
    /// `allow_root_path=True` flag all SDK surfaces expose).
    pub(crate) fn normalize_hibe_path(
        id_path: &str,
        what: &str,
        allow_root: bool,
    ) -> Result<String> {
        if id_path.is_empty() {
            if allow_root {
                return Ok(String::new());
            }
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not be blank; pass allow_root_path=True \
                 to use the root identity path explicitly"
            )));
        }
        if id_path != id_path.trim() {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not have leading or trailing whitespace"
            )));
        }
        if id_path.contains('\r') || id_path.contains('\n') {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not contain line breaks"
            )));
        }
        let labels: Vec<&str> = id_path.split('/').collect();
        if labels.iter().any(|label| label.is_empty()) {
            return Err(Error::InvalidConfig(format!(
                "HIBE: {what} must not contain empty path segments"
            )));
        }
        for (idx, label) in labels.iter().enumerate() {
            validate_hibe_label(label, &format!("{what} segment {idx}"))?;
        }
        Ok(id_path.to_string())
    }

    /// Encode one validated path for the line-oriented idpath history file.
    /// Mirrors `tn/cipher.py::_encode_hibe_history_path`.
    pub(crate) fn encode_hibe_history_path(path: &str) -> &str {
        if path.is_empty() {
            HIBE_HISTORY_ROOT_SENTINEL
        } else {
            path
        }
    }

    /// Decode one idpath history line, including explicit prior root paths.
    /// Mirrors `tn/cipher.py::_decode_hibe_history_line`.
    pub(crate) fn decode_hibe_history_line(line: &str, what: &str) -> Result<String> {
        if line == HIBE_HISTORY_ROOT_SENTINEL {
            return Ok(String::new());
        }
        normalize_hibe_path(line, what, false)
    }

    fn add_candidate(
        pp: &PublicParams,
        out: &mut Vec<PrivateKey>,
        seen: &mut HashSet<String>,
        sk: PrivateKey,
    ) -> Result<()> {
        let key_path = path_of(&sk)?;
        if seen.insert(key_path) {
            validate_key_binding(pp, &sk)?;
            out.push(sk);
        }
        Ok(())
    }

    fn validate_key_binding(pp: &PublicParams, sk: &PrivateKey) -> Result<()> {
        const PROBE: &[u8] = b"tn.hibe.reader-key-binding.v1";
        let sealed = seal_with_aad(pp, sk.identity(), PROBE, PROBE, OsRng).map_err(hibe_err)?;
        if open_with_aad(pp, sk, &sealed, PROBE).is_ok_and(|opened| opened == PROBE) {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "HIBE reader key is not bound to the configured master public key".into(),
        ))
    }

    /// One hibe group's key material, loaded from the keystore.
    ///
    /// Mirrors `HibeGroupCipher`: the authority master public key, this
    /// group's identity path, an optional held reader key, an optional
    /// master secret (present only in the authority's own keystore), the
    /// prior sealing paths from rotations, and superseded reader keys kept
    /// so a survivor still opens pre-rotation entries. Reader material is
    /// parsed, path-scoped, and bound to the MPK during construction.
    pub struct HibeCipher {
        pp: PublicParams,
        id_path: String,
        decrypt_keys: Vec<PrivateKey>,
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
            validate_identity_path(id_path)?;
            for prior_path in &prior_paths {
                validate_identity_path(prior_path)?;
            }
            let decrypt_keys = build_candidate_keys(
                &pp,
                id_path,
                sk.as_deref(),
                msk.as_deref(),
                &prior_paths,
                &prior_sks,
            )?;
            Ok(Self {
                pp,
                id_path: id_path.to_string(),
                decrypt_keys,
            })
        }
    }

    fn build_candidate_keys(
        pp: &PublicParams,
        id_path: &str,
        sk: Option<&[u8]>,
        msk: Option<&[u8]>,
        prior_paths: &[String],
        prior_sks: &[Vec<u8>],
    ) -> Result<Vec<PrivateKey>> {
        let targets: Vec<&str> = std::iter::once(id_path)
            .chain(prior_paths.iter().map(String::as_str))
            .collect();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        if let Some(bytes) = sk {
            add_held_candidates(pp, bytes, &targets, &mut out, &mut seen)?;
        }
        for bytes in prior_sks {
            add_held_candidates(pp, bytes, &targets, &mut out, &mut seen)?;
        }
        if let Some(bytes) = msk {
            add_authority_candidates(pp, bytes, &targets, &mut out, &mut seen)?;
        }
        Ok(out)
    }

    fn add_held_candidates(
        pp: &PublicParams,
        bytes: &[u8],
        targets: &[&str],
        out: &mut Vec<PrivateKey>,
        seen: &mut HashSet<String>,
    ) -> Result<()> {
        let held = PrivateKey::from_bytes(bytes).map_err(hibe_err)?;
        for target in targets {
            if let Some(candidate) = derive_from_held(pp, &held, target)? {
                add_candidate(pp, out, seen, candidate)?;
            }
        }
        Ok(())
    }

    fn add_authority_candidates(
        pp: &PublicParams,
        bytes: &[u8],
        targets: &[&str],
        out: &mut Vec<PrivateKey>,
        seen: &mut HashSet<String>,
    ) -> Result<()> {
        let msk = MasterKey::from_bytes(bytes).map_err(hibe_err)?;
        for target in targets {
            if seen.contains(*target) {
                continue;
            }
            let id = validate_identity_path(target)?;
            add_candidate(
                pp,
                out,
                seen,
                keygen(pp, &msk, &id, OsRng).map_err(hibe_err)?,
            )?;
        }
        Ok(())
    }

    impl crate::cipher::GroupCipher for HibeCipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.encrypt_with_aad(plaintext, &[])
        }

        fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            let id = validate_identity_path(&self.id_path)?;
            seal_with_aad(&self.pp, &id, plaintext, aad, OsRng).map_err(hibe_err)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            self.decrypt_with_aad(ciphertext, &[])
        }

        fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            if self.decrypt_keys.is_empty() {
                return Err(Error::NotEntitled {
                    group: "hibe".into(),
                });
            }
            for sk in &self.decrypt_keys {
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
    fn path_of(sk: &PrivateKey) -> Result<String> {
        identity_to_path(sk.identity())
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
        let target = validate_identity_path(target_path)?;
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
mod path_test {
    use super::real::{decode_hibe_history_line, encode_hibe_history_path, normalize_hibe_path};

    #[test]
    fn normalize_matches_python_boundary_rules() {
        // Accepted paths come back unchanged.
        assert_eq!(
            normalize_hibe_path("team/policy-a", "id_path", false).unwrap(),
            "team/policy-a"
        );
        assert_eq!(
            normalize_hibe_path("solo", "id_path", false).unwrap(),
            "solo"
        );

        // Root only with the explicit flag — same message Python raises.
        let err = normalize_hibe_path("", "id_path", false).unwrap_err();
        assert!(err.to_string().contains("must not be blank"), "{err}");
        assert!(err.to_string().contains("allow_root_path=True"), "{err}");
        assert_eq!(normalize_hibe_path("", "id_path", true).unwrap(), "");

        // The Python-parity rejection set (test_hibe_boundary.py's
        // ambiguous-path parametrization).
        for bad in [
            "/",
            "team//reader",
            "team/reader/",
            " team/reader",
            "team/reader ",
            "team/\nreader",
        ] {
            let err = normalize_hibe_path(bad, "id_path", false).unwrap_err();
            assert!(err.to_string().contains("HIBE: id_path"), "{bad:?}: {err}");
        }
        let err = normalize_hibe_path("a\rb", "id_path", false).unwrap_err();
        assert!(err.to_string().contains("line breaks"), "{err}");
        // Per-segment whitespace check fires even when the ends are clean.
        let err = normalize_hibe_path("a/ b/c", "id_path", false).unwrap_err();
        assert!(err.to_string().contains("segment 1"), "{err}");
    }

    #[test]
    fn history_root_sentinel_round_trips() {
        assert_eq!(encode_hibe_history_path(""), "\troot");
        assert_eq!(encode_hibe_history_path("a/b"), "a/b");
        assert_eq!(decode_hibe_history_line("\troot", "line 1").unwrap(), "");
        assert_eq!(decode_hibe_history_line("a/b", "line 1").unwrap(), "a/b");
        assert!(decode_hibe_history_line(" bad", "line 1").is_err());
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
        let reader =
            HibeCipher::new(&mpk, "reader/policy", Some(reader_sk), None, vec![], vec![]).unwrap();
        let blob = reader.encrypt(b"body").unwrap();
        assert_eq!(reader.decrypt(&blob).unwrap(), b"body");

        // AAD bind + gate + no-aad back-compat.
        let sealed = reader
            .encrypt_with_aad(b"governed", b"policy=finra")
            .unwrap();
        assert_eq!(
            reader.decrypt_with_aad(&sealed, b"policy=finra").unwrap(),
            b"governed"
        );
        assert!(reader.decrypt_with_aad(&sealed, b"policy=other").is_err());
        assert!(reader.decrypt(&sealed).is_err());

        // Authority cipher (holds msk, not the exact sk) opens by minting the
        // path key on demand — exercises the msk-minted candidate branch.
        let authority = HibeCipher::new(
            &mpk,
            "reader/policy",
            None,
            Some(msk.to_bytes()),
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(authority.decrypt(&blob).unwrap(), b"body");

        // An ancestor-path key opens by deriving down (derive_from_held).
        let dept_sk = keygen(&pp, &msk, &Identity::from_str_path("reader"), OsRng)
            .unwrap()
            .to_bytes();
        let dept =
            HibeCipher::new(&mpk, "reader/policy", Some(dept_sk), None, vec![], vec![]).unwrap();
        assert_eq!(dept.decrypt(&blob).unwrap(), b"body");

        // A stranger's key cannot open.
        let stranger_sk = keygen(&pp, &msk, &Identity::from_str_path("other/policy"), OsRng)
            .unwrap()
            .to_bytes();
        let stranger = HibeCipher::new(
            &mpk,
            "reader/policy",
            Some(stranger_sk),
            None,
            vec![],
            vec![],
        )
        .unwrap();
        assert!(stranger.decrypt(&blob).is_err());
    }

    #[test]
    fn prior_ancestor_key_derives_to_current_and_prior_paths() {
        let (pp, msk) = setup(2, OsRng).unwrap();
        let mpk = pp.to_bytes();

        let old_writer = HibeCipher::new(&mpk, "reader/old", None, None, vec![], vec![]).unwrap();
        let old_blob = old_writer.encrypt(b"old body").unwrap();
        let new_writer = HibeCipher::new(&mpk, "reader/new", None, None, vec![], vec![]).unwrap();
        let new_blob = new_writer.encrypt(b"new body").unwrap();

        let archived_ancestor_sk = keygen(&pp, &msk, &Identity::from_str_path("reader"), OsRng)
            .unwrap()
            .to_bytes();
        let reader = HibeCipher::new(
            &mpk,
            "reader/new",
            None,
            None,
            vec!["reader/old".to_string()],
            vec![archived_ancestor_sk],
        )
        .unwrap();

        assert_eq!(reader.decrypt(&old_blob).unwrap(), b"old body");
        assert_eq!(reader.decrypt(&new_blob).unwrap(), b"new body");
    }

    #[test]
    fn ancestor_key_is_scoped_to_the_configured_target_path() {
        let (pp, msk) = setup(2, OsRng).unwrap();
        let mpk = pp.to_bytes();
        let ancestor_sk = keygen(&pp, &msk, &Identity::from_str_path("reader"), OsRng)
            .unwrap()
            .to_bytes();
        let reader = HibeCipher::new(
            &mpk,
            "reader/policy",
            Some(ancestor_sk),
            None,
            vec![],
            vec![],
        )
        .unwrap();
        let ancestor_writer = HibeCipher::new(&mpk, "reader", None, None, vec![], vec![]).unwrap();
        let hostile = ancestor_writer
            .encrypt(b"outside configured scope")
            .unwrap();

        assert!(reader.decrypt(&hostile).is_err());
    }

    #[test]
    fn malformed_reader_key_is_rejected_during_construction() {
        let (pp, _) = setup(2, OsRng).unwrap();
        let result = HibeCipher::new(
            &pp.to_bytes(),
            "reader/policy",
            Some(vec![0x55; 17]),
            None,
            vec![],
            vec![],
        );
        let error = match result {
            Ok(_) => panic!("reader material must be parsed before scanning records"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("malformed PrivateKey"),
            "{error}"
        );
    }

    #[test]
    fn wrong_authority_reader_key_is_rejected_during_construction() {
        let (pp, _) = setup(2, OsRng).unwrap();
        let (other_pp, other_msk) = setup(2, OsRng).unwrap();
        let wrong = keygen(
            &other_pp,
            &other_msk,
            &Identity::from_str_path("reader/policy"),
            OsRng,
        )
        .unwrap()
        .to_bytes();
        let result = HibeCipher::new(
            &pp.to_bytes(),
            "reader/policy",
            Some(wrong),
            None,
            vec![],
            vec![],
        );
        let error = match result {
            Ok(_) => panic!("reader key from another authority must fail at load time"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("master public key"), "{error}");
    }
}
