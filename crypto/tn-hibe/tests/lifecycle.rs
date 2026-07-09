//! Full cipher lifecycle at the Rust layer, as one story:
//! authority setup → material persisted and reloaded as bytes → seals →
//! grant (fresh keygen) and delegation (parent → child, no msk) → reads →
//! wrong-identity refusal → policy-path rotation with its honest semantics
//! (old exact-path key loses new seals, keeps old ones; ancestor keys
//! survive rotation; the authority opens everything).
//!
//! Everything crosses a serialize/deserialize boundary before use, so the
//! test exercises the canonical encodings the way real keystores do.

#![cfg(not(target_arch = "wasm32"))]

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tn_hibe::{
    delegate, kem_unwrap, kem_wrap, keygen, mpk_fingerprint, open, seal, setup, HibeError,
    Identity, MasterKey, PrivateKey, PublicParams,
};

fn reload_pp(pp: &PublicParams) -> PublicParams {
    PublicParams::from_bytes(&pp.to_bytes()).expect("pp reload")
}

fn reload_sk(sk: &PrivateKey) -> PrivateKey {
    PrivateKey::from_bytes(&sk.to_bytes()).expect("sk reload")
}

fn identity(path: &str) -> Identity {
    Identity::try_from_str_path(path).unwrap()
}

#[test]
fn full_lifecycle() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6c69666563796c65); // "lifecyle"

    // --- Act 1: authority bootstraps and persists its material.
    let (pp0, msk0) = setup(3, &mut rng).unwrap();
    let pp = reload_pp(&pp0);
    let msk = MasterKey::from_bytes(&msk0.to_bytes()).unwrap();
    let fp = mpk_fingerprint(&pp);
    assert_eq!(
        fp,
        mpk_fingerprint(&pp0),
        "fingerprint stable across reload"
    );

    // --- Act 2: seals to the reader's admission path, epoch A.
    let path_a = identity("reader-did/policy-a");
    let e1 = seal(&pp, &path_a, b"epoch-a entry 1", &mut rng).unwrap();
    let e2 = seal(&pp, &path_a, b"epoch-a entry 2", &mut rng).unwrap();

    // --- Act 3: grant. The authority mints the reader's key; it travels
    // as bytes (the kit) and is reloaded on the reader's side.
    let reader_sk = reload_sk(&keygen(&pp, &msk, &path_a, &mut rng).unwrap());
    assert_eq!(reader_sk.identity(), &path_a);
    assert_eq!(open(&pp, &reader_sk, &e1).unwrap(), b"epoch-a entry 1");
    assert_eq!(open(&pp, &reader_sk, &e2).unwrap(), b"epoch-a entry 2");

    // A second grant for the same path is independently randomized but
    // equally able to read.
    let reader2_sk = keygen(&pp, &msk, &path_a, &mut rng).unwrap();
    assert_ne!(reader2_sk.to_bytes(), reader_sk.to_bytes());
    assert_eq!(open(&pp, &reader2_sk, &e1).unwrap(), b"epoch-a entry 1");

    // --- Act 4: delegation. A department key holder derives the admission
    // key locally — the msk is never involved.
    let dept_sk = reload_sk(&keygen(&pp, &msk, &identity("reader-did"), &mut rng).unwrap());
    let derived = delegate(&pp, &dept_sk, b"policy-a", &mut rng).unwrap();
    assert_eq!(open(&pp, &derived, &e1).unwrap(), b"epoch-a entry 1");

    // --- Act 5: wrong identities are refused, not garbled.
    let stranger = keygen(&pp, &msk, &identity("other-did/policy-a"), &mut rng).unwrap();
    assert!(matches!(open(&pp, &stranger, &e1), Err(HibeError::Unwrap)));

    // The KEM alone shows the same behavior (this is what rides inside a
    // group's ciphertext blob).
    let cek = [7u8; 32];
    let wrapped = kem_wrap(&pp, &path_a, &cek, &mut rng).unwrap();
    assert_eq!(kem_unwrap(&pp, &reader_sk, &wrapped).unwrap(), cek);
    assert!(kem_unwrap(&pp, &stranger, &wrapped).is_err());

    // --- Act 6: policy-path rotation. New seals move to policy-b.
    let path_b = identity("reader-did/policy-b");
    let e3 = seal(&pp, &path_b, b"epoch-b entry", &mut rng).unwrap();

    // The old exact-path grantee loses new seals but keeps history — the
    // documented permanent-key property.
    assert!(open(&pp, &reader_sk, &e3).is_err());
    assert_eq!(open(&pp, &reader_sk, &e1).unwrap(), b"epoch-a entry 1");

    // An ANCESTOR key survives rotation by design: it delegates down.
    let derived_b = delegate(&pp, &dept_sk, b"policy-b", &mut rng).unwrap();
    assert_eq!(open(&pp, &derived_b, &e3).unwrap(), b"epoch-b entry");

    // The authority spans every epoch: the msk mints any path on demand.
    let fresh_b = keygen(&pp, &msk, &path_b, &mut rng).unwrap();
    assert_eq!(open(&pp, &fresh_b, &e3).unwrap(), b"epoch-b entry");

    // --- Act 7: the public material is still byte-stable at the end.
    assert_eq!(mpk_fingerprint(&reload_pp(&pp)), fp);
}
