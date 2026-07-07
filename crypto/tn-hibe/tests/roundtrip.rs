//! Phase 1 test plan: BBG round-trips at depths 1-3, delegate-then-decrypt,
//! wrong-identity negatives, constant-size ciphertext, KEM round-trip and
//! tamper checks, and canonical-encoding round-trips.
//!
//! Native-only harness; the wasm32 gate is tests/golden.rs.
#![cfg(not(target_arch = "wasm32"))]

use bls12_381_plus::group::Group;
use bls12_381_plus::Gt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tn_hibe::{
    decrypt, delegate, encrypt, kem_unwrap, kem_wrap, keygen, mpk_fingerprint, open, open_with_aad,
    seal, seal_with_aad, setup, Ciphertext, HibeError, Identity, MasterKey, PrivateKey,
    PublicParams, WRAPPED_CEK_LEN,
};

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

#[test]
fn encrypt_decrypt_round_trip_depths_1_2_3() {
    let mut r = rng(1);
    let (pp, msk) = setup(3, &mut r).unwrap();
    for path in ["alice", "alice/policy-1", "alice/policy-1/epoch-0"] {
        let id = Identity::from_str_path(path);
        let sk = keygen(&pp, &msk, &id, &mut r).unwrap();
        let m = Gt::random(&mut r);
        let ct = encrypt(&pp, &id, &m, &mut r).unwrap();
        assert_eq!(decrypt(&pp, &sk, &ct).unwrap(), m, "depth {}", id.depth());
    }
}

#[test]
fn delegate_then_decrypt_without_msk() {
    let mut r = rng(2);
    let (pp, msk) = setup(3, &mut r).unwrap();
    // The authority hands out a depth-1 key; the holder delegates down twice.
    let parent = keygen(&pp, &msk, &Identity::from_str_path("dept"), &mut r).unwrap();
    let child = delegate(&pp, &parent, b"team", &mut r).unwrap();
    let leaf = delegate(&pp, &child, b"reader", &mut r).unwrap();
    assert_eq!(leaf.identity().depth(), 3);

    let id = Identity::from_str_path("dept/team/reader");
    let m = Gt::random(&mut r);
    let ct = encrypt(&pp, &id, &m, &mut r).unwrap();
    assert_eq!(decrypt(&pp, &leaf, &ct).unwrap(), m);
    // The parent still opens its own path.
    let m2 = Gt::random(&mut r);
    let ct2 = encrypt(&pp, &Identity::from_str_path("dept"), &m2, &mut r).unwrap();
    assert_eq!(decrypt(&pp, &parent, &ct2).unwrap(), m2);
}

#[test]
fn wrong_identity_cannot_decrypt() {
    let mut r = rng(3);
    let (pp, msk) = setup(2, &mut r).unwrap();
    let m = Gt::random(&mut r);
    let ct = encrypt(&pp, &Identity::from_str_path("alice/p"), &m, &mut r).unwrap();
    // Sibling and unrelated identities recover garbage, never the message.
    for other in ["alice/q", "bob/p", "bob"] {
        let sk = keygen(&pp, &msk, &Identity::from_str_path(other), &mut r).unwrap();
        assert_ne!(decrypt(&pp, &sk, &ct).unwrap(), m, "id {other}");
    }
}

#[test]
fn ciphertext_is_constant_size_across_depths() {
    let mut r = rng(4);
    let (pp, _) = setup(3, &mut r).unwrap();
    let m = Gt::random(&mut r);
    let mut sizes = Vec::new();
    for path in ["a", "a/b", "a/b/c"] {
        let ct = encrypt(&pp, &Identity::from_str_path(path), &m, &mut r).unwrap();
        sizes.push(ct.to_bytes().len());
    }
    assert_eq!(sizes[0], sizes[1]);
    assert_eq!(sizes[1], sizes[2]);
}

#[test]
fn depth_limits_are_enforced() {
    let mut r = rng(5);
    assert!(matches!(setup(0, &mut r), Err(HibeError::BadMaxDepth(0))));
    let (pp, msk) = setup(1, &mut r).unwrap();
    let too_deep = Identity::from_str_path("a/b");
    assert!(matches!(
        keygen(&pp, &msk, &too_deep, &mut r),
        Err(HibeError::IdentityTooDeep)
    ));
    let leaf = keygen(&pp, &msk, &Identity::from_str_path("a"), &mut r).unwrap();
    assert!(delegate(&pp, &leaf, b"b", &mut r).is_err());
}

#[test]
fn kem_round_trip_and_negatives() {
    let mut r = rng(6);
    let (pp, msk) = setup(2, &mut r).unwrap();
    let id = Identity::from_str_path("reader/policy");
    let sk = keygen(&pp, &msk, &id, &mut r).unwrap();

    let mut cek = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut r, &mut cek);
    let wrapped = kem_wrap(&pp, &id, &cek, &mut r).unwrap();
    assert_eq!(wrapped.len(), WRAPPED_CEK_LEN);
    assert_eq!(kem_unwrap(&pp, &sk, &wrapped).unwrap(), cek);

    // Any flipped byte fails the AEAD (header is bound as associated data).
    for i in [1, 1 + 48, 1 + 48 + 96, wrapped.len() - 1] {
        let mut bad = wrapped.clone();
        bad[i] ^= 1;
        assert!(kem_unwrap(&pp, &sk, &bad).is_err(), "tamper at byte {i}");
    }

    // A key on a different path cannot unwrap.
    let other = keygen(&pp, &msk, &Identity::from_str_path("reader/other"), &mut r).unwrap();
    assert!(matches!(
        kem_unwrap(&pp, &other, &wrapped),
        Err(HibeError::Unwrap)
    ));

    // A delegated key on the right path CAN unwrap.
    let parent = keygen(&pp, &msk, &Identity::from_str_path("reader"), &mut r).unwrap();
    let delegated = delegate(&pp, &parent, b"policy", &mut r).unwrap();
    assert_eq!(kem_unwrap(&pp, &delegated, &wrapped).unwrap(), cek);
}

#[test]
fn seal_open_round_trip_and_negatives() {
    let mut r = rng(8);
    let (pp, msk) = setup(2, &mut r).unwrap();
    let id = Identity::from_str_path("reader/policy");
    let sk = keygen(&pp, &msk, &id, &mut r).unwrap();

    let blob = seal(&pp, &id, b"the governed section body", &mut r).unwrap();
    assert_eq!(open(&pp, &sk, &blob).unwrap(), b"the governed section body");

    // Empty body round-trips too (a group can seal zero-length plaintext).
    let empty = seal(&pp, &id, b"", &mut r).unwrap();
    assert_eq!(open(&pp, &sk, &empty).unwrap(), b"");

    // Any flipped byte anywhere in the blob fails: KEM header bytes fail the
    // CEK AEAD; nonce/body/tag bytes fail the body AEAD (header is its AAD).
    for i in [0, 1, 120, 239, blob.len() - 1] {
        let mut bad = blob.clone();
        bad[i] ^= 1;
        assert!(open(&pp, &sk, &bad).is_err(), "tamper at byte {i}");
    }

    // Wrong-path key cannot open.
    let other = keygen(&pp, &msk, &Identity::from_str_path("reader/other"), &mut r).unwrap();
    assert!(open(&pp, &other, &blob).is_err());
}

#[test]
fn aad_binding_seals_and_gates() {
    let mut r = rng(9);
    let (pp, msk) = setup(2, &mut r).unwrap();
    let id = Identity::from_str_path("reader/policy");
    let sk = keygen(&pp, &msk, &id, &mut r).unwrap();
    let aad = b"policy=finra-oba;v=1";

    let blob = seal_with_aad(&pp, &id, b"governed body", aad, &mut r).unwrap();
    // Same AAD opens.
    assert_eq!(open_with_aad(&pp, &sk, &blob, aad).unwrap(), b"governed body");
    // Different AAD fails.
    assert!(open_with_aad(&pp, &sk, &blob, b"policy=none").is_err());
    // Absent AAD fails (a stripped flag breaks decryption).
    assert!(open(&pp, &sk, &blob).is_err());

    // Empty AAD is byte-identical to plain seal: a plain-sealed blob opens
    // with either the no-aad or the empty-aad path, and vice versa.
    let plain = seal(&pp, &id, b"ungoverned", &mut r).unwrap();
    assert_eq!(open_with_aad(&pp, &sk, &plain, b"").unwrap(), b"ungoverned");
    let empty = seal_with_aad(&pp, &id, b"ungoverned", b"", &mut r).unwrap();
    assert_eq!(open(&pp, &sk, &empty).unwrap(), b"ungoverned");
}

#[test]
fn canonical_encodings_round_trip() {
    let mut r = rng(7);
    let (pp, msk) = setup(3, &mut r).unwrap();
    let pp2 = PublicParams::from_bytes(&pp.to_bytes()).unwrap();
    assert_eq!(pp, pp2);
    assert_eq!(mpk_fingerprint(&pp), mpk_fingerprint(&pp2));

    let msk2 = MasterKey::from_bytes(&msk.to_bytes()).unwrap();
    let id = Identity::from_str_path("alice/policy");
    // Keys generated from the round-tripped msk must interoperate.
    let sk = keygen(&pp2, &msk2, &id, &mut r).unwrap();
    let sk2 = PrivateKey::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk, sk2);
    assert_eq!(sk2.identity(), &id);

    let m = Gt::random(&mut r);
    let ct = encrypt(&pp, &id, &m, &mut r).unwrap();
    let ct2 = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
    assert_eq!(ct, ct2);
    assert_eq!(decrypt(&pp, &sk2, &ct2).unwrap(), m);

    // Truncation and version corruption fail loudly.
    assert!(PublicParams::from_bytes(&pp.to_bytes()[..10]).is_err());
    let mut bad = pp.to_bytes();
    bad[0] = 99;
    assert!(PublicParams::from_bytes(&bad).is_err());
}
