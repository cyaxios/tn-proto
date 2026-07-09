//! THE ACCEPTANCE GATE.
//!
//! Reads the frozen hohibe-generated golden vectors (crypto/tn-hibe's
//! tests/golden/vectors.json) and proves that tn-bbg — our own Apache-2.0 BBG
//! reimplementation — opens them with zero wire change. If this passes, hohibe
//! can be swapped out behind tn-hibe with no on-wire difference.
//!
//! The golden bytes were produced by hohibe (LGPL), used here strictly as a
//! black-box correctness oracle — no hohibe source is linked or read.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use tn_bbg::{
    delegate, kem_unwrap, kem_wrap, mpk_fingerprint, open, raw, seal, Identity, MasterKey,
    PrivateKey, PublicParams,
};

fn h(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn id(path: &str) -> Identity {
    Identity::try_from_str_path(path).expect("valid fixture path")
}

const GOLDEN: &str = include_str!("../../tn-hibe/tests/golden/vectors.json");

#[test]
fn interop_gate_tn_bbg_opens_frozen_hohibe_vectors() {
    let v: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    assert_eq!(v["format"], 1);

    // System material: frozen pp/msk decode and re-encode byte-stably, and the
    // mpk fingerprint matches.
    let pp = PublicParams::from_bytes(&h(&v["pp"])).unwrap();
    assert_eq!(pp.max_depth(), 3);
    let msk = MasterKey::from_bytes(&h(&v["msk"])).unwrap();
    assert_eq!(msk.to_bytes(), h(&v["msk"]));
    assert_eq!(mpk_fingerprint(&pp).to_vec(), h(&v["mpk_fp"]), "mpk_fp");

    for entry in v["paths"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let id = id(path);

        // The frozen (hohibe-generated) private key for this path.
        let sk = PrivateKey::from_bytes(&h(&entry["sk"])).unwrap();
        assert_eq!(sk.identity(), &id, "identity labels: {path}");

        // GATE 1a — BBG decrypt: our decrypt opens the FROZEN hohibe ciphertext
        // with the FROZEN hohibe key, recovering the frozen GT message.
        let ct = raw::Ciphertext::from_bytes(&h(&entry["ct"])).unwrap();
        let m = raw::decrypt(&pp, &sk, &ct).expect("decrypt");
        assert_eq!(
            raw::gt_to_bytes(&m),
            h(&entry["m"]),
            "BBG DECRYPT INTEROP FAILED at {path}: recovered GT != frozen m"
        );

        // GATE 1b — KEM: our kem_unwrap recovers the FROZEN CEK from the FROZEN
        // wrapped blob. This is the wire path a real hibe group rides.
        let cek: [u8; 32] = h(&entry["cek"]).try_into().unwrap();
        assert_eq!(
            kem_unwrap(&pp, &sk, &h(&entry["wrapped"])).expect("kem_unwrap"),
            cek,
            "KEM UNWRAP INTEROP FAILED at {path}"
        );

        // GATE 1c — full hybrid blob: our open() recovers the frozen body from
        // the FROZEN sealed blob (KEM + AES-GCM body).
        assert_eq!(
            open(&pp, &sk, &h(&entry["sealed"])).expect("open"),
            h(&entry["body"]),
            "SEALED-BLOB INTEROP FAILED at {path}"
        );
    }

    // GATE 1d — cross-direction: a LIVE tn-bbg wrap opens with the FROZEN
    // hohibe key, and delegation from a frozen parent opens a historical wrap.
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let entries = v["paths"].as_array().unwrap();
    for entry in entries {
        let id = id(entry["path"].as_str().unwrap());
        let sk = PrivateKey::from_bytes(&h(&entry["sk"])).unwrap();
        let fresh = [0x42u8; 32];
        let wrapped = kem_wrap(&pp, &id, &fresh, &mut rng).unwrap();
        assert_eq!(kem_unwrap(&pp, &sk, &wrapped).unwrap(), fresh);
        let sealed = seal(&pp, &id, b"live body", &mut rng).unwrap();
        assert_eq!(open(&pp, &sk, &sealed).unwrap(), b"live body");
    }

    // tn-bbg delegate from the FROZEN depth-1 hohibe key opens the FROZEN
    // depth-2 wrapped CEK — proves delegation is construction-compatible.
    let parent = PrivateKey::from_bytes(&h(&entries[0]["sk"])).unwrap();
    let delegated = delegate(&pp, &parent, b"policy-1", &mut rng).unwrap();
    let cek1: [u8; 32] = h(&entries[1]["cek"]).try_into().unwrap();
    assert_eq!(
        kem_unwrap(&pp, &delegated, &h(&entries[1]["wrapped"])).unwrap(),
        cek1,
        "DELEGATION INTEROP FAILED: tn-bbg delegated key can't open the frozen depth-2 wrap"
    );
}
