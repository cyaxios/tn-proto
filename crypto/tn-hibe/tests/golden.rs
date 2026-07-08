//! Golden-vector gate (Phase 2): byte-frozen fixtures for the canonical
//! encodings, the identity mapping, BBG decrypt, and the CEK KEM.
//!
//! The same assertions run natively (`cargo test`) and under wasm32
//! (`wasm-pack test --node`), which is the cross-impl guarantee: every build
//! of the SDK must read these exact bytes forever. Regenerating the fixtures
//! is a wire-format break and needs a version bump (see examples/gen_golden.rs).

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tn_hibe::{
    decrypt, delegate, gt_to_bytes, kem_unwrap, kem_wrap, mpk_fingerprint, open, seal, Ciphertext,
    Identity, MasterKey, PrivateKey, PublicParams,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

fn h(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn golden_vectors_hold() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("golden/vectors.json")).expect("fixture parses");
    assert_eq!(v["format"], 1);

    // System material is byte-stable through decode/encode.
    let pp_bytes = h(&v["pp"]);
    let pp = PublicParams::from_bytes(&pp_bytes).expect("pp decodes");
    assert_eq!(pp.to_bytes(), pp_bytes, "PublicParams encoding drifted");
    assert_eq!(pp.max_depth(), 3);
    let msk_bytes = h(&v["msk"]);
    let msk = MasterKey::from_bytes(&msk_bytes).expect("msk decodes");
    assert_eq!(msk.to_bytes(), msk_bytes, "MasterKey encoding drifted");
    assert_eq!(
        mpk_fingerprint(&pp).to_vec(),
        h(&v["mpk_fp"]),
        "mpk fingerprint drifted"
    );

    // Deterministic RNG for the live-side assertions below.
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    for entry in v["paths"].as_array().expect("paths") {
        let path = entry["path"].as_str().unwrap();
        let id = Identity::from_str_path(path);

        let sk_bytes = h(&entry["sk"]);
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("sk decodes");
        assert_eq!(sk.to_bytes(), sk_bytes, "PrivateKey encoding drifted: {path}");
        assert_eq!(sk.identity(), &id, "identity labels drifted: {path}");

        // Frozen KEM blob opens to the frozen CEK.
        let cek: [u8; 32] = h(&entry["cek"]).try_into().unwrap();
        assert_eq!(
            kem_unwrap(&pp, &sk, &h(&entry["wrapped"])).expect("unwrap"),
            cek,
            "KEM unwrap drifted: {path}"
        );

        // Frozen BBG ciphertext decrypts to the frozen GT message.
        let ct_bytes = h(&entry["ct"]);
        let ct = Ciphertext::from_bytes(&ct_bytes).expect("ct decodes");
        assert_eq!(ct.to_bytes(), ct_bytes, "Ciphertext encoding drifted: {path}");
        let m = decrypt(&pp, &sk, &ct).expect("decrypt");
        assert_eq!(gt_to_bytes(&m), h(&entry["m"]), "BBG decrypt drifted: {path}");

        // Frozen full group blob opens to the frozen body.
        assert_eq!(
            open(&pp, &sk, &h(&entry["sealed"])).expect("open"),
            h(&entry["body"]),
            "sealed-blob layout drifted: {path}"
        );

        // A LIVE wrap to this path must open with the FROZEN key — this pins
        // the label→scalar identity mapping without exposing scalars.
        let fresh = [0x42u8; 32];
        let wrapped = kem_wrap(&pp, &id, &fresh, &mut rng).expect("live wrap");
        assert_eq!(
            kem_unwrap(&pp, &sk, &wrapped).expect("live unwrap"),
            fresh,
            "identity mapping drifted: {path}"
        );

        // Live seal ↔ frozen key, both directions of the hybrid layer.
        let sealed = seal(&pp, &id, b"live body", &mut rng).expect("live seal");
        assert_eq!(
            open(&pp, &sk, &sealed).expect("live open"),
            b"live body",
            "hybrid seal/open drifted: {path}"
        );
    }

    // Live delegation from the frozen depth-1 key opens the frozen depth-2
    // KEM blob: pins delegation compatibility with historical grants.
    let entries = v["paths"].as_array().unwrap();
    let parent = PrivateKey::from_bytes(&h(&entries[0]["sk"])).unwrap();
    let delegated = delegate(&pp, &parent, b"policy-1", &mut rng).expect("delegate");
    let cek1: [u8; 32] = h(&entries[1]["cek"]).try_into().unwrap();
    assert_eq!(
        kem_unwrap(&pp, &delegated, &h(&entries[1]["wrapped"])).expect("delegated unwrap"),
        cek1,
        "delegated key no longer opens a historical wrap"
    );
}
