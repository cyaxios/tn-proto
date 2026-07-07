//! Regenerates `tests/golden/vectors.json`.
//!
//! Run manually with `cargo run -p tn-hibe --example gen_golden` and commit
//! the result. The fixtures freeze one system (pp/msk) and, per identity
//! depth, a private key, a wrapped CEK, and a BBG ciphertext, so any change
//! to an encoding, the identity mapping, or the KEM breaks the golden test
//! loudly instead of silently forking the wire format.

use bls12_381_plus::group::Group;
use bls12_381_plus::Gt;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tn_hibe::{
    encrypt, gt_to_bytes, kem_wrap, keygen, mpk_fingerprint, seal, setup, Identity,
};

const PATHS: [&str; 3] = ["alice", "alice/policy-1", "alice/policy-1/epoch-0"];

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x746e_2d68_6962_6531); // "tn-hibe1"
    let (pp, msk) = setup(3, &mut rng).expect("setup");

    let mut paths = Vec::new();
    for path in PATHS {
        let id = Identity::from_str_path(path);
        let sk = keygen(&pp, &msk, &id, &mut rng).expect("keygen");
        let mut cek = [0u8; 32];
        rng.fill_bytes(&mut cek);
        let wrapped = kem_wrap(&pp, &id, &cek, &mut rng).expect("kem_wrap");
        let m = Gt::random(&mut rng);
        let ct = encrypt(&pp, &id, &m, &mut rng).expect("encrypt");
        let body = format!("tn-hibe golden body for {path}").into_bytes();
        let sealed = seal(&pp, &id, &body, &mut rng).expect("seal");
        paths.push(serde_json::json!({
            "path": path,
            "sk": hex::encode(sk.to_bytes()),
            "cek": hex::encode(cek),
            "wrapped": hex::encode(&wrapped),
            "m": hex::encode(gt_to_bytes(&m)),
            "ct": hex::encode(ct.to_bytes()),
            "body": hex::encode(&body),
            "sealed": hex::encode(&sealed),
        }));
    }

    let doc = serde_json::json!({
        "format": 1,
        "comment": "Frozen tn-hibe golden vectors. Regenerate ONLY for a deliberate, versioned format change: cargo run -p tn-hibe --example gen_golden",
        "max_depth": 3,
        "pp": hex::encode(pp.to_bytes()),
        "msk": hex::encode(msk.to_bytes()),
        "mpk_fp": hex::encode(mpk_fingerprint(&pp)),
        "paths": paths,
    });

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/vectors.json");
    std::fs::create_dir_all(out.parent().unwrap()).expect("mkdir");
    std::fs::write(&out, serde_json::to_string_pretty(&doc).unwrap()).expect("write");
    println!("wrote {}", out.display());
}
