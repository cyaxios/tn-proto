//! Executable reference for the Rust HIBE primitives (`tn_hibe`, which
//! re-exports `tn_bbg`). Run: cargo run -p tn-hibe --example primitives

use rand_core::OsRng;
use tn_hibe::{
    delegate, kem_unwrap, kem_wrap, keygen, mpk_fingerprint, open, open_with_aad, seal,
    seal_with_aad, setup, Identity, MasterKey, PrivateKey, PublicParams,
};

fn short(b: &[u8]) -> String {
    format!("{}... ({} bytes)", hex::encode(&b[..8]), b.len())
}

fn main() {
    // setup: one authority's system keypair. Keys move as bytes.
    let (pp, msk) = setup(2, OsRng).unwrap();
    let mpk = pp.to_bytes();
    println!("setup           mpk: {}", short(&mpk));
    println!("mpk_fingerprint    : {}", hex::encode(mpk_fingerprint(&pp)));
    println!("max_depth          : {}", pp.max_depth());

    // keygen: a reader key for an identity path, minted from the msk.
    let id = Identity::from_str_path("alice/reports");
    let sk = keygen(&pp, &msk, &id, OsRng).unwrap();
    println!("keygen           sk: {}", short(&sk.to_bytes()));

    // seal / open a body; the empty-aad path is a plain seal.
    let blob = seal(&pp, &id, b"quarterly numbers", OsRng).unwrap();
    assert_eq!(open(&pp, &sk, &blob).unwrap(), b"quarterly numbers");
    // Bind a marker (authenticated, not stored):
    let aad = b"policy=finra-oba";
    let gov = seal_with_aad(&pp, &id, b"governed body", aad, OsRng).unwrap();
    assert_eq!(open_with_aad(&pp, &sk, &gov, aad).unwrap(), b"governed body");
    assert!(open_with_aad(&pp, &sk, &gov, b"policy=other").is_err());
    println!("seal/open (+aad)   : ok (wrong aad rejected)");

    // KEM directly (KEM-not-direct: only AEAD output + points on the wire).
    let cek = [7u8; 32];
    let wrapped = kem_wrap(&pp, &id, &cek, OsRng).unwrap();
    assert_eq!(kem_unwrap(&pp, &sk, &wrapped).unwrap(), cek);
    println!("kem_wrap/unwrap    : {} round-trip ok", short(&wrapped));

    // delegate parent -> child, no msk.
    let parent = keygen(&pp, &msk, &Identity::from_str_path("alice"), OsRng).unwrap();
    let child = delegate(&pp, &parent, b"reports", OsRng).unwrap();
    assert_eq!(child.identity(), &id);
    assert_eq!(open(&pp, &child, &blob).unwrap(), b"quarterly numbers");
    println!("delegate           : alice -> alice/reports opens the blob");

    // Round-trip the canonical encodings (bytes are the whole API).
    assert_eq!(PublicParams::from_bytes(&mpk).unwrap(), pp);
    assert_eq!(PrivateKey::from_bytes(&sk.to_bytes()).unwrap(), sk);
    let _ = MasterKey::from_bytes(&msk.to_bytes()).unwrap();
    println!("encodings          : round-trip ok\n\nrust HIBE primitives: ALL OK");
}
