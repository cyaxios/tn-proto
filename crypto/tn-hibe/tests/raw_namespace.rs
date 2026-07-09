#![cfg(not(target_arch = "wasm32"))]

use bls12_381_plus::group::Group;
use bls12_381_plus::Gt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tn_hibe::{keygen, raw, setup, Identity};

#[test]
fn raw_namespace_holds_direct_bbg_surface() {
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (pp, msk) = setup(2, &mut rng).unwrap();
    let id = Identity::try_from_str_path("reader/policy").unwrap();
    let sk = keygen(&pp, &msk, &id, &mut rng).unwrap();
    let msg = Gt::random(&mut rng);

    let ct = raw::encrypt(&pp, &id, &msg, &mut rng).unwrap();
    let encoded = ct.to_bytes();
    let decoded = raw::Ciphertext::from_bytes(&encoded).unwrap();
    assert_eq!(raw::decrypt(&pp, &sk, &decoded).unwrap(), msg);
    assert_eq!(raw::gt_from_bytes(&raw::gt_to_bytes(&msg)).unwrap(), msg);
}
