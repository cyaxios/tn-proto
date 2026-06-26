//! End-to-end integration test: the "six verbs" tour from the spec.
//!
//! setup → mint → encrypt → decrypt → revoke → encrypt → revoked
//! reader fails, survivors succeed.

use tn_btn::{Config, Error, PublisherState};

#[test]
fn six_verb_tour() {
    let mut state = PublisherState::setup(Config).expect("setup");

    let alice = state.mint().expect("mint alice");
    let bob = state.mint().expect("mint bob");
    let carol = state.mint().expect("mint carol");
    assert_eq!(state.issued_count(), 3);
    assert_eq!(state.revoked_count(), 0);

    // Broadcast 1: everyone can read.
    let ct1 = state.encrypt(b"hello all").unwrap();
    assert_eq!(alice.decrypt(&ct1).unwrap(), b"hello all");
    assert_eq!(bob.decrypt(&ct1).unwrap(), b"hello all");
    assert_eq!(carol.decrypt(&ct1).unwrap(), b"hello all");

    // Revoke carol.
    state.revoke(&carol).unwrap();
    assert_eq!(state.issued_count(), 2);
    assert_eq!(state.revoked_count(), 1);

    // Broadcast 2: carol cannot read.
    let ct2 = state.encrypt(b"members only").unwrap();
    assert_eq!(alice.decrypt(&ct2).unwrap(), b"members only");
    assert_eq!(bob.decrypt(&ct2).unwrap(), b"members only");
    assert!(matches!(carol.decrypt(&ct2), Err(Error::NotEntitled)));

    // Carol still reads the pre-revocation broadcast (intrinsic to
    // NNL — we can't retroactively revoke access).
    assert_eq!(carol.decrypt(&ct1).unwrap(), b"hello all");
}

#[test]
fn cross_publisher_rejection_is_cheap() {
    // A reader from one publisher should fail fast on ciphertexts
    // from another publisher — publisher_id mismatch is checked
    // before any crypto work.
    let mut a = PublisherState::setup(Config).unwrap();
    let mut b = PublisherState::setup(Config).unwrap();
    let alice = a.mint().unwrap();
    let bob_b = b.mint().unwrap();

    let ct_from_a = a.encrypt(b"alice's secret").unwrap();
    let ct_from_b = b.encrypt(b"bob's secret").unwrap();

    assert_eq!(alice.decrypt(&ct_from_a).unwrap(), b"alice's secret");
    assert!(matches!(alice.decrypt(&ct_from_b), Err(Error::NotEntitled)));
    assert!(matches!(bob_b.decrypt(&ct_from_a), Err(Error::NotEntitled)));
    assert_eq!(bob_b.decrypt(&ct_from_b).unwrap(), b"bob's secret");
}

#[test]
fn deterministic_publisher_from_seed() {
    // setup_with_seed produces the same publisher_id every time.
    // Useful for tests and for ceremonies where the publisher wants
    // stable identity derived from some external key material.
    let seed = [0xABu8; 32];
    let a = PublisherState::setup_with_seed(Config, seed).unwrap();
    let b = PublisherState::setup_with_seed(Config, seed).unwrap();
    assert_eq!(a.publisher_id(), b.publisher_id());
    assert_eq!(a.epoch(), b.epoch());
}

#[test]
fn many_reader_fan_out() {
    // Fill the tree with MAX_LEAVES readers. Revoke half. Confirm exactly
    // the non-revoked half decrypts.
    let mut state = PublisherState::setup(Config).unwrap();
    let mut kits = Vec::with_capacity(tn_btn::config::MAX_LEAVES as usize);
    for _ in 0..tn_btn::config::MAX_LEAVES {
        kits.push(state.mint().unwrap());
    }
    // Revoke every odd-leaf reader.
    for kit in kits.iter().filter(|k| k.leaf().0 % 2 == 1) {
        state.revoke(kit).unwrap();
    }
    assert_eq!(state.revoked_count() as u64, tn_btn::config::MAX_LEAVES / 2);

    let ct = state.encrypt(b"evens only").unwrap();
    for kit in &kits {
        let result = kit.decrypt(&ct);
        if kit.leaf().0 % 2 == 0 {
            assert_eq!(result.unwrap(), b"evens only", "leaf {}", kit.leaf().0);
        } else {
            assert!(
                matches!(result, Err(Error::NotEntitled)),
                "leaf {} should be revoked",
                kit.leaf().0
            );
        }
    }
}
