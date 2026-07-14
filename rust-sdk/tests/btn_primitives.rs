use tn_proto::{btn, Error};

fn assert_not_entitled(error: Error) {
    assert!(matches!(error, Error::NotEntitled(_)));
}

#[test]
fn raw_bytes_round_trip_and_producer_decrypt_does_not_mint() -> tn_proto::Result<()> {
    let mut producer = btn::setup()?;
    let ciphertext = producer.encrypt(b"producer copy")?;

    assert_eq!(producer.issued_count(), 0);
    assert_eq!(producer.decrypt(&ciphertext)?, b"producer copy");
    assert_eq!(producer.issued_count(), 0, "decrypt must not mint a kit");

    let kit = producer.mint()?;
    let subscriber = btn::subscribe([kit])?;
    assert_eq!(subscriber.decrypt(&ciphertext)?, b"producer copy");

    let mut other_producer = btn::setup()?;
    let wrong_kit = other_producer.mint()?;
    let right_kit = producer.mint()?;
    let fallback_subscriber = btn::subscribe([wrong_kit, right_kit])?;
    assert_eq!(
        fallback_subscriber.decrypt(&ciphertext)?,
        b"producer copy",
        "a later kit must be tried after the first is not entitled"
    );
    Ok(())
}

#[test]
fn aad_must_match_for_producer_and_subscriber() -> tn_proto::Result<()> {
    let mut producer = btn::setup()?;
    let kit = producer.mint()?;
    let subscriber = btn::subscribe([kit])?;
    let ciphertext = producer.encrypt_with_aad(b"bound body", b"purpose=local")?;

    assert_eq!(
        producer.decrypt_with_aad(&ciphertext, b"purpose=local")?,
        b"bound body"
    );
    assert_eq!(
        subscriber.decrypt_with_aad(&ciphertext, b"purpose=local")?,
        b"bound body"
    );
    assert_not_entitled(
        producer
            .decrypt_with_aad(&ciphertext, b"purpose=changed")
            .expect_err("changed producer AAD must fail"),
    );
    assert_not_entitled(
        subscriber
            .decrypt_with_aad(&ciphertext, b"purpose=changed")
            .expect_err("changed subscriber AAD must fail"),
    );
    Ok(())
}

#[test]
fn producer_state_restores_from_portable_bytes() -> tn_proto::Result<()> {
    let mut producer = btn::setup()?;
    let kit = producer.mint()?;
    let first = producer.encrypt(b"before restart")?;
    let state = producer.to_bytes();

    let restored = btn::Producer::from_bytes(&state)?;
    assert_eq!(restored.publisher_id(), producer.publisher_id());
    assert_eq!(restored.epoch(), producer.epoch());
    assert_eq!(restored.issued_count(), producer.issued_count());
    assert_eq!(restored.revoked_count(), producer.revoked_count());
    assert_eq!(restored.decrypt(&first)?, b"before restart");

    let subscriber = btn::subscribe([kit])?;
    let second = restored.encrypt(b"after restart")?;
    assert_eq!(subscriber.decrypt(&second)?, b"after restart");
    Ok(())
}

#[test]
fn subscribe_rejects_zero_kits_and_add_key_parses_before_storing() -> tn_proto::Result<()> {
    let empty = btn::subscribe(std::iter::empty::<Vec<u8>>())
        .expect_err("a subscriber needs at least one kit");
    assert!(matches!(empty, Error::InvalidArgument(_)));

    let mut producer = btn::setup()?;
    let first_kit = producer.mint()?;
    let second_kit = producer.mint()?;
    let mut subscriber = btn::subscribe([first_kit])?;
    let malformed = subscriber
        .add_key(b"not a reader kit")
        .expect_err("malformed kit must be rejected before storage");
    assert!(matches!(malformed, Error::Malformed(_)));
    subscriber.add_key(second_kit)?;

    let ciphertext = producer.encrypt(b"both keys are usable")?;
    assert_eq!(subscriber.decrypt(&ciphertext)?, b"both keys are usable");
    Ok(())
}

#[test]
fn revocation_only_blocks_future_ciphertexts() -> tn_proto::Result<()> {
    let mut producer = btn::setup()?;
    let alice_kit = producer.mint()?;
    let bob_kit = producer.mint()?;
    let alice = btn::subscribe([alice_kit])?;
    let bob = btn::subscribe([bob_kit.clone()])?;
    let before = producer.encrypt(b"before revocation")?;

    producer.revoke(&bob_kit)?;
    assert_eq!(producer.issued_count(), 1);
    assert_eq!(producer.revoked_count(), 1);
    let after = producer.encrypt(b"after revocation")?;

    assert_eq!(alice.decrypt(&after)?, b"after revocation");
    assert_not_entitled(
        bob.decrypt(&after)
            .expect_err("revoked subscriber must not open future ciphertext"),
    );
    assert_eq!(bob.decrypt(&before)?, b"before revocation");
    Ok(())
}

#[test]
fn btn_boundary_maps_limits_and_preserves_internal_errors() -> tn_proto::Result<()> {
    let mut producer = btn::setup()?;
    for _ in 0..tn_btn::config::MAX_LEAVES {
        producer.mint()?;
    }
    assert!(matches!(
        producer.mint().expect_err("the BTN tree must be full"),
        Error::LimitExceeded(_)
    ));

    assert!(matches!(
        producer
            .revoke_by_leaf(tn_btn::config::MAX_LEAVES)
            .expect_err("an out-of-range leaf is an internal BTN invariant failure"),
        Error::Btn(tn_btn::Error::Internal(_))
    ));
    Ok(())
}
