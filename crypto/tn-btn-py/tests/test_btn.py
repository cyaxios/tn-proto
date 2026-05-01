"""Round-trip and correctness tests for the btn Python bindings.

Run with: pytest tests/ from the btn-py directory after
`maturin develop` has built the extension into the current venv.
"""
import pytest
import tn_btn as btn


def test_module_has_expected_surface():
    # Basic sanity: all the verbs exist.
    assert hasattr(btn, "PublisherState")
    assert hasattr(btn, "decrypt")
    assert hasattr(btn, "NotEntitled")
    assert hasattr(btn, "BtnRuntimeError")
    assert hasattr(btn, "tree_height")
    assert hasattr(btn, "max_leaves")
    # Values match the Rust consts (h=8 → 256 leaves).
    assert btn.tree_height() == 8
    assert btn.max_leaves() == 256


def test_roundtrip_no_revoke():
    state = btn.PublisherState()
    alice = state.mint()
    bob = state.mint()
    carol = state.mint()
    assert state.issued_count == 3
    assert state.revoked_count == 0

    ct = state.encrypt(b"hello all")
    assert btn.decrypt(alice, ct) == b"hello all"
    assert btn.decrypt(bob, ct) == b"hello all"
    assert btn.decrypt(carol, ct) == b"hello all"


def test_revoke_blocks_future_decrypt():
    state = btn.PublisherState()
    alice = state.mint()
    bob = state.mint()
    ct_before = state.encrypt(b"pre-revoke")
    state.revoke_kit(bob)
    ct_after = state.encrypt(b"post-revoke")

    # Before revocation: everyone decrypts.
    assert btn.decrypt(alice, ct_before) == b"pre-revoke"
    assert btn.decrypt(bob, ct_before) == b"pre-revoke"

    # After revocation: bob cannot read new ciphertexts.
    assert btn.decrypt(alice, ct_after) == b"post-revoke"
    with pytest.raises(btn.NotEntitled):
        btn.decrypt(bob, ct_after)

    # Bob retains access to pre-revocation content — intrinsic to NNL.
    assert btn.decrypt(bob, ct_before) == b"pre-revoke"


def test_revoke_by_leaf_also_works():
    state = btn.PublisherState()
    alice = state.mint()
    bob = state.mint()
    bob_leaf = btn.kit_leaf(bob)
    state.revoke_by_leaf(bob_leaf)

    ct = state.encrypt(b"evens only")
    assert btn.decrypt(alice, ct) == b"evens only"
    with pytest.raises(btn.NotEntitled):
        btn.decrypt(bob, ct)


def test_revoke_is_idempotent():
    state = btn.PublisherState()
    bob = state.mint()
    state.revoke_kit(bob)
    state.revoke_kit(bob)  # second call should be a no-op, not an error
    assert state.revoked_count == 1


def test_deterministic_from_seed():
    seed = b"\xab" * 32
    a = btn.PublisherState(seed=seed)
    b = btn.PublisherState(seed=seed)
    assert a.publisher_id == b.publisher_id
    assert a.epoch == b.epoch


def test_random_seeds_differ():
    a = btn.PublisherState()
    b = btn.PublisherState()
    assert a.publisher_id != b.publisher_id


def test_bad_seed_length_rejected():
    with pytest.raises(ValueError) as exc:
        btn.PublisherState(seed=b"too-short")
    assert "32 bytes" in str(exc.value)


def test_cross_publisher_decrypt_rejected():
    a = btn.PublisherState()
    b = btn.PublisherState()
    alice_kit = a.mint()
    _ = b.mint()
    ct_from_b = b.encrypt(b"from b")
    # Alice's kit from publisher A cannot decrypt publisher B's ct.
    with pytest.raises(btn.NotEntitled):
        btn.decrypt(alice_kit, ct_from_b)


def test_publisher_id_matches_between_kit_and_ciphertext():
    state = btn.PublisherState()
    kit = state.mint()
    ct = state.encrypt(b"x")
    assert btn.kit_publisher_id(kit) == state.publisher_id
    assert btn.ciphertext_publisher_id(ct) == state.publisher_id


def test_kit_bytes_are_stable_wire_format():
    # Reader kit size: 3 (header) + 32 (pub) + 4 (epoch) + 8 (leaf) +
    #   2 (len) + h(h+1)/2 * (1+8+1+8+32 = 50) + 32 (fulltree)
    # h=4: 3+32+4+8+2 + 10*50 + 32 = 581 bytes
    state = btn.PublisherState()
    kit = state.mint()
    h = btn.tree_height()
    expected = 3 + 32 + 4 + 8 + 2 + (h * (h + 1) // 2) * 50 + 32
    assert len(kit) == expected


def test_ciphertext_size_no_revocations():
    # FullTree ciphertext for an empty plaintext: 114 bytes.
    state = btn.PublisherState()
    state.mint()
    ct = state.encrypt(b"")
    assert len(ct) == 114


def test_many_readers_and_selective_revoke():
    state = btn.PublisherState(seed=b"\x42" * 32)
    # At h=4 we can only mint 16. Mint 10 for a useful size.
    kits = [state.mint() for _ in range(10)]
    # Revoke every third reader by leaf.
    revoked_leaves = set()
    for kit in kits[::3]:
        leaf = btn.kit_leaf(kit)
        state.revoke_by_leaf(leaf)
        revoked_leaves.add(leaf)

    ct = state.encrypt(b"selective broadcast")
    for kit in kits:
        leaf = btn.kit_leaf(kit)
        if leaf in revoked_leaves:
            with pytest.raises(btn.NotEntitled):
                btn.decrypt(kit, ct)
        else:
            assert btn.decrypt(kit, ct) == b"selective broadcast"


def test_empty_plaintext():
    state = btn.PublisherState()
    kit = state.mint()
    ct = state.encrypt(b"")
    assert btn.decrypt(kit, ct) == b""


def test_large_plaintext():
    state = btn.PublisherState()
    kit = state.mint()
    big = b"A" * 1_000_000  # 1 MB
    ct = state.encrypt(big)
    assert btn.decrypt(kit, ct) == big


def test_publisher_repr_shape():
    state = btn.PublisherState(seed=b"\x01" * 32)
    r = repr(state)
    assert "PublisherState" in r
    assert "publisher_id=" in r
    assert "issued=" in r
