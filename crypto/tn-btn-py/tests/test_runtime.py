"""Runtime (init / log / read / close / reopen) integration tests."""
from pathlib import Path
import pytest
import tn_btn as btn


def test_init_creates_directory_and_state(tmp_path: Path):
    d = tmp_path / "ceremony1"
    rt = btn.init(d)
    assert d.exists()
    assert (d / "state.btn").exists()
    assert rt.issued_count == 0
    assert rt.revoked_count == 0
    rt.close()


def test_log_and_read_roundtrip(tmp_path: Path):
    d = tmp_path / "ceremony2"
    with btn.init(d) as rt:
        alice = rt.mint()
        bob = rt.mint()
        rt.log(b"event 1")
        rt.log(b"event 2")
        rt.log(b"event 3")

    # Read as alice.
    entries = list(btn.read(d / "log.btn", alice))
    assert [pt for _, pt in entries] == [b"event 1", b"event 2", b"event 3"]
    indices = [i for i, _ in entries]
    assert indices == [0, 1, 2]

    # Read as bob — same three entries.
    entries_bob = list(btn.read(d / "log.btn", bob))
    assert [pt for _, pt in entries_bob] == [b"event 1", b"event 2", b"event 3"]


def test_revoke_then_log_skips_for_revoked_reader(tmp_path: Path):
    d = tmp_path / "ceremony3"
    with btn.init(d) as rt:
        alice = rt.mint()
        bob = rt.mint()
        rt.log(b"pre-revoke 1")
        rt.log(b"pre-revoke 2")
        rt.revoke_kit(bob)
        rt.log(b"post-revoke")

    # Alice sees all three.
    alice_entries = [pt for _, pt in btn.read(d / "log.btn", alice)]
    assert alice_entries == [b"pre-revoke 1", b"pre-revoke 2", b"post-revoke"]

    # Bob sees the first two (kept from before his revocation) but not
    # the post-revoke entry — _iter_log silently skips NotEntitled.
    bob_entries = [pt for _, pt in btn.read(d / "log.btn", bob)]
    assert bob_entries == [b"pre-revoke 1", b"pre-revoke 2"]


def test_state_persists_across_reopen(tmp_path: Path):
    d = tmp_path / "ceremony4"

    with btn.init(d) as rt:
        alice = rt.mint()
        original_publisher_id = rt.publisher_id
        rt.log(b"before restart")

    # New Runtime on the same directory should load the same state.
    with btn.init(d) as rt2:
        assert rt2.publisher_id == original_publisher_id
        assert rt2.issued_count >= 1
        rt2.log(b"after restart")

    # Both messages should be readable with alice's kit.
    entries = [pt for _, pt in btn.read(d / "log.btn", alice)]
    assert entries == [b"before restart", b"after restart"]


def test_publisher_can_read_own_log(tmp_path: Path):
    d = tmp_path / "ceremony5"
    with btn.init(d) as rt:
        rt.log(b"only for me")
        rt.log(b"also for me")
        entries = [pt for _, pt in rt.read()]
    assert entries == [b"only for me", b"also for me"]


def test_log_is_binary_with_length_prefix(tmp_path: Path):
    d = tmp_path / "ceremony6"
    with btn.init(d) as rt:
        rt.mint()
        rt.log(b"small")
        rt.log(b"a bit bigger payload than the first")
    # Inspect the log: first 4 bytes = length of first ciphertext.
    raw = (d / "log.btn").read_bytes()
    import struct
    (first_len,) = struct.unpack(">I", raw[:4])
    # Ciphertext size = 114 (empty cover header) + 5 (payload) + 16 (GCM tag) -
    # wait, 114 is for empty plaintext. With 5 bytes, it should be 114 + 5 = 119.
    # Actually 114 = header+cover+nonce+4-byte-len+16-byte-tag for empty payload.
    # Adding 5 bytes of plaintext -> 119.
    assert first_len == 119


def test_many_log_entries_roundtrip(tmp_path: Path):
    """Write 1000 entries, read them back, verify all are correct."""
    d = tmp_path / "ceremony7"
    with btn.init(d) as rt:
        alice = rt.mint()
        for i in range(1000):
            rt.log(f"entry {i}".encode())

    entries = list(btn.read(d / "log.btn", alice))
    assert len(entries) == 1000
    for idx, (i, pt) in enumerate(entries):
        assert i == idx
        assert pt == f"entry {idx}".encode()


def test_runtime_context_manager_closes_cleanly(tmp_path: Path):
    d = tmp_path / "ceremony8"
    with btn.init(d) as rt:
        rt.log(b"inside with block")
    # After close, files are flushed.
    assert (d / "state.btn").exists()
    assert (d / "log.btn").exists()


def test_empty_log_iterates_zero_entries(tmp_path: Path):
    d = tmp_path / "ceremony9"
    with btn.init(d) as rt:
        alice = rt.mint()
    # Log file doesn't exist yet (never logged).
    entries = list(btn.read(d / "log.btn", alice))
    assert entries == []


def test_truncated_log_raises(tmp_path: Path):
    d = tmp_path / "ceremony10"
    with btn.init(d) as rt:
        alice = rt.mint()
        rt.log(b"x")
    # Truncate mid-record.
    raw = (d / "log.btn").read_bytes()
    (d / "log.btn").write_bytes(raw[:len(raw) - 3])
    with pytest.raises(btn.BtnRuntimeError) as exc:
        list(btn.read(d / "log.btn", alice))
    assert "truncated" in str(exc.value)


def test_state_bytes_roundtrip_standalone(tmp_path: Path):
    # Explicit test for the from_bytes/to_bytes pair without going
    # through Runtime.
    a = btn.PublisherState(seed=b"\x55" * 32)
    a.mint()
    a.mint()
    blob = a.to_bytes()
    b = btn.PublisherState.from_bytes(blob)
    assert a.publisher_id == b.publisher_id
    assert a.issued_count == b.issued_count
    # And b can encrypt for the same readers.
    kit = a.mint()  # mint a new one on a
    ct = b.encrypt(b"from restored state")
    assert btn.decrypt(kit, ct) == b"from restored state"
