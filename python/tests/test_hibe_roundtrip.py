"""End-to-end tn.log round-trip under a HIBE-configured ceremony, plus the
envelope-coverage regression from the HIBE spec (Phase 4).

Mirrors the hibe leg of ``test_tnlog_roundtrip.py`` for the pipeline half.
The coverage half pins the contract-D4 design rule: the HIBE-wrapped CEK
lives INSIDE the group's ``ciphertext`` blob, so `row_hash` covers it with
zero hash-function change — stripping the group, swapping the blob for one
sealed under a different authority, or flipping any byte must each break
verification, and the group dict must carry no sibling keys.

(Rust never SEALS hibe groups in this plan — cipher_build returns
NotImplemented — and `compute_row_hash` is cipher-agnostic bytes-in, so
Rust/Python parity is inherited rather than re-proven here.)
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader
from tn import _hibe


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires) and empty
    request context (set_context would otherwise leak into later tests
    in the same process)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()


def _read_lines(log_path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_lines(log_path: Path, docs: list[dict]) -> None:
    log_path.write_text(
        "".join(json.dumps(d, separators=(",", ":")) + "\n" for d in docs),
        encoding="utf-8",
    )


def test_hibe_roundtrip_and_envelope_coverage(tmp_path):
    ws = tmp_path
    yaml_path = ws / "tn.yaml"
    log_path = ws / ".tn/tn/logs" / "tn.ndjson"

    tn.init(yaml_path, log_path=log_path, cipher="hibe")
    cfg = tn.current_config()
    assert cfg.cipher_name == "hibe", f"expected hibe, got {cfg.cipher_name}"

    tn.set_context(
        server_did="did:key:z6Mk-service-stub",
        request_id="req-abc-123",
        method="POST",
        path="/orders",
        user_id=42,
    )
    tn.info("order.created", amount=999, currency="USD")
    tn.info("order.created", amount=250, currency="EUR")
    tn.warning("auth.retry", attempts=3)
    tn.flush_and_close()

    # Reopen to exercise the load() path under hibe.
    tn.init(yaml_path, log_path=log_path, cipher="hibe")
    cfg = tn.current_config()
    assert cfg.cipher_name == "hibe"

    entries = list(tn.reader.read(log_path, cfg))
    assert len(entries) == 3, f"expected 3 entries, got {len(entries)}"
    for e in entries:
        env = e["envelope"]
        assert e["valid"]["signature"], f"bad signature: {env['event_id']}"
        assert e["valid"]["row_hash"], f"bad row_hash: {env['event_id']}"
        assert e["valid"]["chain"], f"broken chain: {env['event_id']}"
        assert "default" in e["plaintext"], f"decrypt failed: {env['event_id']}"
        assert e["plaintext"]["default"]["user_id"] == 42

    # ------------------------------------------------------------------
    # Envelope-coverage regression (contract D4).
    # ------------------------------------------------------------------
    # On the wire each group sits at the top level under its name as
    # {"ciphertext": b64, "field_hashes": {...}}.
    docs = _read_lines(log_path)
    groups = {
        k: v
        for k, v in docs[0].items()
        if isinstance(v, dict) and "ciphertext" in v
    }
    assert groups, f"no group dicts found in envelope: {sorted(docs[0])}"
    for gname, g in groups.items():
        assert set(g.keys()) <= {"ciphertext", "field_hashes"}, (
            f"sibling keys crept into group {gname!r}: {sorted(g)} — "
            f"anything outside ciphertext/field_hashes is NOT covered by "
            f"row_hash (chain.py hashes only those two)"
        )
    gname = next(iter(groups))
    pristine = json.dumps(docs[0], separators=(",", ":"))

    def _reread_first_valid() -> dict:
        fresh = list(tn.reader.read(log_path, cfg))
        return fresh[0]["valid"]

    # (a) STRIP the group entirely.
    docs = _read_lines(log_path)
    del docs[0][gname]
    _write_lines(log_path, docs)
    assert not _reread_first_valid()["row_hash"], "stripping the group must break row_hash"

    # (b) SWAP the blob for one sealed to an identity under a DIFFERENT
    # (attacker-controlled) authority — same length, valid hibe blob.
    docs = [json.loads(pristine)] + _read_lines(log_path)[1:]
    _write_lines(log_path, docs)
    mpk_evil, _msk_evil = _hibe.setup(2)
    evil_blob = _hibe.seal(mpk_evil, "attacker/path", b'{"user_id": 666}')
    docs = _read_lines(log_path)
    docs[0][gname]["ciphertext"] = base64.b64encode(evil_blob).decode("ascii")
    _write_lines(log_path, docs)
    assert not _reread_first_valid()["row_hash"], "swapping the blob must break row_hash"

    # (c) FLIP one byte inside the stored ciphertext.
    docs = [json.loads(pristine)] + _read_lines(log_path)[1:]
    _write_lines(log_path, docs)
    docs = _read_lines(log_path)
    raw = bytearray(base64.b64decode(docs[0][gname]["ciphertext"]))
    raw[len(raw) // 2] ^= 1
    docs[0][gname]["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    _write_lines(log_path, docs)
    first = list(tn.reader.read(log_path, cfg))[0]
    assert not first["valid"]["row_hash"], "byte flip must break row_hash"
    # A failed decrypt surfaces as the reader's sentinel shape, never as
    # recovered plaintext.
    assert first["plaintext"].get(gname) in (
        {"$no_read_key": True},
        {"$decrypt_error": True},
    ), f"tampered blob must not decrypt: {first['plaintext'].get(gname)!r}"

    # Restore and confirm everything verifies again (the tamper harness
    # itself isn't what failed the checks).
    docs = [json.loads(pristine)] + _read_lines(log_path)[1:]
    _write_lines(log_path, docs)
    assert _reread_first_valid()["row_hash"]

    tn.flush_and_close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
