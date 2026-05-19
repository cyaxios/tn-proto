"""tn.read(verify='skip') survives parse errors mid-stream.

Covers a high-severity finding filed after 0.4.2a2: ``verify='skip'``
correctly skipped verify failures (signature, row_hash, chain) but
the iterator TERMINATED after the first malformed entry (e.g.
corrupt base64 ciphertext from a partial write or disk corruption).
Production read mode needs to be resilient to any per-entry failure.

Fix (0.4.2a3): the Rust read path (``read_from`` /
``read_from_with_validity``) now wraps each row's body so per-row
errors (JSON parse, base64 decode, post-decrypt plaintext json)
yield a sentinel envelope (``event_type == "<parse-error>"``) and
continue to the next line. The Python ``tn.read`` verify loop
recognises the sentinel and routes it to ``stats.skipped_parse``.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest


@pytest.fixture()
def three_entries_with_bad_middle(tmp_path: Path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    os.environ["TN_NO_STDOUT"] = "1"
    import tn

    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.init()
    tn.info("a", x=1)
    tn.info("b", x=2)
    tn.info("c", x=3)
    tn.flush_and_close()

    log = tmp_path / ".tn" / "default" / "logs" / "tn.ndjson"
    lines = log.read_text().splitlines()
    assert len(lines) >= 3, f"expected 3 user entries, got {lines!r}"
    doc = json.loads(lines[1])
    raw = bytearray(
        base64.urlsafe_b64decode(doc["default"]["ciphertext"] + "==")
    )
    raw[20] ^= 0x01  # corrupt one byte of ciphertext
    doc["default"]["ciphertext"] = (
        base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    )
    lines[1] = json.dumps(doc)
    log.write_text("\n".join(lines) + "\n")

    tn.init()  # rebind runtime against the mutated file
    try:
        yield tn
    finally:
        tn.flush_and_close()
        os.chdir(cwd)


def test_skip_yields_clean_entries_around_parse_error(
    three_entries_with_bad_middle,
):
    """The spec the tester filed: with one parse-failing entry
    between two clean ones, ``tn.read(verify='skip', on_skip=cb)``
    yields BOTH clean entries and fires ``cb`` once for the bad one."""
    tn = three_entries_with_bad_middle
    seen = []
    result = tn.read(
        verify="skip",
        on_skip=lambda env, reason: seen.append((env, reason)),
    )
    out = [e.event_type for e in result]

    assert out == ["a", "c"], (
        f"expected clean entries on either side of the parse error to "
        f"yield, got {out!r}"
    )
    assert result.stats.yielded == 2
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 0
    assert len(seen) == 1
    sentinel_env, reason = seen[0]
    assert sentinel_env.get("event_type") == "<parse-error>"
    assert reason.startswith("parse:")


def test_verify_true_fires_callback_then_raises_on_parse_error(
    three_entries_with_bad_middle,
):
    """``verify=True`` still raises on parse errors, but the
    ``on_skip`` callback fires once before the exception so callers
    can log/alert before the read exits."""
    tn = three_entries_with_bad_middle
    seen = []
    result = tn.read(
        verify=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )
    with pytest.raises(Exception, match=r"parse|chain|failed"):
        list(result)
    assert len(seen) == 1, (
        f"observer should fire exactly once before raise; got {seen!r}"
    )
    assert seen[0][1].startswith("parse:")


def test_stats_count_distinguishes_parse_from_verify(
    three_entries_with_bad_middle,
):
    """The headline stats split: parse failures count toward
    ``skipped_parse``, not ``skipped_verify``. Lets callers tell
    "the bytes are malformed" from "verify failed."""
    tn = three_entries_with_bad_middle
    result = tn.read(verify="skip")
    list(result)
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 0
    assert any(
        r.startswith("parse:") for r in result.stats.skipped_reasons
    ), f"expected a 'parse:'-prefixed reason; got {result.stats.skipped_reasons!r}"
