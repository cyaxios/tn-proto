"""Genesis-anchor opt-in: a reader can require a COMPLETE chain to start at
ZERO_HASH, catching a front-truncation (rows lopped off the chain's head).

This is OFF by default. Ordinary logging and partial/tailed/rotated reads
trust the first entry they see (they routinely hold only a slice of a chain,
so requiring a genesis anchor would false-positive). The capability is wired
through ``read_with_keybag(..., expect_genesis=True)`` for callers that know
they hold a whole log from byte zero (an audit), and is the foundation for a
later checkpoint-based rotation/resume distinction.

The chain check reads only ``event_type``/``prev_hash``/``row_hash`` from each
envelope, independent of decryption, so these tests drive the reader with
hand-built envelopes and ``verify_signatures=False`` — deterministic and with
no crypto setup.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from tn.chain import ZERO_HASH
from tn.reader import read_with_keybag


def _write_log(tmp_path: Path, envelopes: list[dict]) -> tuple[Path, Path]:
    """Write NDJSON envelopes to a log file; return (log_path, empty_keystore)."""
    log = tmp_path / "log.ndjson"
    log.write_text("".join(json.dumps(e) + "\n" for e in envelopes), encoding="utf-8")
    keystore = tmp_path / "keys"
    keystore.mkdir()
    return log, keystore


def _chain_entries(tmp_path: Path, envelopes: list[dict], *, expect_genesis: bool):
    log, keystore = _write_log(tmp_path, envelopes)
    return [
        e["valid"]["chain"]
        for e in read_with_keybag(
            log, keystore, verify_signatures=False, expect_genesis=expect_genesis
        )
    ]


# A valid 3-link chain for one event_type: ZERO_HASH -> H1 -> H2 -> H3.
_FULL = [
    {"event_type": "order.created", "prev_hash": ZERO_HASH, "row_hash": "sha256:h1"},
    {"event_type": "order.created", "prev_hash": "sha256:h1", "row_hash": "sha256:h2"},
    {"event_type": "order.created", "prev_hash": "sha256:h2", "row_hash": "sha256:h3"},
]
# The same chain with the genesis row lopped off (front-truncation): the new
# first entry's prev_hash points at h1, a row that is no longer present.
_TRUNCATED = _FULL[1:]


def test_default_full_chain_all_links_ok(tmp_path):
    """Default read of a complete chain: every link verifies."""
    assert _chain_entries(tmp_path, _FULL, expect_genesis=False) == [True, True, True]


def test_default_tolerates_front_truncation(tmp_path):
    """Default read of a front-truncated chain trusts the first entry it sees,
    so truncation is NOT flagged — this is the behavior ordinary logging,
    resumed reads, and rotated logs rely on and MUST keep."""
    assert _chain_entries(tmp_path, _TRUNCATED, expect_genesis=False) == [True, True]


def test_genesis_optin_full_chain_anchors_clean(tmp_path):
    """With the opt-in, a complete chain that starts at ZERO_HASH still passes
    on every link — the genuine genesis anchors fine."""
    assert _chain_entries(tmp_path, _FULL, expect_genesis=True) == [True, True, True]


def test_genesis_optin_catches_front_truncation(tmp_path):
    """With the opt-in, the front-truncated chain's new first entry fails: its
    prev_hash is not ZERO_HASH, so the missing head is detected."""
    assert _chain_entries(tmp_path, _TRUNCATED, expect_genesis=True) == [False, True]


def test_genesis_optin_is_per_event_type(tmp_path):
    """The genesis requirement is per (publisher, event_type) chain: each
    distinct event_type's first entry must anchor at ZERO_HASH independently."""
    envelopes = [
        {"event_type": "a", "prev_hash": ZERO_HASH, "row_hash": "sha256:a1"},
        {"event_type": "b", "prev_hash": ZERO_HASH, "row_hash": "sha256:b1"},
        {"event_type": "a", "prev_hash": "sha256:a1", "row_hash": "sha256:a2"},
        # `b`'s second link is broken (points at a row that never existed).
        {"event_type": "b", "prev_hash": "sha256:nope", "row_hash": "sha256:b2"},
    ]
    assert _chain_entries(tmp_path, envelopes, expect_genesis=True) == [
        True,  # a1 anchors at ZERO_HASH
        True,  # b1 anchors at ZERO_HASH
        True,  # a2 links to a1
        False,  # b2 does not link to b1
    ]
