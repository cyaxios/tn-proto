"""
SILO: C7 — Default key custody
TEST: the claim URL written by `tn.init(link=True)` matches the documented
      pattern and round-trip-parses cleanly.
SEE: regression/crawl/c7_key_custody_default/README.md

Spec (from tn_proto_web/docs/superpowers/plans/2026-04-28-pending-claim-flow.md
§"Wire contract"):

    <vault_base>/claim/<vault_id_ulid>#k=<bek_b64url_no_pad>

where:
  - vault_id is a 26-char ULID (Crockford alphabet, uppercase).
  - bek is 32 bytes encoded base64url, padding stripped.

The URL must round-trip through `parse_claim_url(...)` to yield the
SAME vault_id we see in sync_state and a 32-byte BEK.

Asserts (named):
  - "claim-url-matches-spec-regex"
  - "parsed-vault-id-matches-sync-state"
  - "parsed-bek-is-32-bytes"
  - "user-home-untouched"
"""
from __future__ import annotations

import re
from pathlib import Path

import tn

from regression._shared.assertions import assert_named, assert_named_match
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.vault_test_helpers import parse_claim_url


# Spec regex. Matches:
#   http(s)://anything:port/claim/<26-char ULID>#k=<base64url no pad>
_CLAIM_URL_RE = re.compile(
    r"^https?://[^/]+/claim/[0-9A-HJKMNP-TV-Z]{26}#k=[A-Za-z0-9_-]+$"
)


def test_claim_url_matches_spec(
    hermetic_machine_with_live_vault: Path,
    vault_cleanup: list[str],
) -> None:
    tn.init(link=True)
    cfg = tn.current_config()
    yaml_dir = Path(cfg.yaml_path).parent

    claim_url = (yaml_dir / ".tn" / "sync" / "claim_url.txt").read_text(
        encoding="utf-8"
    ).strip()

    # Regex shape check — distinct from the parse check below because
    # this catches subtle spec drifts (lowercase ULIDs, wrong fragment
    # key name, trailing slash, etc.) that a tolerant parser might
    # accept silently.
    assert_named_match(
        name="claim-url-matches-spec-regex",
        pattern=_CLAIM_URL_RE.pattern,
        observed=claim_url,
        on_miss=(
            f"Claim URL drifted from the spec shape "
            f"<vault>/claim/<ULID>#k=<b64url>. URL was: {claim_url!r}. "
            f"The spec lives in tn_proto_web/docs/superpowers/plans/"
            f"2026-04-28-pending-claim-flow.md §'Wire contract'; the "
            f"URL is built in python/tn/handlers/vault_push.py:init_upload."
        ),
    )

    # Parse + cross-check against sync_state.
    parsed_vault_id, parsed_bek = parse_claim_url(claim_url)
    vault_cleanup.append(parsed_vault_id)

    from tn.sync_state import get_pending_claim

    pc = get_pending_claim(cfg.yaml_path)
    state_vault_id = pc.get("vault_id") if pc else None

    assert_named(
        name="parsed-vault-id-matches-sync-state",
        expected=state_vault_id,
        observed=parsed_vault_id,
        on_miss=(
            f"vault_id extracted from URL ({parsed_vault_id!r}) differs "
            f"from sync_state.pending_claim.vault_id ({state_vault_id!r}). "
            f"The URL builder and the sync_state writer are sharing the "
            f"same source-of-truth — check vault_push.py:init_upload "
            f"where set_pending_claim is called with the same vault_id "
            f"used to build the URL."
        ),
    )

    assert_named(
        name="parsed-bek-is-32-bytes",
        expected=32,
        observed=len(parsed_bek),
        on_miss=(
            f"BEK extracted from URL fragment is {len(parsed_bek)} bytes "
            f"(expected 32 for AES-256). The BEK is minted by "
            f"secrets.token_bytes(32) in vault_push.py:init_upload."
        ),
    )

    assert_user_home_untouched()
