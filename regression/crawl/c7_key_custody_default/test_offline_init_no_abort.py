"""
SILO: C7 — Default key custody
TEST: when the vault is unreachable, `tn.init(link=True)` still succeeds —
      the ceremony is minted, logging works, and a warning is surfaced.
      Auto-link must be a soft dependency; if it weren't, every offline
      developer would see `tn init` crash instead of degrading gracefully.
SEE: regression/crawl/c7_key_custody_default/README.md

Why we care:
  - A user might run `tn init` on a plane, behind a corp firewall, or
    while the vault is mid-deploy. The ceremony has to mint
    successfully and the SDK has to come up usable. The auto-link
    retry will happen on the next successful push.
  - Concretely: `tn.init(link=True)` must NOT raise, must NOT block
    indefinitely, and must NOT write a bogus claim_url.txt.

Flow:
  1. Hermetic machine — TN_VAULT_URL pointed at a dead port (free port
     that nobody's listening on).
  2. `tn.init(link=True)` — should return normally.
  3. Assert: ceremony is alive (cfg.yaml_path resolves, tn.info works).
  4. Assert: no claim_url.txt was produced (it would be misleading to
     persist a URL we never minted).

Asserts (named):
  - "init-did-not-raise"
  - "ceremony-yaml-on-disk"
  - "log-event-after-init-works"
  - "no-claim-url-file"
  - "user-home-untouched"

Failure modes the test catches:
  - The auto-link path is hard-required (raises on failure) — the user
    sees a crash instead of a working ceremony.
  - claim_url.txt is written speculatively before the POST succeeds,
    leaving a dangling URL that won't claim.
  - tn.init() hangs forever waiting on the unreachable vault.
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest
import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def _dead_url() -> str:
    """Return a URL whose host:port nobody's listening on.

    Pattern: bind to port 0, get the kernel's assignment, immediately
    close. The port is now free for the kernel to re-assign, so an HTTP
    connection there will get ECONNREFUSED quickly. (Tiny race window
    where another listener might grab it — irrelevant for a single-
    process test.)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def test_init_with_unreachable_vault_does_not_abort(
    hermetic_machine: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Point at a dead URL + opt in to link mode.
    monkeypatch.setenv("TN_VAULT_URL", _dead_url())
    monkeypatch.delenv("TN_NO_LINK", raising=False)

    # ── init must not raise ──────────────────────────────────────────
    init_raised: BaseException | None = None
    try:
        tn.init(link=True)
    except BaseException as exc:  # noqa: BLE001
        init_raised = exc

    assert_named(
        name="init-did-not-raise",
        expected=None,
        observed=type(init_raised).__name__ if init_raised else None,
        on_miss=(
            f"tn.init(link=True) raised {init_raised!r} when the vault "
            f"was unreachable. The auto-link path must be a soft "
            f"dependency; check python/tn/__init__.py:"
            f"_auto_link_after_init for the exception-swallowing logic."
        ),
    )

    # ── ceremony is alive ────────────────────────────────────────────
    cfg = tn.current_config()
    assert_named(
        name="ceremony-yaml-on-disk",
        expected=True,
        observed=Path(cfg.yaml_path).exists(),
        on_miss=(
            f"Ceremony yaml at {cfg.yaml_path} not on disk after "
            f"tn.init(link=True). The mint path must run BEFORE the "
            f"vault upload — check python/tn/__init__.py order of "
            f"operations."
        ),
    )

    # Logging must still work after the failed auto-link.
    tn.info("c7.offline.smoke", note="ceremony-alive-despite-dead-vault")
    log = LogQuery(ceremony_path=cfg.yaml_path)
    log.assert_contains(
        name="log-event-after-init-works",
        where={"event_type": "c7.offline.smoke"},
        on_miss=(
            "tn.info() didn't produce an envelope after a vault-offline "
            "init. The runtime must come up clean even when auto-link "
            "fails — investigate the handler-stack assembly."
        ),
    )

    # ── No claim_url.txt should be present ──────────────────────────
    # The auto-link path writes the URL AFTER the POST succeeds. With
    # a dead vault the POST should fail and the file should not exist.
    claim_url_file = Path(cfg.yaml_path).parent / ".tn" / "sync" / "claim_url.txt"
    assert_named(
        name="no-claim-url-file",
        expected=False,
        observed=claim_url_file.exists(),
        on_miss=(
            f"Found claim_url.txt at {claim_url_file} after a vault-"
            f"offline init. The auto-link path is writing the file "
            f"speculatively — the URL won't claim because the vault "
            f"never saw the upload. Check python/tn/handlers/"
            f"vault_push.py:init_upload for the write order: POST must "
            f"succeed BEFORE the URL is persisted."
        ),
    )

    assert_user_home_untouched()
