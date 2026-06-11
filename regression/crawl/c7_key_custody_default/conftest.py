"""C7 silo conftest — wires the vault subprocess + hermetic machine.

Re-exports:
  - `vault_server` — session-scoped FastAPI subprocess (from
    `_shared/vault_subprocess.py`). Skips the silo if mongo or
    tn_proto_web isn't available.
  - `hermetic_machine_with_vault` — per-test hermetic redirect plus
    `TN_VAULT_URL` pointing at the live subprocess and `TN_NO_LINK`
    cleared so `tn.init(link=True)` is opt-in per test.

Every C7 test gets both fixtures.
"""
from collections.abc import Iterator
from pathlib import Path

import pytest

from regression._shared.fixtures import (  # noqa: F401 — re-exported for pytest discovery
    hermetic_machine,
    hermetic_machine_with_vault,
    vault_cleanup,
)
from regression._shared.vault_subprocess import (  # noqa: F401 — re-exported
    VaultServer,
    vault_server,
)


@pytest.fixture
def hermetic_machine_with_live_vault(
    hermetic_machine: Path,
    vault_server: VaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """`hermetic_machine` + points `TN_VAULT_URL` at the LIVE subprocess
    booted by the `vault_server` fixture (not the default localhost:8790).

    The base `hermetic_machine_with_vault` fixture hard-codes
    `TN_VAULT_URL=http://127.0.0.1:8790`. For C7 we want the test to
    drive the freshly-booted ephemeral subprocess (random free port,
    own ephemeral mongo) — so we override here. Also clears TN_NO_LINK
    so `tn.init(link=True)` is opt-in.
    """
    monkeypatch.setenv("TN_VAULT_URL", vault_server.base_url)
    monkeypatch.delenv("TN_NO_LINK", raising=False)
    # The auto-link path needs a deterministic location for
    # sync_state. The hermetic_machine fixture already redirects
    # TN_IDENTITY_DIR; nothing more to do.
    yield hermetic_machine
