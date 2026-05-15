"""C8 silo conftest — same shape as C7.

Re-exports the vault subprocess + hermetic-machine fixtures, plus a
two-machine helper that makes test bodies read naturally:

    def test_restore(machine_a, machine_b, vault_server):
        ...

Each "machine" is a fresh tmpdir; the test drives A's `tn.init(link=
True)` then B's dev-auth + fetch + decrypt + re-init.
"""
from __future__ import annotations

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
    """Same shape as C7's fixture: hermetic machine + TN_VAULT_URL
    pointed at the live subprocess + TN_NO_LINK cleared.
    """
    monkeypatch.setenv("TN_VAULT_URL", vault_server.base_url)
    monkeypatch.delenv("TN_NO_LINK", raising=False)
    yield hermetic_machine


@pytest.fixture
def machine_b_tmpdir(tmp_path: Path) -> Path:
    """A second tmpdir representing 'machine B' — a fresh, unconfigured
    machine that's about to restore from the vault.

    Distinct from the `hermetic_machine` cwd (which represents machine
    A). The test lays out tn.yaml + keys/ under here, then calls
    `tn.init(yaml_path=machine_b_tmpdir / 'tn.yaml')`.
    """
    b = tmp_path / "machine_b"
    b.mkdir(parents=True, exist_ok=True)
    return b
