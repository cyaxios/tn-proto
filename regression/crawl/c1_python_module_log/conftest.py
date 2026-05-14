"""C1 silo-local fixtures.

Every Python silo will eventually need:

- A fresh tmpdir per test (so ceremonies don't bleed across tests).
- A fresh `tn.init(...)` against that tmpdir.
- Teardown that calls `tn.flush_and_close()` so the module singleton
  doesn't leak runtime state into the next test.

If a second silo duplicates this conftest verbatim, lift it into
`regression/_shared/fixtures.py` and import. For now, keep it here so
the silo is self-contained.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def fresh_ceremony(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Yields a yaml-path-to-be in a fresh tmpdir. The test calls
    `tn.init(yaml_path)` itself — the fixture deliberately does NOT
    pre-init, because some tests want to control init kwargs
    (stdout=False, etc.).

    Teardown: always calls `tn.flush_and_close()` so the module
    singleton is clean for the next test. Also stamps `TN_NO_LINK=1`
    so init doesn't try to phone home to a real vault.
    """
    # Don't auto-link to the real vault during regression tests.
    monkeypatch.setenv("TN_NO_LINK", "1")

    yaml_path = tmp_path / "tn.yaml"
    yield yaml_path

    import tn

    try:
        tn.flush_and_close()
    except Exception:  # noqa: BLE001
        # Teardown is best-effort. If close itself is broken, the
        # actual test should have caught it; we don't want the
        # fixture to mask the real failure.
        pass
