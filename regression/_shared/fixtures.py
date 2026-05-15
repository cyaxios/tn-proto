"""Hermetic-machine fixtures for every silo.

The non-negotiable rule for TN regression tests: each test starts as if
the user has nothing cached on their machine. No `~/AppData/Roaming/tn/`,
no `$XDG_DATA_HOME/tn/`, no inherited TN_* env vars. Tests that pass
because of a stale cache instead of the code under test are silent
landmines — exactly what the regression suite must catch.

The `hermetic_machine` fixture below redirects every TN user-home write
into a per-test tmpdir via `TN_IDENTITY_DIR`. The real `~/AppData/.../tn/`
is never touched, even if a test's `tn.init(link=True)` would normally
mint a fresh identity there.

Use cases this guards against:
  - Test 1 leaves a cached identity.json behind; Test 2 silently reuses
    it and "passes" without exercising the init-from-zero path.
  - The user-home DID happens to match the ceremony DID because of a
    coincidence in a prior run, masking a real bug in `local.private`
    restoration.
  - A test that's supposed to prove "fresh machine → vault restore →
    chain continues" actually proves "machine has the right cached
    state from a prior test → looks like the restore worked."

Usage in a silo's conftest:

    from regression._shared.fixtures import hermetic_machine  # re-export

The fixture yields the Path of the test's tmpdir (which it has chdir'd
into). Every test under that conftest gets a clean machine + clean cwd
+ clean tn state, with teardown that calls `tn.flush_and_close()`.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def hermetic_machine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Yields a tmpdir that the test runs in, with TN's per-user state
    redirected away from the real machine.

    What this fixture promises:
      - `~/AppData/Roaming/tn/` (and the POSIX equivalent) is NOT
        touched by anything the test does.
      - `TN_IDENTITY_DIR` points at a per-test tmpdir, so any user-home
        identity writes (e.g. `tn.init(link=True)`) land there.
      - cwd is the test's tmpdir, so `tn.init()` discovery mints into
        the tmpdir, not into the repo or anywhere on the real machine.
      - `TN_NO_LINK=1` is set by default — the auto-link path is
        opt-in for each test, not the global default. Tests that want
        to exercise `link=True` explicitly unset this themselves.
      - `TN_VAULT_URL` is left as caller-provided (typically pointing
        at the local test vault at 127.0.0.1:8790). If unset, the SDK's
        default of vault.tn-proto.org applies — most tests won't
        opt-in to link without also pointing at a local vault.
      - Teardown calls `tn.flush_and_close()` so module-singleton
        state doesn't bleed into the next test.

    The fixture does NOT clean up `~/AppData/Roaming/tn/` itself —
    that's the user's real state, and we shouldn't touch it.
    """
    # 1. Redirect user-home identity into the tmpdir.
    identity_dir = tmp_path / "_tn_user_home"
    identity_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("TN_IDENTITY_DIR", str(identity_dir))

    # 2. Default: no auto-link. Tests that exercise the vault flow
    # `monkeypatch.delenv("TN_NO_LINK", raising=False)` to opt in.
    monkeypatch.setenv("TN_NO_LINK", "1")

    # 3. Clear any TN_YAML pointer so discovery doesn't find a parent
    # ceremony if the test runner happens to be inside a TN project.
    monkeypatch.delenv("TN_YAML", raising=False)

    # 4. Hop into the per-test tmpdir. Discovery will mint at
    # `<tmpdir>/.tn/default/` (or wherever the test asks).
    cwd_dir = tmp_path / "cwd"
    cwd_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(cwd_dir)

    # 5. Reset process-wide one-shot guards in the tn module so each
    # test starts clean. The auto-link path uses
    # `_link_done_this_process = True` after its first successful
    # upload so a single Python process doesn't print the claim banner
    # twice. In a pytest session each test should see a fresh world —
    # otherwise tests 2+ would silently skip auto-link entirely.
    try:
        import tn as _tn_mod

        if hasattr(_tn_mod, "_link_done_this_process"):
            _tn_mod._link_done_this_process = False  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    try:
        yield cwd_dir
    finally:
        # 6. Drop the module singleton + reset the one-shot guard so
        # the next test starts clean.
        try:
            import tn

            tn.flush_and_close()
            if hasattr(tn, "_link_done_this_process"):
                tn._link_done_this_process = False  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            # Teardown is best-effort; don't mask the real test failure.
            pass


@pytest.fixture
def hermetic_machine_with_vault(
    hermetic_machine: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """`hermetic_machine` + opts in to the local test vault + clears the
    no-link gate. Use this fixture for silos that exercise `link=True`.

    Caller MUST have a vault running at `http://127.0.0.1:8790` (the
    standard test vault — see `tn_proto_web/.venv/Scripts/python -m
    uvicorn src.app:app --port 8790` with `TN_DEV_AUTH_BYPASS=1`).
    """
    monkeypatch.setenv("TN_VAULT_URL", "http://127.0.0.1:8790")
    monkeypatch.delenv("TN_NO_LINK", raising=False)
    yield hermetic_machine


@pytest.fixture
def vault_cleanup() -> Iterator[list[str]]:
    """Per-test registry of vault_ids the test created.

    Usage in a test:

        def test_x(vault_server, vault_cleanup):
            tn.init(link=True)
            pc = get_pending_claim(...)
            vault_cleanup.append(pc["vault_id"])
            ...

    In the default (live-vault) mode the fixture's finalizer DELETEs
    every registered vault_id from the live vault so test-created
    pending_claims don't accumulate. In ephemeral mode
    (TN_REGRESSION_USE_EPHEMERAL_VAULT=1) the registry is recorded but
    no DELETEs fire — the ephemeral DB drops at session end anyway.

    The cleanup is best-effort: a 404 (already gone) or a 409
    (already bound) is silently OK; nothing raises here, so the
    underlying test failure (if any) surfaces cleanly.
    """
    registered: list[str] = []
    yield registered

    # Cleanup runs in live mode (the default). In ephemeral mode the
    # DB drop at session teardown handles it for us.
    if os.environ.get("TN_REGRESSION_USE_EPHEMERAL_VAULT") == "1":
        return
    if not registered:
        return

    # Need a live bearer JWT to DELETE. Use the same dev-auth path
    # the test fixture uses.
    try:
        from regression._shared.vault_test_helpers import (
            delete_pending_claim,
            dev_auth_login,
        )

        live_url = os.environ.get("TN_VAULT_URL", "http://127.0.0.1:8790")
        login = dev_auth_login(live_url, handle="alice")
        token = login.get("token")
        if not token:
            return
        for vid in registered:
            delete_pending_claim(live_url, vid, token)
    except Exception:  # noqa: BLE001
        # Best-effort cleanup — never mask the real test failure.
        pass


def assert_user_home_untouched() -> None:
    """Assert that the REAL ~/AppData/Roaming/tn/ (or POSIX
    equivalent) was not modified during the test. Called inside a test
    to prove that the hermetic redirect worked end-to-end.

    The real user-home tn dir is wherever `_default_identity_dir()`
    would resolve to absent `TN_IDENTITY_DIR`. Compute that fresh —
    don't trust env vars at this point because the fixture set them.
    """
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    real_user_home_tn = Path(base) / "tn"
    if real_user_home_tn.exists():
        contents = sorted(p.name for p in real_user_home_tn.iterdir())
        raise AssertionError(
            f"Hermetic violation: {real_user_home_tn} exists with contents={contents}. "
            f"A test wrote to the real user-home tn directory. The `hermetic_machine` "
            f"fixture should have redirected to TN_IDENTITY_DIR=<tmpdir>. Investigate "
            f"which test polluted it; clean up via `rm -rf {real_user_home_tn}` and "
            f"re-run."
        )
