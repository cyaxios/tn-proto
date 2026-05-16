"""
SILO: C6 — `tn` CLI verbs
TEST: `tn init <projectdir>` produces a valid ceremony on disk.
SEE: regression/crawl/c6_cli_verbs/README.md

Flow:
  1. Hermetic machine — no vault contact, TN_NO_LINK=1.
  2. Run: `python -m tn.cli init myproject --skip-confirm --keep-mnemonic`
  3. Assert exit 0.
  4. Assert <hermetic_machine>/myproject/tn.yaml exists + is loadable.
  5. Assert a keystore dir exists.
  6. Assert stdout mentions the DID.

Asserts (named):
  - "tn-init-exit-0"
  - "tn-init-writes-yaml"
  - "tn-init-yaml-is-parseable"
  - "tn-init-writes-keystore-dir"
  - "tn-init-stdout-mentions-did"
  - "user-home-untouched"
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml as _yaml

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


def test_tn_init_creates_ceremony(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    project = hermetic_machine / "myproject"

    # `--skip-confirm --keep-mnemonic` matches the non-TTY path the
    # CI runner uses: no Enter-prompt to wait for, mnemonic persisted
    # into identity.json (the test will assert_user_home_untouched
    # because TN_IDENTITY_DIR is redirected to the tmpdir).
    #
    # `--no-link` is REQUIRED here: the CLI's cmd_init has its own
    # auto-link block that does NOT honor `TN_NO_LINK=1` from env.
    # Without --no-link, `tn init` would POST a real pending-claim to
    # https://vault.tn-proto.org (the production vault). See
    # critic log C6 #1.
    result = cli_run(  # type: ignore[arg-type]
        "init",
        str(project),
        "--skip-confirm",
        "--keep-mnemonic",
        "--no-link",
    )

    assert_named(
        name="tn-init-exit-0",
        expected=0,
        observed=getattr(result, "code", -1),
        on_miss=(
            f"`tn init {project}` exited {getattr(result, 'code', -1)}. "
            f"stderr={getattr(result, 'stderr', '')[:600]!r}"
        ),
    )

    yaml_path = project / "tn.yaml"
    assert_named(
        name="tn-init-writes-yaml",
        expected=True,
        observed=yaml_path.exists(),
        on_miss=(
            f"After `tn init`, expected {yaml_path} on disk. Project dir "
            f"contents: {sorted(p.name for p in project.iterdir()) if project.exists() else 'no-dir'}"
        ),
    )

    # The yaml must be parseable — argparse can't catch a malformed
    # yaml writer, but pytest can.
    parseable = False
    try:
        doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        parseable = isinstance(doc, dict) and "ceremony" in doc
    except Exception:  # noqa: BLE001
        parseable = False
    assert_named(
        name="tn-init-yaml-is-parseable",
        expected=True,
        observed=parseable,
        on_miss=(
            f"{yaml_path} either failed YAML parse or has no 'ceremony' "
            f"section. Inspect the file; check python/tn/cli.py:cmd_init's "
            f"yaml-write block."
        ),
    )

    # Keystore layout:
    #   - `.tn/tn/keys/`     legacy convention `tn init` actually uses
    #     today (see migrateLegacyLayout in ts-sdk/src/multi.ts for the
    #     migration story; the CLI hasn't moved yet)
    #   - `.tn/default/keys/` newer multi-ceremony layout
    #   - `keys/`            ancient single-yaml layout
    keystore_candidates = [
        project / ".tn" / "tn" / "keys",
        project / ".tn" / "default" / "keys",
        project / "keys",
    ]
    keystore_dir = next((p for p in keystore_candidates if p.exists()), None)
    assert_named(
        name="tn-init-writes-keystore-dir",
        expected=True,
        observed=keystore_dir is not None
        and any(keystore_dir.iterdir()),
        on_miss=(
            f"No populated keystore dir found in {keystore_candidates!r}. "
            f"`tn init` should mint at least the publisher's self-kit "
            f"and write `local.private`. Check cli.py:cmd_init."
        ),
    )

    stdout = getattr(result, "stdout", "")
    assert_named(
        name="tn-init-stdout-mentions-did",
        expected=True,
        observed="did:key:" in stdout,
        on_miss=(
            f"stdout did not include a did:key:... line. The operator's "
            f"feedback loop is broken — they need to know what DID was "
            f"minted. stdout={stdout[:600]!r}"
        ),
    )

    assert_user_home_untouched()
