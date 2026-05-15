"""
SILO: C6 — `tn` CLI verbs
TEST: invalid CLI invocations exit non-zero with useful diagnostics.

Cron + CI tooling depends on the exit code; an "always exit 0" CLI
silently lies about failure. Three negative cases:

  1. Unknown subcommand (`tn nonsense`).
  2. Missing required positional (`tn init` with no project arg).
  3. Pointing at a non-existent yaml (`tn read --yaml /does/not/exist`).

Each must:
  - exit non-zero, and
  - print a useful message to stderr (NOT stdout).

The exact wording of the message isn't asserted — only that it's
non-empty and references the failing surface area in some recognizable
way. (Pinning exact wording would make the test brittle to wording
tweaks that don't change behavior.)

Asserts (named):
  - "unknown-verb-exits-nonzero"
  - "unknown-verb-stderr-not-empty"
  - "missing-positional-exits-nonzero"
  - "missing-positional-stderr-mentions-arg"
  - "nonexistent-yaml-exits-nonzero"
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


def test_unknown_verb_exits_nonzero(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    r = cli_run("nonsense-verb-does-not-exist")  # type: ignore[arg-type]

    assert_named(
        name="unknown-verb-exits-nonzero",
        expected=True,
        observed=getattr(r, "code", 0) != 0,
        on_miss=(
            f"`tn nonsense-verb-does-not-exist` exited "
            f"{getattr(r, 'code', '?')}. argparse should reject unknown "
            f"subcommands with a non-zero exit."
        ),
    )
    assert_named(
        name="unknown-verb-stderr-not-empty",
        expected=True,
        observed=bool(getattr(r, "stderr", "").strip()),
        on_miss=(
            f"`tn <unknown>` failed silently — stderr is empty. The "
            f"operator needs a message. stdout={getattr(r, 'stdout', '')[:200]!r}"
        ),
    )

    assert_user_home_untouched()


def test_missing_positional_exits_nonzero(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    # `tn init` without the required <project> positional.
    r = cli_run("init")  # type: ignore[arg-type]

    assert_named(
        name="missing-positional-exits-nonzero",
        expected=True,
        observed=getattr(r, "code", 0) != 0,
        on_miss=(
            f"`tn init` (no project) exited {getattr(r, 'code', '?')}. "
            f"argparse should reject missing required positional with "
            f"non-zero exit."
        ),
    )
    stderr = getattr(r, "stderr", "")
    assert_named(
        name="missing-positional-stderr-mentions-arg",
        expected=True,
        observed=("project" in stderr) or ("required" in stderr) or ("argument" in stderr),
        on_miss=(
            f"`tn init` stderr should explain the missing arg in some "
            f"recognizable way (mention 'project' or 'required' or "
            f"'argument'). Got: stderr={stderr[:400]!r}"
        ),
    )

    assert_user_home_untouched()


def test_nonexistent_yaml_exits_nonzero(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    # `tn read` against a yaml that doesn't exist.
    fake = hermetic_machine / "does" / "not" / "exist.yaml"
    r = cli_run("read", "--yaml", str(fake))  # type: ignore[arg-type]

    assert_named(
        name="nonexistent-yaml-exits-nonzero",
        expected=True,
        observed=getattr(r, "code", 0) != 0,
        on_miss=(
            f"`tn read --yaml {fake}` exited {getattr(r, 'code', '?')}. "
            f"Reading a non-existent yaml should be an error, not a "
            f"silent empty-output success. "
            f"stdout={getattr(r, 'stdout', '')[:200]!r} "
            f"stderr={getattr(r, 'stderr', '')[:200]!r}"
        ),
    )

    assert_user_home_untouched()
