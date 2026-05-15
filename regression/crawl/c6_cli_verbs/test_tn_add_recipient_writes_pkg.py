"""
SILO: C6 — `tn` CLI verbs
TEST: after `tn init`, `tn add_recipient default <label>` produces a .tnpkg
      artifact AND records `tn.recipient.added` in the admin log.

Flow:
  1. Hermetic machine. `tn init myproject --no-link`.
  2. `tn add_recipient default alice_label --yaml <proj>/tn.yaml`.
  3. Assert exit 0.
  4. Assert at least one *.tnpkg file landed somewhere reachable
     (default is <cwd>/alice_label.tnpkg per cli help).
  5. Assert the ceremony's admin log contains a `tn.recipient.added`
     envelope referencing the recipient.

Asserts (named):
  - "tn-init-exit-0" — precondition
  - "tn-add-recipient-exit-0"
  - "tn-add-recipient-writes-tnpkg"
  - "tn-add-recipient-emits-admin-event"
  - "user-home-untouched"
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_tn_add_recipient_writes_pkg(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    project = hermetic_machine / "myproject"
    yaml_path = project / "tn.yaml"

    init_r = cli_run(  # type: ignore[arg-type]
        "init", str(project), "--skip-confirm", "--keep-mnemonic", "--no-link",
    )
    assert_named(
        name="tn-init-exit-0",
        expected=0,
        observed=getattr(init_r, "code", -1),
        on_miss=f"precondition failed: stderr={getattr(init_r, 'stderr', '')[:400]!r}",
    )

    # add_recipient — passes a friendly label; the CLI auto-prefixes
    # with did:key:zLabel-... per cli.py:cmd_add_recipient.
    add_r = cli_run(  # type: ignore[arg-type]
        "add_recipient",
        "default",
        "alice_test_label",
        "--yaml", str(yaml_path),
    )
    assert_named(
        name="tn-add-recipient-exit-0",
        expected=0,
        observed=getattr(add_r, "code", -1),
        on_miss=(
            f"`tn add_recipient default alice_test_label` exited "
            f"{getattr(add_r, 'code', -1)}. "
            f"stderr={getattr(add_r, 'stderr', '')[:600]!r}"
        ),
    )

    # A .tnpkg file must have landed. The default `--out` path is
    # <cwd>/<label>.tnpkg per cli help; cwd is hermetic_machine.
    tnpkg_files = sorted(hermetic_machine.glob("*.tnpkg"))
    assert_named(
        name="tn-add-recipient-writes-tnpkg",
        expected=True,
        observed=len(tnpkg_files) > 0,
        on_miss=(
            f"No *.tnpkg file in {hermetic_machine}. The CLI claims to "
            f"write <label>.tnpkg by default. "
            f"stdout={getattr(add_r, 'stdout', '')[:400]!r}"
        ),
    )

    # Admin log must record the event.
    log = LogQuery(ceremony_path=yaml_path)
    env = log.assert_contains(
        name="tn-add-recipient-emits-admin-event",
        where={"event_type": "tn.recipient.added", "group": "default"},
        on_miss=(
            "After `tn add_recipient default ...`, expected a "
            "`tn.recipient.added` envelope in the admin log for "
            "group=default. The CLI wrote the .tnpkg but didn't attest. "
            "Check python/tn/admin/__init__.py:add_recipient's emit path."
        ),
    )
    # Defensive: the envelope should reference SOME recipient_did
    # (label normalization is a separate concern).
    assert_named(
        name="tn-add-recipient-event-has-recipient-did",
        expected=True,
        observed=isinstance(env.get("recipient_did"), str)
        and env.get("recipient_did", "").startswith("did:key:"),
        on_miss=(
            f"Admin event for `tn.recipient.added` lacks a valid "
            f"recipient_did field. Got {env.get('recipient_did')!r}. "
            f"Check admin/__init__.py:add_recipient envelope shape."
        ),
    )

    assert_user_home_untouched()
