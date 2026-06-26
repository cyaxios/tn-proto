"""Python side of the cross-impl vault.setLinkState interop test.

Driven by ts-sdk/test/vault_set_link_state_interop.test.ts. Exercises
the SAME ceremony yaml the TS side mutates so both implementations agree
on the `ceremony.mode` field written by Python's `tn.admin.set_link_state`
and TS's `tn.vault.setLinkState` (-> NodeRuntime.setCeremonyMode).

Usage:
    python vault_set_link_state_py_helper.py read  <yaml_path>
    python vault_set_link_state_py_helper.py set   <yaml_path> <local|linked>

`read` prints ONE json object: {"mode": <ceremony.mode as loaded>}.
`set`  flips ceremony.mode via tn.admin.set_link_state(cfg, mode=...) and
       then prints {"mode": <reloaded ceremony.mode>} so the caller can
       confirm the write landed.

Both subcommands resolve the same in-tree `tn` package the sibling
helpers use (ts-sdk/test/ -> ts-sdk -> <root>; <root>/python is the
package parent).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write(
            "usage: vault_set_link_state_py_helper.py read|set <yaml_path> [mode]\n"
        )
        return 1

    cmd = sys.argv[1]
    yaml_path = sys.argv[2]

    import tn

    # Load (not re-create) the ceremony the TS side built on disk.
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    if cmd == "read":
        _write(
            json.dumps(
                {"mode": cfg.mode, "linked_vault": cfg.linked_vault},
                sort_keys=True,
            )
            + "\n"
        )
        return 0

    if cmd == "set":
        if len(sys.argv) < 4:
            sys.stderr.write("set requires a mode argument (local|linked)\n")
            return 1
        mode = sys.argv[3]
        # set_link_state requires linked_vault when mode == "linked"; the
        # round-trip test only flips Python -> unlinked, so pass mode
        # straight through. Provide linked_vault defensively if asked to
        # link so the helper stays usable either direction.
        if mode == "linked":
            tn.set_link_state(cfg, mode="linked", linked_vault="https://vault.example")
        else:
            tn.set_link_state(cfg, mode=mode)
        # Reload from disk so we report what actually persisted (not just
        # the in-memory cfg the call mutated).
        reloaded = tn.config.load(Path(yaml_path))
        _write(
            json.dumps(
                {"mode": reloaded.mode, "linked_vault": reloaded.linked_vault},
                sort_keys=True,
            )
            + "\n"
        )
        return 0

    sys.stderr.write(f"unknown subcommand {cmd!r}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
