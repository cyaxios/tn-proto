"""Python side of the cross-impl GOLDEN admin-state interop test.

Driven by ts-sdk/test/admin_state_interop.test.ts. The TS side builds a
deterministic btn ceremony on disk, provisions two recipients via init
reconcile, revokes one, then spawns THIS helper against the SAME yaml so
both implementations replay the SAME attested log. The TS test then
compares the two outputs field-for-field.

Usage:
    python admin_state_py_helper.py <yaml_path> <group>

Prints ONE json object to stdout:
    {
      "state":      tn.admin.state(<group>),
      "recipients": tn.admin.recipients(<group>, include_revoked=True),
    }

Keys are Python-native snake_case; the TS side maps its camelCase output
onto this shape before comparing. `default=str` renders any stray
non-JSON-native value (e.g. a Path) deterministically; `sort_keys=True`
keeps object key order stable so the comparison is order-independent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Route stdout through the raw buffer so Windows does not rewrite \n to
# \r\n (the TS side reads stdout as utf8 and json-parses it; a stray \r
# inside the payload would not break json, but keeping the byte stream
# clean matches the sibling interop helpers).
_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


# Import the in-tree `tn` package from this worktree's python/ dir, exactly
# like full_runtime_py_helper.py does. ts-sdk/test/ -> ts-sdk -> <root>;
# <root>/python is the package parent.
TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write(
            "usage: admin_state_py_helper.py <yaml_path> <group>\n"
        )
        return 1

    yaml_path = sys.argv[1]
    group = sys.argv[2]

    import tn

    # Point tn at the exact ceremony the TS side built on disk. cipher=btn
    # matches the yaml; init loads (does not re-create) the existing
    # keystore + log.
    tn.init(yaml_path, cipher="btn")

    payload = {
        "state": tn.admin.state(group),
        "recipients": tn.admin.recipients(group, include_revoked=True),
    }

    _write(json.dumps(payload, sort_keys=True, default=str) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
