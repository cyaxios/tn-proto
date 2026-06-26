"""``tn read [<log>]`` — print a ceremony's log in flat decoded form.

Resolves a stream/ceremony NAME from the project's ``.tn/<name>/`` registry
before falling back to a literal log path, re-initing against the named stream
so :func:`tn.read` decrypts with the right per-stream config. Thin over
:func:`tn.read`; the one-line view inlines user kwargs and omits envelope/chain
plumbing by design.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import tn

from ._multi import ceremony_yaml_path
from .cli_common import _resolve_yaml_or_discover


def cmd_read(args: argparse.Namespace) -> int:
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path)
    # 0.4.2a9: `tn read <name>` resolves a stream/ceremony name from the
    # local project's `.tn/<name>/tn.yaml` registry before falling back
    # to treating the positional as a literal log path. Matches what
    # `tn streams` lists. The lookup is anchored at the discovered
    # yaml's parent (the project root) so it works regardless of cwd.
    log_path = None
    if args.log:
        as_name = args.log
        # First, see if it's a registered stream name.
        project_dir = yaml_path.parent.parent.parent  # .tn/default/tn.yaml -> project root
        try:
            candidate_yaml = ceremony_yaml_path(as_name, project_dir=project_dir)
        except Exception:  # noqa: BLE001 — invalid name, fall through to path mode
            candidate_yaml = None
        if candidate_yaml is not None and candidate_yaml.is_file():
            # It IS a stream name. Re-init against that stream's yaml so
            # tn.read decrypts with the right per-stream config, then
            # read its main log file directly.
            tn.init(candidate_yaml)
            log_path = None  # use the stream's own resolved log path
        else:
            log_path = Path(args.log).resolve()
    try:
        for entry in tn.read(log=log_path, all_runs=args.all_runs):
            ts = entry.timestamp.isoformat() if entry.timestamp else "?"
            level = entry.level or ""
            et = entry.event_type or "?"
            # Inline user-emitted kwargs so the operator can eyeball the
            # log without piping to jq for every command. Envelope /
            # chain plumbing (did, sequence, hashes, signature, run_id,
            # hidden_groups) lives on typed attributes and is omitted
            # from the one-line view by design.
            extra_str = " ".join(f"{k}={v!r}" for k, v in entry.fields.items())
            print(f"{ts}  {level:<7} {et}  {extra_str}".rstrip())
    finally:
        tn.flush_and_close()
    return 0
