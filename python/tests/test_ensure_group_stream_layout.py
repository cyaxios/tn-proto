"""``ensure_group`` must persist groups AUTHORITATIVELY under the
project-root stream layout.

A named stream (``tn.use("X")``) has an overlay at
``<cwd>/.tn/<project>/streams/X.yaml`` carrying ``extends: ../tn.yaml`` and
inherits ``device`` / ``keystore`` / ``groups`` / ``fields`` /
``recipients`` from the project root ``.tn/<project>/tn.yaml``. Those keys
are parent-owned — ``config._resolve_extends`` discards a child's copy
on the next load ("child sets parent-owned key 'groups'; parent wins").

Regression (pre-fix): ``ensure_group`` wrote the new group into the
*stream* yaml via ``cfg.yaml_path``, where ``groups`` is
non-authoritative. The group survived in-process (hot-reload kept the
live cfg consistent) but vanished on the next load, and a fresh-process
``tn add_recipient <group> ...`` failed with "unknown groups". The fix:
group / field / recipient writes target the authoritative root yaml at
the head of the ``extends:`` chain.

These tests pin the on-disk persistence contract; the same-process
hot-reload behaviour is covered by ``test_ensure_group_hot_reload.py``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

try:
    from tn._native import btn as tn_btn  # type: ignore[import-not-found]  # noqa: F401

    _HAS_BTN = True
except ImportError:
    _HAS_BTN = False

requires_btn = pytest.mark.skipif(
    not _HAS_BTN,
    reason="tn_btn Rust extension not installed in this environment",
)


_PYTHON_DIR = Path(__file__).resolve().parent.parent


def _run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run ``python -m tn.cli ...`` against ``tmp_path`` as cwd."""
    import os

    env = os.environ.copy()
    env["PYTHONPATH"] = str(_PYTHON_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["TN_NO_STDOUT"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", *args],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _run(tmp_path: Path, body: str, name: str = "case.py") -> str:
    script = tmp_path / name
    # Force UTF-8 so non-ASCII chars in test bodies survive the
    # Windows default cp1252 write encoding.
    script.write_text(body, encoding="utf-8")
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"subprocess failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    lines = rc.stdout.decode().strip().splitlines()
    return lines[-1] if lines else ""


def test_ensure_group_on_stream_writes_to_authoritative_root(tmp_path: Path):
    """ensure_group on a named stream must land the group in the root
    ``.tn/<project>/tn.yaml`` (authoritative), NOT the stream yaml, and
    must NOT trip the "child sets parent-owned key" warning."""
    body = textwrap.dedent('''
        import os, json, logging, pathlib
        os.environ["TN_NO_STDOUT"] = "1"

        warned = []
        class _H(logging.Handler):
            def emit(self, r): warned.append(r.getMessage())
        lg = logging.getLogger("tn")
        lg.addHandler(_H()); lg.setLevel(logging.WARNING)

        import tn
        tn.init(link=False)
        handle = tn.use("X")
        cfg = handle.cfg
        tn.ensure_group(cfg, "partners", fields=["amount", "status"])
        tn.flush_and_close()

        project = pathlib.Path.cwd().name
        root = pathlib.Path("./.tn") / project / "tn.yaml"
        stream = pathlib.Path("./.tn") / project / "streams" / "X.yaml"
        import yaml
        root_doc = yaml.safe_load(root.read_text())
        print(json.dumps({
            "root_has_partners": "partners" in (root_doc.get("groups") or {}),
            "root_has_amount_field": "amount" in (root_doc.get("fields") or {}),
            "stream_declares_groups": "groups" in (yaml.safe_load(stream.read_text()) or {}),
            "parent_owned_warnings": [m for m in warned if "parent-owned" in m],
        }))
    ''').strip()
    payload = json.loads(_run(tmp_path, body))
    assert payload["root_has_partners"], (
        "group 'partners' did not persist in the authoritative root yaml "
        ".tn/<project>/tn.yaml; ensure_group wrote it to the stream yaml "
        "where groups are non-authoritative."
    )
    assert payload["root_has_amount_field"], (
        "field route for 'amount' did not persist in the root yaml's "
        "flat fields block."
    )
    assert not payload["stream_declares_groups"], (
        "ensure_group wrote a `groups:` block into the stream yaml — that "
        "is the parent-owned key the loader discards. Got a stream yaml "
        "that declares groups."
    )
    assert payload["parent_owned_warnings"] == [], (
        "ensure_group tripped the parent-owned-key warning, meaning it "
        f"wrote groups/fields into the stream yaml: {payload['parent_owned_warnings']!r}"
    )


def test_group_added_on_stream_survives_fresh_process(tmp_path: Path):
    """Process A ensures the group on stream X; a FRESH process B that
    re-inits stream X sees 'partners' in cfg.groups and routes an emit
    through it."""
    proc_a = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init(link=False)
        handle = tn.use("X")
        tn.ensure_group(handle.cfg, "partners", fields=["amount", "status"])
        tn.flush_and_close()
    ''').strip()
    _run(tmp_path, proc_a, name="proc_a.py")

    proc_b = textwrap.dedent('''
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init(link=False)
        handle = tn.use("X")
        cfg = handle.cfg
        has_partners = "partners" in cfg.groups
        handle.info("deal.signed", amount=4999, status="closed", note="x")
        tn.flush_and_close()
        project = pathlib.Path.cwd().name
        last = json.loads(
            (pathlib.Path("./.tn") / project / "logs" / "X.ndjson")
                .read_text().splitlines()[-1]
        )
        groups = [
            k for k in last
            if isinstance(last[k], dict) and "ciphertext" in last[k]
        ]
        print(json.dumps({"has_partners": has_partners, "emit_groups": sorted(groups)}))
    ''').strip()
    payload = json.loads(_run(tmp_path, proc_b, name="proc_b.py"))
    assert payload["has_partners"], (
        "fresh process B did not see the 'partners' group in cfg.groups; "
        "the group did not persist authoritatively across the process "
        "boundary."
    )
    assert "partners" in payload["emit_groups"], (
        "fresh-process emit did not route the 'amount'/'status' fields "
        f"through the 'partners' group; got {payload['emit_groups']!r}."
    )


@requires_btn
def test_add_recipient_on_stream_added_group_in_fresh_process(tmp_path: Path):
    """The headline repro: ensure_group on a stream, then a fresh process
    add_recipient against that group must succeed and mint a .tnpkg —
    and a tn.group.added admin event must have been recorded."""
    proc_a = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init(link=False)
        handle = tn.use("X")
        tn.ensure_group(handle.cfg, "partners", fields=["amount", "status"])
        tn.flush_and_close()
    ''').strip()
    _run(tmp_path, proc_a, name="proc_a.py")

    proc_b = textwrap.dedent('''
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        from tn import admin
        tn.init(link=False)
        handle = tn.use("X")
        out = admin.add_recipient(
            "partners",
            recipient_did="did:key:zLabel-bob",
            out_path="bob.tnpkg",
            cfg=handle.cfg,
        )
        tn.flush_and_close()
        project = pathlib.Path.cwd().name
        # ensure_group emits through the active Project root runtime; tn.use()
        # does not rebind the singleton.
        admin_log = pathlib.Path("./.tn") / project / "admin" / "default.ndjson"
        added = False
        if admin_log.is_file():
            for line in admin_log.read_text().splitlines():
                env = json.loads(line)
                if env.get("event_type") == "tn.group.added" and env.get("group") == "partners":
                    added = True
        print(json.dumps({
            "bundle_exists": pathlib.Path("bob.tnpkg").is_file(),
            "leaf_index": out.leaf_index,
            "group_added_event": added,
        }))
    ''').strip()
    payload = json.loads(_run(tmp_path, proc_b, name="proc_b.py"))
    assert payload["bundle_exists"], (
        "add_recipient did not mint a .tnpkg bundle for the stream-added "
        "group; the group likely failed the 'unknown group' check."
    )
    assert payload["leaf_index"] is not None, (
        "add_recipient returned no leaf_index — the btn recipient mint "
        "did not run."
    )
    assert payload["group_added_event"], (
            "no tn.group.added admin event for 'partners' was recorded on the "
            "Project root admin log."
        )


@requires_btn
def test_cli_group_add_writes_to_authoritative_root_on_stream(tmp_path: Path):
    """`tn group add` against a stream yaml must persist the group in the
    authoritative root, and a follow-up `tn add_recipient` must succeed."""
    # Build the genuine extends-stream layout via the SDK (the CLI `init`
    # path treats a bare name as a standalone ceremony).
    bootstrap = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init(link=False)
        tn.use("X")
        tn.flush_and_close()
    ''').strip()
    _run(tmp_path, bootstrap, name="bootstrap.py")
    project = tmp_path.name
    stream_yaml = tmp_path / ".tn" / project / "streams" / "X.yaml"
    assert stream_yaml.is_file()

    add = _run_cli(
        tmp_path, "group", "add", "partners",
        "--fields", "amount,status", "--yaml", f".tn/{project}/streams/X.yaml",
    )
    assert add.returncode == 0, f"group add failed: {add.stderr!r}"
    assert "child sets parent-owned key" not in add.stderr, (
        f"`tn group add` tripped the parent-owned-key warning: {add.stderr!r}"
    )

    import yaml as _yaml

    root_doc = _yaml.safe_load((tmp_path / ".tn" / project / "tn.yaml").read_text())
    stream_doc = _yaml.safe_load(stream_yaml.read_text())
    assert "partners" in (root_doc.get("groups") or {}), (
        "`tn group add` did not persist 'partners' in the authoritative "
        "root .tn/<project>/tn.yaml."
    )
    assert "groups" not in stream_doc, (
        "`tn group add` polluted the stream yaml with a parent-owned "
        "groups block."
    )

    # The full repro: a fresh-process add_recipient against the
    # stream-added group succeeds and mints a bundle.
    add_rcpt = _run_cli(
        tmp_path,
        "add_recipient",
        "partners",
        "bob",
        "--yaml",
        f".tn/{project}/streams/X.yaml",
    )
    assert add_rcpt.returncode == 0, (
        f"add_recipient against the stream-added group failed: {add_rcpt.stderr!r}"
    )
    assert (tmp_path / "bob.tnpkg").is_file(), (
        "add_recipient did not mint bob.tnpkg for the stream-added group."
    )
