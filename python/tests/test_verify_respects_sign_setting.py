"""tn.read(verify=True) must respect ceremony.sign=False.

Covers DX review #6: previously, setting ``ceremony.sign: false`` in
yaml produced entries with empty ``signature`` strings (by design).
``tn.read(verify=True)`` then raised
``VerifyError: failed: signature`` on the first entry — the
configuration silently produced logs that could never pass
verification.

Fix surfaces ``ceremony.sign`` on the loaded config and has
``tn.read`` drop the signature check from the reasons list when
the writer chose unsigned emit. Other integrity checks (chain,
row_hash, decrypt) continue to fire.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path


def _setup_unsigned_ceremony(tmp_path: Path, sign_value: bool) -> Path:
    """Init a ceremony, mutate ceremony.sign to the chosen value,
    return the path."""
    init_script = tmp_path / "init.py"
    init_script.write_text(textwrap.dedent("""
        import os, yaml, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.flush_and_close()
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(init_script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr
    yaml_path = tmp_path / ".tn" / tmp_path.name / "tn.yaml"
    import yaml as pyyaml
    doc = pyyaml.safe_load(yaml_path.read_text())
    doc["ceremony"]["sign"] = sign_value
    yaml_path.write_text(pyyaml.safe_dump(doc, sort_keys=False))
    return yaml_path


def _emit_and_read(tmp_path: Path, verify_mode: str) -> dict:
    """Emit one entry then read with the chosen verify= and return
    (events, raised) in a subprocess."""
    script = tmp_path / "use.py"
    script.write_text(textwrap.dedent(f"""
        import os, json
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.info("nosign.evt", x=1)
        tn.flush_and_close()
        try:
            entries = [(e.event_type, bool(getattr(e, 'signature', None) or
                                            (e.fields or {{}}).get('signature')))
                       for e in tn.read(verify={verify_mode})]
            print(json.dumps({{"events": entries, "raised": None}}))
        except Exception as exc:
            print(json.dumps({{
                "events": None,
                "raised": type(exc).__name__ + ': ' + str(exc),
            }}))
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"use.py failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    return json.loads(rc.stdout.decode().strip().splitlines()[-1])


def test_sign_false_verify_true_does_not_raise(tmp_path: Path):
    """The headline fix: sign=False + verify=True must not raise
    VerifyError on every entry."""
    _setup_unsigned_ceremony(tmp_path, sign_value=False)
    result = _emit_and_read(tmp_path, verify_mode="True")
    assert result["raised"] is None, (
        f"verify=True raised on sign:false ceremony: {result['raised']!r}"
    )
    event_types = [et for et, _has_sig in result["events"]]
    assert "nosign.evt" in event_types


def test_sign_false_verify_true_yields_entries(tmp_path: Path):
    """Confirm entries actually come through, not silently swallowed."""
    _setup_unsigned_ceremony(tmp_path, sign_value=False)
    result = _emit_and_read(tmp_path, verify_mode="True")
    assert result["events"], "expected at least one yielded entry"


def test_sign_true_verify_true_still_works(tmp_path: Path):
    """Backwards-compat sanity: signed ceremonies still verify."""
    _setup_unsigned_ceremony(tmp_path, sign_value=True)
    result = _emit_and_read(tmp_path, verify_mode="True")
    assert result["raised"] is None
    assert result["events"]


def test_sign_false_verify_skip_yields_entries(tmp_path: Path):
    """verify='skip' on a sign:false ceremony should yield entries,
    not silently drop them (the signature 'failure' is by design)."""
    _setup_unsigned_ceremony(tmp_path, sign_value=False)
    result = _emit_and_read(tmp_path, verify_mode="'skip'")
    assert result["raised"] is None
    event_types = [et for et, _has_sig in result["events"]]
    assert "nosign.evt" in event_types
