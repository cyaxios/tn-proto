"""Cross-impl golden conformance test for the canonical tn.yaml schema.

Phase 1 of the yaml-identity-ironout (spec:
docs/specs/2026-05-29-tn-yaml-canonical-schema-and-restore-contract.md).

This single test drives all FOUR tn.yaml producers, normalizes volatile
values, and asserts the canonical SHAPE (spec §8.3). It is the RATCHET:
conformant producers PASS, non-conformant producers FAIL. It does NOT
modify any producer code.

The four surfaces (spec §5 Surfaces Inventory):
  1. python_sdk  -- real `tn.cli init GoldenProj --no-link`
  2. ts_sdk_core -- createFreshCeremony from the BUILT dist (node harness)
  3. tn_js_cli   -- `node ts-sdk/bin/tn-js.mjs init GoldenProj --no-link`
  4. browser     -- buildTnYaml from yaml_profile.js (pure node harness)

Each surface is its own pytest parametrize case so the report names the
exact surface that fails and why.

EXPECTED first-run result (spec §6 DRIFT + §8.3):
  python_sdk, ts_sdk_core, tn_js_cli  -> PASS
  browser                              -> FAIL assertion (b): the browser
      producer emits dead top-level `project_id:` and `label:` keys
      (yaml_profile.js:124-125). That red is the bug this ratchet exists
      to catch.

Run:
  .venv/Scripts/python.exe -m pytest tests/golden/test_canonical_conformance.py -v
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
PYTHON = sys.executable
HARNESS = Path(__file__).resolve().parent / "harness"
GOLDEN = Path(__file__).resolve().parent / "canonical_tn.yaml"
PLACEHOLDER_DID = "did:key:z6GOLDENdevicexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

TS_SDK = REPO / "ts-sdk"
TN_JS = TS_SDK / "bin" / "tn-js.mjs"

# Make the in-tree python package importable for the loader leg.
sys.path.insert(0, str(REPO / "python"))


# ---------------------------------------------------------------------------
# Node resolution
# ---------------------------------------------------------------------------

def _node() -> str:
    exe = shutil.which("node")
    if exe is None:  # pragma: no cover - environment guard
        pytest.skip("node not on PATH; cannot drive the JS producers")
    return exe


# ---------------------------------------------------------------------------
# Producers: each returns the raw tn.yaml STRING for a fresh GoldenProj
# ceremony, plus the on-disk yaml Path (or None when the producer is a pure
# string builder with no real keystore, i.e. the browser surface).
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"producer command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def produce_python_sdk() -> tuple[str, Path | None, Path]:
    """Real Python CLI: `tn.cli init GoldenProj --no-link` in a fresh cwd."""
    tmp = Path(tempfile.mkdtemp(prefix="conf_pycli_"))
    _run(
        [PYTHON, "-m", "tn.cli", "init", "GoldenProj",
         "--cipher", "btn", "--no-link", "--words", "12"],
        cwd=tmp,
    )
    yaml_path = tmp / ".tn" / "GoldenProj" / "tn.yaml"
    if not yaml_path.exists():  # pragma: no cover
        raise RuntimeError(f"python CLI did not write {yaml_path}")
    return yaml_path.read_text(encoding="utf-8"), yaml_path, tmp


def produce_ts_sdk_core() -> tuple[str, Path | None, Path]:
    """ts-sdk core createFreshCeremony from the BUILT dist (node harness)."""
    tmp = Path(tempfile.mkdtemp(prefix="conf_tssdk_"))
    out = tmp / "tn.yaml"
    proc = _run([_node(), str(HARNESS / "ts_sdk_core.mjs"), str(out)])
    # The harness writes the yaml AND its keystore into a temp dir of its own;
    # for the loader leg we treat ts_sdk_core like the browser (no co-located
    # keystore here), so flag yaml_path as None -> mint+substitute path.
    text = out.read_text(encoding="utf-8") if out.exists() else proc.stdout
    return text, None, tmp


def produce_tn_js_cli() -> tuple[str, Path | None, Path]:
    """tn-js CLI: `node tn-js.mjs init GoldenProj --no-link` in a fresh cwd."""
    tmp = Path(tempfile.mkdtemp(prefix="conf_tnjs_"))
    _run([_node(), str(TN_JS), "init", "GoldenProj", "--no-link"], cwd=tmp)
    yaml_path = tmp / ".tn" / "GoldenProj" / "tn.yaml"
    if not yaml_path.exists():  # pragma: no cover
        raise RuntimeError(f"tn-js did not write {yaml_path}")
    return yaml_path.read_text(encoding="utf-8"), yaml_path, tmp


def produce_browser() -> tuple[str, Path | None, Path]:
    """Browser buildTnYaml from yaml_profile.js (pure node harness)."""
    tmp = Path(tempfile.mkdtemp(prefix="conf_browser_"))
    proc = _run([_node(), str(HARNESS / "browser_yaml.mjs")])
    return proc.stdout, None, tmp


PRODUCERS = {
    "python_sdk": produce_python_sdk,
    "ts_sdk_core": produce_ts_sdk_core,
    "tn_js_cli": produce_tn_js_cli,
    "browser": produce_browser,
}


# ---------------------------------------------------------------------------
# Normalization (spec §8.3): replace volatile values with stable tokens, then
# compare normalized STRUCTURE (keys + nesting + non-volatile scalars).
# ---------------------------------------------------------------------------

# DID: real producers emit base58 did:key; the golden carries a synthetic
# placeholder (`did:key:z6GOLDENdevice...`) with chars outside base58. Match
# any `did:key:<word>` so BOTH normalize to <DID>.
_DID_RE = re.compile(r"^did:key:\w+$")
_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"  # ISO-8601 timestamp
)
# Ceremony id: real producers emit `local_<hex>`; the golden's placeholder
# (`local_90lde9a1`) is not strict hex. Match `local_<alnum>` for both.
_CID_RE = re.compile(r"^local_[0-9A-Za-z]+$")

# Keys whose VALUE is volatile (path-like / link-like / id-like) and must be
# tokenized regardless of where they appear in the tree.
_PATH_KEYS = {"path", "admin_log_location", "protocol_events_location"}
_LINK_KEYS = {"linked_vault", "linked_project_id"}


def _norm_scalar(key: str | None, value: Any) -> Any:
    if isinstance(value, str):
        if _DID_RE.match(value):
            return "<DID>"
        if _TS_RE.match(value):
            return "<TS>"
        if key in _PATH_KEYS:
            return "<PATH>"
        if key in _LINK_KEYS:
            return "<LINK>"
        if key == "id" and _CID_RE.match(value):
            return "<CID>"
        if key == "project_id":  # browser dead key value is volatile too
            return "<LINK>"
    return value


def _normalize(node: Any, key: str | None = None) -> Any:
    if isinstance(node, dict):
        return {k: _normalize(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [_normalize(item, key) for item in node]
    return _norm_scalar(key, node)


def _parse_norm(text: str) -> dict:
    doc = yaml.safe_load(text)
    assert isinstance(doc, dict), "top-level yaml is not a mapping"
    return _normalize(doc)


# ---------------------------------------------------------------------------
# Loader leg (assertion c): every producer's yaml must load through
# tn.config.load. Producers with a co-located real keystore load in place;
# pure string-builders (browser, ts_sdk_core harness) get the load_check
# treatment -- mint a real keystore, substitute every DID, then load.
# ---------------------------------------------------------------------------

def _loads_in_place(yaml_path: Path) -> None:
    from tn import config as _config

    _config.load(yaml_path)


def _loads_via_mint(text: str) -> None:
    """Mint a real ceremony, swap every did:key:... in `text` for the minted
    DID, drop it over the minted yaml, and load -- IN A SUBPROCESS so the
    module-global `tn` runtime is never shared across surfaces (one tn flow
    per process). Mirrors load_check_canonical.
    """
    proc = subprocess.run(
        [PYTHON, str(HARNESS / "load_via_mint.py")],
        input=text,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0 and "LOADED_OK" in proc.stdout, (
        f"config.load rejected the produced yaml:\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# Conformance assertions (spec §8.3)
# ---------------------------------------------------------------------------

REQUIRED_CEREMONY_KEYS = {"id", "mode", "cipher", "project_name"}
FORBIDDEN_TOP_LEVEL = {"me", "project_id", "label"}
OPTIONAL_KEYS = {"llm_classifier", "handlers"}  # may differ/absent; never fail


def _assert_required_shape(doc: dict, surface: str) -> None:
    # (a) top-level device.device_identity
    assert "device" in doc, f"[{surface}] missing top-level `device` block"
    assert isinstance(doc["device"], dict), f"[{surface}] `device` is not a mapping"
    assert "device_identity" in doc["device"], (
        f"[{surface}] missing `device.device_identity`"
    )

    # (a) groups.<g>.recipients[].recipient_identity
    assert "groups" in doc, f"[{surface}] missing top-level `groups` block"
    groups = doc["groups"]
    assert isinstance(groups, dict) and groups, f"[{surface}] `groups` empty/not a mapping"
    for gname, gbody in groups.items():
        recips = gbody.get("recipients")
        assert recips, f"[{surface}] group {gname!r} has no recipients"
        for entry in recips:
            assert isinstance(entry, dict) and "recipient_identity" in entry, (
                f"[{surface}] group {gname!r} recipient missing `recipient_identity`: {entry!r}"
            )

    # (a) required ceremony.* keys
    assert "ceremony" in doc, f"[{surface}] missing `ceremony` block"
    cer = doc["ceremony"]
    missing = REQUIRED_CEREMONY_KEYS - set(cer)
    assert not missing, f"[{surface}] ceremony missing required keys: {sorted(missing)}"


def _assert_no_forbidden(doc: dict, surface: str) -> None:
    # (b) FORBIDDEN top-level keys absent.
    present = FORBIDDEN_TOP_LEVEL & set(doc)
    offending = {k: doc[k] for k in present}
    assert not present, (
        f"[{surface}] FORBIDDEN top-level keys present: {sorted(present)} "
        f"-> {offending}"
    )


def _assert_matches_golden(doc: dict, golden: dict, surface: str) -> None:
    # (d) required-key shapes match the golden's normalized shape. Compare the
    # device block, the ceremony required keys, and the group/recipient shape.
    # Optional keys (llm_classifier/handlers/public_fields/fields) are NOT
    # required to match -- the two ts-sdk producers legitimately differ there.
    assert doc["device"] == golden["device"], (
        f"[{surface}] device block differs from golden:\n"
        f"  got:    {doc['device']}\n  golden: {golden['device']}"
    )
    for k in REQUIRED_CEREMONY_KEYS:
        assert doc["ceremony"].get(k) == golden["ceremony"].get(k), (
            f"[{surface}] ceremony.{k} differs: "
            f"got {doc['ceremony'].get(k)!r}, golden {golden['ceremony'].get(k)!r}"
        )
    # group/recipient shape: same group names, each with recipient_identity entries.
    assert set(doc["groups"]) == set(golden["groups"]), (
        f"[{surface}] group names differ: got {sorted(doc['groups'])}, "
        f"golden {sorted(golden['groups'])}"
    )
    for gname in golden["groups"]:
        got_recips = [set(r) for r in doc["groups"][gname]["recipients"]]
        golden_recips = [set(r) for r in golden["groups"][gname]["recipients"]]
        assert got_recips == golden_recips, (
            f"[{surface}] group {gname!r} recipient shape differs: "
            f"got {got_recips}, golden {golden_recips}"
        )


# ---------------------------------------------------------------------------
# The parametrized ratchet
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def golden_norm() -> dict:
    return _parse_norm(GOLDEN.read_text(encoding="utf-8"))


@pytest.mark.parametrize("surface", list(PRODUCERS))
def test_canonical_conformance(surface: str, golden_norm: dict) -> None:
    producer = PRODUCERS[surface]
    text, yaml_path, tmp = producer()
    try:
        norm = _parse_norm(text)

        # (a) required canonical shape present
        _assert_required_shape(norm, surface)
        # (b) forbidden keys absent  <-- browser is EXPECTED to fail here
        _assert_no_forbidden(norm, surface)
        # (d) required-key shapes match golden
        _assert_matches_golden(norm, golden_norm, surface)
        # (c) loads through tn.config.load
        if yaml_path is not None:
            _loads_in_place(yaml_path)
        else:
            _loads_via_mint(text)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
