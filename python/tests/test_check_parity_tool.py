"""Tests for tools/check_parity.py, the verb-centric parity gate.

These are the deliverable's own checks: they prove the matrix builder flags a
synthetic one-sided verb as drift, recognizes a both-sides verb as matched,
and that the real tool exits 0 on the current (already-parity) tree with the
proven ``admin.revoked_count`` case showing as matched.

Self-contained: ``tools/check_parity.py`` lives at the repo root and is not a
package, so we load it by file path via importlib. No dependency on the ``tn``
package itself.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

# repo root = python/tests/ -> python/ -> <root>
_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOL_PATH = _ROOT / "tools" / "check_parity.py"


def _load_tool() -> ModuleType:
    name = "_check_parity_under_test"
    spec = importlib.util.spec_from_file_location(name, _TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: the module defines frozen dataclasses with string
    # annotations, and dataclasses resolves field types via
    # sys.modules[cls.__module__]. Without this, that lookup returns None.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cp = _load_tool()


# --------------------------------------------------------------------------
# canon() folding: the cross-language matching primitive.
# --------------------------------------------------------------------------


def test_canon_folds_camel_and_snake_to_same_key():
    assert cp.canon("revokedCount") == "revoked_count"
    assert cp.canon("revoked_count") == "revoked_count"
    # camelCase verb and snake_case verb collapse to one key -> they match.
    assert cp.canon("addRecipient") == cp.canon("add_recipient")
    assert cp.canon("listCeremonies") == cp.canon("list_ceremonies")


def test_qualify_namespaces_the_canonical_verb():
    assert cp.qualify("admin", "revokedCount") == "admin.revoked_count"
    assert cp.qualify(None, "setLevel") == "set_level"


# --------------------------------------------------------------------------
# Core logic: a synthetic one-sided verb is drift; a both-sides verb is ok.
# --------------------------------------------------------------------------


def _classify(surfaces, documented=None, allowlist=None):
    """Build a matrix from synthetic surface sets and classify it."""
    matrix = cp.build_matrix(surfaces)
    matched, allowed, drift = cp.classify(
        matrix,
        documented=set(documented or ()),
        allowlist=dict(allowlist or {}),
    )
    return matrix, matched, allowed, drift


def test_synthetic_one_sided_verb_is_flagged_as_drift():
    # ``ghostVerb`` exists ONLY on a TS surface, is not documented, and is
    # not allowlisted -> it must be reported as undocumented drift.
    surfaces = {
        "py_module": set(),
        "py_namespace": set(),
        "ts_module": set(),
        "ts_instance": {"ghost_verb"},
        "ts_namespace": set(),
    }
    matrix, matched, allowed, drift = _classify(surfaces)

    drift_verbs = {d.verb for d in drift}
    assert "ghost_verb" in drift_verbs, "one-sided verb must be flagged"
    assert matched == []
    assert allowed == []

    # The matrix row itself records the one-sided reality: present on a TS
    # surface only, never matched.
    ghost_row = matrix["ghost_verb"]
    assert ghost_row.matched is False
    assert ghost_row.one_sided is True
    assert ghost_row.lone_side == "ts"

    # And the run()-shaped contract: a drift makes the exit code non-zero.
    ghost = next(d for d in drift if d.verb == "ghost_verb")
    assert ghost.side == "ts"
    assert "ts_instance" in ghost.present_surfaces


def test_synthetic_both_sides_verb_is_matched_not_drift():
    # ``pairVerb`` appears on a Python surface AND a TS surface -> matched,
    # regardless of which specific surface within each language.
    surfaces = {
        "py_module": set(),
        "py_namespace": {"admin.pair_verb"},
        "ts_module": set(),
        "ts_instance": set(),
        "ts_namespace": {"admin.pair_verb"},
    }
    matrix, matched, allowed, drift = _classify(surfaces)

    assert drift == [], "a both-sides verb must not be drift"
    # A both-sides verb is matched, so it is neither drift nor one-sided/allowed.
    assert allowed == [], "a matched verb must not be on the one-sided list"
    matched_verbs = {r.verb for r in matched}
    assert "admin.pair_verb" in matched_verbs
    assert matrix["admin.pair_verb"].matched is True
    assert matrix["admin.pair_verb"].one_sided is False


def test_one_sided_verb_is_allowed_when_documented():
    surfaces = {
        "py_module": {"py_only_verb"},
        "py_namespace": set(),
        "ts_module": set(),
        "ts_instance": set(),
        "ts_namespace": set(),
    }
    # Documented in the parity doc -> allowed, not drift.
    _matrix, _matched, allowed, drift = _classify(
        surfaces, documented={"py_only_verb"}
    )
    assert drift == []
    assert {r.verb for r in allowed} == {"py_only_verb"}


def test_one_sided_verb_is_allowed_when_allowlisted_with_reason():
    surfaces = {
        "py_module": set(),
        "py_namespace": set(),
        "ts_module": {"ts_only_verb"},
        "ts_instance": set(),
        "ts_namespace": set(),
    }
    allow = {"ts_only_verb": cp.Allow("intentional TS-only helper", side="ts")}
    _matrix, _matched, allowed, drift = _classify(surfaces, allowlist=allow)
    assert drift == []
    assert {r.verb for r in allowed} == {"ts_only_verb"}


def test_both_sides_verb_ignores_allowlist_and_doc():
    # Even with no doc/allowlist entry, both-sides verbs are matched.
    surfaces = {
        "py_module": {"both_verb"},
        "py_namespace": set(),
        "ts_module": {"both_verb"},
        "ts_instance": set(),
        "ts_namespace": set(),
    }
    _matrix, matched, _allowed, drift = _classify(surfaces)
    assert drift == []
    assert {r.verb for r in matched} == {"both_verb"}


# --------------------------------------------------------------------------
# Throw-stub detection: a stub body is NOT a real implementation.
# --------------------------------------------------------------------------


def test_is_throw_stub_body_recognizes_single_throw():
    # One-liner NotYetWired throw, and the multi-line throw new Error(...) shape.
    assert cp._is_throw_stub_body('throw new NotYetWiredForBrowserError("use");')
    assert cp._is_throw_stub_body(
        "\n  throw new Error(\n    `not yet ported`,\n  );\n"
    )
    assert cp._is_throw_stub_body("throw err")  # bare throw, no semicolon


def test_is_throw_stub_body_rejects_real_bodies():
    # A body that does real work (even if it also throws conditionally) is real.
    assert not cp._is_throw_stub_body("return this._rt.read();")
    assert not cp._is_throw_stub_body(
        "if (x) { throw new Error('bad'); }\n  return ok;"
    )
    assert not cp._is_throw_stub_body("")
    # A real statement followed by a throw is not a pure stub.
    assert not cp._is_throw_stub_body("const x = 1;\n  throw new Error('no');")


def test_throw_stub_only_ts_verb_is_not_matched_but_flagged():
    # ``stubVerb`` is REAL on Python but only a throw-stub on a TS surface.
    # It must NOT be matched (a throw is not an implementation) and, absent an
    # allowlist/doc entry, must be reported as drift -- a stub gap, not parity.
    real = {
        "py_module": {"stub_verb"},
        "py_namespace": set(),
        "ts_module": set(),
        "ts_instance": set(),
        "ts_namespace": set(),
        "ts_browser": set(),
    }
    stubs = {"ts_browser": {"stub_verb"}}
    matrix = cp.build_matrix(real, stubs)
    row = matrix["stub_verb"]
    assert row.present["ts_browser"] is False
    assert row.stub["ts_browser"] is True
    assert row.ts_side is False, "a throw-stub is not a real TS side"
    assert row.matched is False, "stub-only TS presence must not count as parity"
    assert row.status == "stub"

    _matched, _allowed, drift = cp.classify(matrix, documented=set(), allowlist={})
    drift_verbs = {d.verb for d in drift}
    assert "stub_verb" in drift_verbs, "an un-allowlisted stub gap must be drift"
    d = next(x for x in drift if x.verb == "stub_verb")
    assert d.is_stub_gap is True
    assert "ts_browser" in d.stub_surfaces

    # Allowlisting (or documenting) the stub gap clears the drift.
    _m2, allowed2, drift2 = cp.classify(
        matrix, documented=set(), allowlist={"stub_verb": cp.Allow("known stub", side="ts")}
    )
    assert drift2 == []
    assert {r.verb for r in allowed2} == {"stub_verb"}


def test_matched_verb_with_browser_stub_keeps_parity_but_is_annotated():
    # Real on py + node-ts, throw-stub in the browser: still matched (parity is
    # Node/Python), but the browser-stub reality is annotated, not hidden.
    real = {
        "py_namespace": {"admin.add_recipient"},
        "ts_namespace": {"admin.add_recipient"},
    }
    stubs = {"ts_browser": {"admin.add_recipient"}}
    matrix = cp.build_matrix(real, stubs)
    row = matrix["admin.add_recipient"]
    assert row.matched is True
    assert row.browser_stub is True
    assert row.status == "match*browser-stub"


# --------------------------------------------------------------------------
# Real-tree integration: exits 0, and the proven revoked_count case matches.
# --------------------------------------------------------------------------


def test_real_tree_has_no_drift():
    code, matrix, _documented, _allowlist, drift = cp.run()
    assert code == 0, f"unexpected drift: {[d.verb for d in drift]}"
    assert drift == []
    # The real tree actually produced a populated matrix (not an empty parse
    # that trivially has no drift), and the proven case is matched on it.
    assert matrix, "real-tree matrix must not be empty"
    assert matrix["admin.revoked_count"].matched is True


# --------------------------------------------------------------------------
# Browser surface: the new ts_browser column is parsed and honest.
# --------------------------------------------------------------------------


def test_browser_surface_is_parsed_as_a_distinct_column():
    # Finding 1: ts_browser is a real column, and a wired browser verb (read)
    # registers as a real impl there (not a stub).
    assert "ts_browser" in cp.SURFACES
    assert "ts_browser" in cp.TS_SURFACES
    _code, matrix, _documented, _allowlist, _drift = cp.run()
    row = matrix.get("read")
    assert row is not None
    assert row.present["ts_browser"] is True
    assert row.stub["ts_browser"] is False


def test_browser_namespace_tier_is_detected_as_throw_stub():
    # Finding 2: the browser admin/pkg/vault/agents/handlers tier throws
    # NotYetWiredForBrowserError. Those verbs must register as stubs on
    # ts_browser, never as real implementations.
    _code, matrix, _documented, _allowlist, _drift = cp.run()
    for verb in (
        "admin.add_recipient",
        "admin.revoke_recipient",
        "vault.link",
        "vault.unlink",
        "pkg.absorb",
        "pkg.export",
    ):
        row = matrix[verb]
        assert row.stub["ts_browser"] is True, f"{verb} browser side must be a stub"
        assert row.present["ts_browser"] is False, f"{verb} browser side is not real"
        # Real on Node + Python, so parity holds, annotated as browser-stub.
        assert row.matched is True
        assert row.browser_stub is True
        assert row.status == "match*browser-stub"


def test_browser_class_throw_stub_methods_are_stubs_not_real():
    # The browser Tn class statics use/absorb/ephemeral/listCeremonies and the
    # watch method are throw-stubs; they must not be counted as real on the
    # browser surface (they remain matched via the real Node/Python sides).
    real, stub = cp.ts_class_methods_split(
        cp.TS_TN_CLASS_BROWSER, r"class\s+Tn\b"
    )
    for name in ("use", "absorb", "ephemeral", "listCeremonies", "watch"):
        assert name in stub, f"{name} should be a detected throw-stub"
        assert name not in real
    # And genuinely-wired methods are real.
    for name in ("info", "read", "close", "did"):
        assert name in real
        assert name not in stub


def test_node_vault_set_link_state_is_implemented_not_a_stub():
    # Gap #3 (docs/round-trip-gaps.md): ts-sdk/src/vault/index.ts setLinkState
    # used to throw "not yet ported"; it now writes ceremony.mode to the
    # authoritative yaml (NodeRuntime.setCeremonyMode), so it is a REAL TS impl,
    # not a throw-stub. The verb is one-sided ts-only because Python keeps the
    # same intent under tn.admin.set_link_state (the namespace asymmetry is
    # carried by the allowlist + the parity-doc tn.admin row).
    real, stub = cp.ts_class_methods_split(
        cp.TS_NAMESPACE_CLASSES["vault"][0], cp.TS_NAMESPACE_CLASSES["vault"][1]
    )
    assert "setLinkState" in real
    assert "setLinkState" not in stub
    assert "link" in real and "unlink" in real

    _code, matrix, _documented, _allowlist, _drift = cp.run()
    row = matrix["vault.set_link_state"]
    assert row.present["ts_namespace"] is True
    assert row.stub["ts_namespace"] is False
    assert row.ts_side is True
    assert row.status == "ts-only"


def test_browser_stub_verbs_are_allowlisted_so_gate_passes():
    # Exit 0 is preserved: every browser stub / browser-only / TS-gap surface
    # is either documented or allowlisted with a reason. (Guards finding 5.)
    code, matrix, documented, allowlist, drift = cp.run()
    assert code == 0
    assert drift == [], f"gate must pass with no drift, got: {[d.verb for d in drift]}"
    # The pure browser-stub placeholders (no real impl) are explicitly allowed.
    for verb in ("admin.cached_admin_state", "agents.load_policy", "handlers.remove"):
        row = matrix[verb]
        assert row.status == "stub"
        assert verb in allowlist or verb in documented


def test_revoked_count_is_matched_on_both_sides():
    # The proven miss from Finding 5: revoked_count (py admin) / revokedCount
    # (ts admin) are public on BOTH sides. The deepened matrix must see both
    # and mark the verb matched (parity), not drift.
    _code, matrix, _documented, _allowlist, _drift = cp.run()
    row = matrix.get("admin.revoked_count")
    assert row is not None, "admin.revoked_count must appear in the matrix"
    assert row.present["py_namespace"] is True
    assert row.present["ts_namespace"] is True
    assert row.matched is True


def test_core_namespace_verbs_are_matched():
    # A sample of verbs that exist on both languages must be matched. Guards
    # against the tool being weakened so it stops seeing namespace surfaces.
    _code, matrix, _documented, _allowlist, _drift = cp.run()
    for verb in (
        "admin.add_recipient",
        "admin.revoke_recipient",
        "admin.rotate",
        "admin.state",
        "pkg.export",
        "pkg.absorb",
        "vault.link",
        "vault.unlink",
        "read",
        "watch",
        "info",
    ):
        assert verb in matrix, f"{verb} missing from matrix"
        assert matrix[verb].matched is True, f"{verb} should be matched"


# --------------------------------------------------------------------------
# Allowlist entries carry real reasons (no empty placeholders).
# --------------------------------------------------------------------------


def test_allowlist_entries_have_nonempty_reasons():
    allowlist = cp.build_allowlist()
    assert allowlist, "allowlist should not be empty"
    for verb, allow in allowlist.items():
        assert isinstance(allow, cp.Allow)
        assert allow.reason.strip(), f"allowlist entry {verb!r} has an empty reason"


def test_genuine_gap_entries_have_specific_nongeneric_reasons():
    # Finding 4: the four real Python-only TS gaps must NOT be silenced by the
    # generic legacy catch-all reason. Each carries a specific reason, is
    # flagged as a genuine gap, and is no longer folded under _LEGACY_REASON.
    allowlist = cp.build_allowlist()
    for verb in ("wallet", "vault_client", "classifier", "is_keystore_diverged"):
        assert verb in allowlist, f"{verb} must be in the allowlist"
        allow = allowlist[verb]
        assert allow.reason != cp._LEGACY_REASON, (
            f"{verb} must have a specific reason, not the generic legacy one"
        )
        assert allow.reason != cp._BROWSER_ONLY_REASON, (
            f"{verb} is a Python-only gap, not browser plumbing"
        )
        assert allow.gap is True, f"{verb} must be flagged as a genuine TS gap"
        # The specific reason names it as un-ported future work.
        assert "no TS port" in allow.reason or "TypeScript counterpart" in allow.reason

    # And they are NOT in the legacy name list any more (would re-bury them).
    legacy_canon = {cp.canon(n) for n in cp._LEGACY_OMISSION_NAMES}
    for verb in ("wallet", "vault_client", "classifier"):
        assert verb not in legacy_canon, (
            f"{verb} must be split OUT of the legacy catch-all"
        )


def test_genuine_one_sided_verbs_are_in_allowlist():
    # The hand-curated one-sided verbs (real reasons) must be present.
    allowlist = cp.build_allowlist()
    for verb in (
        "admin.add_agent_runtime",
        "agents.add_runtime",
        "pkg.compile_enrolment",
        "pkg.offer",
        "vault.set_link_state",
        "handlers.list",
        "handlers.flush",
    ):
        assert verb in allowlist, f"{verb} should be allowlisted with a reason"


# --------------------------------------------------------------------------
# CLI surface: default exit 0, --matrix prints a table, --json is valid JSON.
# --------------------------------------------------------------------------


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, str(_TOOL_PATH), *args],
        capture_output=True,
        text=True,
        cwd=str(_ROOT),
    )


def test_cli_default_exits_zero_and_prints_ok():
    proc = _run_cli()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "parity: ok" in proc.stdout


def test_cli_default_summary_surfaces_browser_stub_and_ts_gaps():
    # Finding 5: exit 0 is kept, but the summary must SHOW the browser-stub
    # reality and the genuine TS gaps explicitly (not a flat "ok").
    proc = _run_cli()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    # Browser throw-stub reality is named.
    assert "browser surface is a throw-stub" in out
    assert "NotYetWiredForBrowserError" in out
    # The browser stub-namespace placeholders (no real impl on ANY surface) are
    # surfaced as TS-stub-only. vault.set_link_state is NO LONGER here: it is a
    # real node impl now (see test_node_vault_set_link_state_is_implemented...).
    assert "TS exposes ONLY a throw-stub" in out
    for verb in ("admin.cached_admin_state", "agents.load_policy", "handlers.remove"):
        assert verb in out, f"{verb} browser stub-only must be shown in the summary"
    # The genuine Python-only TS gaps are named with their specific reasons.
    assert "no TS port yet" in out
    for verb in ("wallet", "vault_client", "classifier", "is_keystore_diverged"):
        assert verb in out, f"{verb} TS gap must be shown in the summary"


def test_cli_matrix_flag_prints_table():
    proc = _run_cli("--matrix")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Header (incl. the new browser column) + the proven row are present.
    assert "py_module" in proc.stdout
    assert "ts_namespace" in proc.stdout
    assert "ts_browser" in proc.stdout
    assert "admin.revoked_count" in proc.stdout
    # The matrix legend explains the stub glyph.
    assert "throw-stub" in proc.stdout


def test_cli_matrix_shows_browser_stub_and_stub_rows():
    # Finding 5: --matrix must reveal browser-stub + stub-gap rows, with the
    # honest statuses, rather than a uniform "match".
    proc = _run_cli("--matrix")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = {
        ln.split()[0]: ln
        for ln in proc.stdout.splitlines()
        if ln and not ln.startswith(("verb", "-", "legend"))
    }
    # A matched verb whose browser side is a throw-stub: status annotated.
    assert "match*browser-stub" in lines["admin.add_recipient"]
    assert "~" in lines["admin.add_recipient"]  # browser cell shows the stub glyph
    # A genuine browser stub-only placeholder row still reads "stub".
    assert lines["admin.cached_admin_state"].split()[-1] == "stub"
    # The node vault.setLinkState row now reads "ts-only" (real TS impl; Python
    # keeps the verb under tn.admin), not "stub".
    assert lines["vault.set_link_state"].split()[-1] == "ts-only"


def test_cli_json_flag_emits_valid_matrix_json():
    proc = _run_cli("--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    by_verb = {e["verb"]: e for e in payload}
    assert "admin.revoked_count" in by_verb
    rc = by_verb["admin.revoked_count"]
    assert rc["matched"] is True
    assert rc["surfaces"]["py_namespace"] is True
    assert rc["surfaces"]["ts_namespace"] is True


def test_cli_json_carries_stub_and_browser_stub_fields():
    # The JSON view must expose the new honesty fields so downstream tooling
    # can see throw-stub status, not just real presence.
    proc = _run_cli("--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    by_verb = {e["verb"]: e for e in json.loads(proc.stdout)}

    # A matched verb that is a browser throw-stub.
    ar = by_verb["admin.add_recipient"]
    assert ar["matched"] is True
    assert ar["browser_stub"] is True
    assert ar["stubs"]["ts_browser"] is True
    assert ar["surfaces"]["ts_browser"] is False
    assert ar["status"] == "match*browser-stub"

    # A genuine browser stub-only placeholder: throw-stub on ts_browser with no
    # real impl on any surface.
    cas = by_verb["admin.cached_admin_state"]
    assert cas["matched"] is False
    assert cas["stubs"]["ts_browser"] is True
    assert cas["surfaces"]["ts_browser"] is False
    assert cas["status"] == "stub"

    # The node vault.setLinkState verb is now a REAL TS impl (one-sided ts-only;
    # Python keeps it under tn.admin.set_link_state), no longer a throw-stub.
    vs = by_verb["vault.set_link_state"]
    assert vs["matched"] is False
    assert vs["stubs"]["ts_namespace"] is False
    assert vs["surfaces"]["ts_namespace"] is True
    assert vs["status"] == "ts-only"
