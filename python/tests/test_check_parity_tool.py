from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECK_PARITY = ROOT / "tools" / "check_parity.py"


def _load_check_parity():
    spec = importlib.util.spec_from_file_location("check_parity_tool", CHECK_PARITY)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_ts_tn_class_members_include_public_methods_and_properties():
    parity = _load_check_parity()

    members = parity.ts_tn_class_members()

    assert members["static_methods"] >= {
        "init",
        "use",
        "openCeremony",
        "listCeremonies",
        "setLevel",
        "getLevel",
        "isEnabledFor",
        "setSigning",
        "setStrict",
        "clearStrict",
        "isStrict",
        "absorb",
    }
    assert members["instance_methods"] >= {
        "config",
        "usingRust",
        "initUpload",
        "close",
        "scope",
        "setContext",
        "updateContext",
        "clearContext",
        "getContext",
        "log",
        "debug",
        "info",
        "warning",
        "error",
        "emit",
        "emitWith",
        "emitOverrideSign",
        "emitWithOverrideSign",
        "read",
        "watch",
    }
    assert members["properties"] >= {
        "admin",
        "pkg",
        "vault",
        "agents",
        "handlers",
        "lastAbsorbReceipt",
        "did",
        "logPath",
        "yamlPath",
        "name",
        "isDefault",
    }
    assert "_hasReplaySurface" not in members["instance_methods"]
    assert "_emitTamperedRowSkipped" not in members["instance_methods"]
    assert "_rt" not in members["properties"]


def test_ts_namespace_methods_include_public_namespace_methods_only():
    parity = _load_check_parity()

    namespaces = parity.ts_namespace_methods()

    assert namespaces["admin"] >= {
        "addRecipient",
        "revokeRecipient",
        "rotate",
        "ensureGroup",
        "recipients",
        "state",
        "cache",
        "revokedCount",
    }
    assert "_resolveLeafForDid" not in namespaces["admin"]
    assert namespaces["pkg"] >= {
        "export",
        "absorb",
        "bundleForRecipient",
        "compileEnrolment",
        "offer",
    }
    assert namespaces["vault"] >= {"link", "unlink", "setLinkState"}
    assert namespaces["agents"] >= {"addRuntime", "policy", "reloadPolicy"}
    assert namespaces["handlers"] >= {"add", "list", "flush"}


def test_surface_matrix_uses_qualified_doc_matches_for_namespace_methods():
    parity = _load_check_parity()

    documented = {"tn.admin.addRecipient"}
    rows = {
        row.qualified: row
        for row in parity.surface_matrix_rows(documented=documented, omissions=set())
    }

    assert rows["tn.admin.addRecipient"].documented is True
    assert rows["tn.admin.revokedCount"].documented is False
