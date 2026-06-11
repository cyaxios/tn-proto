"""Generate the shared cross-language absorb vault-metadata-adoption golden.

Outputs tests/fixtures/absorb/vault_adoption_cases.json (repo root),
consumed identically by:

  * Python: python/tests/test_absorb_vault_adoption_contract.py
  * TS:     ts-sdk/test/absorb_vault_adoption_contract.test.ts

It pins the additive root-authority rule from docs/spec-next/absorb.md:
when a project_seed is absorbed over an existing project YAML, vault
metadata is filled only where the local value is empty, never
overwritten, and `enabled: false` blocks adoption entirely.

The two implementations serialize YAML differently
(`yaml.safe_dump` vs the TS `yaml` package), so the golden records the
SEMANTIC outcome (did it change? vault_only? resulting vault/ceremony
values), not raw patched bytes. Each side runs its own
`_project_seed_vault_yaml_patch` / `_projectSeedVaultYamlPatch`, parses
the patched YAML, and asserts these parsed values match.

Expected outcomes are computed from the Python reference. Never
hand-edit; regenerate after any change to the adoption rule:

    source .venv_linux/bin/activate
    python python/tools/generate_absorb_vault_adoption_fixture.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PYDIR = ROOT / "python"
sys.path.insert(0, str(PYDIR))

import yaml as _yaml  # noqa: E402

from tn.absorb import _project_seed_vault_yaml_patch  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "absorb" / "vault_adoption_cases.json"


def _doc(vault: dict | None, *, ceremony_extra: dict | None = None) -> str:
    """Build a representative project root YAML with a fixed identity and
    an optional vault block."""
    doc: dict = {
        "device": {"device_identity": "did:key:zProjectRoot"},
        "keystore": {"path": "./.tn/default/keys"},
        "ceremony": {"id": "ceremony-abc", **(ceremony_extra or {})},
    }
    if vault is not None:
        doc["vault"] = vault
    return _yaml.safe_dump(doc, sort_keys=False)


_FULL_INCOMING = {
    "enabled": True,
    "url": "https://vault.tn-proto.org",
    "linked_project_id": "proj-remote-123",
    "autosync": True,
    "sync_interval_seconds": 600,
}

CASES = [
    {
        "name": "empty_local_vault_adopts_both",
        "existing": _doc({"enabled": True, "url": "", "linked_project_id": "",
                          "autosync": True, "sync_interval_seconds": 600}),
        "incoming": _doc(_FULL_INCOMING),
    },
    {
        "name": "nonempty_local_vault_not_overwritten",
        "existing": _doc({"enabled": True, "url": "https://my.vault",
                          "linked_project_id": "local-pid",
                          "autosync": True, "sync_interval_seconds": 600}),
        "incoming": _doc(_FULL_INCOMING),
    },
    {
        "name": "disabled_local_vault_blocks_adoption",
        "existing": _doc({"enabled": False, "url": "", "linked_project_id": ""}),
        "incoming": _doc(_FULL_INCOMING),
    },
    {
        "name": "partial_adopt_only_empty_field",
        "existing": _doc({"enabled": True, "url": "https://my.vault",
                          "linked_project_id": "",
                          "autosync": True, "sync_interval_seconds": 600}),
        "incoming": _doc(_FULL_INCOMING),
    },
    {
        "name": "no_local_vault_block_no_adoption",
        "existing": _doc(None),
        "incoming": _doc(_FULL_INCOMING),
    },
]


def _result_view(patched: bytes | None, existing: str) -> dict | None:
    """Parse the effective YAML (patched if present, else existing) and
    extract the serializer-independent fields consumers assert on."""
    text = patched.decode("utf-8") if patched is not None else existing
    doc = _yaml.safe_load(text) or {}
    vault = doc.get("vault") if isinstance(doc, dict) else None
    ceremony = doc.get("ceremony") if isinstance(doc, dict) else None
    if not isinstance(vault, dict):
        return None
    return {
        "url": vault.get("url", ""),
        "linked_project_id": vault.get("linked_project_id", ""),
        "enabled": vault.get("enabled"),
        "autosync": vault.get("autosync"),
        "sync_interval_seconds": vault.get("sync_interval_seconds"),
        "ceremony_linked_vault": (ceremony or {}).get("linked_vault", "")
        if isinstance(ceremony, dict) else "",
        "ceremony_linked_project_id": (ceremony or {}).get("linked_project_id", "")
        if isinstance(ceremony, dict) else "",
    }


def main() -> None:
    out_cases = []
    for case in CASES:
        patched, vault_only = _project_seed_vault_yaml_patch(
            case["existing"].encode("utf-8"),
            case["incoming"].encode("utf-8"),
        )
        out_cases.append({
            "name": case["name"],
            "existing_yaml": case["existing"],
            "incoming_yaml": case["incoming"],
            "expected": {
                "changed": patched is not None,
                "vault_only": vault_only,
                "result": _result_view(patched, case["existing"]),
            },
        })

    fixture = {
        "_doc": (
            "Generated by python/tools/generate_absorb_vault_adoption_fixture.py. "
            "Each consumer runs its own project-seed vault-adoption patch over "
            "(existing_yaml, incoming_yaml) and asserts changed/vault_only plus the "
            "parsed result fields match `expected`. Never hand-edit."
        ),
        "cases": out_cases,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(out_cases)} cases)")


if __name__ == "__main__":
    main()
