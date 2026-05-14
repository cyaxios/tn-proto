"""Persona registry — Alice, Frank, Bob, Carol, …

Personas are characters who thread through regression silos. Their
identities (DID seed, passphrase) are stable across runs so the same
Alice in C5 can be referenced in C7 without re-minting keys.

Stable identity matters for two reasons:

- **Cross-silo references work.** A future walk-tier test can say
  "Frank from C7 absorbs Alice's invite" and the identities line up
  because both silos draw from the same registry.
- **Flake reduction.** Tests don't generate keys with the OS RNG;
  same seed in → same DID out, every CI run.

The yaml shape is intentionally small — name, seed, passphrase, role
note. Tests derive Did/keys on demand from the seed.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import yaml


_PERSONAS_DIR = Path(__file__).resolve().parent / "personas"


@dataclasses.dataclass(frozen=True)
class Persona:
    name: str
    role: str
    device_seed_hex: str
    passphrase: str
    notes: str

    @property
    def device_seed_bytes(self) -> bytes:
        return bytes.fromhex(self.device_seed_hex)


def load_persona(name: str) -> Persona:
    """Load a persona by name. Raises `FileNotFoundError` with a
    clear message if the persona isn't in the registry.

    Args:
        name: lowercase persona id (`"alice"`, `"frank"`, …). Matches
            the yaml filename without extension.
    """
    path = _PERSONAS_DIR / f"{name}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in _PERSONAS_DIR.glob("*.yaml"))
        raise FileNotFoundError(
            f"persona {name!r} not found at {path}. "
            f"Available: {available}. "
            f"Add a new persona by creating regression/_shared/personas/{name}.yaml."
        )

    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise ValueError(f"persona {name}: yaml root must be a mapping, got {type(doc).__name__}")

    return _from_dict(name, doc)


def list_personas() -> list[str]:
    """Names of every persona currently registered."""
    return sorted(p.stem for p in _PERSONAS_DIR.glob("*.yaml"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _from_dict(name: str, doc: dict[str, Any]) -> Persona:
    required = ("role", "device_seed_hex", "passphrase")
    missing = [k for k in required if k not in doc]
    if missing:
        raise ValueError(f"persona {name}: missing required keys {missing}")

    seed_hex = str(doc["device_seed_hex"]).strip().lower()
    if len(seed_hex) != 64 or not all(c in "0123456789abcdef" for c in seed_hex):
        raise ValueError(
            f"persona {name}: device_seed_hex must be exactly 64 hex chars "
            f"(32 bytes); got {len(seed_hex)} chars"
        )

    return Persona(
        name=name,
        role=str(doc["role"]),
        device_seed_hex=seed_hex,
        passphrase=str(doc["passphrase"]),
        notes=str(doc.get("notes", "")).strip(),
    )
