"""Portable signed package format (.tnpkg) — bilateral lifecycle artifact.

A package is the on-the-wire unit that publishers and recipients exchange
to stay in sync about group state. Signed, idempotent to absorb, opaque
to transports (filesystem, wallet, QR). Covers both JWE and bearer (BGW)
lifecycles — the cipher kind lives in the payload, not the envelope.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass
class Package:
    package_version: int
    package_kind: str
    # JWE kinds: "enrolment" | "offer" | "rotation" | "key_update"
    # Bearer kinds: "bearer_coupon" | "bearer_rotation"
    # Shared: "revocation_notice"
    ceremony_id: str
    group: str
    group_epoch: int
    signer_did: str
    signer_verify_pub_b64: str
    peer_did: str | None
    payload: dict[str, Any]
    compiled_at: str
    sig_b64: str | None = None


def _canonical_bytes(pkg: Package) -> bytes:
    """Deterministic serialization over every field EXCEPT sig_b64."""
    d = asdict(pkg)
    d.pop("sig_b64", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(pkg: Package, sk: Ed25519PrivateKey) -> Package:
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pkg.signer_verify_pub_b64 = base64.b64encode(pub).decode("ascii")
    pkg.sig_b64 = base64.b64encode(sk.sign(_canonical_bytes(pkg))).decode("ascii")
    return pkg


def verify(pkg: Package) -> bool:
    if not pkg.sig_b64 or not pkg.signer_verify_pub_b64:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pkg.signer_verify_pub_b64))
        pub.verify(base64.b64decode(pkg.sig_b64), _canonical_bytes(pkg))
        return True
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        return False


def dump_tnpkg(pkg: Package, path: Path) -> None:
    """Write `pkg` to ``path`` as a `.tnpkg`.

    Back-compat shim: callers that pre-date the universal manifest still
    treat the file as a flat JSON Package. We keep that wire format for
    now (the tests serialize / mutate the file directly to test signature
    rejection) while ``tn.export(kind=...)`` is the new producer entry
    that emits the wrapped form. Once external consumers migrate this
    function will switch to ``tn.export``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(pkg), sort_keys=True, indent=2),
        encoding="utf-8",
    )


def load_tnpkg(path: Path) -> Package:
    """Load a Package written by ``dump_tnpkg``.

    Falls through to the new universal `.tnpkg` shape: if the file is a
    zip with ``manifest.json`` + ``body/package.json``, parse the body as
    the Package. This way callers can hand either format to ``load_tnpkg``
    and get the same Package back.
    """
    p = Path(path)
    raw = p.read_bytes()
    if raw[:4] == b"PK\x03\x04":
        # New wrapped form. Body holds the canonical Package json.
        from .tnpkg import _read_manifest

        _manifest, body = _read_manifest(p)
        body_bytes = body.get("body/package.json")
        if body_bytes is None:
            raise ValueError(f"{p}: zipped `.tnpkg` missing body/package.json")
        return Package(**json.loads(body_bytes.decode("utf-8")))
    return Package(**json.loads(raw.decode("utf-8")))
