"""Tests for the cipher-agnostic unified admin API.

Proves that tn.admin.add_recipient / revoke_recipient / rotate dispatch
to the right cipher-specific implementation based on the group's cipher,
returning a structured AddRecipientResult / RevokeRecipientResult / RotateGroupResult.
"""
from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import tn
from tn.config import load_or_create


def _fresh_x25519_pub() -> bytes:
    """Generate a real 32-byte X25519 public key — the JWE cipher rejects
    low-order points (e.g. b'\\x00' * 32) at recipient-add time."""
    from cryptography.hazmat.primitives import serialization

    sk = X25519PrivateKey.generate()
    pub = sk.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_add_recipient_btn_returns_leaf_index(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    result = tn.admin.add_recipient(
        "default",
        recipient_did="did:key:zAlice",
        out_path=out,
    )
    assert out.exists(), "kit file must be written"
    assert result.leaf_index is not None and isinstance(result.leaf_index, int)
    assert result.kit_path == out
    assert result.updated_cfg is None  # btn doesn't return cfg


def test_add_recipient_jwe_returns_updated_cfg(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    pub = _fresh_x25519_pub()
    result = tn.admin.add_recipient(
        "default",
        recipient_did="did:key:zBob",
        public_key=pub,
        cfg=cfg,
    )
    assert result.updated_cfg is not None
    assert result.leaf_index is None
    assert result.kit_path is None


def test_add_recipient_btn_rejects_jwe_kwargs(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    with pytest.raises(ValueError, match=r"public_key.*JWE-only"):
        tn.admin.add_recipient(
            "default",
            recipient_did="did:key:zAlice",
            out_path=out,
            public_key=b"\x00" * 32,
        )


def test_add_recipient_jwe_rejects_btn_kwargs(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    out = tmp_path / "ignored.btn.mykit"
    with pytest.raises(ValueError, match=r"out_path.*btn-only"):
        tn.admin.add_recipient(
            "default",
            recipient_did="did:key:zBob",
            out_path=out,
            public_key=b"\x00" * 32,
            cfg=cfg,
        )


def test_revoke_recipient_btn_uses_leaf_index(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    add = tn.admin.add_recipient(
        "default",
        recipient_did="did:key:zAlice",
        out_path=out,
    )
    leaf = add.leaf_index
    result = tn.admin.revoke_recipient("default", leaf_index=leaf)
    assert result.revoked is True


def test_revoke_recipient_jwe_uses_recipient_did(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    cfg = tn.admin.add_recipient(
        "default",
        recipient_did="did:key:zBob",
        public_key=_fresh_x25519_pub(),
        cfg=cfg,
    ).updated_cfg
    result = tn.admin.revoke_recipient(
        "default", recipient_did="did:key:zBob", cfg=cfg,
    )
    assert result.revoked is True


def test_rotate_btn(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    result = tn.admin.rotate("default")
    assert result.cipher == "btn"
    assert result.generation == 1, (
        f"btn rotate must surface index_epoch as generation; got {result.generation!r}"
    )
    assert result.updated_cfg is None


def test_rotate_jwe_with_revoke_did(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    cfg = tn.admin.add_recipient(
        "default",
        recipient_did="did:key:zCharlie",
        public_key=_fresh_x25519_pub(),
        cfg=cfg,
    ).updated_cfg
    result = tn.admin.rotate(
        "default", revoke_did="did:key:zCharlie", cfg=cfg,
    )
    assert result.cipher == "jwe"
    assert result.updated_cfg is not None


# ----------------------------------------------------------------------
# Polymorphic recipient= resolver. Covers the four input shapes:
#   - DID string
#   - int leaf_index
#   - 32-byte X25519 public key
#   - AddRecipientResult / dict / attr-bearing object
# Existing recipient_did= / leaf_index= / public_key= kwargs keep working
# (covered above) and override the resolved fields if both are passed.
# ----------------------------------------------------------------------


def test_add_recipient_btn_polymorphic_did_string(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    result = tn.admin.add_recipient(
        "default", recipient="did:key:zAlice", out_path=out,
    )
    assert out.exists()
    assert result.leaf_index is not None


def test_add_recipient_jwe_polymorphic_bytes(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    pub = _fresh_x25519_pub()
    # 32 raw bytes resolve to public_key; DID still required as kwarg
    # since jwe needs both (the resolver doesn't fabricate DIDs).
    result = tn.admin.add_recipient(
        "default", recipient=pub, recipient_did="did:key:zBob", cfg=cfg,
    )
    assert result.updated_cfg is not None


def test_add_recipient_jwe_polymorphic_dict(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher=_workflow_cipher("jwe"))
    pub = _fresh_x25519_pub()
    result = tn.admin.add_recipient(
        "default",
        recipient={"recipient_identity": "did:key:zBob", "public_key": pub},
        cfg=cfg,
    )
    assert result.updated_cfg is not None


def test_revoke_recipient_btn_polymorphic_did_resolves_leaf(tmp_path: Path):
    """Backlog #14: btn revoke accepts recipient_did and resolves the leaf."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    tn.admin.add_recipient(
        "default", recipient_did="did:key:zAlice", out_path=out,
    )
    # Did-based revoke on a btn group — previously rejected.
    result = tn.admin.revoke_recipient(
        "default", recipient_did="did:key:zAlice",
    )
    assert result.revoked is True
    assert result.cipher == "btn"


def test_revoke_recipient_btn_polymorphic_via_add_result(tmp_path: Path):
    """`recipient=<AddRecipientResult>` should round-trip add then revoke."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    add = tn.admin.add_recipient(
        "default", recipient_did="did:key:zAlice", out_path=out,
    )
    result = tn.admin.revoke_recipient("default", recipient=add)
    assert result.revoked is True


def test_revoke_recipient_btn_polymorphic_int_leaf(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    out = tmp_path / "alice.btn.mykit"
    add = tn.admin.add_recipient(
        "default", recipient_did="did:key:zAlice", out_path=out,
    )
    result = tn.admin.revoke_recipient("default", recipient=add.leaf_index)
    assert result.revoked is True


def test_revoke_recipient_btn_did_not_found_errors(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    with pytest.raises(ValueError, match=r"no active recipient"):
        tn.admin.revoke_recipient("default", recipient_did="did:key:zGhost")


def test_resolve_recipient_rejects_bool():
    from tn.admin import _resolve_recipient

    with pytest.raises(TypeError, match=r"bool"):
        _resolve_recipient(True)


def test_resolve_recipient_rejects_short_bytes():
    from tn.admin import _resolve_recipient

    with pytest.raises(ValueError, match=r"32-byte"):
        _resolve_recipient(b"too-short")


def test_resolve_recipient_rejects_non_did_string():
    from tn.admin import _resolve_recipient

    with pytest.raises(ValueError, match=r"DID"):
        _resolve_recipient("not-a-did")


def test_resolve_recipient_negative_leaf():
    from tn.admin import _resolve_recipient

    with pytest.raises(ValueError, match=r"non-negative"):
        _resolve_recipient(-1)


def test_resolve_recipient_x25519_pub_b64_dict():
    """contacts.yaml row shape: x25519_pub_b64 is b64-decoded into bytes."""
    import base64

    from tn.admin import _resolve_recipient

    pub = _fresh_x25519_pub()
    row = {
        "recipient_identity": "did:key:zCarol",
        "x25519_pub_b64": base64.b64encode(pub).decode(),
    }
    out = _resolve_recipient(row)
    assert out.recipient_did == "did:key:zCarol"
    assert out.public_key == pub
