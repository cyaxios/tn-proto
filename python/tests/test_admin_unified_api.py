"""Tests for the cipher-agnostic unified admin API.

Proves that tn.admin.add_recipient / revoke_recipient / rotate dispatch
to the right cipher-specific implementation based on the group's cipher,
returning a structured AddRecipientResult / RevokeRecipientResult / RotateGroupResult.
"""
from __future__ import annotations

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
    tn.init(yaml, cipher="btn")
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
    cfg = load_or_create(yaml, cipher="jwe")
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
    tn.init(yaml, cipher="btn")
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
    cfg = load_or_create(yaml, cipher="jwe")
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
    tn.init(yaml, cipher="btn")
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
    cfg = load_or_create(yaml, cipher="jwe")
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
    tn.init(yaml, cipher="btn")
    result = tn.admin.rotate("default")
    assert result.cipher == "btn"
    assert result.generation == 1, (
        f"btn rotate must surface index_epoch as generation; got {result.generation!r}"
    )
    assert result.updated_cfg is None


def test_rotate_jwe_with_revoke_did(tmp_path: Path):
    yaml = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml, cipher="jwe")
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
