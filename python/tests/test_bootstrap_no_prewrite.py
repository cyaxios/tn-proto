"""Bootstrap cold-start never writes anything to the keystore dir
before _absorb_dispatch — the bearer's seed lives in cfg.device for
the duration of absorb only.

Method: monkeypatch the HTTP + auth layers so bootstrap reaches the
keystore-prep + absorb dispatch portion without real network. Spy on
Path.write_bytes / Path.write_text and confirm no writes to the
keystore directory happen before absorb is given the sealed bytes.
With the pre-write dropped, the spy sees zero writes when absorb
rejects.

See docs/superpowers/specs/2026-05-12-cold-start-completeness-design.md
(Cluster B1).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import tn.bootstrap as _bootstrap


def _fake_bearer() -> str:
    """Return an api-key bearer with the shape the parser expects:
    base64url(32-byte seed || did:key derived from it). Uses an
    all-zeros seed — never accepted in production but parser-valid.
    """
    # Look at _parse_bearer for the canonical shape; reproduce here.
    # The simplest valid shape per the parser today: bearer = key_id ":" seed_b64
    # but the actual format is project-specific. To keep this test
    # self-contained, we monkeypatch _parse_bearer to return a known triple.
    return "fake_bearer_placeholder"


def test_bootstrap_never_writes_keystore_before_absorb_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keystore = tmp_path / "keystore"
    keystore.mkdir()

    seed = bytes(32)
    fake_did = "did:key:z6MkfakeFakeFakeFake"

    # Bypass parsing — return (seed, "fake_key_id_b64", b"\x00"*32).
    monkeypatch.setattr(
        _bootstrap,
        "_parse_bearer",
        lambda bearer: (seed, "fake_key_id_b64", bytes(32)),
    )
    # Bypass DID endpoint resolution
    monkeypatch.setattr(
        _bootstrap,
        "_resolve_did_endpoint",
        lambda did: "https://vault.test",
    )
    # Bypass challenge/verify — pretend we got a token
    monkeypatch.setattr(
        _bootstrap,
        "_challenge_verify",
        lambda base, did, priv: "fake_jwt",
    )
    # Sealed-bundle GET returns garbage bytes → absorb will reject
    sealed_payload = base64.b64encode(b"not-a-valid-tnpkg").decode("ascii")
    monkeypatch.setattr(
        _bootstrap,
        "_http_get",
        lambda url, *, headers=None: (
            200,
            json.dumps({"sealed_bundle_b64": sealed_payload}).encode("utf-8"),
        ),
    )

    # Spy on every Path write into the keystore dir
    writes: list[tuple[str, str]] = []
    real_write_bytes = Path.write_bytes
    real_write_text = Path.write_text

    def spy_bytes(self: Path, data: bytes, **kw: object) -> int:
        try:
            keystore_resolved = keystore.resolve()
            self_resolved = self.resolve()
            if keystore_resolved in self_resolved.parents or self_resolved == keystore_resolved:
                writes.append(("bytes", str(self_resolved)))
        except OSError:
            pass
        return real_write_bytes(self, data, **kw)  # type: ignore[arg-type]

    def spy_text(self: Path, data: str, **kw: object) -> int:
        try:
            keystore_resolved = keystore.resolve()
            self_resolved = self.resolve()
            if keystore_resolved in self_resolved.parents or self_resolved == keystore_resolved:
                writes.append(("text", str(self_resolved)))
        except OSError:
            pass
        return real_write_text(self, data, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_bytes", spy_bytes)
    monkeypatch.setattr(Path, "write_text", spy_text)

    result = _bootstrap.bootstrap_from_api_key(
        yaml_path=tmp_path / "tn.yaml",
        keystore_path=keystore,
        vault_did=fake_did,
        api_key="fake-api-key",
    )

    assert result is False, "bootstrap should fail when sealed bundle is bogus"
    assert writes == [], (
        f"bootstrap wrote to keystore before/around a failed absorb: {writes}"
    )
