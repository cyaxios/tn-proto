from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tn.config import LoadedConfig
from tn.read_trust import (
    InMemoryReadTrustProvider,
    LocalReadTrustProvider,
    ReadTrustSource,
    validate_ed25519_did,
)


LOCAL_DID = "did:key:z6MkkqvUW1dLXh4JQv3VScGgbqbS85qGQM9G2jFHJ76vY2xt"
VERIFIED_DID = "did:key:z6MkhDA92BRnspkcBZVVMhfdRVhZSHWejjYqUipaj8zvXUs5"
CONFIG_DID = "did:key:z6Mkf1YtL1qR91LXM63W4mSmU18wCqFJCEGBWayXn7ykPuZ3"


def _base58btc(value: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    return "1" * leading_zeroes + encoded


NON_ED25519_DID = "did:key:z" + _base58btc(b"\xec\x01" + b"x" * 32)


def _config(yaml_path: Path, keystore: Path, device_did: str = LOCAL_DID) -> LoadedConfig:
    value = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=SimpleNamespace(device_identity=device_did, did=device_did),
    )
    return cast(LoadedConfig, cast(Any, value))


def test_in_memory_provider_freezes_exact_keys_and_sources() -> None:
    entries: dict[str, ReadTrustSource] = {
        LOCAL_DID: "local-device",
        VERIFIED_DID: "verified-package",
        CONFIG_DID: "explicit-config",
    }
    provider = InMemoryReadTrustProvider(entries)

    entries.clear()
    assert provider.trusted_writer_dids(cast(Any, object())) == frozenset(
        {LOCAL_DID, VERIFIED_DID, CONFIG_DID},
    )
    assert provider.source_for(LOCAL_DID) == "local-device"
    assert provider.source_for(VERIFIED_DID) == "verified-package"
    assert provider.source_for(CONFIG_DID) == "explicit-config"
    assert provider.source_for(LOCAL_DID + " ") is None


@pytest.mark.parametrize(
    "did",
    [
        "",
        "did:web:example.com",
        "did:key:znot0base58",
        NON_ED25519_DID,
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2d",
    ],
)
def test_ed25519_did_validation_rejects_malformed_or_non_ed25519_values(did: str) -> None:
    with pytest.raises(ValueError, match="Ed25519"):
        validate_ed25519_did(did)


@pytest.mark.parametrize(
    "entries",
    [
        {"did:web:example.com": "explicit-config"},
        {NON_ED25519_DID: "verified-package"},
        {LOCAL_DID: "configuration"},
    ],
)
def test_in_memory_provider_rejects_invalid_entries(entries: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        InMemoryReadTrustProvider(entries)  # type: ignore[arg-type]


def test_local_provider_merges_receiver_local_sources_with_frozen_precedence(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / ".tn"
    keystore = state_root / "ceremony" / "keys"
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text(
        f"trust:\n  writers:\n    - {CONFIG_DID}\n    - {VERIFIED_DID}\n    - {LOCAL_DID}\n",
        encoding="utf-8",
    )
    private_path = keystore / "trust" / "verified_publishers.v1.json"
    private_path.parent.mkdir(parents=True)
    private_path.write_text(
        json.dumps(
            {
                "schema": "tn.verified-publishers/v1",
                "publishers": {
                    VERIFIED_DID: {"proof_source": "enrollment-response"},
                    LOCAL_DID: {"proof_source": "local-package"},
                },
            },
        ),
        encoding="utf-8",
    )

    provider = LocalReadTrustProvider(_config(yaml_path, keystore), state_root)

    assert provider.private_record_path == private_path
    assert provider.trusted_writer_dids(cast(Any, object())) == frozenset(
        {LOCAL_DID, VERIFIED_DID, CONFIG_DID},
    )
    assert provider.source_for(LOCAL_DID) == "local-device"
    assert provider.source_for(VERIFIED_DID) == "verified-package"
    assert provider.source_for(CONFIG_DID) == "explicit-config"


def test_local_provider_uses_exact_private_path_not_state_root_trust_directory(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    keystore = state_root / "keys"
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    decoy = state_root / "trust" / "verified_publishers.v1.json"
    decoy.parent.mkdir(parents=True)
    decoy.write_text(
        json.dumps({"publishers": {CONFIG_DID: {}}}),
        encoding="utf-8",
    )

    provider = LocalReadTrustProvider(_config(yaml_path, keystore), state_root)

    assert provider.private_record_path == keystore / "trust" / "verified_publishers.v1.json"
    assert provider.trusted_writer_dids(cast(Any, object())) == frozenset({LOCAL_DID})
    assert provider.source_for(CONFIG_DID) is None


def test_local_provider_does_not_assume_an_enrollment_owned_schema_label(
    tmp_path: Path,
) -> None:
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    private_path = keystore / "trust" / "verified_publishers.v1.json"
    private_path.parent.mkdir(parents=True)
    private_path.write_text(
        json.dumps(
            {
                "schema": "enrollment-owned/private-state-v1",
                "publishers": {VERIFIED_DID: {"proof_digest": "sha256:example"}},
            },
        ),
        encoding="utf-8",
    )

    provider = LocalReadTrustProvider(_config(yaml_path, keystore), tmp_path)

    assert provider.source_for(VERIFIED_DID) == "verified-package"


def test_local_provider_caches_config_and_private_records_at_construction(
    tmp_path: Path,
) -> None:
    keystore = tmp_path / "keys"
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text(
        f"trust:\n  writers:\n    - {CONFIG_DID}\n",
        encoding="utf-8",
    )
    private_path = keystore / "trust" / "verified_publishers.v1.json"
    private_path.parent.mkdir(parents=True)
    private_path.write_text(
        json.dumps({"publishers": {VERIFIED_DID: {}}}),
        encoding="utf-8",
    )
    provider = LocalReadTrustProvider(_config(yaml_path, keystore), tmp_path)

    yaml_path.write_text("{}\n", encoding="utf-8")
    private_path.write_text(json.dumps({"publishers": {}}), encoding="utf-8")

    assert provider.trusted_writer_dids(cast(Any, object())) == frozenset(
        {LOCAL_DID, VERIFIED_DID, CONFIG_DID},
    )


@pytest.mark.parametrize("source", ["local", "config", "private"])
@pytest.mark.parametrize("bad_did", ["did:web:example.com", NON_ED25519_DID])
def test_every_local_provider_source_rejects_invalid_dids(
    tmp_path: Path,
    source: str,
    bad_did: str,
) -> None:
    keystore = tmp_path / "keys"
    yaml_path = tmp_path / "tn.yaml"
    device_did = bad_did if source == "local" else LOCAL_DID
    if source == "config":
        yaml_path.write_text(f"trust:\n  writers:\n    - {bad_did}\n", encoding="utf-8")
    else:
        yaml_path.write_text("{}\n", encoding="utf-8")
    if source == "private":
        private_path = keystore / "trust" / "verified_publishers.v1.json"
        private_path.parent.mkdir(parents=True)
        private_path.write_text(
            json.dumps({"publishers": {bad_did: {}}}),
            encoding="utf-8",
        )

    with pytest.raises(ValueError, match="Ed25519"):
        LocalReadTrustProvider(_config(yaml_path, keystore, device_did), tmp_path)


@pytest.mark.parametrize(
    "yaml_text",
    [
        "trust: []\n",
        "trust:\n  writers: did:key:z6Mknot-a-list\n",
        "trust:\n  writers:\n    - 7\n",
    ],
)
def test_local_provider_rejects_malformed_explicit_config(
    tmp_path: Path,
    yaml_text: str,
) -> None:
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8")

    with pytest.raises(ValueError, match="trust"):
        LocalReadTrustProvider(_config(yaml_path, tmp_path / "keys"), tmp_path)


@pytest.mark.parametrize(
    "private_document",
    [
        [],
        {"publishers": []},
        {"publishers": {VERIFIED_DID: "not-an-object"}},
        {"publishers": {"not-a-did": {}}},
    ],
)
def test_local_provider_rejects_malformed_private_records(
    tmp_path: Path,
    private_document: object,
) -> None:
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    private_path = keystore / "trust" / "verified_publishers.v1.json"
    private_path.parent.mkdir(parents=True)
    private_path.write_text(json.dumps(private_document), encoding="utf-8")

    with pytest.raises(ValueError, match="verified publisher"):
        LocalReadTrustProvider(_config(yaml_path, keystore), tmp_path)
