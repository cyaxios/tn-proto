import json, os, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import tn.awk_pickup as ap
from tn.recipient_seal import seal_bek_for_recipient
from tn.credential_store import FileCredentialStore, awk_key_name
from tn.bootstrap import _did_key_for_ed25519_pub

ACCOUNT = "01ACCTTESTAAAAAAAAAAAAAAAA"


def test_redeem_caches_awk(tmp_path, monkeypatch):
    seed = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                         format=serialization.PublicFormat.Raw)
    did = _did_key_for_ed25519_pub(pub)
    awk = os.urandom(32)
    wrap = seal_bek_for_recipient(awk, did, ap.awk_pickup_aad(ACCOUNT))
    monkeypatch.setattr(ap, "_challenge_verify", lambda base, d, p: "faketoken")
    monkeypatch.setattr(ap, "_http_get",
        lambda url, headers=None: (200, json.dumps({"wrap": wrap, "account_id": ACCOUNT}).encode()))
    store = FileCredentialStore(tmp_path / "credentials.json")
    assert ap.redeem_awk_pickup(vault_url="http://vault.test",
        device_seed=seed, account_id=ACCOUNT, key_id_b64="kid", store=store) is True
    assert store.get(awk_key_name(ACCOUNT)) == awk


def test_redeem_false_on_http_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ap, "_challenge_verify", lambda base, d, p: "faketoken")
    monkeypatch.setattr(ap, "_http_get", lambda url, headers=None: (404, b"gone"))
    store = FileCredentialStore(tmp_path / "credentials.json")
    assert ap.redeem_awk_pickup(vault_url="http://x",
        device_seed=secrets.token_bytes(32), account_id=ACCOUNT, key_id_b64="kid", store=store) is False
    assert store.get(awk_key_name(ACCOUNT)) is None
