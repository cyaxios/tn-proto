"""Generate the sealed-object wire-parity vectors for tn-core.

Writes ``crypto/tn-core/tests/fixtures/sealed_object_vectors.json``
(sealed objects produced by this Python reference, plus the key
material to open them and the expected plaintexts) and extends
``row_hash_vectors.json`` with container-public-field cases (Python
``str(value)`` rendering of lists/dicts in the row-hash preimage).

Consumers:
- Rust:   ``crypto/tn-core/tests/sealed_object_golden.rs``
          and ``chain_golden.rs`` (row-hash cases)
- Python: ``python/tests/test_sealed_object_vectors.py``
          and ``test_conformance_vectors.py`` (row-hash cases)

Run from ``tn_proto/python``::

    python tools/gen_sealed_object_vectors.py

Determinism: the device seed and index master key are pinned (fixed
DID, fixed index tokens for fixed inputs), but btn/hibe scheme material
and the AEAD nonces are drawn from the OS RNG, so regeneration changes
ciphertext bytes. That is fine — these are VERIFY vectors: each
committed case is self-consistent (wire + keys + expected plaintext),
and determinism matters on the unseal side only. The generator
self-checks every case through the same assertions the test consumers
run before writing anything.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path

import yaml

import tn
from tn import VerifyError, admin
from tn.chain import _compute_row_hash
from tn.config import load_or_create
from tn.signing import DeviceKey

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "crypto" / "tn-core" / "tests" / "fixtures"

#: Pinned identity material. The btn publisher state (and hibe master
#: material) have no seed hooks through the public API, so those stay
#: random per generation — see the module docstring.
DEVICE_SEED = bytes([7]) * 32
INDEX_MASTER = bytes([0x11]) * 32


def _pin_and_reload(yaml_path: Path, keystore: Path, *, public_fields: tuple[str, ...] = ()):
    """Close the fresh ceremony, pin device seed + index master, reshape
    the yaml (vault off, local mode, extra public fields), reload."""
    tn.flush_and_close()
    fixed = DeviceKey.from_private_bytes(DEVICE_SEED)
    (keystore / "local.private").write_bytes(DEVICE_SEED)
    (keystore / "index_master.key").write_bytes(INDEX_MASTER)
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["device"]["device_identity"] = fixed.did
    if "vault" in doc:
        doc["vault"]["enabled"] = False
    doc["ceremony"]["mode"] = "local"
    if public_fields:
        doc["public_fields"].extend(public_fields)
    yaml_path.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    tn.init(str(yaml_path))


def _fresh_ceremony(root: Path, *, cipher: str, public_fields: tuple[str, ...] = ()) -> Path:
    """Mint a ceremony under ``root`` and return its keystore path."""
    yaml_path = root / "tn.yaml"
    tn.init(yaml_path, cipher=cipher)
    keystore = Path(tn.current_config().keystore)
    _pin_and_reload(yaml_path, keystore, public_fields=public_fields)
    return keystore


def _case(name, cipher, sealed, keystore: Path, key_files, open_groups, public):
    """Assemble one fixture case and SELF-CHECK it exactly the way the
    Rust and Python consumers will (verify + as-recipient open)."""
    keys = {
        f: base64.b64encode((keystore / f).read_bytes()).decode("ascii")
        for f in key_files
    }
    case = {
        "name": name,
        "cipher": cipher,
        "wire": str(sealed),
        "keys": keys,
        "open_groups": open_groups,
        "public": public,
    }
    env = json.loads(case["wire"])
    for k, v in public.items():
        assert env[k] == v, f"{name}: public {k!r} mismatch"
    with tempfile.TemporaryDirectory() as tdir:
        td = Path(tdir)
        for fname, b64 in keys.items():
            (td / fname).write_bytes(base64.b64decode(b64))
        for group, expected in open_groups.items():
            triple = tn.unseal(case["wire"], raw=True, as_recipient=td, group=group)
            assert triple["valid"] == {"signature": True, "row_hash": True}, name
            assert triple["plaintext"][group] == expected, name
    return case


def _tampered(name, env: dict, expected_failed_checks):
    """Assemble one tampered case; self-oracle the failed-check set and
    ORDER against this Python's own VerifyError."""
    wire = json.dumps(env, separators=(",", ":"))
    try:
        tn.unseal(wire)
        raise SystemExit(f"tampered case {name!r} unexpectedly verified")
    except VerifyError as e:
        assert e.failed_checks == expected_failed_checks, (
            f"{name}: expected {expected_failed_checks}, got {e.failed_checks}"
        )
    return {"name": name, "wire": wire, "expected_failed_checks": expected_failed_checks}


def build_sealed_object_vectors(work: Path) -> dict:
    cases = []
    tampered = []

    # -- btn ceremony with container/unicode public routes ------------
    btn_root = work / "btn"
    btn_root.mkdir()
    btn_keystore = _fresh_ceremony(
        btn_root, cipher="btn", public_fields=("pv", "pv2", "pv3")
    )

    minimal = tn.seal("obj.invoice.v1", receipt=False, amount=9800, customer="acme")
    cases.append(
        _case(
            "minimal_btn",
            "btn",
            minimal,
            btn_keystore,
            ["default.btn.mykit"],
            {"default": {"amount": 9800, "customer": "acme"}},
            {"tn_sealed": 1},
        )
    )

    # Containers in PUBLIC position — the R1 rendering proof: the wire
    # carries them as JSON, the row hash committed to Python str(value)
    # (insertion-order dict repr included: pv2 is deliberately b-then-a).
    container_public = tn.seal(
        "obj.rt.v1",
        receipt=False,
        pv=[1, 2, 3],
        pv2={"b": 2, "a": 1},
        pv3=["it's", 'say "hi"', "both ' and \"", "plain"],
        x=1,
    )
    cases.append(
        _case(
            "container_public_values",
            "btn",
            container_public,
            btn_keystore,
            ["default.btn.mykit"],
            {"default": {"x": 1}},
            {
                "pv": [1, 2, 3],
                "pv2": {"b": 2, "a": 1},
                "pv3": ["it's", 'say "hi"', "both ' and \"", "plain"],
                "tn_sealed": 1,
            },
        )
    )

    unicode_public = tn.seal("obj.rt.v1", receipt=False, pv="café — naïve", x=1)
    cases.append(
        _case(
            "unicode_public_value",
            "btn",
            unicode_public,
            btn_keystore,
            ["default.btn.mykit"],
            {"default": {"x": 1}},
            {"pv": "café — naïve", "tn_sealed": 1},
        )
    )

    aad_case = tn.seal("obj.rt.v1", receipt=False, aad={"case": "A-17"}, x=1)
    assert "tn_aad" in aad_case
    cases.append(
        _case(
            "aad_echo",
            "btn",
            aad_case,
            btn_keystore,
            ["default.btn.mykit"],
            {"default": {"x": 1}},
            {"tn_aad": aad_case["tn_aad"], "tn_sealed": 1},
        )
    )

    # -- multi-group btn ceremony --------------------------------------
    multi_root = work / "multi"
    multi_root.mkdir()
    tn.flush_and_close()
    cfg = load_or_create(multi_root / "tn.yaml", cipher="btn")
    admin.ensure_group(cfg, "partners", fields=["body"])
    tn.init(str(multi_root / "tn.yaml"))
    multi_keystore = Path(tn.current_config().keystore)
    _pin_and_reload(multi_root / "tn.yaml", multi_keystore)
    multi = tn.seal("obj.memo.v1", receipt=False, body="for partners", note="own")
    blocks = sorted(k for k, v in multi.items() if isinstance(v, dict) and "ciphertext" in v)
    assert blocks == ["default", "partners"], blocks
    cases.append(
        _case(
            "multi_group_btn",
            "btn",
            multi,
            multi_keystore,
            ["default.btn.mykit", "partners.btn.mykit"],
            {"default": {"note": "own"}, "partners": {"body": "for partners"}},
            {"tn_sealed": 1},
        )
    )

    # -- hibe ceremony (consumed by Rust only under the hibe feature) --
    hibe_root = work / "hibe"
    hibe_root.mkdir()
    tn.flush_and_close()
    hibe_keystore = _fresh_ceremony(hibe_root, cipher="hibe")
    hibe = tn.seal("obj.gov.v1", receipt=False, secret="s3")
    cases.append(
        _case(
            "hibe_group",
            "hibe",
            hibe,
            hibe_keystore,
            ["default.hibe.mpk", "default.hibe.idpath", "default.hibe.sk"],
            {"default": {"secret": "s3"}},
            {"tn_sealed": 1},
        )
    )

    # -- tampered variants (self-oracled failed-check sets + order) ----
    env = dict(json.loads(str(minimal)))
    env["tn_sealed"] = 2
    tampered.append(_tampered("tn_sealed_flipped", env, ["row_hash"]))

    env = dict(json.loads(str(minimal)))
    env["signature"] = unicode_public["signature"]  # validly-encoded foreign signature
    tampered.append(_tampered("signature_swapped", env, ["signature"]))

    env = dict(json.loads(str(minimal)))
    block = dict(env["default"])
    ct = block["ciphertext"]
    block["ciphertext"] = ct[:-4] + ("AAAA" if ct[-4:] != "AAAA" else "BBBB")
    env["default"] = block
    tampered.append(_tampered("ciphertext_bit_flip", env, ["row_hash"]))

    env = dict(json.loads(str(minimal)))
    env["tn_sealed"] = 2
    env["signature"] = "AAAA"  # decodes, cannot verify
    tampered.append(_tampered("both_checks_fail", env, ["signature", "row_hash"]))

    tn.flush_and_close()
    return {
        "generated_by": "python/tools/gen_sealed_object_vectors.py",
        "cases": cases,
        "tampered": tampered,
    }


#: Container-public row-hash cases (exercise the R1 Python-repr
#: rendering in every implementation's compute_row_hash). Deterministic
#: inputs; expected hashes are computed below by the Python reference.
_ROW_HASH_CONTAINER_CASES = [
    {
        "name": "container_public_list_and_dict",
        "inputs": {
            "did": "did:key:zContainers",
            "timestamp": "2026-07-09T00:00:00.000000Z",
            "event_id": "00000000-0000-4000-8000-0000000000c1",
            "event_type": "obj.rt.v1",
            "level": "",
            "prev_hash": "",
            "public_fields": {
                "pv": [1, 2, 3],
                # Insertion order (b before a) is deliberate: Python
                # dict repr renders insertion order, NOT sorted keys.
                "pv2": {"b": 2, "a": 1},
                "tn_sealed": 1,
            },
            "groups": {},
        },
    },
    {
        "name": "container_nested_string_quoting",
        "inputs": {
            "did": "did:key:zContainers",
            "timestamp": "2026-07-09T00:00:01.000000Z",
            "event_id": "00000000-0000-4000-8000-0000000000c2",
            "event_type": "obj.rt.v1",
            "level": "",
            "prev_hash": "",
            "public_fields": {
                "pv": ["it's", 'say "hi"', "both ' and \"", "plain"],
                "pv2": {"k": [1, {"x": "y"}]},
            },
            "groups": {},
        },
    },
    {
        "name": "container_scalars_unicode_and_controls",
        "inputs": {
            "did": "did:key:zContainers",
            "timestamp": "2026-07-09T00:00:02.000000Z",
            "event_id": "00000000-0000-4000-8000-0000000000c3",
            "event_type": "obj.rt.v1",
            "level": "",
            "prev_hash": "",
            "public_fields": {
                "pv": [True, False, None],
                "pv2": ["café — naïve"],
                "pv3": ["\n", "\t", "\\", "\x00"],
            },
            "groups": {},
        },
    },
]


def extend_row_hash_vectors() -> int:
    """Append the container cases to row_hash_vectors.json (idempotent
    by case name). Returns how many cases were added."""
    path = FIXTURES / "row_hash_vectors.json"
    vecs = json.loads(path.read_text(encoding="utf-8"))
    have = {v["name"] for v in vecs}
    added = 0
    for case in _ROW_HASH_CONTAINER_CASES:
        if case["name"] in have:
            continue
        inp = case["inputs"]
        expected = _compute_row_hash(
            device_identity=inp["did"],
            timestamp=inp["timestamp"],
            event_id=inp["event_id"],
            event_type=inp["event_type"],
            level=inp["level"],
            prev_hash=inp["prev_hash"],
            public_fields=inp["public_fields"],
            groups={},
        )
        vecs.append({**case, "expected_row_hash": expected})
        added += 1
    path.write_text(
        json.dumps(vecs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return added


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        data = build_sealed_object_vectors(Path(work))
    out = FIXTURES / "sealed_object_vectors.json"
    out.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    added = extend_row_hash_vectors()
    print(f"wrote {out} ({len(data['cases'])} cases, {len(data['tampered'])} tampered)")
    print(f"extended row_hash_vectors.json (+{added} container cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
