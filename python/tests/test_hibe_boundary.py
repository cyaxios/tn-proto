from __future__ import annotations

import importlib.util
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tn import cipher as cipher_mod
from tn.cipher import BtnGroupCipher, HibeGroupCipher, NotARecipientError


def _load_hibe_with_native(native: types.ModuleType):
    original_tn = sys.modules.get("tn")
    original_native = sys.modules.get("tn._native")
    original_hibe = sys.modules.get("tn._native.hibe")
    fake_tn = types.ModuleType("tn")
    fake_tn.__path__ = []
    sys.modules["tn"] = fake_tn
    sys.modules["tn._native"] = native
    sys.modules.pop("tn._native.hibe", None)
    try:
        spec = importlib.util.spec_from_file_location(
            "tn._hibe_import_probe",
            HERE.parent / "tn" / "_hibe.py",
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("tn._hibe_import_probe", None)
        if original_tn is None:
            sys.modules.pop("tn", None)
        else:
            sys.modules["tn"] = original_tn
        if original_native is None:
            sys.modules.pop("tn._native", None)
        else:
            sys.modules["tn._native"] = original_native
        if original_hibe is None:
            sys.modules.pop("tn._native.hibe", None)
        else:
            sys.modules["tn._native.hibe"] = original_hibe


def test_hibe_import_uses_extension_module_attribute() -> None:
    native = types.ModuleType("tn._native")
    hibe = types.SimpleNamespace(
        HibeCryptoError=type("HibeCryptoError", (Exception,), {}),
        delegate=lambda *args: b"delegate",
        kem_unwrap=lambda *args: b"cek",
        kem_wrap=lambda *args: b"wrapped",
        key_id_path=lambda *args: "reader",
        keygen=lambda *args: b"sk",
        mpk_fingerprint=lambda *args: b"\x00" * 32,
        mpk_max_depth=lambda *args: 2,
        open=lambda *args: b"plaintext",
        seal=lambda *args: b"ciphertext",
        setup=lambda *args: (b"mpk", b"msk"),
    )
    native.hibe = hibe

    module = _load_hibe_with_native(native)

    assert module.setup is hibe.setup
    assert module.HibeCryptoError is hibe.HibeCryptoError


def test_hibe_import_has_clear_runtime_failure_when_unavailable() -> None:
    native = types.ModuleType("tn._native")

    module = _load_hibe_with_native(native)

    with pytest.raises(RuntimeError, match="HIBE native extension is unavailable"):
        module.setup(2)


class _FakeHibe:
    class HibeCryptoError(Exception):
        pass

    def setup(self, max_depth: int) -> tuple[bytes, bytes]:
        return b"mpk", b"msk"

    def keygen(self, mpk: bytes, msk: bytes, id_path: str) -> bytes:
        return f"sk:{id_path}".encode()

    def delegate(self, mpk: bytes, parent_sk: bytes, child_label: str) -> bytes:
        parent = self.key_id_path(parent_sk)
        path = f"{parent}/{child_label}" if parent else child_label
        return f"sk:{path}".encode()

    def key_id_path(self, sk: bytes) -> str:
        return sk.decode("utf-8").removeprefix("sk:")

    def seal(self, mpk: bytes, id_path: str, plaintext: bytes, aad: bytes | None = None) -> bytes:
        return b"sealed:" + id_path.encode("utf-8") + b":" + plaintext

    def open(self, mpk: bytes, sk: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        path = self.key_id_path(sk).encode("utf-8")
        prefix = b"sealed:" + path + b":"
        if not ciphertext.startswith(prefix):
            raise self.HibeCryptoError("wrong path")
        return ciphertext[len(prefix) :]

    def mpk_fingerprint(self, mpk: bytes) -> bytes:
        return b"\x01" * 32

    def mpk_max_depth(self, mpk: bytes) -> int:
        return 3


@pytest.fixture
def fake_hibe(monkeypatch: pytest.MonkeyPatch) -> _FakeHibe:
    fake = _FakeHibe()
    monkeypatch.setattr(cipher_mod, "_native_hibe", lambda: fake)
    return fake


@pytest.mark.parametrize(
    "id_path",
    [
        "",
        "/",
        "team//reader",
        "team/reader/",
        " team/reader",
        "team/reader ",
        "team/\nreader",
    ],
)
def test_hibe_create_rejects_ambiguous_id_paths(
    tmp_path: Path, fake_hibe: _FakeHibe, id_path: str
) -> None:
    with pytest.raises(ValueError, match="HIBE.*id_path"):
        HibeGroupCipher.create(tmp_path, "g", id_path=id_path)


def test_hibe_delegate_rejects_slash_child_label(tmp_path: Path, fake_hibe: _FakeHibe) -> None:
    cipher = HibeGroupCipher.create(tmp_path, "g", id_path="team")

    with pytest.raises(ValueError, match="HIBE.*child_label"):
        cipher.delegate_reader_key("policy/v2")


def test_hibe_rotate_persists_old_path_and_key_before_active_swap(
    tmp_path: Path, fake_hibe: _FakeHibe, monkeypatch: pytest.MonkeyPatch
) -> None:
    cipher = HibeGroupCipher.create(tmp_path, "g", id_path="team/policy-a")
    order: list[str] = []
    real_secret_write = cipher_mod._atomic_write_secret_bytes
    real_text_write = cipher_mod._atomic_write_text

    def tracked_secret_write(path: Path, data: bytes) -> None:
        name = path.name
        if name == "g.hibe.sk":
            order.append("active-sk")
        elif ".hibe.sk.previous." in name:
            order.append("previous-sk")
        real_secret_write(path, data)

    def tracked_text_write(path: Path, content: str) -> None:
        name = path.name
        if name == "g.hibe.idpath":
            order.append("active-idpath")
        elif name == "g.hibe.idpath.history":
            order.append("history")
        real_text_write(path, content)

    monkeypatch.setattr(cipher_mod, "_atomic_write_secret_bytes", tracked_secret_write)
    monkeypatch.setattr(cipher_mod, "_atomic_write_text", tracked_text_write)

    cipher.rotate_id_path("team/policy-b")

    assert order.index("history") < order.index("active-sk")
    assert order.index("previous-sk") < order.index("active-sk")
    assert order.index("history") < order.index("active-idpath")
    assert (tmp_path / "g.hibe.idpath.history").read_text(encoding="utf-8").splitlines() == [
        "team/policy-a"
    ]
    archived = list(tmp_path.glob("g.hibe.sk.previous.*"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == b"sk:team/policy-a"


def test_hibe_prior_ancestor_key_derives_to_current_and_prior_paths(
    fake_hibe: _FakeHibe,
) -> None:
    cipher = HibeGroupCipher(
        _mpk=b"mpk",
        _id_path="team/policy-b",
        _prior_paths=["team/policy-a"],
        _prior_sks=[b"sk:team"],
    )

    candidates = list(cipher._candidate_keys())

    assert b"sk:team/policy-b" in candidates
    assert b"sk:team/policy-a" in candidates


def test_btn_candidate_classifies_a_hibe_wire_frame_as_another_cipher(
    tmp_path: Path,
) -> None:
    hibe = HibeGroupCipher.create(tmp_path / "hibe", "g", id_path="reader")
    btn = BtnGroupCipher.create(tmp_path / "btn", "g")
    hibe_ciphertext = hibe.encrypt(b"governed")

    with pytest.raises(NotARecipientError, match="cipher frame"):
        btn.decrypt(hibe_ciphertext)


def test_grant_manifest_state_augmentation_is_additive_and_rejects_collisions() -> None:
    from tn.export import _merge_manifest_state

    original = {"kind": "readers-only", "kits": []}
    augmented = _merge_manifest_state(
        original,
        {
            "hibe_grant": {
                "delivery": "recipient-seal-v1",
                "delegated_subauthority": False,
                "id_path": "team/policy",
                "unsafe": False,
            }
        },
    )

    assert augmented["kind"] == "readers-only"
    assert augmented["hibe_grant"]["id_path"] == "team/policy"
    assert original == {"kind": "readers-only", "kits": []}
    with pytest.raises(ValueError, match="collision"):
        _merge_manifest_state(original, {"kind": "overwritten"})


def test_export_without_internal_augmentation_preserves_absent_manifest_state(
    tmp_path: Path,
) -> None:
    import tn
    from tn.export import export
    from tn.packaging import Package
    from tn.tnpkg import _read_manifest

    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.init(tmp_path / "publisher" / "tn.yaml")
    cfg = tn.current_config()
    package = Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id=cfg.ceremony_id,
        group="default",
        group_epoch=0,
        device_identity=cfg.device.device_identity,
        signer_verify_pub_b64="",
        recipient_identity=None,
        payload={},
        compiled_at=datetime.now(UTC).isoformat(),
        sig_b64=None,
    )
    out = tmp_path / "enrolment.tnpkg"

    export(out, kind="enrolment", cfg=cfg, package=package)
    manifest, _ = _read_manifest(out, verify_signature=True)

    assert manifest.state is None
    tn.flush_and_close()
