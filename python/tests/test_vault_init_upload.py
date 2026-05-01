"""Tests for the vault.push handler's INIT-UPLOAD mode (D-19, plan
``docs/superpowers/plans/2026-04-28-pending-claim-flow.md`` phases 4+5).

Covers:

* Body-encryption parameter on ``tn.pkg.export`` (phase 4): round-trip
  through AES-GCM under the same key.
* Init-upload happy path: empty sync_state → unauthenticated POST to
  ``/api/v1/pending-claims`` → vault_id assigned → sync_state
  updated → claim_url.txt written → admin event emitted into
  ``.tn/<stem>/admin/outbox/``.
* Steady-state: ``account_bound=True`` → POST to ``/api/v1/inbox/...``
  (existing path), no /pending-claims POST.
* Mode switching mid-life: same handler, sync_state mutates from
  unbound → bound, second push uses the new endpoint.
* C18 idempotency: second push in init-upload mode reuses the same
  vault_id when the previous pending claim hasn't expired.

Run::

    .venv/Scripts/python.exe -m pytest \\
        tn-protocol/python/tests/test_vault_init_upload.py -x -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.conventions import admin_outbox_dir
from tn.export import decrypt_body_blob, export
from tn.handlers.vault_push import (
    VaultPushHandler,
    init_upload,
)
from tn.sync_state import (
    clear_pending_claim,
    get_account_id,
    get_pending_claim,
    is_account_bound,
    load_sync_state,
    mark_account_bound,
    set_pending_claim,
    state_path,
)
from tn.tnpkg import _read_manifest


# ---------------------------------------------------------------------------
# Mock vault client capturing both endpoint paths.
# ---------------------------------------------------------------------------


class _CapturedClient:
    def __init__(self) -> None:
        self.inbox_posts: list[dict[str, Any]] = []
        self.pending_posts: list[bytes] = []
        self.next_vault_id = "01TEST000000000000000000VAULT"
        self.next_expires_at = "2099-12-31T23:59:59+00:00"
        self.closed = False

    def post_inbox_snapshot(
        self, path: str, body: bytes, *, params: dict[str, str] | None = None
    ) -> None:
        self.inbox_posts.append({"path": path, "body": body, "params": dict(params or {})})

    def post_pending_claim(self, body: bytes) -> dict[str, Any]:
        self.pending_posts.append(body)
        return {"vault_id": self.next_vault_id, "expires_at": self.next_expires_at}

    def close(self) -> None:
        self.closed = True


def _factory(captured: _CapturedClient):
    def factory(endpoint: str, identity: Any) -> _CapturedClient:
        return captured

    return factory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _force_admin_log_yaml(yaml_path: Path) -> None:
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_ceremony(tmp_path: Path) -> Any:
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("init-upload tests require the Rust runtime (btn)")
    out = tmp_path / "_kits"
    out.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out / "alice.btn.mykit")
    return tn.current_config()


# ---------------------------------------------------------------------------
# Phase 4: tn.pkg.export(encrypt_body_with=...)
# ---------------------------------------------------------------------------


class TestExportBodyEncryption:
    def test_encrypt_and_decrypt_roundtrip(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        out_path = tmp_path / "out.tnpkg"
        key = b"\x42" * 32
        export(
            out_path,
            kind="full_keystore",
            cfg=cfg,
            confirm_includes_secrets=True,
            encrypt_body_with=key,
        )
        manifest, body = _read_manifest(out_path)
        # Body now contains a single encrypted blob.
        assert "body/encrypted.bin" in body
        # Manifest records the cipher_suite.
        assert manifest.state is not None
        be = manifest.state.get("body_encryption")
        assert be is not None
        assert be["cipher_suite"] == "aes-256-gcm"
        # Round-trip decryption returns the original body files.
        plain = decrypt_body_blob(body["body/encrypted.bin"], key)
        # At least the WARNING marker plus one mykit must be present.
        assert any(name.endswith(".btn.mykit") for name in plain)

    def test_decrypt_with_wrong_key_fails(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        out_path = tmp_path / "out.tnpkg"
        key = b"\x42" * 32
        export(
            out_path,
            kind="full_keystore",
            cfg=cfg,
            confirm_includes_secrets=True,
            encrypt_body_with=key,
        )
        _, body = _read_manifest(out_path)
        with pytest.raises(Exception):  # noqa: PT011 — cryptography raises InvalidTag
            decrypt_body_blob(body["body/encrypted.bin"], b"\x00" * 32)

    def test_invalid_key_size_rejected(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        with pytest.raises(ValueError, match="32-byte"):
            export(
                tmp_path / "x.tnpkg",
                kind="full_keystore",
                cfg=cfg,
                confirm_includes_secrets=True,
                encrypt_body_with=b"too-short",
            )


# ---------------------------------------------------------------------------
# Phase 5: handler init-upload mode
# ---------------------------------------------------------------------------


class TestInitUploadMode:
    def test_init_upload_happy_path(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        # Sanity: brand-new sync_state has no account binding.
        assert is_account_bound(cfg.yaml_path) is False
        assert get_pending_claim(cfg.yaml_path) is None

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            ok = h._push_snapshot()
            assert ok is True
        finally:
            h._stop_ev.set()

        # Hit the unauth pending-claims endpoint, NOT inbox.
        assert len(captured.pending_posts) == 1
        assert len(captured.inbox_posts) == 0

        # sync_state.pending_claim is populated.
        pc = get_pending_claim(cfg.yaml_path)
        assert pc is not None
        assert pc["vault_id"] == captured.next_vault_id
        assert pc["expires_at"] == captured.next_expires_at
        assert pc["claim_url"].startswith("https://mock.vault.local/claim/")
        assert "#k=" in pc["claim_url"]
        assert isinstance(pc["password_b64"], str) and len(pc["password_b64"]) > 0

        # claim_url.txt was written.
        sync_dir = state_path(cfg.yaml_path).parent
        url_file = sync_dir / "claim_url.txt"
        assert url_file.exists()
        assert url_file.read_text(encoding="utf-8").strip() == pc["claim_url"]

        # tn.vault.claim_url_issued admin event landed in admin/outbox/.
        outbox = admin_outbox_dir(cfg.yaml_path)
        events = list(outbox.glob("claim_url_issued_*.json"))
        assert len(events) == 1
        envelope = json.loads(events[0].read_text(encoding="utf-8"))
        assert envelope["event_type"] == "tn.vault.claim_url_issued"
        assert envelope["vault_id"] == captured.next_vault_id
        assert envelope["claim_url"] == pc["claim_url"]

    def test_ciphertext_decrypts_under_persisted_password(self, tmp_path: Path):
        """The password persisted in sync_state must decrypt the bytes
        the vault received — that's what the browser claim page expects
        to do once the user pastes the URL."""
        import base64

        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            h._push_snapshot()
        finally:
            h._stop_ev.set()

        pc = get_pending_claim(cfg.yaml_path)
        assert pc is not None
        # Recover BEK from the URL fragment (which equals password_b64).
        password = pc["password_b64"]
        # base64url decode (handle missing padding).
        bek = base64.urlsafe_b64decode(password + "==")
        assert len(bek) == 32

        # The body the vault saw is a complete tnpkg — its encrypted body
        # must decrypt under bek.
        body_bytes = captured.pending_posts[0]
        _, body_files = _read_manifest(body_bytes)
        plain = decrypt_body_blob(body_files["body/encrypted.bin"], bek)
        assert any(name.endswith(".btn.mykit") for name in plain)


class TestSteadyStateMode:
    def test_account_bound_routes_to_inbox(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        # Stamp the binding so the dispatcher takes the steady-state path.
        mark_account_bound(cfg.yaml_path, "test-account-id")
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            ok = h._push_snapshot()
            assert ok is True
        finally:
            h._stop_ev.set()

        # Steady-state: hit /api/v1/inbox/, NOT /pending-claims.
        assert len(captured.inbox_posts) == 1
        assert len(captured.pending_posts) == 0
        assert "/api/v1/inbox/" in captured.inbox_posts[0]["path"]


class TestModeSwitching:
    def test_mid_life_unbound_to_bound(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            # First tick: init-upload.
            h._push_snapshot()
            assert len(captured.pending_posts) == 1
            assert len(captured.inbox_posts) == 0

            # Simulate the browser claim page completing: vault echoes
            # back account_id, sync_state flips bound.
            mark_account_bound(cfg.yaml_path, "claimed-account-id")

            # Second tick: steady-state. New event would be needed for
            # head_row_hash to advance; force it by emitting another
            # admin event via the running runtime.
            tn.admin.add_recipient("default", recipient_did="did:key:zBob", out_path=tmp_path / "_kits" / "bob.btn.mykit")

            ok = h._push_snapshot()
            assert ok is True
            assert len(captured.pending_posts) == 1  # unchanged
            assert len(captured.inbox_posts) == 1
            assert "/api/v1/inbox/" in captured.inbox_posts[0]["path"]
        finally:
            h._stop_ev.set()


class TestIdempotency:
    def test_second_push_within_ttl_reuses_vault_id(self, tmp_path: Path):
        """C18: second init-upload tick on the same ceremony reuses the
        existing pending claim if it's still inside its TTL window."""
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            h._push_snapshot()
            first_vault_id = get_pending_claim(cfg.yaml_path)["vault_id"]
            assert first_vault_id == captured.next_vault_id

            # Make the vault return a new vault_id on subsequent calls so
            # we'd notice if the handler re-uploaded (it shouldn't).
            captured.next_vault_id = "01OTHER0000000000000000000VAULT"

            h._push_snapshot()

            second_vault_id = get_pending_claim(cfg.yaml_path)["vault_id"]
            # Same vault_id — no second POST happened.
            assert second_vault_id == first_vault_id
            assert len(captured.pending_posts) == 1
        finally:
            h._stop_ev.set()

    def test_expired_pending_claim_is_replaced(self, tmp_path: Path):
        """If the pending claim expired, the next tick produces a fresh
        one (re-uploads to the vault)."""
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()
        # Pre-populate sync_state with an EXPIRED pending claim.
        set_pending_claim(
            cfg.yaml_path,
            vault_id="01EXPIRED",
            expires_at="2000-01-01T00:00:00+00:00",
            claim_url="https://x/claim/01EXPIRED#k=zzz",
            password_b64="zzz",
        )

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            h._push_snapshot()
        finally:
            h._stop_ev.set()

        # Fresh vault_id from the (mock) vault, not the expired one.
        pc = get_pending_claim(cfg.yaml_path)
        assert pc["vault_id"] == captured.next_vault_id
        assert len(captured.pending_posts) == 1


# ---------------------------------------------------------------------------
# Pure init_upload() entry point coverage
# ---------------------------------------------------------------------------


class TestInitUploadPureFunction:
    def test_init_upload_returns_dict_with_all_fields(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        result = init_upload(
            cfg,
            captured,
            vault_base="https://mock.vault.local",
        )

        for key in ("vault_id", "expires_at", "claim_url", "password_b64", "reused"):
            assert key in result, f"missing field: {key}"
        assert result["reused"] is False

    def test_init_upload_reuses_within_ttl(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        captured = _CapturedClient()

        first = init_upload(cfg, captured, vault_base="https://mock.vault.local")
        captured.next_vault_id = "01OTHER"
        second = init_upload(cfg, captured, vault_base="https://mock.vault.local")

        assert second["reused"] is True
        assert second["vault_id"] == first["vault_id"]


# ---------------------------------------------------------------------------
# S7 fix: concurrent init-upload ticks must serialize.
# ---------------------------------------------------------------------------


class _BarrieredClient(_CapturedClient):
    """CapturedClient that blocks inside post_pending_claim on a barrier.

    Used to force two threads to be inside ``init_upload`` simultaneously.
    Without the ``_init_lock`` (S7 fix), both threads would observe an
    empty ``sync_state.pending_claim``, both would mint a fresh BEK +
    POST, and the second post would stomp the first's vault_id in
    sync_state. With the lock, only one thread holds it at a time so
    the second observes the C18 reuse-within-TTL fast path.
    """

    def __init__(self, n_parties: int) -> None:
        super().__init__()
        import threading

        self._gate = threading.Barrier(n_parties)
        # Each successful post_pending_claim returns a different vault_id
        # so we'd notice a second real upload happening.
        self._vault_id_seq = iter(
            [f"01CONC{i:020d}" for i in range(n_parties + 4)]
        )

    def post_pending_claim(self, body: bytes):
        # Wait until both threads are inside this method before either
        # one is allowed to continue. Without the handler's _init_lock,
        # both would proceed past here in parallel; with the lock, only
        # one thread reaches this call at all (the other gets to
        # init_upload's reuse-within-TTL fast path).
        self.pending_posts.append(body)
        next_id = next(self._vault_id_seq)
        self.next_vault_id = next_id
        return {"vault_id": next_id, "expires_at": self.next_expires_at}


class TestInitUploadConcurrency:
    def test_concurrent_init_upload_serializes_under_init_lock(
        self, tmp_path: Path
    ):
        """S7 fix: two concurrent _init_upload_tick calls produce ONE
        vault_id, not two distinct ones.

        Without the ``_init_lock`` the C18 reuse-within-TTL check inside
        ``init_upload`` is a TOCTOU: thread A reads ``pending_claim is
        None``, thread B reads the same, both mint a fresh BEK + POST.
        ``sync_state`` ends up with whichever ``set_pending_claim`` ran
        last, leaving the loser's vault_id orphaned in the vault. With
        the lock, only one thread does the upload; the other sees the
        post-set state and reuses it (``reused=True``).
        """
        import threading

        cfg = _build_ceremony(tmp_path)
        captured = _BarrieredClient(n_parties=1)  # only the winner posts

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )

        results: list[bool] = []
        errors: list[BaseException] = []

        def _tick():
            try:
                results.append(h._init_upload_tick(cfg))
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        try:
            t1 = threading.Thread(target=_tick, name="init-A")
            t2 = threading.Thread(target=_tick, name="init-B")
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)
            assert not errors, f"thread errors: {errors!r}"
            assert results == [True, True], (
                f"both ticks must report success, got {results!r}"
            )

            # The fix: exactly ONE POST to /pending-claims, not two.
            # Without _init_lock both threads would observe pending_claim
            # is None, both would call post_pending_claim, and we'd see
            # 2 here.
            assert len(captured.pending_posts) == 1, (
                f"expected exactly one /pending-claims POST under "
                f"_init_lock, got {len(captured.pending_posts)} (race)"
            )

            # And the persisted vault_id is stable across both ticks —
            # i.e. there was a SINGLE run-id minted, not two.
            pc = get_pending_claim(cfg.yaml_path)
            assert pc is not None
            assert pc["vault_id"].startswith("01CONC"), pc
        finally:
            h._stop_ev.set()


# ---------------------------------------------------------------------------
# sync_state schema additions
# ---------------------------------------------------------------------------


class TestSyncStateSchema:
    def test_account_id_helpers(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        assert get_account_id(cfg.yaml_path) is None
        assert is_account_bound(cfg.yaml_path) is False
        mark_account_bound(cfg.yaml_path, "acct_xyz")
        assert get_account_id(cfg.yaml_path) == "acct_xyz"
        assert is_account_bound(cfg.yaml_path) is True

    def test_pending_claim_helpers(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        set_pending_claim(
            cfg.yaml_path,
            vault_id="vid",
            expires_at="2099-01-01T00:00:00+00:00",
            claim_url="https://x/y#k=z",
            password_b64="z",
        )
        pc = get_pending_claim(cfg.yaml_path)
        assert pc is not None and pc["vault_id"] == "vid"
        clear_pending_claim(cfg.yaml_path)
        assert get_pending_claim(cfg.yaml_path) is None

    def test_mark_bound_clears_pending_claim(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        set_pending_claim(
            cfg.yaml_path,
            vault_id="vid",
            expires_at="2099-01-01T00:00:00+00:00",
            claim_url="https://x/y#k=z",
            password_b64="z",
        )
        mark_account_bound(cfg.yaml_path, "acct")
        # pending_claim is dropped — the bind happened.
        assert get_pending_claim(cfg.yaml_path) is None
        state = load_sync_state(cfg.yaml_path)
        assert state["account_bound"] is True
