"""Alice -> vault -> Frank end-to-end test.

This is the load-bearing demo for the vault inbox transport. It exercises
the full vertical:

    1. Alice's runtime emits attested admin events.
    2. Alice's ``vault.push`` handler exports an ``admin_log_snapshot``
       ``.tnpkg`` and POSTs it to the vault inbox.
    3. The vault (``tnproto-org``) verifies the manifest signature and
       stores the snapshot in the per-recipient inbox.
    4. Frank's ``vault.pull`` handler lists his incoming, downloads the
       blob, and calls ``tn.pkg.absorb()`` which appends Alice's envelopes
       into Frank's local ``.tn/tn/admin/admin.ndjson``.
    5. Frank calls ``tn.secure_read()`` over the absorbed admin log and
       sees Alice's events. Signatures verify. With Alice's
       ``tn.agents`` kit installed, Frank also sees the ``instructions``
       block alongside each admin event that has a populated policy.

Phase A of the 2026-04-25 plan §11 -- SDK-pure pytest e2e. No browser.

The vault is mounted in-process via ``httpx.AsyncClient`` over an
``ASGITransport``; Alice's and Frank's handlers are wired with custom
``client_factory`` objects that translate the SDK's expected sync
interface into async ASGI calls under the hood. This means the test
exercises the REAL routes_inbox.py endpoints (auth challenge/verify,
manifest signature verification, idempotency, listing, download) end
to end without spinning up uvicorn.

Run::

    /c/codex/content_platform/.venv/Scripts/python.exe -m pytest \
        tn-protocol/python/tests/integration/test_vault_push_pull_e2e.py -v
"""

from __future__ import annotations

import asyncio
import base64
import shutil
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml as _yaml

# ── Path bootstrap ────────────────────────────────────────────────────
# Make both the protocol-side SDK and the tnproto-org vault src
# importable. Must precede the ``tn`` and ``src`` imports below.

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent.parent  # content_platform/
_TN_SDK = _REPO_ROOT / "tn-protocol" / "python"
_VAULT = _REPO_ROOT / "tnproto-org"

for p in (_TN_SDK, _VAULT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# tnproto-org's tests/conftest sets the test DB; replicate that here so
# this test file can be invoked by itself OR as part of a wider run.
import os

os.environ.setdefault("VAULT_MONGO_DB", "tn_vault_test_account")
os.environ.setdefault("VAULT_MAX_PROJECTS", "20")
os.environ.setdefault("VAULT_MAX_FILES", "200")

import src.db as _db
from src.app import app

import tn
from tn.admin.log import resolve_admin_log_path
from tn.handlers.vault_pull import VaultPullHandler
from tn.handlers.vault_push import VaultPushHandler

API = "/api/v1"
_VAULT_YAML = str(_REPO_ROOT / "tnproto-org" / "tn.yaml")


# ── Lifecycle housekeeping ────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_motor_client():
    """Drop the motor singleton each test so it binds to a fresh loop.

    Mirrors tnproto-org/tests/conftest.py::reset_motor_client. We can't
    rely on that fixture here because pytest's conftest discovery is
    rooted at the file's directory tree, and this test lives under the
    SDK tree, not the vault tree.
    """
    if _db._client is not None:
        _db._client.close()
    _db._client = None
    yield
    if _db._client is not None:
        _db._client.close()
    _db._client = None


@pytest.fixture(autouse=True)
def _clean_db_before_test(_shared_loop):
    """Wipe the inbox + accounts collections so each test starts clean.

    Runs on the test's shared loop so motor's client (created here on
    first use) binds to that same loop. Subsequent ``_run()`` calls in
    the test continue on this loop, keeping motor happy.
    """

    async def _wipe():
        for coll_name in ("inbox_snapshots",):
            try:
                await getattr(_db, coll_name)().delete_many({})
            except Exception:
                pass
        try:
            await _db.accounts().delete_many({"role": {"$ne": "admin"}})
        except Exception:
            pass

    _shared_loop.run_until_complete(_wipe())
    yield


@pytest.fixture(autouse=True)
def _restore_vault_runtime_after_test():
    """The vault's tn_log module pinned tn.init to its own ceremony at
    process start. Tests that build snapshots call tn.init(...) which
    clobbers that binding. Re-bind back to the vault's yaml after each
    test so subsequent vault HTTP calls find their keystore.
    """
    yield
    try:
        tn.flush_and_close()
        tn.init(_VAULT_YAML)
    except Exception:
        pass


# ── In-process ASGI client adapters ───────────────────────────────────


# A single event loop is reused across every async ASGI hop in the
# test. Motor (the async Mongo driver) binds its connection pool to
# whatever loop was current when its client was first instantiated;
# crossing loops mid-test raises ``RuntimeError: Event loop is closed``
# from ``loop.run_in_executor``. Running every ``_run`` against the
# same loop avoids that hazard.
_LOOP: asyncio.AbstractEventLoop | None = None


@pytest.fixture
def _shared_loop():
    """Create a loop that lives for the duration of one test."""
    global _LOOP
    loop = asyncio.new_event_loop()
    _LOOP = loop
    try:
        yield loop
    finally:
        # Best-effort: close motor's client so its sockets release before
        # the loop they were bound to disappears.
        if _db._client is not None:
            try:
                _db._client.close()
            except Exception:
                pass
            _db._client = None
        # Drain pending callbacks then close.
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()
        _LOOP = None


def _run(coro):
    """Run an async coroutine on the test's shared event loop.

    The handler is sync; the ASGI vault is async. The handler invokes
    ``post_inbox_snapshot`` / ``list_incoming`` / ``download`` on the
    custom client below; each method dispatches via this helper.
    Reusing one loop across every hop keeps motor's connection pool
    bound to a single, still-open loop for the whole round trip.
    """
    if _LOOP is None:
        # Fall-back path for use outside of a fixture.
        return asyncio.run(coro)
    return _LOOP.run_until_complete(coro)


async def _async_authenticate(did: str, priv_bytes: bytes) -> str:
    """DID challenge -> verify; cache the JWT for the lifetime of the test."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        r = await ac.post(f"{API}/auth/challenge", json={"did": did})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        sig = Ed25519PrivateKey.from_private_bytes(priv_bytes).sign(
            nonce.encode("utf-8")
        )
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        r = await ac.post(
            f"{API}/auth/verify",
            json={"did": did, "nonce": nonce, "signature": sig_b64},
        )
        assert r.status_code == 200, r.text
        return r.json()["token"]


class _AsgiPushClient:
    """Sync façade that satisfies VaultPushHandler.client_factory contract.

    The handler calls ``post_inbox_snapshot(path, body, params=...)`` and
    optionally ``close()``. We translate each call into an async ASGI
    request against the in-process vault.
    """

    def __init__(self, did: str, priv_bytes: bytes, token: str) -> None:
        self._did = did
        self._priv = priv_bytes
        self._token = token
        self.posts: list[dict[str, Any]] = []

    def post_inbox_snapshot(
        self, path: str, body: bytes, *, params: dict[str, str] | None = None
    ) -> None:
        async def _go():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as ac:
                url = path
                if params:
                    from urllib.parse import urlencode

                    url = f"{path}?{urlencode(params)}"
                r = await ac.post(
                    url,
                    content=body,
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Content-Type": "application/octet-stream",
                    },
                )
                if r.status_code >= 400:
                    raise AssertionError(
                        f"vault POST {url} -> {r.status_code}: {r.text}"
                    )
                self.posts.append(
                    {"path": path, "body": body, "params": dict(params or {}), "status": r.status_code}
                )

        _run(_go())

    def close(self) -> None:
        return


class _AsgiPullClient:
    """Sync façade satisfying VaultPullHandler.client_factory.

    The handler calls ``list_incoming(did, since=...)`` and
    ``download(path)`` and optionally ``close()``.
    """

    def __init__(self, did: str, priv_bytes: bytes, token: str) -> None:
        self._did = did
        self._priv = priv_bytes
        self._token = token
        self.list_calls: list[str | None] = []
        self.download_calls: list[str] = []

    def list_incoming(self, did: str, *, since: str | None = None):
        self.list_calls.append(since)

        async def _go() -> list[dict[str, Any]]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as ac:
                url = f"{API}/inbox/{did}/incoming"
                if since is not None:
                    from urllib.parse import urlencode

                    url = f"{url}?{urlencode({'since': since})}"
                r = await ac.get(
                    url, headers={"Authorization": f"Bearer {self._token}"}
                )
                if r.status_code >= 400:
                    raise AssertionError(
                        f"vault GET {url} -> {r.status_code}: {r.text}"
                    )
                doc = r.json()
                items = list(doc.get("items", []))
                # The handler tracks ``since_marker`` via ``received_at``
                # (it stores the highest seen received_at as the cursor).
                # The vault returns since_marker fields in each item; the
                # handler doesn't currently round-trip those, but the
                # received_at field is enough for forward progress.
                return items

        return _run(_go())

    def download(self, path: str) -> bytes:
        self.download_calls.append(path)

        async def _go() -> bytes:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as ac:
                r = await ac.get(
                    path, headers={"Authorization": f"Bearer {self._token}"}
                )
                if r.status_code >= 400:
                    raise AssertionError(
                        f"vault GET {path} -> {r.status_code}: {r.text}"
                    )
                return r.content

        return _run(_go())

    def close(self) -> None:
        return


# ── Ceremony helpers ──────────────────────────────────────────────────


_AGENTS_POLICY = """\
# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## tn.recipient.added

### instruction
This row records a newly-issued recipient kit.

### use_for
Replication of recipient roster across mirrors.

### do_not_use_for
Direct merging into any external CRM or marketing list.

### consequences
Reveals the recipient's DID; do not publish broadly.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate
"""


def _write_policy(yaml_dir: Path) -> None:
    p = yaml_dir / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_AGENTS_POLICY, encoding="utf-8")


def _read_local_priv(keystore: Path) -> bytes:
    return (keystore / "local.private").read_bytes()


def _force_admin_log_yaml(yaml_path: Path) -> None:
    """Pin admin events to ``./.tn/admin/admin.ndjson``.

    A fresh-write yaml from ``tn.init`` doesn't inline the
    ``admin_log_location`` key (the loader infers the default), but the
    Rust runtime today writes admin events to the main log unless the
    yaml explicitly opts in. Replicates the helper used by
    test_vault_push_handler / test_vault_pull_handler.
    """
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    # Both the new (admin_log_location) and legacy (protocol_events_location)
    # keys: the Python loader honors admin_log_location, but the Rust
    # ``Config`` deserializer (crypto/tn-core/src/config.rs) still reads
    # the legacy ``protocol_events_location`` field. Set both to keep
    # parity across the runtime split until the Rust side migrates.
    cer = doc.setdefault("ceremony", {})
    cer["admin_log_location"] = "./.tn/admin/admin.ndjson"
    # The Rust runtime resolves relative pel paths against the process
    # cwd (not yaml_dir), so a literal "./.tn/admin/..." would scatter
    # ndjson files at whatever directory the test was invoked from.
    # Use the absolute yaml_dir explicitly via the {yaml_dir} template.
    cer["protocol_events_location"] = "{yaml_dir}/.tn/admin/admin.ndjson"
    # Pin rotate_on_init: false on the file handler. The vault flow
    # does multiple flush_and_close() + tn.init() rounds across the
    # admin-snapshot lifecycle, and session-start rotation (the new
    # default since Round 6) would re-emit `tn.ceremony.init` to the
    # admin log on every init — which then puts Frank's own envelope
    # ahead of any absorbed-from-Alice envelopes and breaks the
    # cross-publisher peek-and-route in `Runtime::read_from`. Tests
    # asserting cross-session continuation legitimately want the
    # legacy "append everything" behavior.
    handlers = doc.setdefault("handlers", [])
    for h in handlers:
        if isinstance(h, dict) and h.get("kind") in ("file.rotating", "file"):
            h["rotate_on_init"] = False
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_alice(tmp_path: Path, frank_did: str) -> dict[str, Any]:
    """Initialise Alice's ceremony with the agents policy and pre-mint a
    kit for Frank in BOTH the ``default`` and ``tn.agents`` groups.
    Returns the bits the test needs after re-binding away from Alice.
    """
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir(parents=True, exist_ok=True)
    yaml = alice_dir / "tn.yaml"
    _write_policy(alice_dir)

    tn.flush_and_close()
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml)
    tn.init(yaml, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("vault e2e test requires the Rust runtime (btn)")

    cfg = tn.current_config()
    keystore = Path(cfg.keystore)
    alice_did = cfg.device.did

    # Mint Frank's kits before Alice closes. These admin actions also
    # produce ``tn.recipient.added`` envelopes in Alice's admin log --
    # those are what Frank will see at the end of the round trip.
    #
    # Critical ordering: mint Frank's kit in ``tn.agents`` FIRST. Each
    # admin event's tn.agents-group ciphertext is encrypted to the
    # current tn.agents recipient set; events emitted before Frank is
    # added to tn.agents won't be decryptable by him. By giving him the
    # tn.agents kit first, every subsequent ``tn.recipient.added`` event
    # carries instructions Frank can read.
    kits_dir = alice_dir / "_kits_for_frank"
    kits_dir.mkdir(parents=True, exist_ok=True)
    default_kit = kits_dir / "default.btn.mykit"
    agents_kit = kits_dir / "tn.agents.btn.mykit"
    tn.admin.add_recipient("tn.agents", recipient_did=frank_did, out_path=agents_kit)
    tn.admin.add_recipient("default", recipient_did=frank_did, out_path=default_kit)
    # A second mint in default to give the snapshot more interesting
    # events. Because Frank's tn.agents kit is already in place, this
    # event's instructions block decrypts cleanly for him too.
    other_default_kit = kits_dir / "default_other.btn.mykit"
    tn.admin.add_recipient("default", recipient_did="did:key:zSomeoneElseForBulk", out_path=other_default_kit)

    alice_priv = _read_local_priv(keystore)
    cfg_obj = tn.current_config()
    return {
        "did": alice_did,
        "priv": alice_priv,
        "yaml": yaml,
        "keystore": keystore,
        "kits_dir": kits_dir,
        "cfg": cfg_obj,
    }


def _build_frank(tmp_path: Path) -> dict[str, Any]:
    """Initialise Frank's empty ceremony (no admin events of his own).

    Returns enough info to re-init Frank later and bootstrap his DID.
    """
    frank_dir = tmp_path / "frank"
    frank_dir.mkdir(parents=True, exist_ok=True)
    yaml = frank_dir / "tn.yaml"

    tn.flush_and_close()
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml)
    tn.init(yaml, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("vault e2e test requires the Rust runtime (btn)")
    cfg = tn.current_config()
    keystore = Path(cfg.keystore)
    frank_did = cfg.device.did
    frank_priv = _read_local_priv(keystore)
    cfg_obj = tn.current_config()
    return {
        "did": frank_did,
        "priv": frank_priv,
        "yaml": yaml,
        "keystore": keystore,
        "cfg": cfg_obj,
    }


def _install_alice_kits_into_franks_keystore(
    alice_kits_dir: Path, frank_keystore: Path
) -> None:
    """Place Alice's mint-kits-for-Frank into Frank's keystore so his
    runtime can decrypt Alice's admin envelopes.

    The ``state`` files stay at Alice's keystore (publishers only); only
    the ``mykit`` files move. Frank's pre-existing self-mykit (minted
    when his own ceremony was created for HIS groups) is overwritten --
    he doesn't need to read his own logs in this test, only Alice's.
    """
    shutil.copyfile(
        alice_kits_dir / "default.btn.mykit",
        frank_keystore / "default.btn.mykit",
    )
    shutil.copyfile(
        alice_kits_dir / "tn.agents.btn.mykit",
        frank_keystore / "tn.agents.btn.mykit",
    )


# ── The end-to-end test ───────────────────────────────────────────────


def test_alice_to_frank_round_trip(tmp_path: Path, _shared_loop) -> None:
    # 1. Frank first -- so we have his DID to mint kits against.
    frank = _build_frank(tmp_path)
    # 2. Alice next, with Frank's DID baked into the recipient mint.
    alice = _build_alice(tmp_path, frank_did=frank["did"])

    # Capture Alice's admin-log path BEFORE re-binding away from her;
    # the snapshot writer will read this same file when exporting.
    alice_admin_log = resolve_admin_log_path(alice["cfg"])
    assert alice_admin_log.exists(), "Alice's admin log should exist after admin_add_recipient"

    # Authenticate as Alice against the in-process vault.
    alice_token = _run(_async_authenticate(alice["did"], alice["priv"]))
    push_client = _AsgiPushClient(alice["did"], alice["priv"], alice_token)

    # 3. Build the push handler. ``to_did=frank["did"]`` ensures the
    #    snapshot's manifest carries the v1-required routing field.
    push = VaultPushHandler(
        "alice-vault-push",
        endpoint="http://test",
        project_id="proj_e2e",
        cfg_provider=lambda: alice["cfg"],
        client_factory=lambda _ep, _id: push_client,
        trigger="on_schedule",
        poll_interval=999.0,  # disable scheduler firing during test
        scope="admin",
        to_did=frank["did"],
    )
    try:
        # 4. Trigger one snapshot push. Returns True iff a POST happened.
        pushed = push._push_snapshot()
        assert pushed is True, "expected vault.push to POST a snapshot"
    finally:
        push._stop_ev.set()

    assert len(push_client.posts) == 1
    posted_path = push_client.posts[0]["path"]
    assert posted_path.startswith(f"{API}/inbox/{alice['did']}/snapshots/")

    # Sanity: the vault's mongo metadata records the snapshot. Run the
    # find via the shared loop so we don't open a new motor pool.
    rec = _run(_db.inbox_snapshots().find_one({"from_did": alice["did"]}))
    assert rec is not None, "vault did not store metadata for the pushed snapshot"
    assert rec["to_did"] == frank["did"]

    # 5. Install Alice's mint-kits into Frank's keystore so decrypts
    #    succeed over the absorbed admin events. (The vault doesn't ship
    #    kits; in production Frank receives them out-of-band, e.g. via
    #    an enrolment package or a vault-side invite flow.)
    #
    #    Do this BEFORE re-init so the Rust runtime loads Frank's
    #    overlaid kits during its own bootstrap rather than the
    #    self-mykit it minted at init time.
    _install_alice_kits_into_franks_keystore(alice["kits_dir"], frank["keystore"])

    # Re-bind to Frank's runtime so his ceremony is the active one and
    # absorb writes to HIS .tn/tn/admin/admin.ndjson.
    tn.flush_and_close()
    tn.init(frank["yaml"], cipher="btn")
    frank_cfg = tn.current_config()

    # 6. Authenticate Frank and run his pull handler against the vault.
    frank_token = _run(_async_authenticate(frank["did"], frank["priv"]))
    pull_client = _AsgiPullClient(frank["did"], frank["priv"], frank_token)

    pull = VaultPullHandler(
        "frank-vault-pull",
        endpoint="http://test",
        project_id="proj_e2e",
        cfg_provider=lambda: frank_cfg,
        client_factory=lambda _ep, _id: pull_client,
        poll_interval=999.0,
        autostart=False,
    )
    absorbed = pull.tick_once()
    pull.close()
    assert absorbed >= 1, (
        f"expected pull handler to absorb >=1 snapshot; "
        f"list_calls={pull_client.list_calls!r} "
        f"download_calls={pull_client.download_calls!r}"
    )
    assert len(pull_client.download_calls) == 1

    # 7. Frank's local admin log now carries Alice's envelopes.
    frank_admin_log = resolve_admin_log_path(frank_cfg)
    assert frank_admin_log.exists(), "Frank's admin log should be created by absorb"
    body = frank_admin_log.read_text(encoding="utf-8")
    assert body.count("\n") >= 3, (
        "expected >=3 lines (Alice's three admin_add_recipient events) "
        f"in Frank's admin log, got body={body!r}"
    )
    assert "tn.recipient.added" in body
    # The DID Alice signed under MUST appear in the absorbed envelopes
    # so Frank's signature verification has the right key.
    assert alice["did"] in body, "Alice's DID must appear in Frank's absorbed admin log"

    # 8. The headline assertion: secure_read returns Alice's events,
    #    fully verified, with instructions attached for events whose
    #    type matches the agents policy. ``on_invalid="skip"`` (the
    #    default) is robust against any future tampering surface; the
    #    cross-language byte-compare matrix in
    #    ``crypto/tn-core/tests/secure_read_interop.rs`` pins canonical
    #    parity for every admin event type so this branch should not
    #    fire under normal operation.
    entries = list(tn.secure_read(log_path=frank_admin_log, cfg=frank_cfg))
    recipient_added = [
        e for e in entries if e.get("event_type") == "tn.recipient.added"
    ]
    assert len(recipient_added) >= 3, (
        f"secure_read should yield Alice's three tn.recipient.added events, "
        f"got {len(recipient_added)}; entries={entries!r}"
    )
    # The publisher's DID is on the envelope -- proves it really came from Alice.
    for e in recipient_added:
        assert e["did"] == alice["did"], (
            f"event came from {e.get('did')!r}, expected Alice ({alice['did']!r})"
        )

    # The agents policy declares a template for ``tn.recipient.added``,
    # so when Frank holds the ``tn.agents`` kit ``secure_read`` MUST
    # surface an ``instructions`` block alongside the data. This is a
    # hard assertion — the Rust runtime's emit-side splice fires
    # unconditionally for any event_type that has a policy template
    # loaded, and the cross-language ``test_agents_group.py`` /
    # ``crypto/tn-core/tests/agents_group.rs`` regression tests pin
    # that contract.
    with_instructions = [e for e in recipient_added if "instructions" in e]
    assert with_instructions, (
        "secure_read returned no ``instructions`` block on any absorbed "
        "tn.recipient.added entry. The agents policy was loaded "
        "(Alice's tn.agents.policy_published is in the log) and Frank's "
        "tn.agents kit is in his keystore, so the splice MUST have "
        "populated the tn.agents group on every admin event. If this "
        "assertion fires the splice has regressed — see "
        "``test_admin_events_splice_tn_agents`` in "
        "``tn-protocol/crypto/tn-core/tests/agents_group.rs`` and the "
        "Python sibling in ``tests/test_agents_group.py`` for the "
        "minimal repro."
    )
    inst = with_instructions[0]["instructions"]
    assert "newly-issued recipient kit" in inst["instruction"]
    assert "Replication" in inst["use_for"]
    # The bare six fields must NOT be flattened to top-level
    # (per spec §3.1).
    assert "instruction" not in with_instructions[0]
    assert "use_for" not in with_instructions[0]


# ── Phase B: Playwright UI wrapper -- DEFERRED ────────────────────────
#
# The plan's Phase B is an optional Playwright-driven test that drives
# the vault dashboard's invite flow before handing off to the SDK
# orchestration done above. We're deferring it pending dashboard auth
# scaffolding -- the existing dashboard.html doesn't yet ship an
# end-to-end "invite reader" wizard the way creator_platform's admin
# studio does, so the UI portion would either stub the navigation or
# wait for the invite UX to land.
#
# Structural sketch for the next session:
#
#   tnproto-org/tests/e2e/test_alice_frank_invite_flow.py
#     - Pytest fixture spawning uvicorn against ``src.app:app`` on a
#       free port, waiting for /healthz to return 200.
#     - Use ``pytest-playwright`` (sync or async API) to drive
#       http://localhost:<port>/dashboard.html.
#     - Alice's session: log in (or inject a JWT directly via
#       localStorage), open the project, click "Invite Reader",
#       receive the kit URL.
#     - Frank's session: paste the URL, accept, land in his panel.
#     - Then drop into the SDK orchestration above
#       (VaultPushHandler / VaultPullHandler / secure_read) to verify
#       the round-trip succeeded against the actual UI-issued kit.
#
# Once landed, the e2e/ directory should follow the same pattern as
# creator_platform/tests/e2e/test_ai_studio_admin_e2e.py.
