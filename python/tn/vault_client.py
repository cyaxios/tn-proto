"""HTTP client for the tnproto-org cloud vault.

Thin wrapper over httpx that speaks the vault's REST API:

- DID challenge/verify auth → JWT
- Projects CRUD
- File upload/download (sealed blobs via tn.sealing)
- Restore manifest
- Account prefs get/put
- Passkey-seed get/put/delete
- Reset (dev/test)

The client is synchronous (httpx.Client) because the wallet/CLI
paths the SDK exposes are synchronous. Async callers can wrap.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import Identity
from .sealing import SealedBlob, _seal, _unseal

DEFAULT_TIMEOUT = 30.0

# Default vault URL when caller doesn't specify one and no TN_VAULT_URL
# env var is set. Points at the hosted tn-proto vault. Set TN_VAULT_URL
# to ``http://localhost:8790`` (or any other base) for local dev against
# a self-hosted tnproto-org instance.
DEFAULT_VAULT_URL = "https://vault.tn-proto.org"
ENV_VAULT_URL = "TN_VAULT_URL"


def _tn_user_agent() -> str:
    """Self-identifying User-Agent for outbound HTTP calls.

    Mirrors ``tn.bootstrap._tn_user_agent`` so the urllib (cold-start
    bootstrap) and httpx (warm-path VaultClient) request shapes carry
    the same UA. Both routes need it because Cloudflare's Browser
    Integrity Check 403s any request whose UA matches the default
    ``Python-urllib/3.x`` shape with ``error code: 1010``. httpx
    happens to send ``python-httpx/X.Y.Z`` which avoids the block
    today, but pinning our own UA gives the vault operational
    visibility into client versions and decouples us from httpx's UA
    string changing.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return f"tn-proto/{version('tn-proto')}"
        except PackageNotFoundError:
            return "tn-proto/dev"
    except Exception:  # noqa: BLE001
        return "tn-proto/dev"


_DEFAULT_HEADERS = {"User-Agent": _tn_user_agent()}


def resolve_vault_url(base_url: str | None = None) -> str:
    """Resolve vault URL with the standard precedence:
    explicit arg > TN_VAULT_URL env var > DEFAULT_VAULT_URL (local).

    Centralized so all callers (VaultClient, CLI, sync verbs) agree on
    where requests go when no URL was passed in.
    """
    if base_url:
        return base_url
    return os.environ.get(ENV_VAULT_URL, DEFAULT_VAULT_URL)


def redeem_connect_code(
    code: str,
    did: str,
    sk: Ed25519PrivateKey,
    *,
    base_url: str | None = None,
    http_client: httpx.Client | None = None,
) -> dict:
    """Redeem a connect code against the vault to bind ``did`` to an account.

    The connect-code flow is the headless companion to the dashboard's
    "Connect a new app or device" action. The account owner mints a code
    in their browser; the operator pastes that code into this CLI; we
    sign the SHA-256 of the code's UTF-8 bytes with the device key and
    POST ``{code, did, signature_b64}`` to
    ``/api/v1/account/connect-codes/redeem``.

    On success the vault $addToSets the DID into ``accounts.minted_dids[]``
    so subsequent OAuth / DID-challenge sessions on this DID are
    recognised as belonging to the account.

    Returns the parsed JSON response (``{account_id, did, project_id,
    project_name, recipient_dids, name, bound_at}``).

    Raises :class:`VaultError` with the server-provided status / body on
    any non-2xx response: 400 (malformed signature), 401 (signature
    verification failed), 404 (unknown code), 409 (consumed or DID
    bound elsewhere), 410 (expired).

    Parameters
    ----------
    code
        The ``tn_connect_<random>`` code copied from the vault UI.
    did
        The redeemer's ``did:key:z...`` (Ed25519 only).
    sk
        Ed25519 private key matching ``did``. Used to sign the SHA-256
        of the code's UTF-8 bytes.
    base_url
        Optional vault base URL. Falls back to ``resolve_vault_url``
        (which honors ``TN_VAULT_URL`` env + ``DEFAULT_VAULT_URL``).
    http_client
        Optional pre-built ``httpx.Client`` for tests / connection
        reuse. A throwaway client is built when omitted.
    """
    message = hashlib.sha256(code.encode("utf-8")).digest()
    signature = sk.sign(message)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    payload = {
        "code": code,
        "did": did,
        "signature_b64": sig_b64,
    }
    url = f"{resolve_vault_url(base_url).rstrip('/')}/api/v1/account/connect-codes/redeem"
    owns_client = http_client is None
    client = http_client or httpx.Client(
        timeout=DEFAULT_TIMEOUT, headers=_DEFAULT_HEADERS
    )
    try:
        resp = client.post(url, json=payload)
    finally:
        if owns_client:
            client.close()
    if resp.status_code >= 400:
        body = resp.text[:512] if resp.text else ""
        raise VaultError(
            f"POST /api/v1/account/connect-codes/redeem returned {resp.status_code}",
            status=resp.status_code,
            body=body,
        )
    return resp.json()


class VaultError(RuntimeError):
    """Raised on any non-2xx vault response or transport failure."""

    def __init__(self, message: str, *, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class VaultClient:
    """Session-scoped vault client.

    Create with `VaultClient.for_identity(identity, base_url)` to get a
    client that's already authed. Tokens refresh automatically on 401.
    """

    base_url: str
    identity: Identity
    token: str | None = None
    _http: httpx.Client = field(default=None, repr=False)  # type: ignore

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")
        if self._http is None:
            self._http = httpx.Client(
                timeout=DEFAULT_TIMEOUT, headers=_DEFAULT_HEADERS
            )

    # -- Factory -----------------------------------------------------

    @classmethod
    def for_identity(
        cls,
        identity: Identity,
        base_url: str | None = None,
        *,
        auto_auth: bool = True,
    ) -> VaultClient:
        """Build a vault client for ``identity`` against ``base_url``.

        The standard factory. URL resolution honours the precedence
        ``explicit arg > TN_VAULT_URL env > DEFAULT_VAULT_URL`` via
        :func:`resolve_vault_url`. With ``auto_auth=True`` the client
        runs the DID challenge/verify dance immediately so callers can
        issue authenticated requests right away; pass ``False`` to
        defer (e.g. when feeding a mock client in tests).

        Args:
            identity: The :class:`tn.identity.Identity` the client
                speaks for. Provides both the DID (for the auth
                challenge) and the wrap key (for :meth:`upload_file` /
                :meth:`download_file`).
            base_url: Optional vault URL override. ``None`` falls back
                to ``TN_VAULT_URL`` then ``DEFAULT_VAULT_URL`` (the
                hosted tn-proto vault). Point at
                ``http://localhost:8790`` for self-hosted dev.
            auto_auth: When ``True`` (default) calls
                :meth:`authenticate` before returning. Set to ``False``
                if the caller will inject a token manually.

        Returns:
            A ready-to-use :class:`VaultClient`. Use it as a context
            manager (``with VaultClient.for_identity(...) as c:``) to
            close the underlying HTTP pool automatically.

        Raises:
            VaultError: If ``auto_auth=True`` and the DID
                challenge/verify roundtrip fails.

        Example:
            >>> from tn.identity import Identity
            >>> from tn.vault_client import VaultClient
            >>> identity = Identity.load()  # doctest: +SKIP
            >>> with VaultClient.for_identity(identity) as vc:  # doctest: +SKIP
            ...     projects = vc.list_projects()

        See Also:
            :func:`resolve_vault_url`: URL precedence logic.
            :meth:`authenticate`: The challenge/verify dance.
        """
        c = cls(base_url=resolve_vault_url(base_url), identity=identity)
        if auto_auth:
            c.authenticate()
        return c

    def close(self) -> None:
        """Close the underlying ``httpx.Client`` connection pool.

        Idempotent. Called automatically by ``__exit__`` so callers
        using ``with VaultClient.for_identity(...) as c:`` don't need
        to invoke this directly.
        """
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- Low-level request plumbing ---------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        h: dict[str, str] = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            body = resp.text[:512] if resp.text else ""
            raise VaultError(
                f"{resp.request.method} {resp.request.url.path} returned {resp.status_code}",
                status=resp.status_code,
                body=body,
            )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        content: bytes | None = None,
        headers: dict | None = None,
        reauth_on_401: bool = True,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        hdrs = self._headers(headers)
        resp = self._http.request(
            method,
            url,
            json=json_body,
            content=content,
            headers=hdrs,
        )
        if resp.status_code == 401 and reauth_on_401 and self.token:
            # Token expired — re-auth and retry once.
            self.token = None
            self.authenticate()
            hdrs = self._headers(headers)
            resp = self._http.request(
                method,
                url,
                json=json_body,
                content=content,
                headers=hdrs,
            )
        return resp

    # -- Auth (DID challenge/verify) --------------------------------

    def authenticate(self) -> str:
        """Run the DID challenge/verify dance and cache the JWT.

        Implements the two-step nonce protocol:

        1. ``POST /api/v1/auth/challenge`` with ``{did}``. The vault
           returns a one-shot nonce bound to that DID.
        2. Sign the UTF-8 bytes of the nonce with the Ed25519 device
           key (URL-safe base64, no padding — matches envelope
           signature convention).
        3. ``POST /api/v1/auth/verify`` with ``{did, nonce, signature}``.
           On success the vault returns a JWT, which gets cached on
           the instance for subsequent requests.

        :meth:`_request` calls this automatically on ``401`` once per
        call, so most callers never invoke it directly — the factory
        :meth:`for_identity` runs it for them at construction time.

        Returns:
            The freshly issued JWT (also cached on ``self.token``).

        Raises:
            VaultError: On any non-2xx response from either step
                (``400`` malformed request, ``401`` signature
                verification failed, ``404`` unknown DID, ``410``
                expired challenge, ``5xx`` server error).

        See Also:
            :meth:`for_identity`: Calls this for you when
                ``auto_auth=True``.
            `docs/spec/vault-http.md#auth <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/vault-http.md#auth>`_:
                Wire spec.
        """
        # Step 1: challenge
        resp = self._http.post(
            f"{self.base_url}/api/v1/auth/challenge",
            json={"did": self.identity.did},
        )
        self._raise_for_status(resp)
        nonce = resp.json()["nonce"]

        # Step 2: sign the nonce with Ed25519 device key
        priv = Ed25519PrivateKey.from_private_bytes(
            self.identity.device_private_key_bytes(),
        )
        signature = priv.sign(nonce.encode("utf-8"))
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

        # Step 3: verify
        resp = self._http.post(
            f"{self.base_url}/api/v1/auth/verify",
            json={
                "did": self.identity.did,
                "nonce": nonce,
                "signature": sig_b64,
            },
        )
        self._raise_for_status(resp)
        token = resp.json()["token"]
        self.token = token
        return token

    # -- Projects ---------------------------------------------------

    def create_project(self, name: str, *, ceremony_id: str | None = None) -> dict:
        """Create a new project bound to the authed account.

        ``POST /api/v1/projects``. Auto-authenticates if no JWT is
        cached.

        Args:
            name: Display name for the project.
            ceremony_id: Optional ceremony id to bind the project to.
                When omitted, the vault generates one.

        Returns:
            The project dict ``{id, name, ceremony_id, created_at, ...}``.

        Raises:
            VaultError: On any non-2xx response.

        See Also:
            :meth:`list_projects`, :meth:`get_project`,
            :meth:`delete_project`.
            `docs/spec/vault-http.md#project-routes <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/vault-http.md#project-routes>`_:
                Wire spec.
        """
        resp = self._request(
            "POST",
            "/api/v1/projects",
            json_body={"name": name, "ceremony_id": ceremony_id},
        )
        self._raise_for_status(resp)
        return resp.json()

    def list_projects(self) -> list[dict]:
        """List every project bound to the authed account.

        ``GET /api/v1/projects``.

        Returns:
            List of project dicts. Empty list if the account owns no
            projects. Order matches the vault's storage order (no
            guarantee).

        Raises:
            VaultError: On any non-2xx response.
        """
        resp = self._request("GET", "/api/v1/projects")
        self._raise_for_status(resp)
        return resp.json()

    def get_project(self, project_id: str) -> dict:
        """Fetch a single project's metadata.

        ``GET /api/v1/projects/{project_id}``.

        Args:
            project_id: The project's UUID-shaped id.

        Returns:
            The project dict ``{id, name, ceremony_id, ...}``.

        Raises:
            VaultError: ``404`` if the project doesn't exist or the
                authed account can't see it; ``403`` if cross-account.
        """
        resp = self._request("GET", f"/api/v1/projects/{project_id}")
        self._raise_for_status(resp)
        return resp.json()

    def delete_project(self, project_id: str) -> None:
        """Delete a project and every file under it.

        ``DELETE /api/v1/projects/{project_id}``. Permanent — the
        vault does NOT keep a soft-delete tombstone. Callers should
        confirm with the user before invoking.

        Args:
            project_id: The project's UUID-shaped id.

        Raises:
            VaultError: ``404`` if missing, ``403`` if cross-account.
        """
        resp = self._request("DELETE", f"/api/v1/projects/{project_id}")
        self._raise_for_status(resp)

    # -- Files ------------------------------------------------------

    def upload_sealed(
        self,
        project_id: str,
        file_name: str,
        sealed: SealedBlob,
    ) -> dict:
        """Upload a pre-sealed blob.

        ``PUT /api/v1/projects/{project_id}/files/{file_name}``.
        Use when the caller has already sealed the blob (e.g. via
        :func:`tn.sealing._seal`) and wants direct upload without
        re-sealing.

        Args:
            project_id: Owner project's id.
            file_name: Destination filename inside the project. The
                vault treats this as an opaque key; namespacing /
                folder separators are caller-defined.
            sealed: Pre-sealed payload. Serialised via
                :meth:`SealedBlob.to_bytes` and sent as
                ``application/octet-stream``.

        Returns:
            The vault's file metadata dict
            ``{name, size, sha256, uploaded_at, ...}``.

        Raises:
            VaultError: ``404`` (no such project), ``413`` (payload
                too large), other 4xx/5xx.

        See Also:
            :meth:`upload_file`: Convenience wrapper that seals the
                plaintext for you.
            :meth:`download_sealed`: The inverse.
        """
        wire = sealed.to_bytes()
        resp = self._request(
            "PUT",
            f"/api/v1/projects/{project_id}/files/{file_name}",
            content=wire,
            headers={"Content-Type": "application/octet-stream"},
        )
        self._raise_for_status(resp)
        return resp.json()

    def upload_file(
        self,
        project_id: str,
        file_name: str,
        plaintext: bytes,
        *,
        ceremony_id: str,
    ) -> dict:
        """Seal ``plaintext`` under this identity's wrap key and upload.

        The convenience wrapper for the common case where the caller
        holds raw bytes. It runs :func:`tn.sealing._seal` with the
        identity's vault wrap key and the standard AAD tuple
        (``did``, ``ceremony_id``, ``file_name``) and then forwards to
        :meth:`upload_sealed`.

        Args:
            project_id: Owner project's id.
            file_name: Destination filename inside the project. Bound
                into the seal AAD — :meth:`download_file` MUST be
                called with the same ``file_name`` or unsealing fails.
            plaintext: Raw bytes to seal and upload.
            ceremony_id: Ceremony that scopes the wrap key. Bound into
                the seal AAD — :meth:`download_file` MUST be called
                with the same ``ceremony_id``.

        Returns:
            The vault's file metadata dict (see :meth:`upload_sealed`).

        Raises:
            VaultError: On any non-2xx response.

        See Also:
            :meth:`upload_sealed`: Lower-level entry that takes a
                pre-built :class:`SealedBlob`.
            :meth:`download_file`: The inverse.
            `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
                AAD construction + seal/unseal spec.
        """
        wk = self.identity.vault_wrap_key()
        blob = _seal(
            plaintext,
            wrap_key=wk,
            did=self.identity.did,
            ceremony_id=ceremony_id,
            file_name=file_name,
        )
        return self.upload_sealed(project_id, file_name, blob)

    def download_sealed(self, project_id: str, file_name: str) -> SealedBlob:
        """Download a file's raw sealed blob without unsealing.

        ``GET /api/v1/projects/{project_id}/files/{file_name}``.

        Use when the caller wants to inspect / forward the sealed
        bytes (e.g. mirroring to another vault, or unsealing later
        with a different wrap key context).

        Args:
            project_id: Owner project's id.
            file_name: File key inside the project.

        Returns:
            The :class:`SealedBlob` parsed from the response body.

        Raises:
            VaultError: ``404`` if the file (or project) doesn't exist;
                ``403`` if cross-account; other 4xx/5xx.

        See Also:
            :meth:`download_file`: Convenience wrapper that unseals for
                you.
            :meth:`upload_sealed`: The inverse.
        """
        resp = self._request(
            "GET",
            f"/api/v1/projects/{project_id}/files/{file_name}",
        )
        self._raise_for_status(resp)
        return SealedBlob.from_bytes(resp.content)

    def download_file(
        self,
        project_id: str,
        file_name: str,
        *,
        ceremony_id: str,
    ) -> bytes:
        """Download a file and unseal it under this identity's wrap key.

        Inverse of :meth:`upload_file`. Runs :meth:`download_sealed`
        then :func:`tn.sealing._unseal` with the AAD tuple
        (``did``, ``ceremony_id``, ``file_name``) — the seal MUST have
        been written with the same tuple or unsealing raises.

        Args:
            project_id: Owner project's id.
            file_name: File key inside the project. Must match what
                was passed to :meth:`upload_file`.
            ceremony_id: Ceremony id that scopes the wrap key. Must
                match what was passed to :meth:`upload_file`.

        Returns:
            The original plaintext bytes.

        Raises:
            VaultError: ``404`` / ``403`` from the HTTP layer.
            cryptography.exceptions.InvalidTag: AAD mismatch or
                tampered ciphertext.

        See Also:
            :meth:`upload_file`: The inverse.
            :meth:`download_sealed`: Lower-level entry that returns the
                raw :class:`SealedBlob` without unsealing.
            `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
                AAD construction + seal/unseal spec.
        """
        blob = self.download_sealed(project_id, file_name)
        return _unseal(
            blob,
            wrap_key=self.identity.vault_wrap_key(),
            expected_did=self.identity.did,
            expected_ceremony_id=ceremony_id,
            expected_file_name=file_name,
        )

    def list_files(self, project_id: str) -> list[dict]:
        """List every file under a project.

        ``GET /api/v1/projects/{project_id}/files``.

        Args:
            project_id: Owner project's id.

        Returns:
            List of file metadata dicts
            ``[{name, size, sha256, uploaded_at, ...}]``. Empty list
            if the project holds no files. Order matches the vault's
            storage order (no guarantee).

        Raises:
            VaultError: ``404`` if the project doesn't exist; ``403``
                if cross-account.
        """
        resp = self._request("GET", f"/api/v1/projects/{project_id}/files")
        self._raise_for_status(resp)
        return resp.json()

    def delete_file(self, project_id: str, file_name: str) -> None:
        """Delete a single file from a project.

        ``DELETE /api/v1/projects/{project_id}/files/{file_name}``.
        Permanent — no soft-delete tombstone.

        Args:
            project_id: Owner project's id.
            file_name: File key inside the project.

        Raises:
            VaultError: ``404`` if the file (or project) doesn't exist;
                ``403`` if cross-account.
        """
        resp = self._request(
            "DELETE",
            f"/api/v1/projects/{project_id}/files/{file_name}",
        )
        self._raise_for_status(resp)

    # -- Restore ----------------------------------------------------

    def restore_manifest(self, project_id: str) -> dict:
        """Fetch the project's restore manifest.

        ``POST /api/v1/projects/{project_id}/restore``. Returns the
        list of files a fresh device needs to pull down to rebuild
        the project's local state. Used by the recovery flow after
        a passkey-driven seed restore.

        Args:
            project_id: Owner project's id.

        Returns:
            Manifest dict ``{project_id, files: [{name, sha256, size,
            ...}], generated_at, ...}``.

        Raises:
            VaultError: ``404`` if the project doesn't exist; ``403``
                if cross-account.
        """
        resp = self._request("POST", f"/api/v1/projects/{project_id}/restore")
        self._raise_for_status(resp)
        return resp.json()

    # -- Account prefs ---------------------------------------------

    def get_prefs(self) -> dict:
        """Fetch the authed account's preferences.

        ``GET /api/v1/account/prefs``.

        Returns:
            Prefs dict. Currently the only field is
            ``default_new_ceremony_mode`` (``"per-project"`` or
            ``"per-recipient"``) but the shape is forward-compatible.

        Raises:
            VaultError: On any non-2xx response.

        See Also:
            :meth:`put_prefs`: The setter.
        """
        resp = self._request("GET", "/api/v1/account/prefs")
        self._raise_for_status(resp)
        return resp.json()

    def put_prefs(self, default_new_ceremony_mode: str) -> dict:
        """Update the authed account's preferences.

        ``PUT /api/v1/account/prefs``. Replaces (not merges) the
        prefs document.

        Args:
            default_new_ceremony_mode: ``"per-project"`` or
                ``"per-recipient"``. Drives whether the dashboard's
                "new ceremony" action mints one ceremony per project
                or one per recipient.

        Returns:
            The persisted prefs dict (mirror of :meth:`get_prefs`).

        Raises:
            VaultError: ``400`` on unknown mode value; other 4xx/5xx.

        See Also:
            :meth:`get_prefs`: The getter.
        """
        resp = self._request(
            "PUT",
            "/api/v1/account/prefs",
            json_body={"default_new_ceremony_mode": default_new_ceremony_mode},
        )
        self._raise_for_status(resp)
        return resp.json()

    # -- Passkey seed ----------------------------------------------

    def put_passkey_seed(
        self,
        *,
        credential_id: str,
        sealed_seed_blob_b64: str,
        nonce_b64: str,
        salt_b64: str,
    ) -> None:
        """Store a passkey-sealed seed for account recovery.

        ``POST /api/v1/account/passkey-seed``. The vault holds the
        ciphertext only — the unwrapping happens browser-side via the
        WebAuthn PRF extension. Without the original authenticator
        nobody (including the vault operator) can recover the seed.

        Args:
            credential_id: WebAuthn credential id (base64url) that
                identifies which passkey produced the seal.
            sealed_seed_blob_b64: Ciphertext of the device seed, base64
                (standard, padded).
            nonce_b64: AEAD nonce used during sealing, base64 (standard,
                padded).
            salt_b64: HKDF salt fed into the PRF-derived KEK, base64
                (standard, padded).

        Raises:
            VaultError: ``400`` on malformed inputs; ``409`` if a seed
                is already stored under a different credential and the
                server policy refuses overwrite.

        See Also:
            :meth:`get_passkey_seed`, :meth:`delete_passkey_seed`.
        """
        resp = self._request(
            "POST",
            "/api/v1/account/passkey-seed",
            json_body={
                "credential_id": credential_id,
                "sealed_seed_blob_b64": sealed_seed_blob_b64,
                "nonce_b64": nonce_b64,
                "salt_b64": salt_b64,
            },
        )
        self._raise_for_status(resp)

    def get_passkey_seed(self) -> dict | None:
        """Fetch the passkey-sealed seed for this account (if any).

        ``GET /api/v1/account/passkey-seed``. The recovery flow on a
        fresh device hits this to pull the ciphertext, then unwraps it
        browser-side via WebAuthn PRF.

        Returns:
            Dict ``{credential_id, sealed_seed_blob_b64, nonce_b64,
            salt_b64}`` if a seed is stored, or ``None`` (HTTP 404)
            if the account hasn't registered one yet.

        Raises:
            VaultError: On any non-2xx response other than 404.

        See Also:
            :meth:`put_passkey_seed`, :meth:`delete_passkey_seed`.
        """
        resp = self._request(
            "GET",
            "/api/v1/account/passkey-seed",
            reauth_on_401=True,
        )
        if resp.status_code == 404:
            return None
        self._raise_for_status(resp)
        return resp.json()

    def delete_passkey_seed(self) -> None:
        """Remove the passkey-sealed seed from the vault.

        ``DELETE /api/v1/account/passkey-seed``. Use when rotating
        the recovery passkey — call this then re-register via
        :meth:`put_passkey_seed`.

        Raises:
            VaultError: On any non-2xx response.

        See Also:
            :meth:`put_passkey_seed`, :meth:`get_passkey_seed`.
        """
        resp = self._request("DELETE", "/api/v1/account/passkey-seed")
        self._raise_for_status(resp)

    # -- Account binding (connect-code redemption) -----------------

    def post_received_kit(
        self,
        *,
        project_id: str,
        publisher_identity: str,
        recipient_identity: str,
        label: str | None,
        kit_blob_b64: str | None,
        manifest: dict | None,
        source_ts: str | None,
        source_ceremony_id: str | None,
    ) -> dict:
        """Record a kit_bundle absorption against the bound vault account.

        Counterpart to the dashboard's Absorb action. Lets a CLI-side
        absorb tell the vault "this account holds a reader leaf in
        <publisher>'s project" so the ``/projects -> Received`` tab on
        the dashboard surfaces it alongside browser-absorbed kits.

        Auth: standard bearer (the DID-challenge JWT this client holds).
        The route accepts that token because the DID was bound to the
        account via :func:`redeem_connect_code`.

        Args:
            project_id: Publisher's project id the kit belongs to.
            publisher_identity: Publisher's ``did:key:z…``.
            recipient_identity: This client's ``did:key:z…`` (the
                reader leaf the kit grants).
            label: Optional human label for the kit (mirrors the
                dashboard's free-text field).
            kit_blob_b64: Standard-padded base64 of the absorbed kit
                bytes, or ``None`` if the caller has already stored
                them out-of-band.
            manifest: Optional decoded manifest dict to embed in the
                record so the dashboard can render it without a
                follow-up fetch.
            source_ts: ISO-8601 timestamp of the originating entry
                (helps the dashboard sort + dedupe).
            source_ceremony_id: Ceremony id the kit was issued under.

        Returns:
            The persisted record dict
            ``{id, project_id, publisher_identity, recipient_identity,
            label, source_ts, source_ceremony_id, created_at, ...}``.

        Raises:
            VaultError: ``400`` on malformed inputs; ``404`` if the
                publisher's project isn't visible to this account.

        See Also:
            :func:`redeem_connect_code`: How the calling DID got bound
                to the account in the first place.
        """
        body = {
            "project_id": project_id,
            "publisher_identity": publisher_identity,
            "recipient_identity": recipient_identity,
            "label": label,
            "kit_blob_b64": kit_blob_b64,
            "manifest": manifest,
            "source_ts": source_ts,
            "source_ceremony_id": source_ceremony_id,
        }
        resp = self._request(
            "POST",
            "/api/v1/account/received-kits",
            json_body=body,
        )
        self._raise_for_status(resp)
        return resp.json()

    # -- Reset (dev/test) ------------------------------------------

    def reset_account(self) -> dict:
        """Wipe all projects, files, passkey-seed, and prefs for the authed DID.

        ``POST /api/v1/account/reset``. Body echoes the DID under
        ``{"confirm": <did>}`` to make accidental triggering harder.

        Dev/test convenience — production accounts should never call
        this. The vault may gate this route behind a deployment-time
        flag.

        Returns:
            Dict ``{wiped: {projects: int, files: int, ...}}`` summarising
            what was removed.

        Raises:
            VaultError: ``403`` if the route is disabled on this
                deployment; other 4xx/5xx.
        """
        resp = self._request(
            "POST",
            "/api/v1/account/reset",
            json_body={"confirm": self.identity.did},
        )
        self._raise_for_status(resp)
        return resp.json()
