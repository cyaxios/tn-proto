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
import os
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import Identity
from .sealing import SealedBlob, _seal, _unseal

DEFAULT_TIMEOUT = 30.0

# Default vault URL when caller doesn't specify one and no TN_VAULT_URL
# env var is set. Points at a locally-running tnproto-org instance
# (the default port from `tnproto-org/src/config.py` and `runme.bat`).
# Override with TN_VAULT_URL env var or by passing base_url explicitly.
DEFAULT_VAULT_URL = "http://localhost:8790"
ENV_VAULT_URL = "TN_VAULT_URL"


def resolve_vault_url(base_url: str | None = None) -> str:
    """Resolve vault URL with the standard precedence:
    explicit arg > TN_VAULT_URL env var > DEFAULT_VAULT_URL (local).

    Centralized so all callers (VaultClient, CLI, sync verbs) agree on
    where requests go when no URL was passed in.
    """
    if base_url:
        return base_url
    return os.environ.get(ENV_VAULT_URL, DEFAULT_VAULT_URL)


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
            self._http = httpx.Client(timeout=DEFAULT_TIMEOUT)

    # -- Factory -----------------------------------------------------

    @classmethod
    def for_identity(
        cls,
        identity: Identity,
        base_url: str | None = None,
        *,
        auto_auth: bool = True,
    ) -> VaultClient:
        """Build a vault client for `identity` against `base_url`.

        If `base_url` is None, falls back to the TN_VAULT_URL env var
        and finally to DEFAULT_VAULT_URL (a local tnproto-org dev
        instance at http://localhost:8790). Pass an explicit base_url
        for production use.
        """
        c = cls(base_url=resolve_vault_url(base_url), identity=identity)
        if auto_auth:
            c.authenticate()
        return c

    def close(self) -> None:
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
        """Run /auth/challenge + /auth/verify and cache the JWT."""
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
        resp = self._request(
            "POST",
            "/api/v1/projects",
            json_body={"name": name, "ceremony_id": ceremony_id},
        )
        self._raise_for_status(resp)
        return resp.json()

    def list_projects(self) -> list[dict]:
        resp = self._request("GET", "/api/v1/projects")
        self._raise_for_status(resp)
        return resp.json()

    def get_project(self, project_id: str) -> dict:
        resp = self._request("GET", f"/api/v1/projects/{project_id}")
        self._raise_for_status(resp)
        return resp.json()

    def delete_project(self, project_id: str) -> None:
        resp = self._request("DELETE", f"/api/v1/projects/{project_id}")
        self._raise_for_status(resp)

    # -- Files ------------------------------------------------------

    def upload_sealed(
        self,
        project_id: str,
        file_name: str,
        sealed: SealedBlob,
    ) -> dict:
        """Upload a pre-sealed blob. Returns the vault's file metadata."""
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
        """Seal `plaintext` under this identity's wrap key and upload."""
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
        """Download + _unseal + verify AAD."""
        blob = self.download_sealed(project_id, file_name)
        return _unseal(
            blob,
            wrap_key=self.identity.vault_wrap_key(),
            expected_did=self.identity.did,
            expected_ceremony_id=ceremony_id,
            expected_file_name=file_name,
        )

    def list_files(self, project_id: str) -> list[dict]:
        resp = self._request("GET", f"/api/v1/projects/{project_id}/files")
        self._raise_for_status(resp)
        return resp.json()

    def delete_file(self, project_id: str, file_name: str) -> None:
        resp = self._request(
            "DELETE",
            f"/api/v1/projects/{project_id}/files/{file_name}",
        )
        self._raise_for_status(resp)

    # -- Restore ----------------------------------------------------

    def restore_manifest(self, project_id: str) -> dict:
        """Get the list of files to pull down for recovery."""
        resp = self._request("POST", f"/api/v1/projects/{project_id}/restore")
        self._raise_for_status(resp)
        return resp.json()

    # -- Account prefs ---------------------------------------------

    def get_prefs(self) -> dict:
        resp = self._request("GET", "/api/v1/account/prefs")
        self._raise_for_status(resp)
        return resp.json()

    def put_prefs(self, default_new_ceremony_mode: str) -> dict:
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
        resp = self._request("DELETE", "/api/v1/account/passkey-seed")
        self._raise_for_status(resp)

    # -- Reset (dev/test) ------------------------------------------

    def reset_account(self) -> dict:
        """Dev/test convenience: wipe all projects+files+passkey-seed+prefs
        for the authenticated DID. Body echoes DID to confirm intent."""
        resp = self._request(
            "POST",
            "/api/v1/account/reset",
            json_body={"confirm": self.identity.did},
        )
        self._raise_for_status(resp)
        return resp.json()
