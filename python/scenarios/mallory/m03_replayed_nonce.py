"""Mallory m03 — replayed nonce at /auth/verify must be rejected.

The DID challenge-response flow issues a nonce once; signing + verifying
consumes it server-side. A second verify with the same nonce must fail
(the nonce row was deleted atomically by find_one_and_delete in
routes_auth.py).
"""

from __future__ import annotations

import base64

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity


class MalloryReplayedNonce(Scenario):
    persona = "mallory"
    name = "m03_replayed_nonce"
    tags = {"vault", "security", "auth"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None
        base = ctx.vault.base_url

        ident = Identity.create_new()
        priv = Ed25519PrivateKey.from_private_bytes(
            ident.device_private_key_bytes(),
        )

        with httpx.Client(timeout=10.0) as c:
            # Step 1: get a nonce
            r = c.post(f"{base}/api/v1/auth/challenge", json={"did": ident.did})
            ctx.assert_invariant("challenge_ok", r.status_code == 200)
            nonce = r.json()["nonce"]

            # Step 2: verify — first time should succeed
            sig = priv.sign(nonce.encode("utf-8"))
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
            r1 = c.post(
                f"{base}/api/v1/auth/verify",
                json={
                    "did": ident.did,
                    "nonce": nonce,
                    "signature": sig_b64,
                },
            )
            ctx.record("first_verify_status", r1.status_code)
            ctx.assert_invariant("first_verify_ok", r1.status_code == 200)

            # Step 3: verify AGAIN with the same nonce — must fail
            r2 = c.post(
                f"{base}/api/v1/auth/verify",
                json={
                    "did": ident.did,
                    "nonce": nonce,
                    "signature": sig_b64,
                },
            )
            ctx.record("replay_status", r2.status_code)
            ctx.record("replay_body", r2.text[:200])
            ctx.assert_invariant(
                "replay_rejected",
                r2.status_code in (400, 401, 403, 404),
            )
