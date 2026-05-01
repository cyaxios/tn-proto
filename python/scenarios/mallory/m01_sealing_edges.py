"""Mallory m01 — sealing security edges.

Exercises the three paths that a vault-operator-gone-rogue or a
network MITM could attack: tampered ciphertext, tampered AAD, and
wrong wrap key. All three must fail cleanly with SealingError.

Does not require the live vault server — this is pure SDK-side
crypto verification. Runs without needing vault fixture.
"""

from __future__ import annotations

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity
from tn.sealing import SealedBlob, SealingError, seal, unseal


class MallorySealingEdges(Scenario):
    persona = "mallory"
    name = "m01_sealing_edges"
    tags = {"jwe", "security", "sealing"}
    needs_vault = False

    def run(self, ctx: ScenarioContext) -> None:
        victim = Identity.create_new()
        wk = victim.vault_wrap_key()
        did = victim.did
        cer_id = "cer_test"
        fname = "default.jwe.mykey"
        plaintext = b"victim's private key material, very secret"

        blob = seal(
            plaintext,
            wrap_key=wk,
            did=did,
            ceremony_id=cer_id,
            file_name=fname,
        )

        # --- Happy path control ---------------------------------
        ok = unseal(
            blob,
            wrap_key=wk,
            expected_did=did,
            expected_ceremony_id=cer_id,
            expected_file_name=fname,
        )
        ctx.assert_invariant("control_unseal_works", ok == plaintext)

        # --- Tampered ciphertext -------------------------------
        tampered_ct = bytes([blob.ct[0] ^ 0xFF]) + blob.ct[1:]
        tampered = SealedBlob(
            v=blob.v,
            nonce=blob.nonce,
            ct=tampered_ct,
            aad=blob.aad,
        )
        try:
            unseal(tampered, wrap_key=wk)
            ctx.assert_invariant("tampered_ct_rejected", False)
        except SealingError:
            ctx.assert_invariant("tampered_ct_rejected", True)

        # --- Tampered AAD (attacker tries to remap blob's logical path) -
        evil_aad = SealedBlob(
            v=blob.v,
            nonce=blob.nonce,
            ct=blob.ct,
            aad=f"did:key:z6Mkattacker/cer_attacker/{fname}",
        )
        try:
            unseal(evil_aad, wrap_key=wk)
            ctx.assert_invariant("tampered_aad_rejected", False)
        except SealingError:
            ctx.assert_invariant("tampered_aad_rejected", True)

        # --- AAD-mismatch detection at caller side -------------
        # Legitimate blob, but caller expects a different file_name.
        try:
            unseal(
                blob,
                wrap_key=wk,
                expected_did=did,
                expected_ceremony_id=cer_id,
                expected_file_name="a.different.file",
            )
            ctx.assert_invariant("expected_aad_mismatch_rejected", False)
        except SealingError:
            ctx.assert_invariant("expected_aad_mismatch_rejected", True)

        # --- Wrong wrap key (attacker has a different mnemonic) ----
        attacker = Identity.create_new()
        try:
            unseal(blob, wrap_key=attacker.vault_wrap_key())
            ctx.assert_invariant("wrong_wrap_key_rejected", False)
        except SealingError:
            ctx.assert_invariant("wrong_wrap_key_rejected", True)

        # --- Cross-mnemonic isolation: two users' blobs don't unseal each other -
        alice = Identity.create_new()
        bob = Identity.create_new()
        alice_blob = seal(
            b"alice payload",
            wrap_key=alice.vault_wrap_key(),
            did=alice.did,
            ceremony_id="cer_a",
            file_name="f",
        )
        try:
            unseal(alice_blob, wrap_key=bob.vault_wrap_key())
            ctx.assert_invariant("cross_user_isolation", False)
        except SealingError:
            ctx.assert_invariant("cross_user_isolation", True)

        # --- Wire format corruption ---------------------------
        bad_wire = b"{not valid sealed blob JSON"
        try:
            SealedBlob.from_bytes(bad_wire)
            ctx.assert_invariant("bad_wire_rejected", False)
        except SealingError:
            ctx.assert_invariant("bad_wire_rejected", True)

        ctx.record("total_attacks_tested", 7)
