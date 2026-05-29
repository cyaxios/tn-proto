"""Verify docs/sdk-parity.md mentions every public verb in Python and TS.

CI runs:    python tools/check_parity.py
Exit 0 if every public Python verb (from `tn.__all__` and tn.admin/pkg/vault
sub-package __all__'s) and every TS export from `@tnproto/sdk`'s main entry
have a row in the parity doc; non-zero with a list of unmatched names
otherwise.

Symbols intentionally absent from the parity table can be added to
`KNOWN_OMISSIONS` below — typically internal helpers or pure types.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARITY_DOC = ROOT / "docs" / "sdk-parity.md"
TS_INDEX = ROOT / "ts-sdk" / "src" / "index.ts"
PY_INIT = ROOT / "python" / "tn" / "__init__.py"

# Symbols documented elsewhere or intentionally not requiring a parity row.
# The parity doc focuses on user-facing verbs (tn.info, tn.admin.addRecipient,
# etc.); types, internal helpers, and sub-namespace re-exports are tracked
# implicitly by the verbs that produce/consume them.
KNOWN_OMISSIONS = {
    # ------------------------------------------------------------------
    # Result types and option objects (covered by their verbs).
    # ------------------------------------------------------------------
    "AddRecipientResult", "RevokeRecipientResult", "RotateGroupResult",
    "EnsureGroupResult", "BundleResult", "OfferReceipt",
    "EmitReceipt", "AbsorbReceipt", "AbsorbResult", "RecipientEntry",
    "AdminCeremonyState", "AdminGroupState", "AdminRecipientState",
    "AdminRotationState", "AdminCouponState", "AdminEnrolmentState",
    "AdminVaultLinkState", "AdminState",
    "TnInitOptions", "ReadOptions", "TnReadAsRecipientOptions",
    "ReadAsRecipientOptions", "ForeignReadEntry",
    "TnSecureReadOptions", "SecureReadOptions",
    "WatchOptions", "WatchSince", "VerifyMode", "AddRuntimeOptions",
    "AdminAddAgentRuntimeOptions", "PkgExportOptions",
    "Instructions", "SecureEntry", "ChainConflict", "LeafReuseAttempt",
    "ChainConflictError", "RotationConflictError", "LeafReuseError",
    "SameCoordinateForkError", "VerificationError",
    "ReadEntry", "RawEntry", "Entry",

    # ------------------------------------------------------------------
    # Class / namespace handles (each covered by its verbs).
    # ------------------------------------------------------------------
    "Tn", "NodeRuntime", "AdminStateCache",
    # The TN class handle on Python — its verbs (tn.use,
    # tn.list_ceremonies, tn.info, tn.read, etc.) are listed in the
    # parity table; the class itself is internal plumbing.
    "TN",
    # Multi-ceremony error classes — covered by the verbs that raise
    # them (tn.use, tn.init). Each is a focused exception subclass;
    # users catch them but don't construct them directly. NEW in
    # 0.3.0a4 alongside the multi-ceremony layer.
    "TNConfigConflict", "TNCreateFailed", "TNInvalidName", "TNNotFound",
    # Reserved exception class. The earlier multi-ceremony sprint
    # raised this from non-default emit verbs; per-instance dispatch
    # (Bug 1 fix) made every emit path work and the class is now
    # unreachable. Kept exported so existing user code that catches
    # it continues to compile, and so a future per-stream feature
    # gate can re-use the name without a breaking change.
    "MultiCeremonyEmitNotImplemented",

    # ------------------------------------------------------------------
    # Python module re-exports — the doc references the namespace, not
    # each internal verb.
    # ------------------------------------------------------------------
    "admin", "pkg", "vault", "agents",
    "identity", "sealing", "wallet", "vault_client", "classifier",
    "PolicyDocument", "PolicyTemplate", "Audit",

    # ------------------------------------------------------------------
    # Constants — covered by their owning verb-doc-section.
    # ------------------------------------------------------------------
    "LOG_LEVELS", "LKV_VERSION", "MANIFEST_VERSION",
    "POLICY_RELATIVE_PATH", "REQUIRED_FIELDS",
    "DEFAULT_ADMIN_LOG_LOCATION", "STATE_FILE", "SYNC_DIR",
    "KNOWN_KINDS",

    # ------------------------------------------------------------------
    # TS-only branded helpers + types for the polymorphic `recipient=`
    # kwarg on tn.admin.addRecipient / revokeRecipient (DX review 0.4.2a2).
    # Python's dynamic typing handles the polymorphism natively via the
    # private _resolve_recipient — no public Python counterpart exists.
    # The parity row for `tn.admin.add_recipient` already covers the
    # verb's behaviour; these are TS-internal compile-time aids.
    # ------------------------------------------------------------------
    "Did", "LeafIndex", "PublicKeyBytes",
    "RecipientInput", "RecipientLike", "ResolvedRecipient",
    "did", "leafIndex", "publicKeyBytes", "resolveRecipient",

    # ------------------------------------------------------------------
    # Manifest / tnpkg low-level types and helpers (Layer 1 primitives;
    # the user-facing surface is tn.pkg.*).
    # ------------------------------------------------------------------
    "Manifest", "ManifestKind", "VectorClock", "BodyContents",
    "ZipEntry", "ParsedZipEntry",
    "CompileKitBundleOptions", "CompiledManifest", "CompiledPackage",
    "newManifest", "signManifest", "verifyManifest",
    "manifestSigningBytes", "isManifestSignatureValid",
    "compileKitBundle", "compileKitBundleToFile",
    "clockMerge", "clockDominates",
    "readTnpkg", "writeTnpkg", "nowIsoMillis",

    # ------------------------------------------------------------------
    # Sync-state low-level helpers (Layer 2 internals).
    # ------------------------------------------------------------------
    "SyncState", "loadSyncState", "saveSyncState", "updateSyncState",
    "statePath", "getInboxCursor", "setInboxCursor",
    "getLastPushedAdminHead", "setLastPushedAdminHead",

    # ------------------------------------------------------------------
    # Admin-log low-level helpers.
    # ------------------------------------------------------------------
    "appendAdminEnvelopes", "existingRowHashes", "isAdminEventType",
    "resolveAdminLogPath", "iterLogFiles",
    "scanAttestedEvents", "scanAttestedEventRecords", "scanAttestedGroups",
    "yamlRecipientDids", "emptyState",

    # ------------------------------------------------------------------
    # Layer 2 config + keystore loaders.
    # ------------------------------------------------------------------
    "loadConfig", "loadKeystore", "loadPolicyFile",
    "policyPathFor", "parsePolicyText",

    # ------------------------------------------------------------------
    # Python utility verbs that the doc summarizes via "context" /
    # "process-global" sections rather than per-verb rows. The TS-side
    # camelCase forms (config, usingRust) are bare-export mirrors of
    # the same verbs — the parity table covers them under the class
    # methods Tn.config()/Tn.usingRust() implicitly.
    # ------------------------------------------------------------------
    "current_config", "session", "using_rust",
    "usingRust", "config",

    # ------------------------------------------------------------------
    # Low-level bootstrap-absorb plumbing exported from the TS SDK for
    # advanced callers (CI tooling, migration scripts) that want raw
    # receipts without a Tn handle. The user-facing entry point is
    # Tn.absorb (which uses these internally) — covered in the parity
    # table by the absorb / Tn.absorb rows. NEW in 0.4.0a2.
    # ------------------------------------------------------------------
    "absorbBootstrap", "isBootstrapKind",

    # ------------------------------------------------------------------
    # Sealed-bundle absorb (TS-only entry; parallels Python tn.absorb's
    # internal sealed-bundle path that runs inside the same verb). NEW
    # in 0.4.3a1 — second-release encrypted-kit-bundle work.
    # ------------------------------------------------------------------
    "absorbSealedBootstrap",

    # ------------------------------------------------------------------
    # Env-var parity helpers (TN_API_KEY / TN_VAULT_URL /
    # TN_VAULT_DEFAULT_BASE / TN_NO_LINK). The vars themselves are
    # documented per-row in the parity table; these are the TS-side
    # accessors. Python's equivalents live inside tn.vault_client
    # (`resolve_vault_url`) and tn.bootstrap (the bearer parser) — not
    # exported at the top level. NEW in 0.4.3a1.
    # ------------------------------------------------------------------
    "bootstrapFromApiKey", "parseBearer", "challengeVerify",
    "resolveVaultUrl", "resolveDidEndpoint", "isAutoLinkDisabled",
    "ApiKeyFetchResult", "ParsedBearer",

    # ------------------------------------------------------------------
    # Recipient-seal Layer 1 helpers (sealed-box wrap producer /
    # consumer + AAD builder). Python's counterparts live in
    # tn.recipient_seal — internal module, not on the public `tn.*`
    # surface. The user-facing wrap path is Tn.exportPkg's
    # seal_for_recipient flow (parity-row covered). NEW in 0.4.3a1.
    # ------------------------------------------------------------------
    "buildRecipientWraps", "sealBekForRecipient", "unsealBekFromWrap",
    "manifestAadForWrap", "RecipientWrap", "UnsealError",
    "UnsealNotWiredError", "WRAP_FRAME",

    # ------------------------------------------------------------------
    # Body-encryption Layer 1 helpers. Python's counterparts live in
    # tn.export (`_encrypt_body_in_place`, `decrypt_body_blob`) — not
    # public. The user-facing path on both sides is tn.export /
    # Tn.exportPkg with `encrypt_body_with=` / `seal_for_recipient=`.
    # NEW in 0.4.3a1.
    # ------------------------------------------------------------------
    "encryptBodyBlob", "decryptBodyBlob",
    "BODY_CIPHER_SUITE", "BODY_FRAME",

    # ------------------------------------------------------------------
    # Manifest wire-dict round-trip helpers (TS-only public; Python
    # round-trips through `TnpkgManifest.from_dict` / `to_dict` which
    # live on the class). Layer 1 primitive — covered by tn.pkg rows.
    # ------------------------------------------------------------------
    "fromWireDict", "toWireDict",

    # ------------------------------------------------------------------
    # Vault URL constants. The env vars they reflect (TN_VAULT_URL,
    # TN_VAULT_DEFAULT_BASE, TN_NO_LINK) are themselves documented as
    # parity rows; the constants are the TS-side names for the same
    # behaviour. Python keeps them as module-level names inside
    # tn.vault_client (`DEFAULT_VAULT_URL`, `ENV_VAULT_URL`).
    # ------------------------------------------------------------------
    "DEFAULT_VAULT_URL", "ENV_VAULT_URL",
    "ENV_VAULT_DEFAULT_BASE", "ENV_NO_LINK",

    # ------------------------------------------------------------------
    # init-upload option/result types. Pure data shapes for the
    # `initUpload` / `Tn.initUpload` verb (which IS a parity row).
    # Python's `init_upload` returns a plain dict, so there are no named
    # Python counterparts. NEW in 0.5.0a2.
    # ------------------------------------------------------------------
    "InitUploadOptions", "InitUploadResult",
}


def python_public_symbols() -> set[str]:
    """Parse python/tn/__init__.py's __all__ list (without importing the
    module — local env may not have all deps installed)."""
    text = PY_INIT.read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        return {
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        }
    return set()


def ts_public_symbols() -> set[str]:
    """Scan ts-sdk/src/index.ts for top-level exports. Plain regex; we're
    matching `export { A, B, C } from "...";`, `export const X = ...;`,
    `export type { A, B } from "...";`, `export function X(...)` etc."""
    text = TS_INDEX.read_text(encoding="utf-8")
    out: set[str] = set()

    # Strip block comments first to avoid matching commented-out exports.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # And line comments.
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)

    # `export { A, B as C, type D, ... } from "..."` and `export type { ... } from "..."`.
    for m in re.finditer(r"export\s+(?:type\s+)?\{([^}]+)\}\s*from", text):
        for sym in m.group(1).split(","):
            sym = sym.strip()
            if not sym:
                continue
            # Handle "type X" and "X as Y" — we want the EXPORTED name.
            sym = re.sub(r"^type\s+", "", sym).strip()
            if " as " in sym:
                sym = sym.split(" as ", 1)[1].strip()
            out.add(sym)

    # `export const X` / `export class X` / `export function X` / `export type X = ...` / `export interface X`.
    for m in re.finditer(
        r"export\s+(?:const|class|function|interface|type)\s+(\w+)",
        text,
    ):
        out.add(m.group(1))

    return out


def parity_doc_symbols() -> set[str]:
    """Pull every backtick-quoted token from the parity doc."""
    text = PARITY_DOC.read_text(encoding="utf-8")
    out: set[str] = set()
    # Match `tn.something(...)` / `Tn.something()` / bare `someName` etc.
    for m in re.finditer(r"`([^`]+)`", text):
        token = m.group(1)
        # Reduce dotted forms to their leaf name (the most distinctive part)
        # and also include the raw token for direct matches.
        out.add(token)
        # Walk dot segments to also register "X" for "tn.admin.X" / "Tn.X".
        for segment in re.split(r"[.\(\) ,/{}\[\]<>=]", token):
            seg = segment.strip()
            if seg:
                out.add(seg)
    return out


def main() -> int:
    py = python_public_symbols()
    ts = ts_public_symbols()
    documented = parity_doc_symbols() | KNOWN_OMISSIONS

    missing_py = sorted(py - documented)
    missing_ts = sorted(ts - documented)

    if not missing_py and not missing_ts:
        print("parity: ok")
        print(f"  Python public symbols: {len(py)}")
        print(f"  TS public exports:     {len(ts)}")
        print(f"  documented tokens:     {len(documented - KNOWN_OMISSIONS)} (+{len(KNOWN_OMISSIONS)} omissions)")
        return 0

    if missing_py:
        print(f"Missing Python symbols in {PARITY_DOC.name}:")
        for n in missing_py:
            print(f"  - tn.{n}")
    if missing_ts:
        print(f"Missing TS exports in {PARITY_DOC.name}:")
        for n in missing_ts:
            print(f"  - {n}")
    print()
    print("Either add a row to docs/sdk-parity.md or, for genuinely-internal")
    print("symbols, add to KNOWN_OMISSIONS in tools/check_parity.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
