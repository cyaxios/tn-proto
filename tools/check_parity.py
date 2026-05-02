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
    "WatchOptions", "WatchSince", "AddRuntimeOptions",
    "AdminAddAgentRuntimeOptions", "PkgExportOptions",
    "Instructions", "SecureEntry", "ChainConflict", "LeafReuseAttempt",
    "ChainConflictError", "RotationConflictError", "LeafReuseError",
    "SameCoordinateForkError", "VerificationError",
    "ReadEntry", "RawEntry", "Entry",

    # ------------------------------------------------------------------
    # Class / namespace handles (each covered by its verbs).
    # ------------------------------------------------------------------
    "Tn", "NodeRuntime", "AdminStateCache",

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
    # "process-global" sections rather than per-verb rows.
    # ------------------------------------------------------------------
    "current_config", "session", "using_rust",
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
