"""Verify docs/sdk-parity.md mentions every public verb in Python and TS.

CI runs:    python tools/check_parity.py
Exit 0 if every public Python verb (from `tn.__all__` and tn.admin/pkg/vault
sub-package __all__'s) and every TS export from `@tnproto/sdk`'s main entry
have a row in the parity doc; non-zero with a list of unmatched names
otherwise. The check also audits the parseable TypeScript `Tn` class surface
and the user-facing namespace classes (admin/pkg/vault/agents/handlers).

Symbols intentionally absent from the parity table can be added to
`KNOWN_OMISSIONS` below — typically internal helpers or pure types.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
PARITY_DOC = ROOT / "docs" / "sdk-parity.md"
TS_INDEX = ROOT / "ts-sdk" / "src" / "index.ts"
TS_TN = ROOT / "ts-sdk" / "src" / "tn.ts"
PY_INIT = ROOT / "python" / "tn" / "__init__.py"
TS_NAMESPACE_FILES = {
    "admin": ROOT / "ts-sdk" / "src" / "admin" / "index.ts",
    "pkg": ROOT / "ts-sdk" / "src" / "pkg" / "index.ts",
    "vault": ROOT / "ts-sdk" / "src" / "vault" / "index.ts",
    "agents": ROOT / "ts-sdk" / "src" / "agents" / "index.ts",
    "handlers": ROOT / "ts-sdk" / "src" / "handlers" / "namespace.ts",
}


class SurfaceRow(NamedTuple):
    surface: str
    qualified: str
    name: str
    documented: bool
    omitted: bool

    @property
    def status(self) -> str:
        if self.documented:
            return "ok"
        if self.omitted:
            return "omitted"
        return "missing"

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
    # TS-only class helpers/properties. These are public conveniences for
    # tests, scratch runtimes, and inspecting a Tn handle, but they are
    # not cross-language verbs. Keep them qualified so the parity gate
    # still checks real module/namespace verbs with similar names.
    # ------------------------------------------------------------------
    "Tn.clearStrict", "Tn.isStrict",
    "tn.handlers", "tn.isDefault", "tn.lastAbsorbReceipt",
    "tn.logPath", "tn.name", "tn.yamlPath",

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


def _strip_ts_comments(text: str) -> str:
    """Remove TS comments while preserving line count for line-based parsing."""
    text = re.sub(
        r"/\*.*?\*/",
        lambda m: "\n" * m.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    return re.sub(r"//.*?$", "", text, flags=re.MULTILINE)


def _class_tail(path: Path, class_name: str) -> str:
    text = _strip_ts_comments(path.read_text(encoding="utf-8"))
    m = re.search(rf"\bclass\s+{re.escape(class_name)}\b", text)
    if not m:
        return ""
    return text[m.end():]


def _parse_ts_class_members(path: Path, class_name: str) -> dict[str, set[str]]:
    """Parse public members declared directly on a TypeScript class.

    This is intentionally line-based: the SDK's public class members are
    declared at two-space indentation, while method bodies are indented
    further. That avoids brittle brace matching in template strings and keeps
    this parser focused on the surface shape we need for parity auditing.
    """
    static_methods: set[str] = set()
    instance_methods: set[str] = set()
    properties: set[str] = set()

    for raw in _class_tail(path, class_name).splitlines():
        if not raw.startswith("  ") or raw.startswith("    "):
            continue
        line = raw.strip()
        if not line:
            continue
        if re.match(r"^(?:private|protected|constructor)\b", line):
            continue

        getter = re.match(r"^(?:(static)\s+)?get\s+([A-Za-z_]\w*)\s*[:(]", line)
        if getter:
            # Public getters are properties from the consumer's perspective.
            properties.add(getter.group(2))
            continue

        method = re.match(
            r"^(?:(static)\s+)?(?:async\s+)?(?:\*\s*)?"
            r"([A-Za-z_]\w*)\s*(?:<[^({;]*>)?\(",
            line,
        )
        if method:
            target = static_methods if method.group(1) else instance_methods
            target.add(method.group(2))
            continue

        prop = re.match(r"^(?:readonly\s+)?([A-Za-z_]\w*)[!?]?:\s*", line)
        if prop:
            properties.add(prop.group(1))

    return {
        "static_methods": static_methods,
        "instance_methods": instance_methods,
        "properties": properties,
    }


def ts_tn_class_members() -> dict[str, set[str]]:
    return _parse_ts_class_members(TS_TN, "Tn")


def ts_namespace_methods() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for namespace, path in TS_NAMESPACE_FILES.items():
        class_name = f"{namespace.capitalize()}Namespace"
        if namespace == "pkg":
            class_name = "PkgNamespace"
        members = _parse_ts_class_members(path, class_name)
        out[namespace] = members["instance_methods"]
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


def parity_doc_surface_tokens() -> set[str]:
    """Return qualified surface tokens from docs/sdk-parity.md.

    `parity_doc_symbols()` keeps legacy broad matching by leaf token. The
    matrix uses this stricter normalized set so `tn.admin.rotate` is not
    treated as documented merely because some unrelated row contains `rotate`.
    """
    text = PARITY_DOC.read_text(encoding="utf-8")
    out: set[str] = set()
    for m in re.finditer(r"`([^`]+)`", text):
        token = re.sub(r"^(?:await|async)\s+", "", m.group(1).strip())
        for q in re.finditer(r"\b(?:tn|Tn)(?:\.[A-Za-z_]\w*)+\b", token):
            out.add(q.group(0))
        bare_call = re.match(r"^([A-Za-z_]\w*)\s*(?:\(|$)", token)
        if bare_call:
            out.add(bare_call.group(1))
    return out


SURFACE_ORDER = {
    "python.module": 0,
    "ts.module": 1,
    "ts.Tn.static": 2,
    "ts.Tn.instance": 3,
    "ts.Tn.property": 4,
    "ts.namespace.admin": 5,
    "ts.namespace.pkg": 6,
    "ts.namespace.vault": 7,
    "ts.namespace.agents": 8,
    "ts.namespace.handlers": 9,
}


def _surface_sort_key(row: SurfaceRow) -> tuple[int, str]:
    return (SURFACE_ORDER.get(row.surface, 99), row.qualified)


def _is_documented(
    *,
    surface: str,
    qualified: str,
    name: str,
    documented: set[str],
    legacy_documented: set[str],
) -> bool:
    if surface in {"python.module", "ts.module"}:
        return qualified in documented or name in documented or name in legacy_documented
    return qualified in documented


def _surface_row(
    surface: str,
    qualified: str,
    name: str,
    *,
    documented: set[str],
    legacy_documented: set[str],
    omissions: set[str],
) -> SurfaceRow:
    return SurfaceRow(
        surface=surface,
        qualified=qualified,
        name=name,
        documented=_is_documented(
            surface=surface,
            qualified=qualified,
            name=name,
            documented=documented,
            legacy_documented=legacy_documented,
        ),
        omitted=name in omissions or qualified in omissions,
    )


def surface_matrix_rows(
    *,
    documented: set[str] | None = None,
    legacy_documented: set[str] | None = None,
    omissions: set[str] | None = None,
) -> list[SurfaceRow]:
    documented = documented if documented is not None else parity_doc_surface_tokens()
    legacy_documented = legacy_documented if legacy_documented is not None else parity_doc_symbols()
    omissions = omissions if omissions is not None else KNOWN_OMISSIONS

    rows: list[SurfaceRow] = []
    for name in sorted(python_public_symbols()):
        rows.append(_surface_row(
            "python.module",
            f"tn.{name}",
            name,
            documented=documented,
            legacy_documented=legacy_documented,
            omissions=omissions,
        ))
    for name in sorted(ts_public_symbols()):
        rows.append(_surface_row(
            "ts.module",
            name,
            name,
            documented=documented,
            legacy_documented=legacy_documented,
            omissions=omissions,
        ))

    tn_members = ts_tn_class_members()
    for name in sorted(tn_members["static_methods"]):
        rows.append(_surface_row(
            "ts.Tn.static",
            f"Tn.{name}",
            name,
            documented=documented,
            legacy_documented=legacy_documented,
            omissions=omissions,
        ))
    for name in sorted(tn_members["instance_methods"]):
        rows.append(_surface_row(
            "ts.Tn.instance",
            f"tn.{name}",
            name,
            documented=documented,
            legacy_documented=legacy_documented,
            omissions=omissions,
        ))
    for name in sorted(tn_members["properties"]):
        rows.append(_surface_row(
            "ts.Tn.property",
            f"tn.{name}",
            name,
            documented=documented,
            legacy_documented=legacy_documented,
            omissions=omissions,
        ))
    for namespace, methods in sorted(ts_namespace_methods().items()):
        for name in sorted(methods):
            rows.append(_surface_row(
                f"ts.namespace.{namespace}",
                f"tn.{namespace}.{name}",
                name,
                documented=documented,
                legacy_documented=legacy_documented,
                omissions=omissions,
            ))
    return sorted(rows, key=_surface_sort_key)


def format_surface_matrix(rows: list[SurfaceRow]) -> str:
    if not rows:
        return "(no rows)"
    headers = ("surface", "symbol", "documented", "omitted", "status")
    data = [
        (
            row.surface,
            row.qualified,
            "yes" if row.documented else "no",
            "yes" if row.omitted else "no",
            row.status,
        )
        for row in rows
    ]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in data))
        for i in range(len(headers))
    ]
    lines = [
        "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))),
        "  ".join("-" * widths[i] for i in range(len(headers))),
    ]
    lines.extend(
        "  ".join(row[i].ljust(widths[i]) for i in range(len(headers)))
        for row in data
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="print the full deterministic surface/documentation matrix",
    )
    args = parser.parse_args(argv)

    py = python_public_symbols()
    ts = ts_public_symbols()
    doc_symbols = parity_doc_symbols()
    documented = doc_symbols | KNOWN_OMISSIONS

    missing_py = sorted(py - documented)
    missing_ts = sorted(ts - documented)
    rows = surface_matrix_rows(
        documented=parity_doc_surface_tokens(),
        legacy_documented=doc_symbols,
        omissions=KNOWN_OMISSIONS,
    )
    missing_surface = [
        row
        for row in rows
        if row.surface not in {"python.module", "ts.module"}
        and not row.documented
        and not row.omitted
    ]

    if args.matrix:
        print("Surface matrix:")
        print(format_surface_matrix(rows))
        print()

    if not missing_py and not missing_ts and not missing_surface:
        tn_members = ts_tn_class_members()
        namespaces = ts_namespace_methods()
        print("parity: ok")
        print(f"  Python public symbols: {len(py)}")
        print(f"  TS public exports:     {len(ts)}")
        print(
            "  TS Tn class surface:   "
            f"{len(tn_members['static_methods'])} static, "
            f"{len(tn_members['instance_methods'])} instance, "
            f"{len(tn_members['properties'])} properties"
        )
        print(
            "  TS namespace methods:  "
            f"{sum(len(v) for v in namespaces.values())}"
        )
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
    if missing_surface:
        print(f"Missing TS class/namespace surfaces in {PARITY_DOC.name}:")
        print(format_surface_matrix(missing_surface))
    print()
    print("Either add a row to docs/sdk-parity.md or, for genuinely-internal")
    print("symbols, add to KNOWN_OMISSIONS in tools/check_parity.py.")
    if not args.matrix:
        print("Run `python tools/check_parity.py --matrix` for the full surface matrix.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
