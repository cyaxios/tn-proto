"""Verb-centric cross-language parity gate for the TN SDKs.

CI runs:    python tools/check_parity.py
Exit 0 when the Python and TypeScript SDKs expose the same public verbs (or
every one-sided verb is accounted for); non-zero, with a list, when a verb
appears on only one language and is neither documented in
``docs/sdk-parity.md`` nor listed in the structured allowlist below.

Why "verb-centric"
------------------
The earlier version of this tool diffed ``python/tn/__init__.py``'s
``__all__`` against the bare exports of ``ts-sdk/src/index.ts`` plus the
backtick tokens in the parity doc. That only looked at two surfaces, so
real drift on the *namespace* and *instance* surfaces slipped through. The
proven miss: ``revoked_count`` (``python/tn/admin/__init__.py``) and
``revokedCount`` (``ts-sdk/src/admin/index.ts``) are public on both sides,
yet neither lived in ``__all__`` nor in ``index.ts``'s bare exports, so the
tool could not see either of them at all.

This version parses six surfaces and folds each public name to a canonical
verb (snake_case, namespace-qualified where applicable, e.g.
``admin.revoke_recipient``):

    py_module       python/tn/__init__.py  __all__
    py_namespace    python/tn/{admin,pkg,vault}  top-level public functions
    ts_module       ts-sdk/src/index.ts  bare exports + module-level verbs
    ts_instance     ts-sdk/src/tn.ts  class Tn public methods
    ts_namespace    ts-sdk/src/{admin,pkg,vault,agents,handlers}  *Namespace methods
    ts_browser      ts-sdk/src/index.browser.ts exports + ts-sdk/src/browser/tn.ts
                    class Tn (incl. its stub namespaces)

A verb's Python side is present when py_module OR py_namespace has a *real*
implementation; its TS side is present when ts_module OR ts_instance OR
ts_namespace OR ts_browser has a *real* implementation. A verb with a real
implementation on both language sides is parity (matched). A verb that is
present on exactly one side -- or whose only presence on a side is a
throw-stub -- is allowed when it is documented in the parity doc OR listed in
ALLOWLIST with a reason; otherwise it is flagged as ``undocumented-drift`` and
the run fails.

Honesty about throw-stubs
-------------------------
The browser admin/pkg/vault/agents/handlers tier in ``browser/tn.ts`` is
entirely placeholders that ``throw new NotYetWiredForBrowserError(...)``; a
handful of browser ``Tn`` statics/methods (``use`` / ``absorb`` /
``ephemeral`` / ``listCeremonies`` / ``watch``) do the same. A method/function
body that is essentially a single ``throw`` is NOT a real implementation. The
tool
detects those bodies and records the verb as a *stub* on that surface
(``present=False, stub=True``) rather than counting it as parity. The matrix
prints ``~`` for a stub cell (vs ``x`` real / ``.`` absent) and the per-verb
status surfaces ``stub`` / ``browser-stub`` so a reader sees the throw-stub
reality instead of a flat "ok".

Source-parse only: this tool never imports the packages or runs a build (the
CI parity job has no build step). Python surfaces come from ``ast``; TS
surfaces come from robust regexes (no node / tsc dependency).
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARITY_DOC = ROOT / "docs" / "sdk-parity.md"

PY_INIT = ROOT / "python" / "tn" / "__init__.py"
# module file -> namespace key. ``admin`` is a package (admin/__init__.py);
# pkg / vault are single-file modules. agents / handlers have no Python
# *verb namespace* on the public ``tn.*`` surface (Python keeps those verbs
# under tn.admin.* or off the top-level surface entirely), so they are not
# parsed here; their TS-only verbs are accounted for in ALLOWLIST.
PY_NAMESPACE_MODULES: dict[str, Path] = {
    "admin": ROOT / "python" / "tn" / "admin" / "__init__.py",
    "pkg": ROOT / "python" / "tn" / "pkg.py",
    "vault": ROOT / "python" / "tn" / "vault.py",
}

TS_INDEX = ROOT / "ts-sdk" / "src" / "index.ts"
TS_TN_CLASS = ROOT / "ts-sdk" / "src" / "tn.ts"

# Browser SDK surfaces. ``index.browser.ts`` is the browser bundle entry
# (module-level exports + namespace proxies); ``browser/tn.ts`` is the
# browser-native ``Tn`` class whose admin/pkg/vault/agents/handlers tier and
# several statics are throw-stubs (NotYetWiredForBrowserError).
TS_INDEX_BROWSER = ROOT / "ts-sdk" / "src" / "index.browser.ts"
TS_TN_CLASS_BROWSER = ROOT / "ts-sdk" / "src" / "browser" / "tn.ts"
# Each TS namespace file -> (namespace key, class name regex).
TS_NAMESPACE_CLASSES: dict[str, tuple[Path, str]] = {
    "admin": (ROOT / "ts-sdk" / "src" / "admin" / "index.ts", r"class\s+AdminNamespace\b"),
    "pkg": (ROOT / "ts-sdk" / "src" / "pkg" / "index.ts", r"class\s+PkgNamespace\b"),
    "vault": (ROOT / "ts-sdk" / "src" / "vault" / "index.ts", r"class\s+VaultNamespace\b"),
    "agents": (ROOT / "ts-sdk" / "src" / "agents" / "index.ts", r"class\s+AgentsNamespace\b"),
    "handlers": (
        ROOT / "ts-sdk" / "src" / "handlers" / "namespace.ts",
        r"class\s+HandlersNamespace\b",
    ),
}

# Surface column order. Also the order printed by --matrix.
SURFACES = (
    "py_module",
    "py_namespace",
    "ts_module",
    "ts_instance",
    "ts_namespace",
    "ts_browser",
)
PY_SURFACES = ("py_module", "py_namespace")
TS_SURFACES = ("ts_module", "ts_instance", "ts_namespace", "ts_browser")


# --------------------------------------------------------------------------
# Structured allowlist.
#
# Keyed by canonical verb (the same snake_case / namespace-qualified form the
# matrix uses). Value carries a human reason and, optionally, the side(s) the
# verb is expected to be one-sided on. A one-sided verb is allowed when it is
# in this map (or documented in the parity doc); a both-sides verb never
# consults this map.
#
# The first block is the set of genuinely one-sided VERBS with real reasons.
# The second block migrates the legacy flat KNOWN_OMISSIONS (types, option
# objects, constants, Layer-1 helpers) so they keep passing; those are
# tracked implicitly by the verbs that produce / consume them.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Allow:
    reason: str
    # Optional expectation: which side this verb may legitimately appear on
    # alone. Informational; the gate allows the verb regardless of side once
    # it is listed here. ("" means "either side".)
    side: str = ""
    # True only for a GENUINE Python-only TS gap: a verb that exists in
    # python/tn.__all__ with NO TypeScript port of any spelling yet (as
    # opposed to a renamed/relocated counterpart). Drives the "TS gaps (no TS
    # port)" rollup so renamed asymmetries (compile_enrolment -> pkg.*, etc.)
    # are not miscounted as un-ported.
    gap: bool = False


# Genuinely one-sided verbs. Each is a real cross-language asymmetry that is
# tracked (and, in every case below, also carried by a row in the parity doc).
_VERB_ALLOW: dict[str, Allow] = {
    # add-agent-runtime is lifted to its own namespace in TS but kept under
    # tn.admin in Python. Two canonical keys, each one-sided by design.
    "admin.add_agent_runtime": Allow(
        "Python keeps add-agent-runtime under tn.admin; TS lifts it to "
        "tn.agents.addRuntime. Parity doc tn.agents row.",
        side="py",
    ),
    "agents.add_runtime": Allow(
        "TS exposes add-agent-runtime as tn.agents.addRuntime; Python's "
        "counterpart is tn.admin.add_agent_runtime. Parity doc tn.agents row.",
        side="ts",
    ),
    # Agents-policy read/reload: public TS namespace verbs; Python's are
    # internal (_agent_policy_doc / _maybe_emit_policy_published).
    "agents.policy": Allow(
        "TS exposes the active agents policy via tn.agents.policy(); Python "
        "keeps it internal (_agent_policy_doc). Parity doc tn.agents row.",
        side="ts",
    ),
    "agents.reload_policy": Allow(
        "TS exposes tn.agents.reloadPolicy(); Python reloads internally on "
        "init. Parity doc tn.agents row.",
        side="ts",
    ),
    # Handlers namespace: TS groups handler ops under tn.handlers.*. Python's
    # add_handler is a runtime method off the bound handle, not on the public
    # tn.* surface; list / flush have no Python public counterpart yet.
    "handlers.add": Allow(
        "TS tn.handlers.add mirrors Python's runtime add_handler (not on the "
        "public tn.* surface). Parity doc tn.handlers row.",
        side="ts",
    ),
    "handlers.list": Allow(
        "TS-only convenience; no Python public counterpart yet. Parity doc "
        "tn.handlers row marks it one-sided (TS).",
        side="ts",
    ),
    "handlers.flush": Allow(
        "TS-only convenience; no Python public counterpart yet. Parity doc "
        "tn.handlers row marks it one-sided (TS).",
        side="ts",
    ),
    # compile-enrolment + offer live at the Python top level but under
    # tn.pkg.* in TS. The Python module forms (compile_enrolment / offer) and
    # the TS namespace forms (pkg.compile_enrolment / pkg.offer) are distinct
    # canonical keys, each one-sided by design.
    "compile_enrolment": Allow(
        "Python keeps compile_enrolment top-level; TS namespaces it under "
        "tn.pkg.compileEnrolment. Parity doc tn.pkg row.",
        side="py",
    ),
    "pkg.compile_enrolment": Allow(
        "TS namespaces compile-enrolment under tn.pkg; Python keeps it "
        "top-level (tn.compile_enrolment). Parity doc tn.pkg row.",
        side="ts",
    ),
    "offer": Allow(
        "Python keeps offer top-level; TS namespaces it under tn.pkg.offer. "
        "Parity doc tn.pkg row.",
        side="py",
    ),
    "pkg.offer": Allow(
        "TS namespaces offer under tn.pkg; Python keeps it top-level "
        "(tn.offer). Parity doc tn.pkg row.",
        side="ts",
    ),
    # set-link-state: Python verb (top-level + tn.admin); TS implements the
    # same intent as tn.vault.setLinkState (writes ceremony.mode to the
    # authoritative yaml). One-sided by namespace, NOT a stub: Python keeps it
    # under tn.admin, TS under tn.vault.
    "set_link_state": Allow(
        "Python top-level set_link_state mutates ceremony yaml; TS exposes "
        "tn.vault.setLinkState (real impl). Parity doc tn.admin row.",
        side="py",
    ),
    "admin.set_link_state": Allow(
        "Python tn.admin.set_link_state mutates ceremony yaml; TS routes the "
        "same intent through tn.vault.setLinkState. Parity doc tn.admin row.",
        side="py",
    ),
    "vault.set_link_state": Allow(
        "TS tn.vault.setLinkState writes ceremony.mode to the authoritative "
        "yaml (real impl); Python's counterpart is tn.admin.set_link_state, so "
        "the verb is one-sided ts-only by namespace. Parity doc tn.admin row.",
        side="ts",
    ),
    # init-upload: TS exposes a bare initUpload + Tn.initUpload; Python's
    # counterpart is tn.handlers.vault_push.init_upload, not on the top-level
    # tn.* surface.
    "init_upload": Allow(
        "TS exposes initUpload / Tn.initUpload; Python's counterpart is "
        "tn.handlers.vault_push.init_upload (not on the public tn.* surface). "
        "Parity doc modules/namespaces row.",
        side="ts",
    ),
    # close: TS instance + module verb; Python's is flush_and_close (which is
    # the both-sides match). tn.close() is the doc-listed TS spelling.
    "close": Allow(
        "TS tn.close() == Python tn.flush_and_close() (the both-sides match); "
        "TS also exports the short close alias. Parity doc core-verbs row.",
        side="ts",
    ),
    # ephemeral / open_ceremony: TS-class factories. Python's equivalents are
    # tn.session (ephemeral) and the deprecated-alias openCeremony->use.
    "ephemeral": Allow(
        "TS Tn.ephemeral() == Python tn.session() (the both-sides match for "
        "session). Parity doc session/ephemeral row.",
        side="ts",
    ),
    "open_ceremony": Allow(
        "TS Tn.openCeremony is a deprecated alias of Tn.use (== Python "
        "tn.use). Parity doc tn.use row.",
        side="ts",
    ),
    # Strict-mode test/lifecycle helpers on the TS class. Python's equivalents
    # (_autoinit.is_strict / reset_state_for_tests) are internal, not on the
    # public tn.* surface; only set_strict is public+documented on both.
    "clear_strict": Allow(
        "TS Tn.clearStrict() drops the programmatic strict override; Python's "
        "equivalent (_autoinit.reset_state_for_tests) is internal, not on the "
        "public tn.* surface.",
        side="ts",
    ),
    "is_strict": Allow(
        "TS Tn.isStrict() reads the effective strict flag; Python's "
        "_autoinit.is_strict is internal, not on the public tn.* surface.",
        side="ts",
    ),
    # TS-only module-level namespace / catalog re-exports. Not verbs: these
    # are object handles. Python exposes the runtime namespaces it has under
    # tn.admin / tn.pkg / tn.vault / tn.agents (matched as bare names); the
    # three below have no Python top-level counterpart.
    "admin_catalog": Allow(
        "TS adminCatalog re-exports the static admin-event catalog "
        "(reduce / catalogKinds / validateEmit); Python's catalog lives "
        "inside tn_core, not on the public tn.* surface.",
        side="ts",
    ),
    "primitives": Allow(
        "TS exposes Layer-1 crypto primitives as tn.primitives; Python has no "
        "Layer-1/Layer-2 split (parity doc browser-only-surface section).",
        side="ts",
    ),
    "handlers": Allow(
        "TS exposes a module-level tn.handlers namespace proxy; Python keeps "
        "handler classes under the tn.handlers package, not as a top-level "
        "tn.* verb namespace. Parity doc tn.handlers row.",
        side="ts",
    ),
    # ----------------------------------------------------------------------
    # Genuine Python-only surface with NO TS port yet. These four live in
    # python/tn.__all__ but have no TypeScript counterpart at all. They were
    # previously buried in the legacy catch-all with a single generic reason;
    # split out here so the gate's output names the real gap instead of
    # silencing it. Each is "TS gap, future work (no TS port yet)".
    # ----------------------------------------------------------------------
    "wallet": Allow(
        "Python module re-export of tn.wallet (link / backup / recovery "
        "story). No longer a TS gap: the TS SDK ships the wallet namespace "
        "(walletNamespace / walletStatus / walletSyncCmd, see "
        "_WALLET_SYNC_NAMES) as the counterpart surface.",
        side="py",
    ),
    "vault_client": Allow(
        "TS gap, future work (no TS port yet): Python's tn.vault_client "
        "(resolve_vault_url and the hosted-vault HTTP client) has no "
        "TypeScript counterpart yet.",
        side="py",
        gap=True,
    ),
    "classifier": Allow(
        "TS gap, future work (no TS port yet): Python's tn.classifier (the LLM "
        "classifier stub, PRD 6.4) has no TypeScript counterpart yet.",
        side="py",
        gap=True,
    ),
    "is_keystore_diverged": Allow(
        "TS gap, future work (no TS port yet): Python's tn.is_keystore_diverged "
        "(divergence-retry predicate over KeystoreConflictError) has no "
        "TypeScript counterpart yet.",
        side="py",
        gap=True,
    ),
    # ----------------------------------------------------------------------
    # Real browser-only verbs (genuine implementations on the browser entry
    # with no Python __all__ / Node-index counterpart).
    # ----------------------------------------------------------------------
    "flush": Allow(
        "Browser-only verb: index.browser.ts exposes a bare tn.flush() (drain "
        "the HTTP queue without closing). Python / Node fold flush into "
        "flush_and_close (the both-sides match); neither exports a bare flush.",
        side="ts",
    ),
    "init_from_seed": Allow(
        "Browser-only verb: Tn.initFromSeed / tn.initFromSeed bootstraps from "
        "server-provisioned seed material (witness flow). No Python __all__ or "
        "Node-index counterpart.",
        side="ts",
    ),
    "runtime": Allow(
        "Browser-only accessor: tn.runtime() returns the BrowserRuntime for "
        "tests / advanced use. No Python / Node-index counterpart.",
        side="ts",
    ),
    # ----------------------------------------------------------------------
    # Browser THROW-STUB placeholders with no real implementation anywhere
    # yet. These are members of the browser _stubNamespace tiers whose verb
    # has no real Node/Python sibling (admin.cache covers cachedAdminState on
    # Node; agents/handlers expose different real verbs). Each throws
    # NotYetWiredForBrowserError. Allowlisted as known browser stubs; the
    # matrix/summary still prints them as ``stub`` so the gap stays visible.
    # ----------------------------------------------------------------------
    "admin.cached_admin_state": Allow(
        "Browser throw-stub (NotYetWiredForBrowserError): browser tn.admin "
        "stub-namespace member with no real impl yet; Node exposes the cached "
        "state via tn.admin.cache(), Python via tn.admin.cached_admin_state on "
        "the package (not a top-level namespace verb).",
        side="ts",
    ),
    "agents.load_policy": Allow(
        "Browser throw-stub (NotYetWiredForBrowserError): browser tn.agents "
        "stub-namespace member with no real impl yet; Node's agents namespace "
        "exposes policy()/reloadPolicy()/addRuntime() instead.",
        side="ts",
    ),
    "handlers.remove": Allow(
        "Browser throw-stub (NotYetWiredForBrowserError): browser tn.handlers "
        "stub-namespace member with no real impl yet; Node's handlers namespace "
        "exposes add()/list()/flush().",
        side="ts",
    ),
}


# Legacy flat omissions migrated verbatim. These are result types, option
# objects, branded-helper types, constants, and Layer-1 / Layer-2 helpers,
# never cross-language verbs. They are tracked implicitly by the verbs that
# produce or consume them; listing them keeps the gate green exactly as the
# old KNOWN_OMISSIONS set did. A generic reason is sufficient.
_LEGACY_OMISSION_NAMES: tuple[str, ...] = (
    # Internal body-zip helper for tnpkg packing.
    "packBodyPlaintextZip",
    # Result types and option objects (covered by their verbs).
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
    # Class / namespace handles (each covered by its verbs).
    "Tn", "NodeRuntime", "AdminStateCache", "TN",
    # Multi-ceremony error classes (covered by the verbs that raise them).
    "TNConfigConflict", "TNCreateFailed", "TNInvalidName", "TNNotFound",
    "MultiCeremonyEmitNotImplemented",
    # Python module re-exports (the doc references the namespace).
    # NOTE: wallet / vault_client / classifier are NOT here -- they are real
    # Python-only TS GAPS, split into explicit _VERB_ALLOW entries above so the
    # gate names the gap instead of burying it under the generic legacy reason.
    "admin", "pkg", "vault", "agents",
    "identity", "sealing",
    "PolicyDocument", "PolicyTemplate", "Audit",
    # Constants (covered by their owning verb-doc-section).
    "LOG_LEVELS", "LKV_VERSION", "MANIFEST_VERSION",
    "POLICY_RELATIVE_PATH", "REQUIRED_FIELDS",
    "DEFAULT_ADMIN_LOG_LOCATION", "STATE_FILE", "SYNC_DIR",
    "KNOWN_KINDS",
    # TS-only branded helpers + types for the polymorphic recipient= kwarg.
    "Did", "LeafIndex", "PublicKeyBytes",
    "RecipientInput", "RecipientLike", "ResolvedRecipient",
    "did", "leafIndex", "publicKeyBytes", "resolveRecipient",
    # Manifest / tnpkg low-level types and helpers (Layer 1 primitives).
    "Manifest", "ManifestKind", "VectorClock", "BodyContents",
    "ZipEntry", "ParsedZipEntry",
    "CompileKitBundleOptions", "CompiledManifest", "CompiledKitMeta", "CompiledPackage",
    "newManifest", "signManifest", "verifyManifest",
    "manifestSigningBytes", "isManifestSignatureValid",
    "compileKitBundle", "compileKitBundleToFile",
    "clockMerge", "clockDominates",
    "readTnpkg", "writeTnpkg", "nowIsoMillis",
    # Sync-state low-level helpers (Layer 2 internals).
    "SyncState", "loadSyncState", "saveSyncState", "updateSyncState",
    "statePath", "getInboxCursor", "setInboxCursor",
    "getLastPushedAdminHead", "setLastPushedAdminHead",
    # Admin-log low-level helpers.
    "appendAdminEnvelopes", "existingRowHashes", "isAdminEventType",
    "resolveAdminLogPath", "iterLogFiles",
    "scanAttestedEvents", "scanAttestedEventRecords", "scanAttestedGroups",
    "yamlRecipientDids", "emptyState",
    # Layer 2 config + keystore loaders.
    "loadConfig", "loadKeystore", "loadPolicyFile",
    "policyPathFor", "parsePolicyText",
    # Python utility verbs the doc summarizes via context / process-global
    # sections (the TS camelCase mirrors are bare-export forms of the same).
    "current_config", "session", "using_rust",
    "usingRust", "config",
    # Low-level bootstrap-absorb plumbing exported from the TS SDK.
    "absorbBootstrap", "isBootstrapKind", "absorbSealedBootstrap",
    # Env-var parity helpers (accessors; the vars are documented per-row).
    "bootstrapFromApiKey", "parseBearer", "challengeVerify",
    "resolveVaultUrl", "resolveDidEndpoint", "isAutoLinkDisabled",
    "ApiKeyFetchResult", "ParsedBearer",
    # Recipient-seal Layer 1 helpers.
    "buildRecipientWraps", "sealBekForRecipient", "unsealBekFromWrap",
    "manifestAadForWrap", "RecipientWrap", "UnsealError",
    "UnsealNotWiredError", "WRAP_FRAME",
    # Body-encryption Layer 1 helpers.
    "encryptBodyBlob", "decryptBodyBlob",
    "BODY_CIPHER_SUITE", "BODY_FRAME",
    # Manifest wire-dict round-trip helpers.
    "fromWireDict", "toWireDict",
    # Vault URL constants.
    "DEFAULT_VAULT_URL", "ENV_VAULT_URL",
    "ENV_VAULT_DEFAULT_BASE", "ENV_NO_LINK",
    # init-upload option / result types.
    "InitUploadOptions", "InitUploadResult",
)

_LEGACY_REASON = (
    "Type / option object / constant / Layer-1 helper (migrated from the "
    "legacy KNOWN_OMISSIONS set); tracked implicitly by its owning verb."
)


# Browser-only plumbing exported from ts-sdk/src/index.browser.ts: the
# wasm/localStorage runtime, its construction helpers, handler factories,
# storage adapters, and the Layer-1 raw primitives re-exported for callers who
# build envelopes by hand. None are protocol verbs and none have a Python /
# Node-index counterpart -- they are browser-runtime infrastructure. Listed
# with their own honest reason (NOT the Node legacy reason, NOT a "TS gap")
# so the summary keeps them separate from the real one-sided verbs and the
# genuine Python-only TS gaps.
_BROWSER_ONLY_NAMES: tuple[str, ...] = (
    # Browser runtime class + its options.
    "BrowserRuntime", "BrowserRuntimeOptions",
    # Ceremony / keystore construction helpers + their option/result types.
    "createFreshCeremony", "CreateFreshOptions", "CreateFreshResult",
    "createFromSeed", "CreateFromSeedOptions", "CreateFromSeedResult",
    # Handler factories + their option/callback types.
    "consoleHandler", "ConsoleHandler",
    "httpHandler", "HttpHandlerOptions", "WasmHandlerCallbacks",
    # Storage adapters + their types.
    "localStorageStorageAdapter", "LocalStorageAdapter",
    "LocalStorageAdapterOptions", "LocalStorageQuotaError",
    "memoryStorageAdapter", "MemoryStorageAdapter",
    "JsStorageCallbacks",
    # Browser-error class + browser-init option-type alias.
    "NotYetWiredForBrowserError", "TnInitFromSeedOptions",
    # Log-level union type re-exported from the browser entry.
    "LogLevel",
    # Layer-1 raw primitives re-exported for hand-rolled envelope building.
    "canonicalBytes", "canonicalJson", "computeRowHash",
    "zeroHash", "buildEnvelope",
    # Keystore / entry plumbing for the browser wallet-restore + group-keys
    # flows: build a keystore handle from restored body files or JSON, decode
    # ndjson log entries, and extract per-group ciphertexts / kit maps.
    "keystoreHandle", "KeystoreHandle",
    "keystoreFromBodyFiles", "keystoreFromJson",
    "decodeEntry", "parseNdjson", "RawEntryInput",
    "extractGroupCts", "buildGroupKitsMap",
)

_BROWSER_ONLY_REASON = (
    "Browser-only runtime infrastructure (wasm/localStorage runtime, "
    "construction helpers, handler factories, storage adapters, or a "
    "re-exported Layer-1 primitive) from index.browser.ts; not a protocol "
    "verb and has no Python / Node-index counterpart."
)


# Two-way wallet-sync / account-bound-restore surface. The TS SDK exports the
# wallet namespace (status / sync / link-state) and the restore machinery
# (passphrase chain, loopback transfer, BEK decrypt, export-frame unpack) as
# public module symbols; Python's counterparts live in the tn.wallet /
# tn.wallet_restore / tn.wallet_pull / tn.sync_state MODULES (reached through
# the allowed ``wallet`` module re-export and the ``tn wallet`` CLI verbs)
# rather than on ``tn.__all__``. One-sided by namespace, not stubs.
_WALLET_SYNC_NAMES: tuple[str, ...] = (
    # Namespace handle + verbs.
    "walletNamespace", "walletNamespaceSurface",
    "walletStatus", "walletSyncCmd",
    "readLinkState", "readSyncQueue",
    "restoreViaPassphrase", "restoreViaLoopback", "restoreWithBek",
    "decryptBlobWithBek", "tryUnpackExportFrame",
    # Option / result / error types (covered by their verbs).
    "WalletSyncCmdOptions", "RestoreOptions", "RestoreResult",
    "RestoreError", "RestoreViaLoopbackOptions", "LinkResult",
)

_WALLET_SYNC_REASON = (
    "TS wallet-sync / restore surface (two-way wallet sync + account-bound "
    "restore); the Python counterpart lives in the tn.wallet* modules and "
    "the `tn wallet` CLI verbs, not on tn.__all__."
)


def build_allowlist() -> dict[str, Allow]:
    """Assemble the structured allowlist.

    Order of precedence (later wins on a canonical-key collision, so the most
    specific reason survives):

    1. Node legacy omissions  -> generic ``_LEGACY_REASON``.
    2. Browser-only plumbing  -> ``_BROWSER_ONLY_REASON``.
    3. Genuine one-sided / throw-stub verbs (``_VERB_ALLOW``) -> specific
       reasons, including the four split-out Python-only TS gaps
       (wallet / vault_client / classifier / is_keystore_diverged).
    """
    out: dict[str, Allow] = {}
    for name in _LEGACY_OMISSION_NAMES:
        out.setdefault(canon(name), Allow(_LEGACY_REASON))
    for name in _BROWSER_ONLY_NAMES:
        out[canon(name)] = Allow(_BROWSER_ONLY_REASON, side="ts")
    for name in _WALLET_SYNC_NAMES:
        out[canon(name)] = Allow(_WALLET_SYNC_REASON, side="ts")
    # Specific verb entries take precedence over both generic reasons.
    out.update(_VERB_ALLOW)
    return out


# --------------------------------------------------------------------------
# Canonicalization.
# --------------------------------------------------------------------------

_CAMEL_BOUNDARY_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_BOUNDARY_2 = re.compile(r"([a-z0-9])([A-Z])")


def canon(name: str) -> str:
    """Fold a public name to its canonical verb form: snake_case, lowercased.

    ``revokedCount`` -> ``revoked_count``; ``revoke_recipient`` ->
    ``revoke_recipient``; ``AddRecipientResult`` -> ``add_recipient_result``;
    ``LOG_LEVELS`` -> ``log_levels``. Cross-language verbs that differ only by
    naming convention (camelCase vs snake_case) collapse to the same key.
    """
    s = _CAMEL_BOUNDARY_1.sub(r"\1_\2", name)
    s = _CAMEL_BOUNDARY_2.sub(r"\1_\2", s)
    s = s.replace("__", "_")
    return s.strip("_").lower()


def qualify(namespace: str | None, name: str) -> str:
    """Canonical key, namespace-qualified when a namespace is given."""
    c = canon(name)
    return f"{namespace}.{c}" if namespace else c


# --------------------------------------------------------------------------
# Python surface discovery (AST only; never imports the package).
# --------------------------------------------------------------------------


def python_module_symbols() -> set[str]:
    """Parse ``__all__`` from python/tn/__init__.py."""
    tree = ast.parse(PY_INIT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        return {
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant)
                            and isinstance(elt.value, str)
                        }
    return set()


def python_namespace_symbols(path: Path) -> set[str]:
    """Top-level public function names (def / async def) in a module file.

    Only module-level functions count as namespace verbs; classes, dataclass
    result types, and underscore-prefixed helpers are excluded.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                out.add(node.name)
    return out


# --------------------------------------------------------------------------
# TypeScript surface discovery (regex only; no node / tsc dependency).
# --------------------------------------------------------------------------


def _strip_ts_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    return text


def _ts_export_symbols(path: Path) -> set[str]:
    """Top-level exports of a TS entry file.

    Matches ``export { A, B as C, type D } from "..."``, ``export type {...}``,
    ``export const/class/function/interface/type X``, and
    ``export * as NS from "..."``.
    """
    text = _strip_ts_comments(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for m in re.finditer(r"export\s+(?:type\s+)?\{([^}]+)\}\s*from", text):
        for sym in m.group(1).split(","):
            sym = sym.strip()
            if not sym:
                continue
            sym = re.sub(r"^type\s+", "", sym).strip()
            if " as " in sym:
                sym = sym.split(" as ", 1)[1].strip()
            out.add(sym)
    # const / class / interface / type / (async) function (incl. generator).
    for m in re.finditer(
        r"export\s+(?:async\s+)?(?:const|class|interface|type|function)\s*\*?\s*(\w+)",
        text,
    ):
        out.add(m.group(1))
    for m in re.finditer(r"export\s+\*\s+as\s+(\w+)\s+from", text):
        out.add(m.group(1))
    return out


def ts_module_symbols() -> set[str]:
    """Top-level exports of ts-sdk/src/index.ts (the Node entry)."""
    return _ts_export_symbols(TS_INDEX)


def ts_browser_module_symbols() -> set[str]:
    """Top-level exports of ts-sdk/src/index.browser.ts (the browser entry)."""
    return _ts_export_symbols(TS_INDEX_BROWSER)


# Reserved words that the class-member regex can otherwise mistake for a
# method declaration when they sit at the member indent (they never should,
# but guard anyway).
_TS_NON_METHOD = {
    "if", "for", "while", "switch", "catch", "return", "throw", "await",
    "const", "let", "var", "new", "do", "else", "yield", "typeof",
    "function", "super", "this", "constructor",
}

# A class member declared at exactly one indent level (2 spaces). Method
# bodies are indented 4+, so anchoring to "^  " (then NOT another space)
# excludes nested statements. Handles modifier prefixes and the
# generator-star (``*read``, ``async *watch``).
_TS_MEMBER_RE = re.compile(
    r"^  (?P<mods>(?:public |private |protected |static |async |readonly |get |set |\* )*)"
    r"\*?(?P<name>[A-Za-z_$#][\w$]*)\s*[(<]",
    re.MULTILINE,
)


def _balanced_body(text: str, open_idx: int) -> tuple[str, int]:
    """Given the index of an opening ``{``, return (inner_body, end_idx) where
    end_idx is the index of the matching ``}``. Brace-balanced."""
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i
        i += 1
    return text[open_idx + 1 :], len(text)


def _ts_class_body(text: str, class_re: str) -> str | None:
    """Return the brace-balanced body of the first class matching class_re."""
    m = re.search(class_re, text)
    if not m:
        return None
    brace = text.index("{", m.end())
    body, _end = _balanced_body(text, brace)
    return body


# A method/function body is a "throw-stub" when, comment-stripped, the only
# statement it contains is a single ``throw ...``. Covers the one-liner
# ``throw new NotYetWiredForBrowserError("use");`` and the multi-line
# ``throw new Error(\n  `...`,\n);`` shape. A body that does any other work
# (a guard, a return, a second statement) is real.
_THROW_WORD_RE = re.compile(r"^throw\b")


def _is_throw_stub_body(body: str) -> bool:
    """True iff ``body`` (already comment-stripped) is essentially one throw.

    The body must start with the ``throw`` keyword and contain no second
    top-level statement after it (a top-level ``;`` may only be followed by
    whitespace). String / template-literal contents and bracketed argument
    lists are skipped so a ``;`` *inside* the thrown expression does not look
    like a statement separator.
    """
    stripped = body.strip()
    if not _THROW_WORD_RE.match(stripped):
        return False
    depth = 0
    i = 0
    n = len(stripped)
    while i < n:
        ch = stripped[i]
        if ch in "\"'`":
            i = _skip_ts_string(stripped, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            # One statement only: nothing but whitespace may follow.
            return stripped[i + 1 :].strip() == ""
        i += 1
    # No top-level ``;`` (e.g. a single ``throw err`` with no semicolon): the
    # whole body is the one throw statement.
    return True


def _skip_ts_string(text: str, start: int) -> int:
    """Return the index just past the string/template literal opened at
    ``start`` (text[start] is the quote). Handles backslash escapes; treats a
    template literal's contents opaquely (no ``${}`` recursion needed here)."""
    quote = text[start]
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return n


def _ts_class_member_bodies(text: str, class_re: str) -> list[tuple[str, str, str]]:
    """Yield (mods, name, body) for each method declaration in the class.

    ``body`` is the brace-balanced text between the signature's ``{`` and its
    matching ``}`` (``""`` for declarations with no body, e.g. overloads /
    arrow-property members handled elsewhere).
    """
    class_body = _ts_class_body(text, class_re)
    if class_body is None:
        return []
    out: list[tuple[str, str, str]] = []
    for mm in _TS_MEMBER_RE.finditer(class_body):
        mods = mm.group("mods")
        name = mm.group("name")
        # Find the body brace: first ``{`` after the signature that is not
        # inside the parameter / generic list. Walk from the match end,
        # skipping balanced ()/<> until a top-level ``{`` or ``;``/``=``.
        brace_idx = _find_signature_body_brace(class_body, mm.end())
        if brace_idx is None:
            out.append((mods, name, ""))
            continue
        body, _end = _balanced_body(class_body, brace_idx)
        out.append((mods, name, body))
    return out


def _find_signature_body_brace(text: str, start: int) -> int | None:
    """From just after a method name+``(``/``<``, return the index of the body
    ``{``, skipping the balanced parameter list and return-type annotation.
    Returns None if a ``;`` (declaration-only) or ``=`` (property) comes first.
    """
    # ``start`` points just past the name; the next char is ``(`` or ``<``.
    depth = 0
    i = start - 1  # re-include the opening ( or < captured by the regex's [(<]
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        elif depth == 0:
            if ch == "{":
                return i
            if ch == ";":
                return None
            if ch == "=":
                # Arrow / property initializer, not a braced method body.
                return None
        i += 1
    return None


def ts_class_methods(path: Path, class_re: str) -> set[str]:
    """Public method names of the named class (real impls only).

    Convenience wrapper around :func:`ts_class_methods_split` that returns just
    the real-implementation set (throw-stub methods excluded). Kept so existing
    callers / tests that only want "what verbs does this class implement"
    continue to work.
    """
    real, _stub = ts_class_methods_split(path, class_re)
    return real


def ts_class_methods_split(path: Path, class_re: str) -> tuple[set[str], set[str]]:
    """Public method names of the named class, split into (real, stub).

    ``real`` are methods with a genuine body; ``stub`` are methods whose body
    is a single ``throw`` (e.g. the browser ``NotYetWiredForBrowserError``
    placeholders). A name never appears in both: a real overload of a stubbed
    name (none today) would land in ``real``.

    Excludes private / protected / ``_``-prefixed / ``#``-prefixed members,
    the constructor, getters and setters (Python mirrors those as attributes,
    not verbs), and reserved words.
    """
    text = _strip_ts_comments(path.read_text(encoding="utf-8"))
    real: set[str] = set()
    stub: set[str] = set()
    for mods, name, body in _ts_class_member_bodies(text, class_re):
        if not _accept_member(mods, name):
            continue
        if body and _is_throw_stub_body(body):
            stub.add(name)
        else:
            real.add(name)
    # A name that is real on any overload wins over a stub spelling.
    stub -= real
    return real, stub


def _accept_member(mods: str, name: str) -> bool:
    """Member-visibility filter shared by the real/stub class parsers."""
    if "private " in mods or "protected " in mods:
        return False
    if "get " in mods or "set " in mods:
        return False
    if name.startswith("_") or name.startswith("#"):
        return False
    if name in _TS_NON_METHOD:
        return False
    return True


# --------------------------------------------------------------------------
# Browser-namespace stub discovery.
# --------------------------------------------------------------------------

# Matches a class-property stub namespace:
#   readonly admin = _stubNamespace<{ ... }>("admin", ["addRecipient", ...]);
# Capturing the registered name and the bracketed key list. Every key is a
# throw-stub (the helper wires each to a function that throws).
_STUB_NAMESPACE_RE = re.compile(
    r"\breadonly\s+(?P<prop>\w+)\s*=\s*_stubNamespace\s*<[\s\S]*?>\s*\(\s*"
    r"(?P<name>[\"'])(?P<ns>\w+)(?P=name)\s*,\s*\[(?P<keys>[\s\S]*?)\]",
)

_STR_ITEM_RE = re.compile(r"""['"]([^'"]+)['"]""")


def ts_browser_stub_namespaces(path: Path) -> dict[str, set[str]]:
    """Return {namespace: {stub_verb, ...}} for every ``_stubNamespace`` member.

    Each key registered in the ``_stubNamespace(name, [...])`` call is a
    throw-stub verb (NotYetWiredForBrowserError) under that namespace.
    """
    text = _strip_ts_comments(path.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for m in _STUB_NAMESPACE_RE.finditer(text):
        ns = m.group("ns")
        keys = {k for k in _STR_ITEM_RE.findall(m.group("keys"))}
        out.setdefault(ns, set()).update(keys)
    return out


# --------------------------------------------------------------------------
# Parity-doc evidence.
# --------------------------------------------------------------------------

_DOC_TOKEN_PREFIXES = re.compile(r"^(?:await\s+)?(?:tn|Tn)\.", re.IGNORECASE)


def parity_doc_verbs() -> set[str]:
    """Canonical verbs referenced by backtick tokens in the parity doc.

    For a token like ``await tn.admin.addRecipient(group, opts)`` we strip the
    leading ``await``/``tn.``/``Tn.``, drop the call args, and emit both the
    namespaced canonical (``admin.add_recipient``) and the bare leaf
    (``add_recipient``). Bare tokens like ``setLevel`` emit ``set_level``.
    """
    text = PARITY_DOC.read_text(encoding="utf-8")
    out: set[str] = set()
    for m in re.finditer(r"`([^`]+)`", text):
        raw = m.group(1).strip()
        # Keep only the leading dotted-call path; drop everything from the
        # first space / paren / brace / bracket / angle / comma / equals.
        head = re.split(r"[\s(){}\[\]<>=,]", raw, maxsplit=1)[0]
        if not head:
            continue
        stripped = _DOC_TOKEN_PREFIXES.sub("", head)
        if not stripped:
            continue
        segments = [s for s in stripped.split(".") if s]
        if not segments:
            continue
        # Bare leaf canonical (always useful for module-level matches).
        out.add(canon(segments[-1]))
        # Namespaced canonical for tokens like admin.cache / pkg.offer.
        if len(segments) >= 2:
            ns = canon(segments[-2])
            out.add(f"{ns}.{canon(segments[-1])}")
    return out


# --------------------------------------------------------------------------
# Matrix construction.
# --------------------------------------------------------------------------


@dataclass
class Row:
    verb: str
    # real implementation present on the surface
    present: dict[str, bool] = field(default_factory=dict)
    # present only as a throw-stub on the surface (NotYetWired / not-yet-ported)
    stub: dict[str, bool] = field(default_factory=dict)

    @property
    def py_side(self) -> bool:
        return any(self.present.get(s, False) for s in PY_SURFACES)

    @property
    def ts_side(self) -> bool:
        return any(self.present.get(s, False) for s in TS_SURFACES)

    @property
    def ts_stub_side(self) -> bool:
        """A throw-stub appears on at least one TS surface."""
        return any(self.stub.get(s, False) for s in TS_SURFACES)

    @property
    def browser_stub(self) -> bool:
        """The browser surface carries this verb only as a throw-stub."""
        return self.stub.get("ts_browser", False) and not self.present.get(
            "ts_browser", False
        )

    @property
    def matched(self) -> bool:
        """A real implementation exists on BOTH language sides."""
        return self.py_side and self.ts_side

    @property
    def one_sided(self) -> bool:
        return self.py_side != self.ts_side

    @property
    def lone_side(self) -> str:
        if self.py_side and not self.ts_side:
            return "py"
        if self.ts_side and not self.py_side:
            return "ts"
        return ""

    @property
    def status(self) -> str:
        """Human status string used by both the matrix table and the JSON.

        - ``match``        : real on both sides (browser-stub annotated below).
        - ``match*browser-stub`` : real on both sides, but the browser surface
          has it only as a throw-stub (honesty annotation, still parity).
        - ``stub``         : a throw-stub is the *only* TS presence (a gap).
        - ``py-only`` / ``ts-only`` : present on exactly one language side.
        - ``absent``       : no real presence on either side (stub-only / doc).
        """
        if self.matched:
            return "match*browser-stub" if self.browser_stub else "match"
        if self.ts_stub_side and not self.ts_side and self.py_side:
            # Python-real, TS only a throw-stub: the honest gap.
            return "stub"
        if self.one_sided:
            return f"{self.lone_side}-only"
        if self.ts_stub_side and not self.ts_side and not self.py_side:
            return "stub"
        return "absent"


# Container for the parsed surfaces: real presence and throw-stub presence.
@dataclass
class Surfaces:
    real: dict[str, set[str]]
    stubs: dict[str, set[str]]


def collect_surfaces() -> Surfaces:
    """Return parsed real + throw-stub presence for all six surfaces.

    ``real`` maps surface -> {canonical verbs with a genuine implementation};
    ``stubs`` maps surface -> {canonical verbs present only as a throw-stub}.
    """
    real: dict[str, set[str]] = {s: set() for s in SURFACES}
    stubs: dict[str, set[str]] = {s: set() for s in SURFACES}

    # --- Python (no throw-stub concept here; AST presence is real). ---
    real["py_module"] = {canon(n) for n in python_module_symbols()}
    for ns, path in PY_NAMESPACE_MODULES.items():
        for n in python_namespace_symbols(path):
            real["py_namespace"].add(qualify(ns, n))

    # --- Node TS module + instance + namespaces. ---
    real["ts_module"] = {canon(n) for n in ts_module_symbols()}

    inst_real, inst_stub = ts_class_methods_split(TS_TN_CLASS, r"class\s+Tn\b")
    real["ts_instance"] = {canon(n) for n in inst_real}
    stubs["ts_instance"] = {canon(n) for n in inst_stub}

    for ns, (path, class_re) in TS_NAMESPACE_CLASSES.items():
        ns_real, ns_stub = ts_class_methods_split(path, class_re)
        for n in ns_real:
            real["ts_namespace"].add(qualify(ns, n))
        for n in ns_stub:
            stubs["ts_namespace"].add(qualify(ns, n))

    # --- Browser surface: index.browser.ts exports + browser/tn.ts class. ---
    br_real, br_stub = _collect_browser_surface()
    real["ts_browser"] = br_real
    stubs["ts_browser"] = br_stub

    return Surfaces(real=real, stubs=stubs)


def _collect_browser_surface() -> tuple[set[str], set[str]]:
    """Parse the browser SDK into (real, stub) canonical-verb sets.

    Real: module-level exports of ``index.browser.ts`` (init/info/read/... and
    the namespace-handle bare exports admin/pkg/vault/agents/handlers) plus the
    real (non-throw) methods of the browser ``Tn`` class.

    Stub: the browser ``Tn`` throw-stub methods (use/absorb/ephemeral/
    listCeremonies/watch) and every member of the ``_stubNamespace`` tiers
    (admin.addRecipient, pkg.absorb, vault.link, ...), all of which throw
    ``NotYetWiredForBrowserError``.

    A class throw-stub is never promoted to "real" by a module-level forwarder
    (``index.browser.ts``'s ``watch`` delegates to the class stub), so the
    honest stub status survives.
    """
    real: set[str] = set()
    stub: set[str] = set()

    # Browser class real / stub methods (statics + instance).
    cls_real, cls_stub = ts_class_methods_split(TS_TN_CLASS_BROWSER, r"class\s+Tn\b")
    real |= {canon(n) for n in cls_real}
    stub |= {canon(n) for n in cls_stub}

    # Module-level exports of the browser entry. These are real bare verbs
    # (init/info/read/close/...) and the namespace-handle proxies. A module
    # export that merely forwards to a class throw-stub (watch) must NOT
    # promote that verb to real, so drop any module name already known stub.
    mod = {canon(n) for n in ts_browser_module_symbols()}
    real |= mod - stub

    # Stub-namespace members: admin.addRecipient, vault.link, etc.
    for ns, keys in ts_browser_stub_namespaces(TS_TN_CLASS_BROWSER).items():
        for k in keys:
            stub.add(qualify(ns, canon(k)))

    # Never let a stub spelling shadow a genuine real one within the surface.
    stub -= real
    return real, stub


def build_matrix(
    surfaces: dict[str, set[str]] | Surfaces,
    stubs: dict[str, set[str]] | None = None,
) -> dict[str, Row]:
    """Fold the surface sets into one verb-keyed matrix.

    Accepts either a :class:`Surfaces` (real + stub) or a bare
    ``{surface: set}`` mapping of real presence (plus an optional ``stubs``
    mapping) for synthetic/test callers. Missing surfaces default to empty, so
    callers passing a subset of the columns still work.
    """
    if isinstance(surfaces, Surfaces):
        real_map = surfaces.real
        stub_map = surfaces.stubs
    else:
        real_map = surfaces
        stub_map = stubs or {}

    all_verbs: set[str] = set()
    for names in real_map.values():
        all_verbs |= names
    for names in stub_map.values():
        all_verbs |= names

    matrix: dict[str, Row] = {}
    for verb in sorted(all_verbs):
        row = Row(verb=verb)
        for s in SURFACES:
            row.present[s] = verb in real_map.get(s, set())
            row.stub[s] = verb in stub_map.get(s, set())
        matrix[verb] = row
    return matrix


# --------------------------------------------------------------------------
# Drift classification.
# --------------------------------------------------------------------------


@dataclass
class Drift:
    verb: str
    side: str  # "py" or "ts": the side the verb is present on
    present_surfaces: list[str]
    stub_surfaces: list[str] = field(default_factory=list)

    @property
    def has_py_side(self) -> bool:
        return any(s in PY_SURFACES for s in self.present_surfaces)

    @property
    def is_stub_gap(self) -> bool:
        """The drift is because TS has only a throw-stub (no real TS verb)."""
        return bool(self.stub_surfaces) and not any(
            s in TS_SURFACES for s in self.present_surfaces
        )


def classify(
    matrix: dict[str, Row],
    documented: set[str],
    allowlist: dict[str, Allow],
) -> tuple[list[Row], list[Row], list[Drift]]:
    """Split the matrix into (matched, allowed_one_sided/stub, drift).

    A verb is matched only when a *real* implementation exists on both
    language sides; a throw-stub never counts. A verb that is one-sided -- or
    whose only TS presence is a throw-stub -- is allowed iff documented or
    allowlisted, else it is drift.
    """
    matched: list[Row] = []
    allowed: list[Row] = []
    drift: list[Drift] = []
    for row in matrix.values():
        if row.matched:
            matched.append(row)
            continue
        # One-sided (or stub-only-on-a-side) from here on.
        if row.verb in allowlist or row.verb in documented:
            allowed.append(row)
            continue
        present = [s for s in SURFACES if row.present[s]]
        stub_surfaces = [s for s in SURFACES if row.stub.get(s, False)]
        drift.append(
            Drift(
                verb=row.verb,
                side=row.lone_side,
                present_surfaces=present,
                stub_surfaces=stub_surfaces,
            )
        )
    return matched, allowed, drift


# --------------------------------------------------------------------------
# Output.
# --------------------------------------------------------------------------

# Cell glyphs: x = real implementation, ~ = throw-stub only, . = absent.
def _cell(row: Row, surface: str) -> str:
    if row.present.get(surface, False):
        return "x"
    if row.stub.get(surface, False):
        return "~"
    return "."


def render_matrix_table(matrix: dict[str, Row]) -> str:
    headers = ["verb", *SURFACES, "status"]
    widths = [len(h) for h in headers]
    rows_out: list[list[str]] = []
    for row in matrix.values():
        cells = [row.verb, *[_cell(row, s) for s in SURFACES], row.status]
        rows_out.append(cells)
        for i, c in enumerate(cells):
            widths[i] = max(widths[i], len(c))
    lines = []
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines.append(fmt.format(*headers))
    lines.append(fmt.format(*["-" * w for w in widths]))
    for cells in rows_out:
        lines.append(fmt.format(*cells))
    lines.append("")
    lines.append("legend: x = real impl   ~ = throw-stub only   . = absent")
    return "\n".join(lines)


def matrix_to_json(
    matrix: dict[str, Row],
    documented: set[str],
    allowlist: dict[str, Allow],
) -> str:
    payload = []
    for row in matrix.values():
        entry = {
            "verb": row.verb,
            "surfaces": {s: row.present[s] for s in SURFACES},
            "stubs": {s: row.stub.get(s, False) for s in SURFACES},
            "py_side": row.py_side,
            "ts_side": row.ts_side,
            "ts_stub_side": row.ts_stub_side,
            "browser_stub": row.browser_stub,
            "matched": row.matched,
            "status": row.status,
            "documented": row.verb in documented,
        }
        allow = allowlist.get(row.verb)
        if allow is not None:
            entry["allowlisted"] = {"reason": allow.reason, "side": allow.side}
        payload.append(entry)
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------
# Entry point.
# --------------------------------------------------------------------------


@dataclass
class Report:
    """One full build + classification pass. Computed once per invocation."""
    code: int
    matrix: dict[str, Row]
    documented: set[str]
    allowlist: dict[str, Allow]
    matched: list[Row]
    allowed: list[Row]
    drift: list[Drift]


def build_report() -> Report:
    """Parse every surface, build the matrix, classify once, and package the
    result. The single source of truth for both :func:`run` and :func:`main`
    so the classification is never recomputed within one invocation."""
    surfaces = collect_surfaces()
    matrix = build_matrix(surfaces)
    documented = parity_doc_verbs()
    allowlist = build_allowlist()
    matched, allowed, drift = classify(matrix, documented, allowlist)
    code = 1 if drift else 0
    return Report(
        code=code,
        matrix=matrix,
        documented=documented,
        allowlist=allowlist,
        matched=matched,
        allowed=allowed,
        drift=drift,
    )


def run() -> tuple[int, dict[str, Row], set[str], dict[str, Allow], list[Drift]]:
    """Build everything and classify. Returns the exit code plus artifacts so
    tests can import and assert on the same data the CLI prints.

    Thin adapter over :func:`build_report` preserving the historical 5-tuple
    shape that the test-suite unpacks.
    """
    r = build_report()
    return r.code, r.matrix, r.documented, r.allowlist, r.drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verb-centric cross-language parity gate for the TN SDKs.",
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="print the full aligned verb x surface matrix table",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the matrix as JSON (implies no exit-code change)",
    )
    args = parser.parse_args(argv)

    report = build_report()
    matrix = report.matrix
    allowlist = report.allowlist
    matched = report.matched
    allowed = report.allowed
    drift = report.drift

    if args.json:
        print(matrix_to_json(matrix, report.documented, allowlist))
        return report.code

    if args.matrix:
        print(render_matrix_table(matrix))
        print()

    # Honesty rollups visible in both the ok and drift paths.
    # browser_stub_rows: verbs REAL on both sides but throw-stub in the browser
    # (parity is Node/Python only). The pure browser-stub placeholders with no
    # real impl land in ts_stub_only instead, so they are not double-counted as
    # "matched".
    browser_stub_rows = [r for r in matrix.values() if r.matched and r.browser_stub]
    ts_stub_only = [r for r in matrix.values() if r.status == "stub"]
    ts_gap_rows = [
        r
        for r in allowed
        if allowlist.get(r.verb) is not None and allowlist[r.verb].gap
    ]

    if not drift:
        print("parity: ok")
        print(f"  verbs in matrix:        {len(matrix)}")
        print(f"  matched (both sides):   {len(matched)}")
        print(f"    of which browser-stub: {len(browser_stub_rows)}")
        print(f"  one-sided (allowed):    {len(allowed)}")
        print(f"  TS throw-stub only:     {len(ts_stub_only)}")
        print(f"  TS gaps (no TS port):   {len(ts_gap_rows)}")
        print(f"  allowlist entries:      {len(allowlist)}")
        if browser_stub_rows:
            print()
            print("  browser surface is a throw-stub for these matched verbs")
            print("  (NotYetWiredForBrowserError -- parity is Node/Python only):")
            for r in sorted(browser_stub_rows, key=lambda x: x.verb):
                print(f"    - {r.verb}")
        if ts_stub_only:
            print()
            print("  TS exposes ONLY a throw-stub for these (no real TS impl):")
            for r in sorted(ts_stub_only, key=lambda x: x.verb):
                where = ", ".join(s for s in TS_SURFACES if r.stub.get(s, False))
                print(f"    - {r.verb}  [stub on: {where}]")
        if ts_gap_rows:
            print()
            print("  Python-only surface, no TS port yet (tracked TS gaps):")
            for r in sorted(ts_gap_rows, key=lambda x: x.verb):
                print(f"    - {r.verb}: {allowlist[r.verb].reason}")
        return 0

    print("parity: DRIFT")
    print(
        f"  {len(drift)} verb(s) present on one language only (or TS-stub only), "
        f"not documented in {PARITY_DOC.name} and not in the allowlist:"
    )
    for d in sorted(drift, key=lambda x: x.verb):
        if d.is_stub_gap:
            where = ", ".join(d.stub_surfaces)
            tail = "real Python side" if d.has_py_side else "no real impl either side"
            print(f"  - {d.verb}  [TS throw-stub only: {where}; {tail}]")
        else:
            surfaces_str = ", ".join(d.present_surfaces)
            print(f"  - {d.verb}  [{d.side}-only: {surfaces_str}]")
    print()
    print("To resolve each: either add the missing counterpart on the other")
    print("language, add a row to docs/sdk-parity.md, or, for a genuinely")
    print("one-sided / throw-stub verb, add an entry (with a reason) to the")
    print("ALLOWLIST in tools/check_parity.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
