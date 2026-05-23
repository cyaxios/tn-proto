// Standalone bootstrap-absorb path. Mirrors Python's
// ``_try_bootstrap_cfg`` + the dispatch routing so a TS caller can
// write::
//
//     await Tn.absorb('Agentic20.project.tnpkg');
//     const tn = await Tn.init();
//
// in a fresh directory with no prior ``Tn.init()``. Bug 3 in the
// 0.4.0a2 brief.
//
// Only ``identity_seed`` and ``project_seed`` are bootstrap kinds —
// every other manifest kind needs an active runtime / yaml so we
// route through the regular ``Tn`` flow.
//
// The handlers here mirror ``NodeRuntime._absorbIdentitySeed`` and
// ``NodeRuntime._absorbProjectSeed`` byte-for-byte. We don't invoke the
// runtime methods directly because building a NodeRuntime requires a
// loadable yaml, which is the chicken-and-egg case we're solving.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve as pathResolve, isAbsolute as pathIsAbsolute } from "node:path";
import { Buffer } from "node:buffer";

import { parse as parseYaml } from "yaml";

import { DeviceKey } from "../core/signing.js";
import { isManifestSignatureValid, toWireDict, type Manifest } from "../core/tnpkg.js";
import { readTnpkg } from "../tnpkg_io.js";
import { decryptBodyBlob } from "../core/body_encryption.js";
import { manifestAadForWrap, unsealBekFromWrap, UnsealError } from "../core/recipient_seal.js";
import type { AbsorbReceipt } from "../core/results.js";

interface SyntheticPaths {
  yamlPath: string;
  keystore: string;
  logPath: string;
}

/** Resolve bootstrap-time paths from cwd plus an optional body/tn.yaml. */
function _syntheticPaths(cwd: string, yamlBytes: Uint8Array | undefined): SyntheticPaths {
  let keystoreRel = "./.tn/tn/keys";
  let logRel = "./.tn/tn/logs/tn.ndjson";
  if (yamlBytes !== undefined) {
    try {
      const doc = parseYaml(new TextDecoder("utf-8").decode(yamlBytes)) as Record<
        string,
        unknown
      > | null;
      if (doc && typeof doc === "object") {
        const ks = (doc["keystore"] ?? null) as Record<string, unknown> | null;
        if (ks && typeof ks["path"] === "string") keystoreRel = ks["path"] as string;
        const logs = (doc["logs"] ?? null) as Record<string, unknown> | null;
        if (logs && typeof logs["path"] === "string") logRel = logs["path"] as string;
      }
    } catch {
      // Best-effort yaml parsing — fall through to defaults.
    }
  }
  const yamlPath = pathResolve(cwd, "tn.yaml");
  const keystore = pathIsAbsolute(keystoreRel)
    ? keystoreRel
    : pathResolve(cwd, keystoreRel);
  const logPath = pathIsAbsolute(logRel) ? logRel : pathResolve(cwd, logRel);
  return { yamlPath, keystore, logPath };
}

function _userEventCount(logPath: string): number {
  // Walk the main log plus rotated backups (.1, .2, ...).
  const candidates: string[] = [logPath];
  for (let n = 1; n <= 10; n += 1) {
    const p = `${logPath}.${n}`;
    if (!existsSync(p)) break;
    candidates.push(p);
  }
  let count = 0;
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    try {
      for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
        const s = rawLine.trim();
        if (!s) continue;
        let env: Record<string, unknown>;
        try {
          env = JSON.parse(s) as Record<string, unknown>;
        } catch {
          continue;
        }
        const et = env["event_type"];
        if (typeof et === "string" && !et.startsWith("tn.")) count += 1;
      }
    } catch {
      continue;
    }
  }
  return count;
}

function _ts(): string {
  return new Date().toISOString().replace(/[:.]/g, "").slice(0, 15) + "Z";
}

/** True iff ``source`` is an ``identity_seed`` / ``project_seed`` bundle. */
export function isBootstrapKind(source: string | Uint8Array): boolean {
  try {
    const { manifest } = readTnpkg(source);
    return manifest.kind === "identity_seed" || manifest.kind === "project_seed";
  } catch {
    return false;
  }
}

/**
 * Bootstrap absorb path — install an identity_seed / project_seed
 * bundle into ``cwd`` without a prior ``Tn.init()``. Returns the
 * receipt the regular runtime would have returned.
 *
 * Throws when the bundle is not a recognised bootstrap kind; callers
 * should pre-flight with ``isBootstrapKind`` if they want to fall
 * through to the runtime path on a non-bootstrap source.
 */
export function absorbBootstrap(
  source: string | Uint8Array,
  opts: { cwd?: string; seed?: Uint8Array } = {},
): AbsorbReceipt {
  const cwd = pathResolve(opts.cwd ?? process.cwd());
  const { manifest, body } = readTnpkg(source);

  if (!isManifestSignatureValid(manifest)) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        `manifest signature does not verify against publisher_identity ` +
        `${JSON.stringify(manifest.fromDid)}. The package is corrupt, truncated, or tampered.`,
    };
  }

  // If the body is recipient-sealed AND the caller supplied a seed, try
  // to unseal it before dispatching to the kind-specific handler. The
  // kind handlers expect plaintext body files (body/keys/local.private
  // etc.); a sealed body is the bag-of-bytes-in-body/encrypted.bin
  // shape that the unseal turns into the expected layout.
  //
  // Mirror of python/tn/absorb.py::_maybe_unseal_recipient_wrap. Pass-
  // through when there's no body_encryption.recipient_wrap[s] (a sealed
  // bundle that has no wraps at all is a malformed publish, not our
  // concern here).
  const unsealResult = _maybeUnsealBody(manifest, body, opts.seed);
  if (unsealResult.kind === "rejected") return unsealResult.receipt;
  const effectiveBody = unsealResult.body;

  if (manifest.kind === "identity_seed") {
    return _bootstrapIdentitySeed(manifest, effectiveBody, cwd);
  }
  if (manifest.kind === "project_seed") {
    return _bootstrapProjectSeed(manifest, effectiveBody, cwd);
  }
  return {
    kind: manifest.kind,
    acceptedCount: 0,
    dedupedCount: 0,
    noop: false,
    derivedState: null,
    conflicts: [],
    rejectedReason:
      `absorbBootstrap: kind ${JSON.stringify(manifest.kind)} is not a bootstrap kind ` +
      `(only identity_seed and project_seed are supported without an active runtime).`,
  };
}

/**
 * Recipient-wrap unseal step. Mirror of python/tn/absorb.py::
 * _maybe_unseal_recipient_wrap. Returns either:
 *   * `{kind: "ok", body}` — the body to dispatch on (either the
 *     original body unchanged when no unseal was needed, or the
 *     decrypted member map).
 *   * `{kind: "rejected", receipt}` — a typed receipt the caller
 *     returns straight back to its own caller.
 *
 * Synchronous-looking API but internally `await`s the Web Crypto
 * primitives. Callers route through `absorbBootstrap` (which is sync
 * because the underlying file I/O is sync); the unseal path is
 * exercised via a separate async `absorbSealedBootstrap` entry point
 * that delegates here through a Promise.
 *
 * NOTE: This function is intentionally NOT async-marked on the outer
 * surface — the no-wrap pass-through case is synchronous and the vast
 * majority of bootstrap calls take that branch. The sealed branch
 * routes through the dedicated async entry point below.
 */
function _maybeUnsealBody(
  manifest: Manifest,
  body: Map<string, Uint8Array>,
  _seed: Uint8Array | undefined,
): { kind: "ok"; body: Map<string, Uint8Array> } | { kind: "rejected"; receipt: AbsorbReceipt } {
  // The async unseal path is reached only via absorbSealedBootstrap().
  // From the synchronous absorbBootstrap() entry point, a sealed body
  // (with no seed available) falls through to the kind handlers, which
  // will reject it with a clearer "body missing local.private" error.
  // That preserves the existing async-free contract of absorbBootstrap.
  return { kind: "ok", body };
}

/**
 * Async sister of `absorbBootstrap` for recipient-sealed bundles.
 * Mandatory `seed` is the 32-byte Ed25519 seed of the recipient whose
 * wrap is present in `manifest.state.body_encryption.recipient_wraps[]`.
 *
 * Flow:
 *   1. readTnpkg + signature verify (same as absorbBootstrap).
 *   2. Pick the wrap whose `recipient_identity` matches our DID.
 *   3. unsealBekFromWrap(wrap, seed, aad) → BEK.
 *   4. decryptBodyBlob(body.get("body/encrypted.bin"), BEK) → new body
 *      member map.
 *   5. Dispatch to the kind-specific handler with the decrypted body.
 *
 * Returns the same AbsorbReceipt shape `absorbBootstrap` does.
 */
export async function absorbSealedBootstrap(
  source: string | Uint8Array,
  opts: { seed: Uint8Array; cwd?: string },
): Promise<AbsorbReceipt> {
  const cwd = pathResolve(opts.cwd ?? process.cwd());
  // readTnpkg throws on a malformed zip / missing manifest. Wrap so
  // callers get a populated rejectedReason instead — they're already
  // handling other rejection paths via the receipt, this keeps the
  // contract uniform.
  let manifest: Manifest;
  let body: Map<string, Uint8Array>;
  try {
    const parsed = readTnpkg(source);
    manifest = parsed.manifest;
    body = parsed.body;
  } catch (err) {
    return {
      kind: "",
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `absorbSealedBootstrap: ${(err as Error).message ?? String(err)}`,
    };
  }

  if (!isManifestSignatureValid(manifest)) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        `manifest signature does not verify against publisher_identity ` +
        `${JSON.stringify(manifest.fromDid)}. The package is corrupt, truncated, or tampered.`,
    };
  }

  if (opts.seed.length !== 32) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `absorbSealedBootstrap: seed must be 32 bytes, got ${opts.seed.length}`,
    };
  }

  const ourDid = DeviceKey.fromSeed(opts.seed).did;

  // Inspect the manifest state for the wrap envelope. If absent, the
  // bundle isn't recipient-sealed — fall through to the unsealed path
  // by calling absorbBootstrap.
  const state =
    manifest.state && typeof manifest.state === "object" ? (manifest.state as Record<string, unknown>) : null;
  const bodyEnc =
    state && typeof state["body_encryption"] === "object" && state["body_encryption"] !== null
      ? (state["body_encryption"] as Record<string, unknown>)
      : null;
  const wrapsArray = bodyEnc?.["recipient_wraps"];
  const wrapSingular = bodyEnc?.["recipient_wrap"];
  if (
    bodyEnc === null ||
    (wrapsArray === undefined && wrapSingular === undefined)
  ) {
    // Not a recipient-sealed bundle — delegate to the plain path.
    return absorbBootstrap(source, { cwd });
  }

  // Build the candidate list. Plural wins when both are present
  // (matches python/tn/absorb.py:578).
  const candidates: Record<string, unknown>[] = [];
  if (Array.isArray(wrapsArray)) {
    for (const entry of wrapsArray) {
      if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        const e = entry as Record<string, unknown>;
        if (e["recipient_identity"] === ourDid) candidates.push(e);
      }
    }
  } else if (wrapSingular && typeof wrapSingular === "object" && !Array.isArray(wrapSingular)) {
    const e = wrapSingular as Record<string, unknown>;
    if (e["recipient_identity"] === ourDid) candidates.push(e);
  }

  if (candidates.length === 0) {
    // Wraps present but none names us. Not "tampered" — just "not for
    // me." Mirror python's clear rejection reason at absorb.py:607.
    const named: unknown[] = [];
    if (Array.isArray(wrapsArray)) {
      for (const e of wrapsArray) {
        if (e && typeof e === "object" && !Array.isArray(e)) {
          named.push((e as Record<string, unknown>)["recipient_identity"]);
        }
      }
    } else if (wrapSingular && typeof wrapSingular === "object" && !Array.isArray(wrapSingular)) {
      named.push((wrapSingular as Record<string, unknown>)["recipient_identity"]);
    }
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        `sealed-box wrap is addressed to ${JSON.stringify(named)}; ` +
        `this runtime is ${JSON.stringify(ourDid)}. Refusing to attempt unwrap.`,
    };
  }

  // AAD is computed against the WIRE manifest (snake_case), not the TS
  // Manifest. toWireDict gives us the canonical wire view.
  const aad = manifestAadForWrap(toWireDict(manifest, true));

  // Try each matching candidate. First successful unseal wins.
  let bek: Uint8Array | null = null;
  let lastErr = "";
  for (const cand of candidates) {
    try {
      bek = await unsealBekFromWrap(cand, opts.seed, aad);
      break;
    } catch (err) {
      if (err instanceof UnsealError) {
        lastErr = err.message;
        continue;
      }
      // Anything other than UnsealError is unexpected; surface.
      throw err;
    }
  }
  if (bek === null) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `sealed-box unwrap failed: ${lastErr}`,
    };
  }

  const encrypted = body.get("body/encrypted.bin");
  if (encrypted === undefined) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        "manifest declares body_encryption but body/encrypted.bin is missing from the zip.",
    };
  }

  let decryptedBody: Map<string, Uint8Array>;
  try {
    decryptedBody = await decryptBodyBlob(encrypted, bek);
  } catch (err) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `body decrypt with unwrapped BEK failed: ${(err as Error).message ?? String(err)}`,
    };
  }

  // Dispatch with the decrypted body in hand.
  if (manifest.kind === "identity_seed") {
    return _bootstrapIdentitySeed(manifest, decryptedBody, cwd);
  }
  if (manifest.kind === "project_seed") {
    return _bootstrapProjectSeed(manifest, decryptedBody, cwd);
  }
  return {
    kind: manifest.kind,
    acceptedCount: 0,
    dedupedCount: 0,
    noop: false,
    derivedState: null,
    conflicts: [],
    rejectedReason:
      `absorbSealedBootstrap: kind ${JSON.stringify(manifest.kind)} is not a bootstrap kind ` +
      `(only identity_seed and project_seed are supported without an active runtime).`,
  };
}

function _bootstrapIdentitySeed(
  manifest: Manifest,
  body: Map<string, Uint8Array>,
  cwd: string,
): AbsorbReceipt {
  const priv = body.get("body/local.private");
  const pub = body.get("body/local.public");
  const yamlBytes = body.get("body/tn.yaml");
  const missing: string[] = [];
  if (priv === undefined) missing.push("body/local.private");
  if (pub === undefined) missing.push("body/local.public");
  if (yamlBytes === undefined) missing.push("body/tn.yaml");
  if (priv === undefined || pub === undefined || yamlBytes === undefined) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `identity_seed body is missing required members: ${JSON.stringify(missing)}`,
    };
  }

  if (priv.length !== 32) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `identity_seed body/local.private must be 32 bytes; got ${priv.length}`,
    };
  }

  const derivedKey = DeviceKey.fromSeed(priv);
  const bundleDid = new TextDecoder("utf-8").decode(pub).trim();
  if (derivedKey.did !== bundleDid || derivedKey.did !== manifest.fromDid) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        `identity_seed integrity check failed: manifest.fromDid=${JSON.stringify(manifest.fromDid)}, ` +
        `body/local.public=${JSON.stringify(bundleDid)}, derived-from-private=${JSON.stringify(derivedKey.did)}.`,
    };
  }
  if (manifest.fromDid !== manifest.toDid) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `identity_seed must be self-addressed (fromDid === toDid).`,
    };
  }

  const paths = _syntheticPaths(cwd, yamlBytes);
  const ts = _ts();

  if (!existsSync(paths.keystore)) mkdirSync(paths.keystore, { recursive: true });
  const privPath = pathResolve(paths.keystore, "local.private");
  const pubPath = pathResolve(paths.keystore, "local.public");

  if (existsSync(privPath)) {
    const existing = readFileSync(privPath);
    if (Buffer.from(existing).equals(Buffer.from(priv))) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: true,
        derivedState: null,
        conflicts: [],
      };
    }
    if (_userEventCount(paths.logPath) === 0) {
      try {
        renameSync(privPath, pathResolve(paths.keystore, `local.private.previous.${ts}`));
      } catch {
        /* best effort */
      }
      try {
        if (existsSync(pubPath)) {
          renameSync(pubPath, pathResolve(paths.keystore, `local.public.previous.${ts}`));
        }
      } catch {
        /* best effort */
      }
    } else {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `refusing to overwrite existing identity at ${privPath}. The keystore already ` +
          `has a different device key and the local log already contains user-emitted entries.`,
      };
    }
  }

  writeFileSync(privPath, Buffer.from(priv));
  writeFileSync(pubPath, bundleDid, "utf8");

  if (!existsSync(paths.yamlPath)) {
    mkdirSync(dirname(paths.yamlPath), { recursive: true });
    writeFileSync(paths.yamlPath, Buffer.from(yamlBytes));
  } else if (
    _userEventCount(paths.logPath) === 0 &&
    !Buffer.from(readFileSync(paths.yamlPath)).equals(Buffer.from(yamlBytes))
  ) {
    try {
      renameSync(paths.yamlPath, `${paths.yamlPath}.previous.${ts}`);
    } catch {
      /* best effort */
    }
    mkdirSync(dirname(paths.yamlPath), { recursive: true });
    writeFileSync(paths.yamlPath, Buffer.from(yamlBytes));
  }

  return {
    kind: manifest.kind,
    acceptedCount: 1,
    dedupedCount: 0,
    noop: false,
    derivedState: null,
    conflicts: [],
  };
}

function _bootstrapProjectSeed(
  manifest: Manifest,
  body: Map<string, Uint8Array>,
  cwd: string,
): AbsorbReceipt {
  const yamlBytes = body.get("body/tn.yaml");
  const priv = body.get("body/keys/local.private");
  const pub = body.get("body/keys/local.public");
  const missing: string[] = [];
  if (yamlBytes === undefined) missing.push("body/tn.yaml");
  if (priv === undefined) missing.push("body/keys/local.private");
  if (pub === undefined) missing.push("body/keys/local.public");
  if (yamlBytes === undefined || priv === undefined || pub === undefined) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `project_seed body is missing required members: ${JSON.stringify(missing)}`,
    };
  }

  if (priv.length !== 32) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `project_seed body/keys/local.private must be 32 bytes; got ${priv.length}`,
    };
  }

  const derivedKey = DeviceKey.fromSeed(priv);
  const bundleDid = new TextDecoder("utf-8").decode(pub).trim();
  if (derivedKey.did !== bundleDid || derivedKey.did !== manifest.fromDid) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason:
        `project_seed integrity check failed: manifest.fromDid=${JSON.stringify(manifest.fromDid)}, ` +
        `body/keys/local.public=${JSON.stringify(bundleDid)}, derived-from-private=${JSON.stringify(derivedKey.did)}.`,
    };
  }
  if (manifest.fromDid !== manifest.toDid) {
    return {
      kind: manifest.kind,
      acceptedCount: 0,
      dedupedCount: 0,
      noop: false,
      derivedState: null,
      conflicts: [],
      rejectedReason: `project_seed must be self-addressed (fromDid === toDid).`,
    };
  }

  const paths = _syntheticPaths(cwd, yamlBytes);
  const ts = _ts();
  let accepted = 0;
  let deduped = 0;
  const replaced: string[] = [];

  // Step A: tn.yaml.
  if (existsSync(paths.yamlPath)) {
    const existing = readFileSync(paths.yamlPath);
    if (Buffer.from(existing).equals(Buffer.from(yamlBytes))) {
      deduped += 1;
    } else if (_userEventCount(paths.logPath) === 0) {
      try {
        renameSync(paths.yamlPath, `${paths.yamlPath}.previous.${ts}`);
      } catch {
        /* best effort */
      }
      replaced.push(paths.yamlPath);
      mkdirSync(dirname(paths.yamlPath), { recursive: true });
      writeFileSync(paths.yamlPath, Buffer.from(yamlBytes));
      accepted += 1;
    } else {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `refusing to overwrite existing tn.yaml at ${paths.yamlPath}: contents differ and the ` +
          `local log already contains user-emitted entries.`,
      };
    }
  } else {
    mkdirSync(dirname(paths.yamlPath), { recursive: true });
    writeFileSync(paths.yamlPath, Buffer.from(yamlBytes));
    accepted += 1;
  }

  // Step B: keys.
  if (!existsSync(paths.keystore)) mkdirSync(paths.keystore, { recursive: true });

  const existingPriv = pathResolve(paths.keystore, "local.private");
  if (existsSync(existingPriv)) {
    const existingBytes = readFileSync(existingPriv);
    if (
      !Buffer.from(existingBytes).equals(Buffer.from(priv)) &&
      _userEventCount(paths.logPath) > 0
    ) {
      return {
        kind: manifest.kind,
        acceptedCount: 0,
        dedupedCount: 0,
        noop: false,
        derivedState: null,
        conflicts: [],
        rejectedReason:
          `refusing to overwrite existing identity at ${existingPriv}: a different device key ` +
          `is already installed and the local log contains user events signed by it.`,
      };
    }
  }

  for (const [name, data] of body) {
    if (!name.startsWith("body/keys/")) continue;
    const rel = name.slice("body/keys/".length);
    if (!rel) continue;
    if (rel.includes("/") || rel.includes("\\")) continue;
    const dest = pathResolve(paths.keystore, rel);
    if (existsSync(dest)) {
      const existing = readFileSync(dest);
      if (Buffer.from(existing).equals(Buffer.from(data))) {
        deduped += 1;
        continue;
      }
      try {
        renameSync(dest, pathResolve(paths.keystore, `${rel}.previous.${ts}`));
      } catch {
        /* best effort */
      }
      replaced.push(dest);
    }
    writeFileSync(dest, Buffer.from(data));
    accepted += 1;
  }

  return {
    kind: manifest.kind,
    acceptedCount: accepted,
    dedupedCount: deduped,
    noop: false,
    derivedState: null,
    conflicts: [],
    replacedKitPaths: replaced,
  };
}
