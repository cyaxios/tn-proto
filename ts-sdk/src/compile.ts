// Compile btn keystore material into a `.tnpkg` file (a ZIP archive)
// that the Chrome extension, the Python SDK, and any other TN reader
// can consume. This is the TS/Node analog of
// `tn.compile.compile_kit_bundle` in Python — which delegates to
// `tn.export`, so the artifact is a *canonical* signed `.tnpkg`, not the
// legacy `"tnpkg-v1"` manifest this module used to write.
//
// .tnpkg layout
// -------------
//
//   manifest.json           canonical signed manifest (see core/tnpkg.ts).
//                           kind "kit_bundle" (readers-only) or
//                           "full_keystore" (with `--full`). The
//                           reader-kit metadata lives under `state.kits`.
//   body/<group>.btn.mykit  raw reader-kit bytes, one per group. Kits live
//                           under `body/`, NOT the zip root — that is the
//                           shape `absorb` accepts.
//   body/<group>.btn.mykit.revoked.<ts>   rotation-preserved kits.
//
// With `full: true` the archive additionally carries the publisher
// seed + state + index master + tn.yaml under `body/` so the recipient
// ends up with a complete ceremony, plus a `body/WARNING_CONTAINS_PRIVATE_KEYS`
// marker. Don't use that for sharing; use it for self-backup only.
//
// The manifest is Ed25519-signed by the keystore's device key so
// `absorb` accepts it (absorb rejects unsigned / mis-signed manifests).
// `publisher_identity` is resolved from the yaml's
// `device.device_identity` when `--yaml` is given, else from the
// keystore's `local.public` (which is the same DID the signing seed
// derives, so the signature always verifies).

import { Buffer } from "node:buffer";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { DeviceKey } from "./core/signing.js";
import {
  type BodyContents,
  type Manifest,
  newManifest,
  signManifest,
  toWireDict,
} from "./core/tnpkg.js";
import { tnpkgWriteBytes } from "./raw.js";
import { loadConfig } from "./runtime/config.js";

export interface CompileKitBundleOptions {
  /** Keystore directory (e.g. `./demo/alice/keys`). Either this or `yamlPath` is required. */
  keystoreDir?: string;
  /** Path to a tn.yaml. If given, `keystoreDir` is inferred from the yaml's keystore.path. */
  yamlPath?: string;
  /** If set, include ONLY these group names (e.g. ["trading", "chat"]). Default: all. */
  groups?: string[];
  /**
   * Human-readable label. Retained for CLI back-compat; the canonical
   * manifest has no `label` field, so this is currently ignored by the
   * artifact (kept so callers don't break).
   */
  label?: string;
  /** Optional free-form note. Retained for back-compat; not serialized. */
  note?: string;
  /**
   * Include publisher-side material (signing seed, publisher state,
   * index master, tn.yaml) alongside the reader kits. Use this for
   * self-backup only.
   */
  full?: boolean;
}

/** A reader-kit entry recorded in the manifest's `state.kits`. */
export interface CompiledKitMeta {
  name: string;
  sha256: string;
  bytes: number;
}

export interface CompiledPackage {
  /** Canonical signed manifest (see core/tnpkg.ts). */
  manifest: Manifest;
  zipBytes: Uint8Array;
}

const KIT_RE = /^(.+?)\.btn\.(mykit|mykit\.revoked\.\d+)$/;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

/** Serialize a signed manifest + body to `.tnpkg` zip bytes (in memory).
 * Mirrors `writeTnpkg` (Layer 2) but returns bytes instead of writing. */
function packManifestBundle(manifest: Manifest, body: BodyContents): Uint8Array {
  if (!manifest.manifestSignatureB64) {
    throw new Error("packManifestBundle: manifest is unsigned; call signManifest(...) first.");
  }
  const wireDoc = toWireDict(manifest, true);
  const entries = Object.keys(body)
    .sort()
    .map((name) => ({ name, data: body[name]! }));
  return new Uint8Array(tnpkgWriteBytes(wireDoc, entries));
}

// ---------------------------------------------------------------------------
// Public: compile to in-memory package + optional write-to-file
// ---------------------------------------------------------------------------

/**
 * Build a canonical `.tnpkg` kit bundle in memory. Reads kits (and, with
 * `full`, private material) from the keystore, builds + signs a canonical
 * manifest, and packs kits under `body/`. Pure w.r.t. disk: reads only.
 */
export function compileKitBundle(opts: CompileKitBundleOptions): CompiledPackage {
  let keystoreDir = opts.keystoreDir ? resolve(opts.keystoreDir) : null;
  let fromDid: string | null = null;
  let ceremonyId = "";
  let yamlPath: string | null = null;

  if (opts.yamlPath) {
    const cfg = loadConfig(opts.yamlPath);
    if (!keystoreDir) keystoreDir = cfg.keystorePath;
    fromDid = cfg.device.device_identity || null;
    ceremonyId = cfg.ceremonyId || "";
    yamlPath = resolve(opts.yamlPath);
  }
  if (!keystoreDir) {
    throw new Error("compileKitBundle: provide keystoreDir or yamlPath");
  }
  if (!existsSync(keystoreDir) || !statSync(keystoreDir).isDirectory()) {
    throw new Error(`compileKitBundle: keystore directory not found: ${keystoreDir}`);
  }

  // Resolve the publisher DID. Prefer the yaml's device.device_identity;
  // otherwise read the keystore's local.public (the DID the signing seed
  // derives), so `manifest_signature_b64` always verifies against it.
  if (!fromDid) {
    const pubPath = join(keystoreDir, "local.public");
    if (!existsSync(pubPath)) {
      throw new Error(`compileKitBundle: no device DID (missing ${pubPath} and no yaml device_identity)`);
    }
    fromDid = readFileSync(pubPath, "utf8").trim();
  }
  if (!fromDid) {
    throw new Error("compileKitBundle: could not resolve a publisher device DID");
  }

  const privPath = join(keystoreDir, "local.private");
  if (!existsSync(privPath)) {
    throw new Error(`compileKitBundle: signing seed not found: ${privPath}`);
  }
  const deviceKey = DeviceKey.fromSeed(new Uint8Array(readFileSync(privPath)));

  const entries = readdirSync(keystoreDir).sort();
  const groupFilter = opts.groups && opts.groups.length > 0 ? new Set(opts.groups) : null;
  const body: BodyContents = {};
  const kitsMeta: CompiledKitMeta[] = [];

  for (const name of entries) {
    const m = KIT_RE.exec(name);
    if (!m) continue;
    const group = m[1]!;
    if (groupFilter && !groupFilter.has(group)) continue;
    const data = new Uint8Array(readFileSync(join(keystoreDir, name)));
    body[`body/${name}`] = data;
    kitsMeta.push({ name, sha256: `sha256:${sha256Hex(data)}`, bytes: data.length });
  }

  if (kitsMeta.length === 0) {
    const suffix = groupFilter ? ` matching groups [${Array.from(groupFilter).sort().join(", ")}]` : "";
    throw new Error(`compileKitBundle: no *.btn.mykit files in ${keystoreDir}${suffix}`);
  }

  if (opts.full) {
    for (const name of ["local.private", "local.public", "index_master.key"]) {
      const p = join(keystoreDir, name);
      if (existsSync(p)) {
        body[`body/${name}`] = new Uint8Array(readFileSync(p));
      }
    }
    for (const name of entries) {
      if (/\.btn\.state$/.test(name)) {
        const group = name.replace(/\.btn\.state$/, "");
        if (groupFilter && !groupFilter.has(group)) continue;
        body[`body/${name}`] = new Uint8Array(readFileSync(join(keystoreDir, name)));
      }
    }
    if (yamlPath && existsSync(yamlPath)) {
      body["body/tn.yaml"] = new Uint8Array(readFileSync(yamlPath));
    }
    body["body/WARNING_CONTAINS_PRIVATE_KEYS"] = new Uint8Array(0);
  }

  const manifest = newManifest({
    kind: opts.full ? "full_keystore" : "kit_bundle",
    fromDid,
    ceremonyId,
    scope: opts.full ? "full" : "kit_bundle",
  });
  manifest.state = {
    kits: kitsMeta,
    kind: opts.full ? "full-keystore" : "readers-only",
  };
  signManifest(manifest, deviceKey);

  return { manifest, zipBytes: packManifestBundle(manifest, body) };
}

/**
 * Compile + write to `outPath`. Returns the canonical manifest, the
 * resolved path, and the kit file basenames (derived from
 * `manifest.state.kits`) so existing callers keep working.
 */
export function compileKitBundleToFile(opts: CompileKitBundleOptions & { outPath: string }): {
  manifest: Manifest;
  outPath: string;
  kits: string[];
} {
  const { manifest, zipBytes } = compileKitBundle(opts);
  const outResolved = resolve(opts.outPath);
  writeFileSync(outResolved, zipBytes);
  const stateKits = (manifest.state?.["kits"] as CompiledKitMeta[] | undefined) ?? [];
  const kits = stateKits.map((k) => k.name);
  return { manifest, outPath: outResolved, kits };
}
