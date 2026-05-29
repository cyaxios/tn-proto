// Port of tn_proto/python/tn/identity.py — the per-user GLOBAL device
// identity stored at `$XDG_DATA_HOME/tn/identity.json` (or the platform
// equivalent), shared across every ceremony minted on this machine.
//
// Why global: Python's `tn init` seeds each ceremony's device key from this
// one identity, so all of a user's projects share a single device DID. That
// shared DID is what makes warm-attach work — once `tn account connect`
// mints the DID onto a vault account (and stamps `linked_account_id` here),
// a brand-new `tn init` reuses the same DID and can authenticate + attach
// without a browser.
//
// File schema is kept compatible with the Python writer (same field names
// for the device key + links) so a shared identity.json round-trips between
// the two CLIs. Unknown fields are preserved on save.

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";
import { Buffer } from "node:buffer";

import { DeviceKey } from "./core/signing.js";

/** Resolve the identity directory. Mirrors Python `_default_identity_dir`. */
export function defaultIdentityDir(): string {
  const override = process.env["TN_IDENTITY_DIR"];
  if (override) return override;
  const xdg = process.env["XDG_DATA_HOME"];
  if (xdg) return join(xdg, "tn");
  if (platform() === "win32") {
    const base = process.env["APPDATA"] ?? join(homedir(), "AppData", "Roaming");
    return join(base, "tn");
  }
  return join(homedir(), ".local", "share", "tn");
}

/** Path to the global identity.json. Mirrors Python `_default_identity_path`. */
export function defaultIdentityPath(): string {
  return join(defaultIdentityDir(), "identity.json");
}

function _b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function _b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/**
 * The machine-global TN device identity. Holds the device Ed25519 seed (so
 * every ceremony minted from it shares one DID) plus the remembered vault +
 * account bindings used to drive warm-attach.
 */
export class Identity {
  readonly did: string;
  /** 32-byte Ed25519 device seed. */
  readonly seed: Uint8Array;
  linkedVault: string | null;
  linkedAccountId: string | null;
  /** Path this identity was loaded from / will be written to. */
  private _path: string;
  /** Raw doc as loaded, so unknown fields survive a save round-trip. */
  private _raw: Record<string, unknown>;

  private constructor(args: {
    did: string;
    seed: Uint8Array;
    linkedVault: string | null;
    linkedAccountId: string | null;
    path: string;
    raw: Record<string, unknown>;
  }) {
    this.did = args.did;
    this.seed = args.seed;
    this.linkedVault = args.linkedVault;
    this.linkedAccountId = args.linkedAccountId;
    this._path = args.path;
    this._raw = args.raw;
  }

  /** Build a VaultIdentity-compatible DeviceKey from the device seed. */
  deviceKey(): DeviceKey {
    return DeviceKey.fromSeed(this.seed);
  }

  /** Read identity.json. Throws if missing or corrupt. */
  static load(path?: string): Identity {
    const p = path ?? defaultIdentityPath();
    if (!existsSync(p)) {
      throw new Error(`identity.json not found at ${p}`);
    }
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
    } catch (e) {
      throw new Error(`identity.json parse error at ${p}: ${(e as Error).message}`, { cause: e });
    }
    const encMethod = String(doc["device_priv_enc_method"] ?? "none");
    if (encMethod !== "none") {
      throw new Error(
        `identity.json device key is stored with encryption ${JSON.stringify(encMethod)}; ` +
          `tn-js cannot unwrap it (use the Python CLI on this machine)`,
      );
    }
    const privB64 = doc["device_priv_b64_enc"];
    if (typeof privB64 !== "string" || !privB64) {
      throw new Error(`identity.json at ${p} is missing device_priv_b64_enc`);
    }
    const seed = _b64urlDecode(privB64);
    if (seed.length !== 32) {
      throw new Error(`identity.json device seed must be 32 bytes; got ${seed.length}`);
    }
    return new Identity({
      did: String(doc["did"] ?? DeviceKey.fromSeed(seed).did),
      seed,
      linkedVault: (doc["linked_vault"] as string | null) ?? null,
      linkedAccountId: (doc["linked_account_id"] as string | null) ?? null,
      path: p,
      raw: doc,
    });
  }

  /**
   * Load the global identity if present, else mint a fresh device key and
   * persist it. Mirrors the Python `tn init` "reuse identity or create one"
   * behaviour so every ceremony on this machine shares one device DID.
   */
  static loadOrMint(path?: string): Identity {
    const p = path ?? defaultIdentityPath();
    if (existsSync(p)) return Identity.load(p);

    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    const dk = DeviceKey.fromSeed(seed);
    const id = new Identity({
      did: dk.did,
      seed,
      linkedVault: null,
      linkedAccountId: null,
      path: p,
      raw: {},
    });
    id.save();
    return id;
  }

  /** Persist identity.json (atomic-ish: write tmp, replace). Preserves
   *  unknown fields loaded from an existing file. Mirrors Python
   *  `Identity.ensure_written`. */
  save(path?: string): string {
    const p = path ?? this._path;
    mkdirSync(dirname(p), { recursive: true });
    const dk = DeviceKey.fromSeed(this.seed);
    const privB64 = _b64urlEncode(this.seed);
    const doc: Record<string, unknown> = {
      ...this._raw,
      version: this._raw["version"] ?? 1,
      did: this.did,
      device_pub_b64: _b64urlEncode(dk.publicKey),
      device_priv_b64_enc: privB64,
      device_priv_enc_method: "none",
      seed_b64: this._raw["seed_b64"] ?? privB64,
      linked_vault: this.linkedVault,
      linked_account_id: this.linkedAccountId,
    };
    // Sort TOP-LEVEL keys for deterministic output (mirrors Python's
    // sort_keys=True) WITHOUT an array replacer — an array replacer would
    // recursively filter out any nested key not in the list (e.g. prefs.*).
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(doc).sort()) sorted[k] = doc[k];
    const tmp = `${p}.tmp`;
    writeFileSync(tmp, JSON.stringify(sorted, null, 2), "utf8");
    if (existsSync(p)) rmSync(p);
    renameSync(tmp, p);
    this._path = p;
    this._raw = doc;
    return p;
  }
}
