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
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist as englishWordlist } from "@scure/bip39/wordlists/english";

// HKDF parameters — byte-identical to python/tn/identity.py (_hkdf + HKDF_INFO_*):
// HKDF-SHA256, salt "tn:v1", info "tn:<stage>:v1", 32-byte output.
const HKDF_SALT = new TextEncoder().encode("tn:v1");
const HKDF_INFO_ROOT = new TextEncoder().encode("tn:root:v1");
const HKDF_INFO_DEVICE = new TextEncoder().encode("tn:device:v1");
const HKDF_INFO_VAULT_WRAP = new TextEncoder().encode("tn:vault:wrap:v1");

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
  /** In-memory 64-byte BIP-39 seed (mnemonic-derived identities only), kept
   *  for vaultWrapKey(); null for random/loaded identities. */
  private _bip39Seed: Uint8Array | null = null;
  /** In-memory mnemonic words. Populated by {@link createNew}/{@link fromMnemonic}
   *  (shown to the user once) and on load from a persisted `mnemonic_stored`.
   *  NEVER written to disk unless the caller opts in via `mnemonicStored`.
   *  Mirrors Python `Identity._mnemonic`. */
  private _mnemonic: string | null = null;

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

  /** Path this identity was loaded from. Mirrors Python's identity_path. */
  get path(): string { return this._path; }

  /**
   * Ceremony-mode preference. Mirrors Python Identity.prefs.default_new_ceremony_mode.
   * Defaults to "local" if not present in the file.
   */
  get prefs(): { defaultNewCeremonyMode: string } {
    const p = this._raw["prefs"] as Record<string, unknown> | undefined;
    return {
      defaultNewCeremonyMode:
        typeof p?.["default_new_ceremony_mode"] === "string"
          ? (p["default_new_ceremony_mode"] as string)
          : "local",
    };
  }

  /**
   * Version counter for account-pulled prefs. Mirrors Python Identity.prefs_version.
   * Defaults to 0 if not present.
   */
  get prefsVersion(): number {
    const v = this._raw["prefs_version"];
    return typeof v === "number" ? v : 0;
  }

  /** Build a VaultIdentity-compatible DeviceKey from the device seed. */
  deviceKey(): DeviceKey {
    return DeviceKey.fromSeed(this.seed);
  }

  /** The in-memory mnemonic words, or null for an identity loaded without a
   *  persisted `mnemonic_stored`. Show ONCE at generation; do not log.
   *  Mirrors Python `Identity._mnemonic`. */
  get mnemonic(): string | null {
    return this._mnemonic;
  }

  /** The persisted recovery phrase (`mnemonic_stored` in identity.json), or
   *  null when not opted in. Mirrors Python `Identity.mnemonic_stored`. */
  get mnemonicStored(): string | null {
    const v = this._raw["mnemonic_stored"];
    return typeof v === "string" ? v : null;
  }

  /** Persist (or clear) the recovery phrase in identity.json on the next
   *  `save()`. Opt-in via `tn init --keep-mnemonic`; storing the phrase on
   *  disk widens the blast radius of a filesystem compromise. */
  set mnemonicStored(words: string | null) {
    if (words === null) delete this._raw["mnemonic_stored"];
    else this._raw["mnemonic_stored"] = words;
  }

  /**
   * Generate a fresh mnemonic and derive a brand-new identity from it.
   * Byte-parity with Python `Identity.create_new(word_count)`: the returned
   * identity carries the mnemonic in-memory ({@link mnemonic}) so the caller
   * can show it once, then `save()` (the phrase is NOT persisted unless the
   * caller also sets {@link mnemonicStored}). `wordCount` selects entropy:
   * 12→128, 15→160, 18→192, 21→224, 24→256 bits.
   */
  static createNew(wordCount = 12, opts: { path?: string } = {}): Identity {
    const strengthBits: Record<number, number> = { 12: 128, 15: 160, 18: 192, 21: 224, 24: 256 };
    const bits = strengthBits[wordCount];
    if (bits === undefined) {
      throw new Error(`word_count must be one of ${JSON.stringify(Object.keys(strengthBits).map(Number))}`);
    }
    const words = generateMnemonic(englishWordlist, bits);
    return Identity.fromMnemonic(words, opts);
  }

  /**
   * Deterministically derive the device identity from a BIP-39 mnemonic.
   * Byte-identical to Python `Identity.from_mnemonic`: BIP-39 seed -> HKDF
   * `tn:root:v1` -> HKDF `tn:device:v1` -> the 32-byte Ed25519 device key.
   * Same words + passphrase => same DID (the recovery path). Rejects a bad
   * checksum, mirroring Python's `Mnemonic.check`.
   */
  static fromMnemonic(
    words: string,
    opts: { passphrase?: string; path?: string } = {},
  ): Identity {
    if (!validateMnemonic(words, englishWordlist)) {
      throw new Error("invalid BIP-39 mnemonic (bad checksum)");
    }
    const bip39Seed = mnemonicToSeedSync(words, opts.passphrase ?? "");
    const root = hkdf(sha256, bip39Seed, HKDF_SALT, HKDF_INFO_ROOT, 32);
    const deviceSeed = hkdf(sha256, root, HKDF_SALT, HKDF_INFO_DEVICE, 32);
    const dk = DeviceKey.fromSeed(deviceSeed);
    const id = new Identity({
      did: dk.did,
      seed: deviceSeed,
      linkedVault: null,
      linkedAccountId: null,
      path: opts.path ?? defaultIdentityPath(),
      // Persist the 64-byte BIP-39 seed in seed_b64 (matches Python) so the
      // vault-wrap key survives a save/load round-trip.
      raw: { seed_b64: Buffer.from(bip39Seed).toString("base64url") },
    });
    id._bip39Seed = bip39Seed;
    // Keep the words in-memory so `tn init` can show the banner / honour
    // --keep-mnemonic. Mirrors Python (create_new sets `_mnemonic`; the
    // mnemonic-file path sets it explicitly). NOT persisted unless the caller
    // opts in via `mnemonicStored`.
    id._mnemonic = words;
    return id;
  }

  /**
   * Re-derive the 32-byte AES-256 vault-wrap key from the BIP-39 seed.
   * Byte-identical to Python `Identity.vault_wrap_key()`. Requires a
   * mnemonic-derived identity (or one loaded with a 64-byte `seed_b64`).
   */
  vaultWrapKey(): Uint8Array {
    let seed = this._bip39Seed;
    if (seed === null) {
      const sb = this._raw["seed_b64"];
      if (typeof sb === "string" && sb) seed = _b64urlDecode(sb);
    }
    if (seed === null) {
      throw new Error(
        "vaultWrapKey requires the BIP-39 seed (re-derive via Identity.fromMnemonic)",
      );
    }
    const root = hkdf(sha256, seed, HKDF_SALT, HKDF_INFO_ROOT, 32);
    return hkdf(sha256, root, HKDF_SALT, HKDF_INFO_VAULT_WRAP, 32);
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
    const id = new Identity({
      did: String(doc["did"] ?? DeviceKey.fromSeed(seed).did),
      seed,
      linkedVault: (doc["linked_vault"] as string | null) ?? null,
      linkedAccountId: (doc["linked_account_id"] as string | null) ?? null,
      path: p,
      raw: doc,
    });
    // Restore the in-memory mnemonic from a persisted phrase (--keep-mnemonic),
    // so `tn wallet export-mnemonic` can re-display it. Mirrors Python load:
    // `ident._mnemonic = ident.mnemonic_stored`.
    if (typeof doc["mnemonic_stored"] === "string") id._mnemonic = doc["mnemonic_stored"];
    return id;
  }

  /**
   * Load the global identity if present, else mint a fresh device key and
   * persist it. Mirrors the Python `tn init` "reuse identity or create one"
   * behaviour so every ceremony on this machine shares one device DID.
   */
  static loadOrMint(path?: string): Identity {
    const p = path ?? defaultIdentityPath();
    if (existsSync(p)) return Identity.load(p);

    // Mint a fresh BIP-39-backed identity, matching Python's
    // Identity.create_new(word_count=12) (12 words = 128 bits of entropy):
    // bip39 seed -> HKDF root -> device key, persisting the 64-byte bip39 seed
    // (via fromMnemonic -> save) so vaultWrapKey() derives the SAME key
    // material as Python and the identity is BIP-39-structured. The previous
    // random 32-byte seed produced an identity whose seed_b64 was the device
    // seed, yielding a vault-wrap key incompatible with Python's.
    const id = Identity.createNew(12, { path: p });
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
