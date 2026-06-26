// Machine credential store — cache a derived key, never the master secret.
//
// The same shape `gh` and the `claude` CLI use: after a one-time unlock, a
// derived credential is cached so later commands run non-interactively. The
// cached value is the account AWK (the account-scoped wrapping key), never the
// passphrase — "token, not password". Mirrors python/tn/credential_store.py.
//
// File-backed (`0600`) only for now — the graceful fallback for headless / CI
// contexts, exactly `gh`'s `hosts.yml` fallback. An OS-keychain backend is a
// future hardening (no keychain dependency in the SDK today). Same posture as
// the device key that already sits in identity.json on disk.

import {
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { b64ToBytes, bytesToB64 } from "../core/encoding.js";
import { defaultIdentityDir } from "../identity.js";

/** Get / set / delete a named secret. `get` returns null for a missing key. */
export interface CredentialStore {
  get(name: string): Uint8Array | null;
  set(name: string, value: Uint8Array): void;
  delete(name: string): void;
}

/** Stable store key under which an account's AWK is cached. */
export function awkKeyName(accountId: string): string {
  return `awk:${accountId}`;
}

/**
 * A single `0600` JSON file mapping name → base64(value). Atomic writes
 * (temp + rename) and POSIX `0600` so the file is owner-only; on Windows the
 * user-profile ACL is the protection (mode is a POSIX no-op there).
 */
export class FileCredentialStore implements CredentialStore {
  constructor(private readonly filePath: string) {}

  private load(): Record<string, string> {
    try {
      const doc = JSON.parse(readFileSync(this.filePath, "utf-8"));
      return doc && typeof doc === "object" ? (doc as Record<string, string>) : {};
    } catch {
      // Missing / corrupt store reads as empty — a fresh set rewrites it.
      return {};
    }
  }

  private save(doc: Record<string, string>): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(doc, null, 2), { encoding: "utf-8", mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  get(name: string): Uint8Array | null {
    const enc = this.load()[name];
    if (enc == null) return null;
    try {
      return b64ToBytes(enc);
    } catch {
      return null;
    }
  }

  set(name: string, value: Uint8Array): void {
    const doc = this.load();
    doc[name] = bytesToB64(value);
    this.save(doc);
  }

  delete(name: string): void {
    const doc = this.load();
    if (name in doc) {
      delete doc[name];
      this.save(doc);
    }
  }
}

/**
 * The default store: a `0600` file next to identity.json. (`filePath` overrides
 * the location.) A keychain backend would slot in here, behind this same
 * interface, without the wallet code knowing.
 */
export function defaultCredentialStore(filePath?: string): CredentialStore {
  return new FileCredentialStore(filePath ?? join(defaultIdentityDir(), "credentials.json"));
}
