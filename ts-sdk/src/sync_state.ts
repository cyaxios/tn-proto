// Persisted sync state for vault interactions (TS mirror of Python `tn.sync_state`).
//
// Tracks state that needs to survive process restarts so that one-shot
// invocations and long-lived handlers agree on what's been shipped.
//
// State file location: `<yamlDir>/.tn/sync/state.json`.
//
// Schema (all fields optional; presence-based):
//
//   {
//     "vault_endpoint": "https://tnproto.org",
//     "last_pushed_admin_head": "sha256:...",
//     "last_pushed_yaml_sha": "sha256:...",
//     "last_synced_generation": 7,
//     "inbox_cursor": "...",
//     "contacts_cursor": "...",
//     "pending_claims_cursor": "..."
//   }
//
// Spec ref: §4.9 (Persisted sync state) and §10 deferred workstream
// item 5. Mirrors `tn-protocol/python/tn/sync_state.py` byte-for-byte
// at the file format level so Python and TS handlers operating on
// the same ceremony agree on persisted state.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const STATE_FILE = "state.json";
export const SYNC_DIR = "sync";

/** Ceremony's sync directory: `<yamlDir>/.tn/sync/` */
function stateDir(yamlPath: string): string {
  return join(dirname(yamlPath), ".tn", SYNC_DIR);
}

/** Absolute path to the sync state file for this ceremony. */
export function statePath(yamlPath: string): string {
  return join(stateDir(yamlPath), STATE_FILE);
}

/** Sync state is a free-form bag of string-keyed values. */
export type SyncState = Record<string, unknown>;

/**
 * Load the sync state for this ceremony.
 *
 * Returns an empty object if the file doesn't exist or is corrupt
 * (warning logged in the corrupt case). Never throws on read errors;
 * callers should treat a missing/corrupt file as "no prior state."
 */
export function loadSyncState(yamlPath: string): SyncState {
  const path = statePath(yamlPath);
  if (!existsSync(path)) return {};
  try {
    const text = readFileSync(path, "utf8");
    const doc = JSON.parse(text);
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
      console.warn(
        `sync_state: ${path} is not a JSON object; resetting`,
      );
      return {};
    }
    return doc as SyncState;
  } catch (e) {
    console.warn(`sync_state: ${path} unreadable (${(e as Error).message}); resetting`);
    return {};
  }
}

/**
 * Atomic-via-rename write of the sync state.
 *
 * Creates the parent directory on demand. Logs and swallows write
 * errors; sync state is best-effort and should not bring down the
 * caller. A failed save means the next process won't see the latest
 * state and may re-push, which is handled by the receiver's
 * idempotency (head_row_hash dedup).
 */
export function saveSyncState(yamlPath: string, state: SyncState): void {
  const path = statePath(yamlPath);
  try {
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const tmp = `${path}.tmp`;
    // Sorted keys + indent so the file is human-readable for debugging.
    const sortedKeys = Object.keys(state).sort();
    const sorted: SyncState = {};
    for (const k of sortedKeys) sorted[k] = state[k];
    writeFileSync(tmp, JSON.stringify(sorted, null, 2), "utf8");
    renameSync(tmp, path);
  } catch (e) {
    console.warn(`sync_state: failed to save ${path}: ${(e as Error).message}`);
  }
}

/**
 * Read-modify-write convenience: load, merge in `fields`, save.
 *
 * Returns the new state. Set a field to `null` (or `undefined`) to
 * delete that key.
 */
export function updateSyncState(
  yamlPath: string,
  fields: Record<string, unknown>,
): SyncState {
  const state = loadSyncState(yamlPath);
  for (const [k, v] of Object.entries(fields)) {
    if (v === null || v === undefined) {
      delete state[k];
    } else {
      state[k] = v;
    }
  }
  saveSyncState(yamlPath, state);
  return state;
}

// --- Field-specific helpers ---

/**
 * Return the persisted `last_pushed_admin_head` if any.
 *
 * Used by the push-side handler / one-shot caller to skip re-pushing
 * the same admin-log snapshot when the head hasn't advanced.
 */
export function getLastPushedAdminHead(yamlPath: string): string | null {
  const state = loadSyncState(yamlPath);
  const v = state["last_pushed_admin_head"];
  return typeof v === "string" ? v : null;
}

/** Persist a new `last_pushed_admin_head` value. */
export function setLastPushedAdminHead(yamlPath: string, head: string): void {
  updateSyncState(yamlPath, { last_pushed_admin_head: head });
}

/** Return the persisted `inbox_cursor` if any. Used by pull-side. */
export function getInboxCursor(yamlPath: string): string | null {
  const state = loadSyncState(yamlPath);
  const v = state["inbox_cursor"];
  return typeof v === "string" ? v : null;
}

/** Persist a new `inbox_cursor` value. */
export function setInboxCursor(yamlPath: string, cursor: string): void {
  updateSyncState(yamlPath, { inbox_cursor: cursor });
}
