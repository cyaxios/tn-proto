// Port of tn_proto/python/tn/wallet.py — WalletNamespace.
//
// link_ceremony — uses VaultClient.createProject + inline yaml mutation to
// flip ceremony.mode local -> linked.
//
// Pattern: methods take an already-authed VaultClient + the ceremony's
// yamlPath. Returning a structured result mirrors Python's dataclasses.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { VaultError, type VaultClient } from "../vault/client.js";

export interface LinkResult {
  /** Project id created (or reused) on the vault. */
  projectId: string;
  /** Vault base URL the ceremony is now linked to. */
  vaultBaseUrl: string;
  /** Whether the ceremony was newly linked vs already linked (idempotency). */
  newlyLinked: boolean;
  /** Project name used at the vault. */
  projectName: string;
}

interface CeremonyYamlShape {
  ceremony?: {
    id?: string;
    mode?: "local" | "linked" | string;
    linked_vault?: string;
    linked_project_id?: string;
    project_name?: string;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

/**
 * Read, mutate, and write a ceremony yaml to flip link state. Mirrors
 * Python's `tn.admin.set_link_state` — the *persistent* half of
 * link_ceremony. Idempotent: writing the same state twice is a no-op.
 */
function setLinkStateInYaml(
  yamlPath: string,
  fields: { mode: "linked" | "local"; linkedVault?: string; linkedProjectId?: string },
): void {
  const raw = readFileSync(yamlPath, "utf-8");
  const doc = parseYaml(raw) as CeremonyYamlShape;
  const ceremony = doc.ceremony ?? (doc.ceremony = {});
  ceremony.mode = fields.mode;
  if (fields.linkedVault !== undefined) ceremony.linked_vault = fields.linkedVault;
  if (fields.linkedProjectId !== undefined) ceremony.linked_project_id = fields.linkedProjectId;
  // For mode=local, clear the linked fields so the on-disk shape mirrors
  // a freshly-initialized local ceremony (Python's set_link_state does
  // the same).
  if (fields.mode === "local") {
    ceremony.linked_vault = "";
    ceremony.linked_project_id = "";
  }
  writeFileSync(yamlPath, stringifyYaml(doc), "utf-8");
}

/** Mirrors Python admin._sync_queue_path: $TN_STATE_DIR/sync_queue/<id>.jsonl */
function syncQueuePath(ceremonyId: string): string {
  const override = process.env["TN_STATE_DIR"];
  if (override) return join(override, "sync_queue", `${ceremonyId}.jsonl`);
  const xdg = process.env["XDG_STATE_HOME"];
  if (xdg) return join(xdg, "tn", "sync_queue", `${ceremonyId}.jsonl`);
  if (platform() === "win32") {
    const appdata = process.env["APPDATA"] ?? join(homedir(), "AppData", "Roaming");
    return join(appdata, "tn", "sync_queue", `${ceremonyId}.jsonl`);
  }
  return join(homedir(), ".local", "state", "tn", "sync_queue", `${ceremonyId}.jsonl`);
}

/**
 * Read pending autosync failures for a ceremony.
 * Mirrors Python `tn.wallet.read_sync_queue(ceremony_id)`.
 * Returns an empty list when the queue file doesn't exist.
 */
export function readSyncQueue(ceremonyId: string): Array<Record<string, unknown>> {
  const p = syncQueuePath(ceremonyId);
  if (!existsSync(p)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const line of readFileSync(p, "utf-8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as Record<string, unknown>);
    } catch { /* skip malformed lines */ }
  }
  return out;
}

/**
 * Read just the ceremony.mode and linked_vault from a yaml without
 * loading the full config. Lets `link` decide whether work is needed.
 */
export function readLinkState(yamlPath: string): { mode: string; linkedVault: string; linkedProjectId: string; projectName: string; ceremonyId: string } {
  const raw = readFileSync(yamlPath, "utf-8");
  const doc = parseYaml(raw) as CeremonyYamlShape;
  const c = doc.ceremony ?? {};
  return {
    mode: typeof c.mode === "string" ? c.mode : "local",
    linkedVault: typeof c.linked_vault === "string" ? c.linked_vault : "",
    linkedProjectId: typeof c.linked_project_id === "string" ? c.linked_project_id : "",
    projectName: typeof c.project_name === "string" ? c.project_name : "",
    ceremonyId: typeof c.id === "string" ? c.id : "",
  };
}

export class WalletNamespace {
  /**
   * Bind a local ceremony to a vault project.
   *
   * Port of Python `tn.wallet.link_ceremony(cfg, client, project_name=...)`.
   *
   * Idempotent: if the ceremony is already linked to the same vault, returns
   * the existing state untouched. If linked to a *different* vault, throws
   * VaultError (the user must `wallet.unlink` first — not yet ported).
   *
   * If `createProject` returns 409, the method falls back to `listProjects`
   * and reuses the matching project (the same recovery path Python takes).
   */
  static async link(
    client: VaultClient,
    yamlPath: string,
    opts: { projectName?: string } = {},
  ): Promise<LinkResult> {
    const state = readLinkState(yamlPath);

    // Idempotent shortcut: "already linked" means a real project EXISTS.
    // A fresh mode:linked ceremony with no linkedProjectId yet (the default
    // mint shape) is NOT yet linked and must proceed to create — keying the
    // guards on linkedProjectId (not mode/vault alone) is what makes the
    // warm-attach create path work. (Mirrors the Python link_ceremony fix.)
    if (state.linkedProjectId && state.linkedVault === client.baseUrl) {
      return {
        projectId: state.linkedProjectId,
        vaultBaseUrl: state.linkedVault,
        newlyLinked: false,
        projectName: state.projectName || state.ceremonyId,
      };
    }
    if (state.linkedProjectId && state.linkedVault && state.linkedVault !== client.baseUrl) {
      throw new VaultError(
        `ceremony ${state.ceremonyId} is already linked to ${state.linkedVault} ` +
          `(project ${state.linkedProjectId}); unlink first before re-linking ` +
          `to ${client.baseUrl}`,
      );
    }

    const name = opts.projectName || state.projectName || state.ceremonyId;
    if (!name) {
      throw new VaultError(
        `wallet.link: ceremony at ${yamlPath} has no project_name or ceremony.id; ` +
          `pass projectName explicitly`,
      );
    }

    let project: Record<string, unknown>;
    try {
      const createOpts: { ceremonyId?: string } = {};
      if (state.ceremonyId) createOpts.ceremonyId = state.ceremonyId;
      project = await client.createProject(name, createOpts);
    } catch (e) {
      if (e instanceof VaultError && e.status === 409) {
        const list = await client.listProjects();
        const match = list.find((p) => p.name === name);
        if (!match) {
          throw new VaultError(
            `wallet.link: vault returned 409 for project ${JSON.stringify(name)} ` +
              `but listProjects returned no match — cannot re-link`,
            { status: 409 },
          );
        }
        project = match;
      } else {
        throw e;
      }
    }

    const projectId = (project.id ?? project._id) as string | undefined;
    if (!projectId) {
      throw new VaultError(
        `wallet.link: createProject response missing id: ${JSON.stringify(project)}`,
      );
    }

    setLinkStateInYaml(yamlPath, {
      mode: "linked",
      linkedVault: client.baseUrl,
      linkedProjectId: projectId,
    });

    return {
      projectId,
      vaultBaseUrl: client.baseUrl,
      newlyLinked: true,
      projectName: name,
    };
  }

  /**
   * Flip the ceremony yaml back to mode=local and clear linked_*. Mirrors
   * Python's `set_link_state(mode="local")`. Does NOT call the vault to
   * delete the project (that's a separate operator decision).
   */
  static unlink(yamlPath: string): void {
    setLinkStateInYaml(yamlPath, { mode: "local" });
  }
}

// Internal exports for tests that want to verify yaml mutation directly.
export const _internals = { setLinkStateInYaml, readLinkState, syncQueuePath };
