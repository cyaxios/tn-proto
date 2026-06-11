// Public `tn.wallet` namespace — the TS analogue of Python's `tn.wallet`
// module (python/tn/wallet.py + wallet_restore.py), which exposes
// link_ceremony / unlink / sync_ceremony / restore_ceremony /
// read_sync_queue as a public verb surface.
//
// The wallet logic already lives across three files:
//   - src/wallet/index.ts       — WalletNamespace.link/unlink, readSyncQueue,
//                                  readLinkState
//   - src/cli/wallet_sync.ts     — walletSyncCmd (the two-way sync verb)
//   - src/wallet/restore.ts      — restoreWithBek / restoreViaPassphrase /
//                                  restoreViaLoopback
//
// This module wires those existing implementations into a single object so
// callers reach them as `tn.wallet.link(...)`, `tn.wallet.sync(...)`, etc.,
// mirroring the Python surface. It adds NO new behavior — every method
// delegates to a committed implementation. The one composite is `status`,
// which is the cheap `readLinkState + readSyncQueue` pair Python's
// `tn wallet status` already prints.

import { walletSyncCmd, type WalletSyncCmdOptions } from "../cli/wallet_sync.js";
import {
  WalletNamespace,
  readLinkState,
  readSyncQueue,
  type LinkResult,
} from "./index.js";
import {
  restoreViaLoopback,
  restoreViaPassphrase,
  restoreWithBek,
  type RestoreOptions,
  type RestoreResult,
  type RestoreViaLoopbackOptions,
} from "./restore.js";
import type { VaultClient } from "../vault/client.js";

/**
 * Status snapshot for a ceremony: its on-disk link state plus any pending
 * autosync failures in the sync queue. Composite of `readLinkState` +
 * `readSyncQueue` — the same two reads Python's `tn wallet status` prints.
 */
export interface WalletStatus {
  /** ceremony.mode — "local" or "linked". */
  mode: string;
  /** Linked vault base URL (empty when local). */
  linkedVault: string;
  /** Linked project id (empty when local). */
  linkedProjectId: string;
  /** Human project label from the ceremony yaml. */
  projectName: string;
  /** ceremony.id. */
  ceremonyId: string;
  /** Pending autosync-failure rows from the sync queue (empty when none). */
  syncQueue: Array<Record<string, unknown>>;
}

/**
 * The public `tn.wallet` verb surface. Plain object (not a class instance)
 * to mirror Python's module-as-namespace shape — `tn.wallet` in Python is
 * the `wallet` module itself.
 */
export const wallet = {
  /**
   * Bind a local ceremony to a vault project. Mirrors Python
   * `tn.wallet.link_ceremony`. Delegates to {@link WalletNamespace.link}.
   */
  link(
    client: VaultClient,
    yamlPath: string,
    opts: { projectName?: string } = {},
  ): Promise<LinkResult> {
    return WalletNamespace.link(client, yamlPath, opts);
  },

  /**
   * Flip the ceremony yaml back to mode=local and clear linked_*. Mirrors
   * Python `tn.wallet.unlink`. Delegates to {@link WalletNamespace.unlink}.
   */
  unlink(yamlPath: string): void {
    WalletNamespace.unlink(yamlPath);
  },

  /**
   * Run the `tn wallet sync` verb (PULL inbox -> ABSORB -> PUSH body).
   * Mirrors Python `tn.wallet.sync_ceremony`. Delegates to
   * {@link walletSyncCmd}; returns the process exit code (0 on success).
   */
  sync(opts: WalletSyncCmdOptions = {}): Promise<number> {
    return walletSyncCmd(opts);
  },

  /**
   * Multi-device restore. Mirrors Python `tn.wallet.restore_ceremony`. The
   * default path is the headless passphrase fallback (D-22). The
   * BEK-in-hand and browser-loopback variants are also exposed for callers
   * who already hold a BEK or want the full passkey-PRF dance.
   */
  restore(
    client: VaultClient,
    opts: { projectId: string; passphrase: string; outDir: string; credentialId?: string },
  ): Promise<RestoreResult> {
    return restoreViaPassphrase(client, opts);
  },

  /** Restore from a BEK already in hand. Delegates to {@link restoreWithBek}. */
  restoreWithBek(opts: RestoreOptions): Promise<RestoreResult> {
    return restoreWithBek(opts);
  },

  /**
   * Restore via the browser passkey-PRF loopback dance. Delegates to
   * {@link restoreViaLoopback}.
   */
  restoreViaLoopback(
    opts: RestoreViaLoopbackOptions,
  ): Promise<RestoreResult & { accountId: string }> {
    return restoreViaLoopback(opts);
  },

  /**
   * Read pending autosync failures for a ceremony. Mirrors Python
   * `tn.wallet.read_sync_queue`. Delegates to {@link readSyncQueue}.
   */
  readSyncQueue(ceremonyId: string): Array<Record<string, unknown>> {
    return readSyncQueue(ceremonyId);
  },

  /**
   * Snapshot a ceremony's link state + pending sync queue. Composite of
   * `readLinkState(yamlPath)` and `readSyncQueue(ceremonyId)` — the same
   * reads Python's `tn wallet status` performs.
   */
  status(yamlPath: string): WalletStatus {
    const link = readLinkState(yamlPath);
    return {
      mode: link.mode,
      linkedVault: link.linkedVault,
      linkedProjectId: link.linkedProjectId,
      projectName: link.projectName,
      ceremonyId: link.ceremonyId,
      syncQueue: link.ceremonyId ? readSyncQueue(link.ceremonyId) : [],
    };
  },
} as const;

export type WalletNamespaceSurface = typeof wallet;
