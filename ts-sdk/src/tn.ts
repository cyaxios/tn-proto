// @tnproto/sdk — main Layer 2 class, the 0.3.0 replacement for TNClient.
//
// Splits into namespaced sub-objects (tn.admin, tn.pkg, tn.vault,
// tn.agents, tn.handlers). I/O verbs are async; emit/read stay sync.
// See docs/superpowers/specs/2026-05-01-ts-sdk-refresh-design.md.
//
// Method bodies are populated in Task 2.4 (statics, log/read/context),
// Task 2.6–2.10 (namespaces), Phase 3 Task 3.2 (watch).

import { NodeRuntime } from "./runtime/node_runtime.js";
import type { Entry, RawEntry, LogLevel } from "./core/types.js";
import type { EmitReceipt } from "./core/results.js";
import type { SecureEntry } from "./core/read_shape.js";
import { AdminNamespace } from "./admin/index.js";
import { PkgNamespace } from "./pkg/index.js";
import { VaultNamespace } from "./vault/index.js";
import { AgentsNamespace } from "./agents/index.js";
import { HandlersNamespace } from "./handlers/namespace.js";

export interface TnInitOptions {
  stdout?: boolean;
}

export interface ReadOptions {
  verify?: boolean;
  raw?: boolean;
  logPath?: string;
  allRuns?: boolean;
  where?: (entry: Record<string, unknown>) => boolean;
}

export interface ReadAsRecipientOptions {
  logPath: string;
  group?: string;
  verifySignatures?: boolean;
}

export interface SecureReadOptions {
  onInvalid?: "skip" | "raise" | "forensic";
  logPath?: string;
}

export class Tn {
  readonly admin: AdminNamespace;
  readonly pkg: PkgNamespace;
  readonly vault: VaultNamespace;
  readonly agents: AgentsNamespace;
  readonly handlers: HandlersNamespace;

  private constructor(
    private readonly _rt: NodeRuntime,
    private readonly _ownedTempdir?: string,
  ) {
    this.admin = new AdminNamespace(_rt);
    this.pkg = new PkgNamespace(_rt);
    this.vault = new VaultNamespace(_rt);
    this.agents = new AgentsNamespace(_rt);
    this.handlers = new HandlersNamespace(_rt);
  }

  static async init(_yamlPath?: string, _opts?: TnInitOptions): Promise<Tn> {
    throw new Error("Tn.init: not implemented (Task 2.4)");
  }

  static async ephemeral(_opts?: TnInitOptions): Promise<Tn> {
    throw new Error("Tn.ephemeral: not implemented (Task 2.4)");
  }

  static setLevel(_level: LogLevel): void {
    throw new Error("Tn.setLevel: not implemented (Task 2.4)");
  }
  static getLevel(): string {
    throw new Error("Tn.getLevel: not implemented (Task 2.4)");
  }
  static isEnabledFor(_level: LogLevel): boolean {
    throw new Error("Tn.isEnabledFor: not implemented (Task 2.4)");
  }
  static setSigning(_enabled: boolean | null): void {
    throw new Error("Tn.setSigning: not implemented (Task 2.4)");
  }
  static setStrict(_enabled: boolean): void {
    throw new Error("Tn.setStrict: not implemented (Task 2.4)");
  }

  log(_eventType: string, _fields?: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.log: not implemented (Task 2.4)");
  }
  debug(_eventType: string, _fields?: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.debug: not implemented (Task 2.4)");
  }
  info(_eventType: string, _fields?: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.info: not implemented (Task 2.4)");
  }
  warning(_eventType: string, _fields?: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.warning: not implemented (Task 2.4)");
  }
  error(_eventType: string, _fields?: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.error: not implemented (Task 2.4)");
  }

  read(_opts?: ReadOptions): Iterable<Entry> {
    throw new Error("Tn.read: not implemented (Task 2.4)");
  }
  readRaw(_logPath?: string): Iterable<RawEntry> {
    throw new Error("Tn.readRaw: not implemented (Task 2.4)");
  }
  readAsRecipient(_opts: ReadAsRecipientOptions): Iterable<Entry> {
    throw new Error("Tn.readAsRecipient: not implemented (Task 2.4)");
  }
  secureRead(_opts?: SecureReadOptions): Iterable<SecureEntry> {
    throw new Error("Tn.secureRead: not implemented (Task 2.4)");
  }

  scope<T>(_fields: Record<string, unknown>, _body: () => T): T {
    throw new Error("Tn.scope: not implemented (Task 2.4)");
  }
  setContext(_fields: Record<string, unknown>): void {
    throw new Error("Tn.setContext: not implemented (Task 2.4)");
  }
  updateContext(_fields: Record<string, unknown>): void {
    throw new Error("Tn.updateContext: not implemented (Task 2.4)");
  }
  clearContext(): void {
    throw new Error("Tn.clearContext: not implemented (Task 2.4)");
  }
  getContext(): Record<string, unknown> {
    throw new Error("Tn.getContext: not implemented (Task 2.4)");
  }

  emit(_level: string, _eventType: string, _fields: Record<string, unknown>): EmitReceipt {
    throw new Error("Tn.emit: not implemented (Task 2.4)");
  }

  config(): unknown {
    throw new Error("Tn.config: not implemented (Task 2.4)");
  }
  usingRust(): boolean {
    throw new Error("Tn.usingRust: not implemented (Task 2.4)");
  }
  async close(): Promise<void> {
    throw new Error("Tn.close: not implemented (Task 2.4)");
  }
}
