// Unit tests for walletWatchCmd (src/cli/wallet_sync.ts).
//
// Uses maxIterations + injectable syncImpl + injectable sleepImpl to run the
// loop in-process without real vault connections or timers.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { walletWatchCmd } from "../src/cli/wallet_sync.js";

// ── helper: minimal ceremony yaml with sync_interval_seconds ─────────────────

function makeCeremonyYaml(dir: string, syncIntervalSeconds?: number): string {
  const yamlPath = join(dir, "tn.yaml");
  const intervalLine =
    syncIntervalSeconds !== undefined
      ? `  sync_interval_seconds: ${syncIntervalSeconds}\n`
      : "";
  writeFileSync(
    yamlPath,
    `ceremony:\n  id: cer_test\n  mode: local\n${intervalLine}device:\n  device_identity: did:key:z6Mk0000\ngroups: {}\n`,
    "utf8",
  );
  return yamlPath;
}

/** Stub stdout/stderr sink */
function sink(): { write(s: string): void; text(): string } {
  let buf = "";
  return { write: (s: string) => { buf += s; }, text: () => buf };
}

// ── two iterations, custom sync impl ─────────────────────────────────────────

test("walletWatchCmd calls syncImpl exactly maxIterations times", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-wwatch-"));
  try {
    const yamlPath = makeCeremonyYaml(dir, 10);

    const syncCalls: unknown[] = [];
    const syncImpl = async (opts: unknown): Promise<number> => {
      syncCalls.push(opts);
      return 0;
    };

    const sleepCalls: number[] = [];
    const sleepImpl = async (ms: number) => { sleepCalls.push(ms); };

    const out = sink();
    const err = sink();
    await walletWatchCmd({
      yaml: yamlPath,
      maxIterations: 2,
      syncImpl,
      sleepImpl,
      stdout: out,
      stderr: err,
    });

    assert.equal(syncCalls.length, 2, "syncImpl must be called exactly maxIterations times");
    // After each sync (except possibly the last) it sleeps.
    // The exact sleep count depends on implementation; at minimum 1 sleep happened.
    assert.ok(sleepCalls.length >= 1, "at least one sleep should have occurred");
    // Sleep duration matches sync_interval_seconds (in ms)
    assert.ok(sleepCalls.every((ms) => ms === 10_000), `unexpected sleep durations: ${sleepCalls}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── default interval (no sync_interval_seconds in yaml) ──────────────────────

test("walletWatchCmd uses 600s default when sync_interval_seconds is absent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-wwatch-def-"));
  try {
    const yamlPath = makeCeremonyYaml(dir); // no interval

    const sleepCalls: number[] = [];
    const code = await walletWatchCmd({
      yaml: yamlPath,
      maxIterations: 1,
      syncImpl: async () => 0,
      sleepImpl: async (ms: number) => { sleepCalls.push(ms); },
      stdout: sink(),
      stderr: sink(),
    });

    assert.equal(code, 0);
    // 1 iteration → 0 or 1 sleep (after the sync); either way it should be 600s when present
    if (sleepCalls.length > 0) {
      assert.equal(sleepCalls[0], 600_000, "default interval is 600s");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── sync error propagation ────────────────────────────────────────────────────

test("walletWatchCmd exits with the last sync exit code on failure", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-wwatch-err-"));
  try {
    const yamlPath = makeCeremonyYaml(dir, 5);

    const code = await walletWatchCmd({
      yaml: yamlPath,
      maxIterations: 1,
      syncImpl: async () => 1,
      sleepImpl: async () => {},
      stdout: sink(),
      stderr: sink(),
    });

    assert.equal(code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── opts are forwarded to syncImpl ───────────────────────────────────────────

test("walletWatchCmd forwards yaml and vault options to syncImpl", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-wwatch-fwd-"));
  try {
    const yamlPath = makeCeremonyYaml(dir, 1);
    const receivedOpts: Array<{ yaml?: string; vault?: string }> = [];

    await walletWatchCmd({
      yaml: yamlPath,
      vault: "https://vault.test",
      maxIterations: 1,
      syncImpl: async (opts) => {
        receivedOpts.push(opts as { yaml?: string; vault?: string });
        return 0;
      },
      sleepImpl: async () => {},
      stdout: sink(),
      stderr: sink(),
    });

    assert.equal(receivedOpts.length, 1);
    assert.equal(receivedOpts[0]!.yaml, yamlPath);
    assert.equal(receivedOpts[0]!.vault, "https://vault.test");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
