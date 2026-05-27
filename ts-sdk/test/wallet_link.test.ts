// Tests for WalletNamespace.link — runs live against the tne2e vault stack.
//
// Verifies the full link round-trip: create-or-reuse vault project,
// mutate ceremony yaml to mode=linked, idempotency on second call.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { DeviceKey } from "../src/core/signing.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "../src/vault/client.ts";
import { WalletNamespace, _internals } from "../src/wallet/index.ts";

const VAULT_URL = process.env.TN_TEST_VAULT_URL ?? "http://localhost:38790";

async function vaultReachable(): Promise<boolean> {
  try {
    const r = await fetch(`${VAULT_URL}/api/v1/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:key:z6MkProbe" }),
    });
    return r.ok || r.status === 400;
  } catch {
    return false;
  }
}

const reachable = await vaultReachable();

async function seedCeremony(): Promise<{ tmp: string; yamlPath: string; device: DeviceKey }> {
  const tmp = mkdtempSync(join(tmpdir(), "wallet-link-test-"));
  const yamlPath = join(tmp, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  // Pull the device key out before we close - we need it for VaultClient auth.
  const cfg = tn.config() as Record<string, unknown>;
  const keystorePath = cfg.keystorePath as string;
  await tn.close();

  // Read the device seed back from disk.
  const seedBytes = new Uint8Array(readFileSync(join(keystorePath, "local.private")));
  const device = DeviceKey.fromSeed(seedBytes);
  return { tmp, yamlPath, device };
}

test("setLinkStateInYaml — mode=linked writes linked_vault + linked_project_id", () => {
  const tmp = mkdtempSync(join(tmpdir(), "wallet-link-unit-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    writeFileSync(
      yamlPath,
      "ceremony:\n  id: local_test01\n  mode: local\n  linked_vault: ''\n  linked_project_id: ''\n",
    );
    _internals.setLinkStateInYaml(yamlPath, {
      mode: "linked",
      linkedVault: "http://vault.example",
      linkedProjectId: "proj-xyz",
    });
    const doc = parseYaml(readFileSync(yamlPath, "utf-8")) as { ceremony: Record<string, unknown> };
    assert.equal(doc.ceremony.mode, "linked");
    assert.equal(doc.ceremony.linked_vault, "http://vault.example");
    assert.equal(doc.ceremony.linked_project_id, "proj-xyz");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("setLinkStateInYaml — mode=local clears linked fields", () => {
  const tmp = mkdtempSync(join(tmpdir(), "wallet-unlink-unit-"));
  try {
    const yamlPath = join(tmp, "tn.yaml");
    writeFileSync(
      yamlPath,
      "ceremony:\n  id: local_test02\n  mode: linked\n  linked_vault: http://x\n  linked_project_id: pid\n",
    );
    _internals.setLinkStateInYaml(yamlPath, { mode: "local" });
    const doc = parseYaml(readFileSync(yamlPath, "utf-8")) as { ceremony: Record<string, unknown> };
    assert.equal(doc.ceremony.mode, "local");
    assert.equal(doc.ceremony.linked_vault, "");
    assert.equal(doc.ceremony.linked_project_id, "");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("WalletNamespace.link — creates project + flips yaml to linked", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath, device } = await seedCeremony();
  try {
    const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(device), VAULT_URL);
    const result = await WalletNamespace.link(client, yamlPath, { projectName: `ts-port-link-${Date.now()}` });

    assert.equal(result.newlyLinked, true);
    assert.equal(result.vaultBaseUrl, VAULT_URL);
    assert.ok(result.projectId, "result must carry projectId");

    // Yaml has been mutated.
    const state = _internals.readLinkState(yamlPath);
    assert.equal(state.mode, "linked");
    assert.equal(state.linkedVault, VAULT_URL);
    assert.equal(state.linkedProjectId, result.projectId);

    // Project actually exists at the vault.
    const projects = await client.listProjects();
    const match = projects.find((p) => (p.id ?? p._id) === result.projectId);
    assert.ok(match, `linked project ${result.projectId} must be in listProjects()`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("WalletNamespace.link — second call is idempotent (newlyLinked=false)", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath, device } = await seedCeremony();
  try {
    const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(device), VAULT_URL);
    const first = await WalletNamespace.link(client, yamlPath, { projectName: `ts-port-link-idem-${Date.now()}` });
    assert.equal(first.newlyLinked, true);

    const second = await WalletNamespace.link(client, yamlPath);
    assert.equal(second.newlyLinked, false, "second link to same vault must be a no-op");
    assert.equal(second.projectId, first.projectId);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("WalletNamespace.link — re-link to a DIFFERENT vault throws VaultError", { skip: !reachable && "vault not reachable" }, async () => {
  const { tmp, yamlPath, device } = await seedCeremony();
  try {
    const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(device), VAULT_URL);
    await WalletNamespace.link(client, yamlPath, { projectName: `ts-port-link-diff-${Date.now()}` });

    // Construct a second client whose baseUrl differs.
    const otherDevice = DeviceKey.generate();
    const otherClient = VaultClient.unauthed({
      baseUrl: "http://other-vault.invalid",
      identity: vaultIdentityFromDeviceKey(otherDevice),
    });
    let caught: Error | null = null;
    try {
      await WalletNamespace.link(otherClient, yamlPath);
    } catch (e) {
      caught = e as Error;
    }
    assert.ok(caught, "re-link to different vault must throw");
    assert.match(caught?.message ?? "", /already linked/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
