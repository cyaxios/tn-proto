// Live test against a running tn_proto_web vault (the tne2e local stack).
// Asserts the auth challenge/verify dance produces a usable JWT and that
// projects CRUD works end-to-end.
//
// Skipped if the vault is not reachable so unit-test runs in CI don't
// require the stack to be up.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { DeviceKey } from "../src/core/signing.js";
import { VaultClient, vaultIdentityFromDeviceKey, VaultError } from "../src/vault/client.ts";

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

test("VaultClient.authenticate — challenge/verify dance issues a JWT", { skip: !reachable && "vault not reachable" }, async () => {
  const device = DeviceKey.generate();
  const identity = vaultIdentityFromDeviceKey(device);
  const client = await VaultClient.forIdentity(identity, VAULT_URL, { autoAuth: true });
  assert.ok(client.token, "client should have a token after authenticate");
  assert.match(client.token ?? "", /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, "expected JWT shape");
});

test("VaultClient.listProjects — returns array for fresh DID", { skip: !reachable && "vault not reachable" }, async () => {
  const device = DeviceKey.generate();
  const identity = vaultIdentityFromDeviceKey(device);
  const client = await VaultClient.forIdentity(identity, VAULT_URL);
  const projects = await client.listProjects();
  assert.ok(Array.isArray(projects), "listProjects must return an array");
  // Fresh DID -> empty list.
  assert.equal(projects.length, 0, `fresh DID should have 0 projects; got ${projects.length}`);
});

test("VaultClient.createProject -> listProjects roundtrip", { skip: !reachable && "vault not reachable" }, async () => {
  const device = DeviceKey.generate();
  const identity = vaultIdentityFromDeviceKey(device);
  const client = await VaultClient.forIdentity(identity, VAULT_URL);

  const created = await client.createProject(`ts-port-test-${Date.now()}`, { ceremonyId: "ceremony-port-001" });
  const projectId = (created.id ?? created._id) as string | undefined;
  assert.ok(typeof projectId === "string" && projectId.length > 0, `expected id; got ${JSON.stringify(created)}`);

  const listed = await client.listProjects();
  const match = listed.find((p) => (p.id ?? p._id) === projectId);
  assert.ok(match, `created project ${projectId} must appear in listProjects()`);

  // NOTE: cleanup via deleteProject is NOT exercised here. The local vault
  // image's DELETE /api/v1/projects/<id> route is admin-tier (returns 401
  // for user tokens). The Python `delete_project` docstring suggests user
  // access but the server actually enforces admin auth. Follow-up: confirm
  // the production vault contract and either gate the method behind a
  // requireAdmin guard, or add a user-tier delete route on the server.
});

test("VaultClient.unauthed — without authenticate() requests are 401", { skip: !reachable && "vault not reachable" }, async () => {
  const device = DeviceKey.generate();
  const identity = vaultIdentityFromDeviceKey(device);
  // autoAuth: false -> no token, no 401 retry.
  const client = await VaultClient.forIdentity(identity, VAULT_URL, { autoAuth: false });
  assert.equal(client.token, null, "token must be null before authenticate()");

  let caught: VaultError | null = null;
  try {
    await client.listProjects();
  } catch (e) {
    caught = e as VaultError;
  }
  assert.ok(caught, "unauthed listProjects must throw");
  // Without a token AND reauthOn401 short-circuiting (token is null), we surface the 401.
  assert.ok(caught && caught.status !== null && caught.status >= 400, `expected error status; got ${caught?.status}`);
});
