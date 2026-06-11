// LIVE test for the credential-cache engine the `.mjs` CLI drives:
// `account connect --passphrase` -> cacheAccountAwk, warm-init -> loadCachedAwk.
//
// Proves end-to-end against the dev vault (TN_DEV_AUTH_BYPASS=1) that
// cacheAccountAwk authenticates as the connected device DID, fetches the
// account credential wrap, derives the AWK from the passphrase, and stores the
// RIGHT 32 bytes — the same AWK the push path would derive — and that
// loadCachedAwk reads them back. This is the credential half of the warm
// "sync-if-exists / push-if-new" init; the SDK push-AWK intake is covered by
// wallet_sync_live / account_sync_full_live, and the .mjs flow shells by
// cli_wallet_account / cli_init_vault_show.
//
// Mirrors Python test_init_attach_live.py::test_wired_connect_cache_then_init.
// CI-safe: probes the vault first and skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/awk_cache_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DeviceKey } from "../src/core/signing.ts";
import { AccountNamespace } from "../src/account/index.ts";
import { VaultClient, vaultIdentityFromDeviceKey } from "../src/vault/client.ts";
import { deriveAwkFromMaterial, type CredentialWrap } from "../src/vault/awk_bek.ts";
import { FileCredentialStore } from "../src/vault/credential_store.ts";
import { cacheAccountAwk, loadCachedAwk } from "../src/vault/awk_cache.ts";

import { VAULT_BASE, devLogin, mintConnectCode, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

test(
  "awk cache — live: cacheAccountAwk stores the passphrase-derived AWK; loadCachedAwk reads it back",
  { skip: !reachable && "dev vault not reachable" },
  async () => {
    // A fresh dev account (deterministic passphrase) + a single-use connect
    // code minted on it. devLogin(handle) is idempotent per handle, so it
    // returns the SAME account the code was minted on, plus its passphrase.
    const handle = uniqueHandle("awkcache");
    const { code } = await mintConnectCode(handle);
    const dev = await devLogin(handle);

    const tmp = mkdtempSync(join(tmpdir(), "awk-cache-live-"));
    try {
      const yamlPath = join(tmp, "tn.yaml");
      writeFileSync(yamlPath, "ceremony:\n  id: awk_cache_live\n  mode: local\n");

      // Bind THIS device's DID to the account (so DID-challenge auth resolves
      // the account when cacheAccountAwk fetches the credential wrap).
      const device = DeviceKey.generate();
      const connected = await AccountNamespace.connect(code, VAULT_BASE, device, { yamlPath });
      assert.equal(connected.accountId, dev.accountId, "connected account == minter account");

      // The new wiring: derive + cache the AWK from the passphrase.
      const store = new FileCredentialStore(join(tmp, "credentials.json"));
      await cacheAccountAwk(device, VAULT_BASE, dev.passphrase, connected.accountId, { store });

      // Read it back: 32 bytes, and BYTE-EQUAL to the AWK the push path would
      // derive directly from the same passphrase + credential wrap.
      const cached = loadCachedAwk(connected.accountId, { store });
      assert.ok(cached, "loadCachedAwk returns the cached AWK");
      assert.equal(cached.length, 32, "AWK is 32 bytes");

      const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(device), VAULT_BASE);
      const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
      const derived = await deriveAwkFromMaterial(dev.passphrase, cred);
      assert.ok(
        Buffer.from(cached).equals(Buffer.from(derived)),
        "cached AWK must equal the freshly-derived AWK (cacheAccountAwk stored the right key)",
      );

      // A never-cached account reads back as null (no throw) — the contained
      // "no AWK yet" path warm-init falls back on.
      assert.equal(loadCachedAwk(`${connected.accountId}-never`, { store }), null);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);

test(
  "awk cache — live: a wrong passphrase fails the derive (no garbage AWK is cached)",
  { skip: !reachable && "dev vault not reachable" },
  async () => {
    const handle = uniqueHandle("awkcache-wrong");
    const { code } = await mintConnectCode(handle);
    const dev = await devLogin(handle);

    const tmp = mkdtempSync(join(tmpdir(), "awk-cache-wrong-"));
    try {
      const yamlPath = join(tmp, "tn.yaml");
      writeFileSync(yamlPath, "ceremony:\n  id: awk_cache_wrong\n  mode: local\n");
      const device = DeviceKey.generate();
      const connected = await AccountNamespace.connect(code, VAULT_BASE, device, { yamlPath });

      const store = new FileCredentialStore(join(tmp, "credentials.json"));
      let caught: Error | null = null;
      try {
        await cacheAccountAwk(device, VAULT_BASE, `${dev.passphrase}-WRONG`, connected.accountId, { store });
      } catch (e) {
        caught = e as Error;
      }
      assert.ok(caught, "a wrong passphrase must throw (AWK unwrap fails)");
      // Nothing cached: the failed derive never reached store.set.
      assert.equal(loadCachedAwk(connected.accountId, { store }), null, "no AWK cached on failure");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
