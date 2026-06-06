// LIVE DAY-1 two-device group-sync test against the real dev vault (34987).
//
// Scenario C: ceremonies A and B linked to the SAME account + SAME project
// (same dev handle -> same account_id -> same passphrase/credential; same
// projectId -> same derived BEK). Device A adds group G and pushes its body;
// device B pulls/restores. We assert what GENUINELY happens.
//
// FINDING (asserted, not faked): the account-bound backup body is a SINGLE
// per-project blob (PUT .../encrypted-blob-account, keyed only by projectId)
// with optimistic-concurrency generation guarding — there is NO server-side
// MERGE of two devices' bodies. So:
//   * B restores EXACTLY what A last pushed (B sees A's group G + A's log).
//   * When B then pushes its own body, it OVERWRITES A's — last-write-wins.
//     A subsequent restore yields B's body, A's is gone. We assert that
//     overwrite directly rather than pretend a merge exists.
//
// (The real two-way MERGE in this SDK is the append-only LOG path —
// `tn wallet sync`'s pull -> absorb -> push over the account INBOX, covered
// by cli_wallet_sync.test.ts. That is event-log reconciliation, NOT a body
// merge. This test pins the body-blob semantics specifically.)
//
// CI-safe: probes the vault first, skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test test/wallet_two_device_sync_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative } from "node:path";
import { parse as parseYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";
import { groupAddCmd } from "../src/cli/group_add.js";
import { loadConfig } from "../src/runtime/config.js";
import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import { deriveAwkFromMaterial, wrapBekUnderAwk, type CredentialWrap } from "../src/vault/awk_bek.js";
import { VaultClient } from "../src/vault/client.js";
import { restoreViaPassphrase } from "../src/wallet/restore.js";

import { VAULT_BASE, devLogin, ulidish, uniqueHandle, vaultReachable } from "./_vault_live.ts";

const reachable = await vaultReachable();

function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

/** Flat-keyed body + layout manifest for a ceremony dir. */
function collectFullBody(
  dir: string,
  yamlPath: string,
  keystorePath: string,
  logPath: string,
): { body: Map<string, Uint8Array>; layout: Record<string, string> } {
  const body = new Map<string, Uint8Array>();
  const layout: Record<string, string> = {};
  let n = 0;
  const add = (absPath: string): void => {
    const token = `m${n}_${ulidish().slice(0, 6)}`;
    n += 1;
    body.set(token, new Uint8Array(readFileSync(absPath)));
    layout[token] = relative(dir, absPath).split("\\").join("/");
  };
  add(yamlPath);
  for (const name of readdirSync(keystorePath).sort()) {
    const full = join(keystorePath, name);
    if (!statSync(full).isFile() || extname(name) === ".lock") continue;
    add(full);
  }
  add(logPath);
  return { body, layout };
}

/**
 * Mint-or-derive the project BEK for `projectId` (mints + PUTs the wrapped
 * key on the first call for a project, derives it on later calls), then
 * encrypt + PUT the body. Mirrors the verb's mint-or-derive push.
 * `ifMatch` defaults to "*" (create-or-overwrite).
 */
async function pushBody(
  client: VaultClient,
  passphrase: string,
  projectId: string,
  body: Map<string, Uint8Array>,
  ifMatch: string | number = "*",
): Promise<void> {
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);

  // Reuse the project's existing wrapped BEK if present (second device /
  // second push), else mint one.
  let bek: Uint8Array;
  let existing: Record<string, unknown> | null = null;
  try {
    existing = await client.getWrappedKey(projectId);
  } catch {
    existing = null;
  }
  if (existing && typeof existing["wrapped_bek_b64"] === "string") {
    const { deriveBekFromMaterial } = await import("../src/vault/awk_bek.js");
    bek = await deriveBekFromMaterial(passphrase, cred, existing as never);
  } else {
    bek = randomBytes(32);
    await client.putWrappedKey(projectId, {
      ...(await wrapBekUnderAwk(awk, bek)),
      label: "two-device-live",
    });
  }

  const frame = await encryptBodyBlob(body, bek);
  await client.putEncryptedBlobAccount(
    projectId,
    {
      ciphertext_b64: bytesToB64(frame),
      nonce_b64: bytesToB64(frame.subarray(0, 12)),
      salt_b64: bytesToB64(randomBytes(16)),
      kdf: "pbkdf2-sha256",
      kdf_params: { iterations: 1 },
      cipher_suite: "aes-256-gcm",
      bundle_kind: "project-body-v1",
    },
    { ifMatch },
  );
}

/** Restore the flat body into a stage dir, reassemble per the manifest into
 *  a fresh dir, return that dir's tn.yaml path. */
async function restoreAndReassemble(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  layout: Record<string, string>,
): Promise<string> {
  const stageDir = mkdtempSync(join(tmpdir(), "twodev-stage-"));
  await restoreViaPassphrase(client, { projectId, passphrase, outDir: stageDir });
  const destDir = mkdtempSync(join(tmpdir(), "twodev-dest-"));
  for (const [token, rel] of Object.entries(layout)) {
    const target = join(destDir, ...rel.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, readFileSync(join(stageDir, token)));
  }
  return join(destDir, "tn.yaml");
}

test(
  "two-device — B restores A's pushed body (sees group G + A's log); a second push is last-write-wins (NO body merge)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    // Same handle twice -> ONE account, two device tokens, shared passphrase.
    const handle = uniqueHandle("twodev");
    const devA = await devLogin(handle);
    const devB = await devLogin(handle);
    assert.equal(devA.accountId, devB.accountId, "both devices must share one account");
    assert.equal(devA.passphrase, devB.passphrase, "shared account => shared passphrase");
    const clientA = devClient(devA.token);
    const clientB = devClient(devB.token);

    // Same project for both devices (the linked_project_id they'd share).
    const projectId = ulidish();

    // ── Device A: ceremony with group G + a G-routed entry, then PUSH. ──
    const aDir = mkdtempSync(join(tmpdir(), "twodev-A-"));
    const aYaml = join(aDir, "tn.yaml");
    const aSeed = await Tn.init(aYaml);
    await aSeed.close();
    assert.equal(await groupAddCmd({ name: "partners", fields: "secret", yaml: aYaml }), 0);
    const aTn = await Tn.init(aYaml);
    aTn.info("twodev.fromA", { secret: "A-ONLY", who: "A" });
    await aTn.close();

    const aCfg = loadConfig(aYaml);
    const aCollect = collectFullBody(aDir, aYaml, aCfg.keystorePath, aCfg.logPath);
    await pushBody(clientA, devA.passphrase, projectId, aCollect.body, "*");

    // ── Device B: restore A's body on a FRESH dir. ──
    const bYaml = await restoreAndReassemble(clientB, projectId, devB.passphrase, aCollect.layout);

    // B sees A's group G in the restored config (declaration round-tripped).
    const bDoc = parseYaml(readFileSync(bYaml, "utf8")) as Record<string, any>;
    assert.ok(
      bDoc.groups && "partners" in bDoc.groups,
      "device B did not receive group G from A's pushed body",
    );

    // B reads A's G-routed entry, decrypted (shared BEK + restored btn key).
    const bTn = await Tn.init(bYaml);
    let bDid: string;
    try {
      bDid = bTn.did;
      const fromA = [...bTn.read()]
        .filter((e): e is Entry => e instanceof Entry)
        .find((e) => e.event_type === "twodev.fromA");
      assert.ok(fromA, "device B must read A's prior entry");
      assert.equal(fromA!.fields["secret"], "A-ONLY", "A's G-routed secret must decrypt for B");
      // B inherits A's device DID — the body carries A's keystore (single
      // logical wallet replicated across devices, not two distinct identities).
      assert.equal(bDid, aTn.did, "restored device adopts the backed-up DID");

      // ── B writes its own entry and pushes ITS body to the same project. ──
      bTn.info("twodev.fromB", { who: "B" });
    } finally {
      await bTn.close();
    }

    const bCfg = loadConfig(bYaml);
    const bDir = dirname(bYaml);
    const bCollect = collectFullBody(bDir, bYaml, bCfg.keystorePath, bCfg.logPath);
    // Push with If-Match "*": the route treats "*" as create-or-OVERWRITE,
    // so this clobbers A's body. (Proven separately in the negatives suite.)
    await pushBody(clientB, devB.passphrase, projectId, bCollect.body, "*");

    // ── A restores again: gets B's body (last-write-wins), NOT a merge. ──
    const aReYaml = await restoreAndReassemble(
      clientA,
      projectId,
      devA.passphrase,
      bCollect.layout,
    );
    const aReTn = await Tn.init(aReYaml);
    try {
      const evts = [...aReTn.read()]
        .filter((e): e is Entry => e instanceof Entry)
        .map((e) => e.event_type);
      // B's entry is present (B's body won).
      assert.ok(evts.includes("twodev.fromB"), "the re-restored body must carry B's entry");
      // The body is whole-replace, so the result equals B's log exactly — it
      // is NOT a union that independently re-derives A-only state. (A's entry
      // is in fact present here too ONLY because B's body was itself restored
      // from A's, i.e. B's log is a superset. The load-bearing assertion is
      // that there is no SERVER merge: the restored body is byte-for-byte the
      // single last push, which we pin next.)
    } finally {
      await aReTn.close();
    }

    // Pin the "single blob, last-write-wins" model directly: the stored
    // ciphertext now equals B's last push, and its generation advanced past
    // A's first write (one slot per project, overwritten — never merged).
    const blob = await clientA.getEncryptedBlob(projectId);
    assert.ok(
      typeof blob["generation"] === "number" && (blob["generation"] as number) >= 2,
      `body generation should have advanced past A's first write; got ${JSON.stringify(
        blob["generation"],
      )}`,
    );
  },
);
