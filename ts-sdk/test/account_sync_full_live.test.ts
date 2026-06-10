// CAPSTONE: the FULL ACCOUNT SYNC end-to-end journey against the LIVE dev
// vault on 34987 (TN_DEV_AUTH_BYPASS=1).
//
// The piecemeal live suites each prove ONE leg of the journey (body push,
// passphrase restore, connect-code redeem, lifecycle, group-key publish/
// absorb, the negatives). This file composes the WHOLE multi-device account
// journey as one continuous test so the legs are proven to compose:
//
//   Device A (new account):
//     init a ceremony -> connect/bind it to a fresh dev account -> add TWO
//     groups (G1, G2) with routed fields -> write several log entries across
//     the default group + G1 + G2 -> `wallet sync` (push body + publish the
//     G1/G2 key snapshots to the OWN account inbox).
//
//   Device B (same account, fresh identity dir = a different machine):
//     connect/bind a SECOND device to the SAME account -> `wallet sync` pull
//     -> absorb. Assert B ends up with: BOTH groups present AND USABLE
//     (B encrypts to G1+G2 and reads its own writes back decrypted), and the
//     ceremony identity adopted (B's account binding resolves the same
//     account). Then B body-restores A's pushed blob and reads A's PRIOR
//     entries (incl. the G1/G2-routed secrets), adopting A's device DID.
//
//   Round-back:
//     B adds a THIRD group G3 + writes + `wallet sync` (publish G3). A
//     `wallet sync` (pull) -> A now has G3 present AND USABLE too. Union both
//     directions (A->B for G1/G2, B->A for G3) with no clobber.
//
//   Negatives woven into the journey:
//     * a wrong passphrase on B's body restore fails CLEAN (throws, no
//       partial keystore written);
//     * a stale If-Match concurrent body push surfaces the 412 conflict
//       rather than silently overwriting.
//
// HARD RULE: real round-trips, no mock. CI-safe: probes the vault first and
// skips cleanly when it is unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test \
//        test/account_sync_full_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative } from "node:path";
import { Buffer } from "node:buffer";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";
import { groupAddCmd } from "../src/cli/group_add.js";
import { walletSyncCmd } from "../src/cli/wallet_sync.js";
import { loadConfig } from "../src/runtime/config.js";
import { encryptBodyBlob } from "../src/core/body_encryption.js";
import { bytesToB64, randomBytes } from "../src/core/encoding.js";
import {
  AwkBekError,
  deriveAwkFromMaterial,
  wrapBekUnderAwk,
  type CredentialWrap,
} from "../src/vault/awk_bek.js";
import { VaultClient, VaultError } from "../src/vault/client.js";
import { RestoreError, restoreViaPassphrase } from "../src/wallet/restore.js";
import { Identity } from "../src/identity.js";
import { AccountNamespace, getAccountId, isAccountBound } from "../src/account/index.ts";

import {
  VAULT_BASE,
  devLogin,
  mintConnectCode,
  ulidish,
  uniqueHandle,
  vaultReachable,
} from "./_vault_live.ts";

const reachable = await vaultReachable();

/** A buffered stdout/stderr sink so we can inspect a verb's output. */
function sink(): { write(s: string): void; text(): string } {
  let buf = "";
  return { write: (s: string) => { buf += s; }, text: () => buf };
}

/** Authed VaultClient bearing a dev-login JWT (no DID dance). */
function devClient(token: string): VaultClient {
  return VaultClient.unauthed({
    baseUrl: VAULT_BASE,
    identity: { did: "did:key:zDevDummy", signNonce: () => new Uint8Array(64) },
    token,
  });
}

interface DeviceCtx {
  dir: string;
  yamlPath: string;
  identityDir: string;
  identity: Identity;
  passphrase: string;
  projectId: string;
}

/**
 * Stand up one device: its own TN_IDENTITY_DIR (distinct device DID), a fresh
 * ceremony flipped to `mode: linked` against the SHARED project id, and an
 * `account connect` binding its identity DID to the shared dev account (each
 * device redeems its OWN single-use connect code minted by the account).
 */
async function setupDevice(
  stem: string,
  minterHandle: string,
  projectId: string,
  passphrase: string,
): Promise<DeviceCtx> {
  const dir = mkdtempSync(join(tmpdir(), `acctfull-${stem}-`));
  const identityDir = join(dir, "identity");
  mkdirSync(identityDir, { recursive: true });
  const identity = Identity.loadOrMint(join(identityDir, "identity.json"));

  const yamlPath = join(dir, "tn.yaml");
  const seed = await Tn.init(yamlPath);
  await seed.close();

  // Bind THIS device's identity DID to the shared account (own connect code).
  const { code, accountId } = await mintConnectCode(minterHandle);
  const result = await AccountNamespace.connect(code, VAULT_BASE, identity.deviceKey(), {
    yamlPath,
  });
  assert.equal(result.accountId, accountId, `${stem}: connect must bind the minter account`);
  assert.equal(isAccountBound(yamlPath), true, `${stem}: sync-state must record account_bound`);
  assert.equal(getAccountId(yamlPath), accountId, `${stem}: sync-state must stamp account_id`);

  // Flip the ceremony to linked against the shared project so push + the
  // group-keys publish run.
  const doc = (parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>) ?? {};
  const ceremony = (doc.ceremony ?? {}) as Record<string, unknown>;
  ceremony.mode = "linked";
  ceremony.linked_vault = VAULT_BASE;
  ceremony.linked_project_id = projectId;
  doc.ceremony = ceremony;
  writeFileSync(yamlPath, stringifyYaml(doc), "utf8");

  return { dir, yamlPath, identityDir, identity, passphrase, projectId };
}

/** Run `tn wallet sync` (full: pull+absorb then push+publish). */
async function sync(dev: DeviceCtx): Promise<string> {
  const out = sink();
  const err = sink();
  const code = await walletSyncCmd({
    yaml: dev.yamlPath,
    identityPath: join(dev.identityDir, "identity.json"),
    passphrase: dev.passphrase,
    vault: VAULT_BASE,
    stdout: out,
    stderr: err,
  });
  assert.equal(code, 0, `wallet sync exit !=0 for ${dev.dir}: ${err.text()}${out.text()}`);
  return out.text();
}

/** User group names declared in a ceremony yaml (sans the default + tn.agents). */
function groupsInYaml(yamlPath: string): string[] {
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>;
  const groups = (doc.groups ?? {}) as Record<string, unknown>;
  return Object.keys(groups)
    .filter((g) => g !== "tn.agents" && g !== "default")
    .sort();
}

/** All decrypted Entry rows a freshly-opened ceremony reads back. */
async function readEntries(yamlPath: string): Promise<Entry[]> {
  const tn = await Tn.init(yamlPath);
  try {
    return [...tn.read()].filter((e): e is Entry => e instanceof Entry);
  } finally {
    await tn.close();
  }
}

/** Write one group-routed entry through a freshly-opened ceremony. */
async function writeEntry(
  yamlPath: string,
  eventType: string,
  fields: Record<string, unknown>,
): Promise<void> {
  const tn = await Tn.init(yamlPath);
  try {
    tn.info(eventType, fields);
  } finally {
    await tn.close();
  }
}

/**
 * Prove a group is USABLE on `dev`: write a fresh entry whose routed field
 * lands in the group's ciphertext block, then read it back DECRYPTED. If the
 * group's btn key did not install, the field would not surface.
 */
async function assertGroupUsable(
  yamlPath: string,
  field: string,
  who: string,
): Promise<void> {
  const eventType = `usable.${who}.${ulidish().slice(0, 6)}`;
  const marker = `${who}-${ulidish().slice(0, 8)}`;
  await writeEntry(yamlPath, eventType, { [field]: marker });
  const back = (await readEntries(yamlPath)).find((e) => e.event_type === eventType);
  assert.ok(back, `${who}: must read back its own routed entry ${eventType}`);
  assert.equal(
    back!.fields[field],
    marker,
    `${who}: routed field '${field}' must decrypt (group USABLE)`,
  );
}

// ── Body-blob collect / push / restore-reassemble (the A->B body leg) ──────

/** Flat-keyed body + a manifest mapping each token to its ceremony-relative path. */
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
    const token = `body/m${n}_${ulidish().slice(0, 6)}`;
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
 * Mint (or reuse) the project BEK and push the body frame. `ifMatch` defaults
 * to "*" (create-or-overwrite). Returns the BEK used (for the negative-path
 * concurrent push) and the generation the push landed at.
 */
async function pushBody(
  client: VaultClient,
  passphrase: string,
  projectId: string,
  body: Map<string, Uint8Array>,
  ifMatch: string | number = "*",
): Promise<{ bek: Uint8Array; generation: number }> {
  const cred = (await client.getCredentialWrap()) as unknown as CredentialWrap;
  const awk = await deriveAwkFromMaterial(passphrase, cred);

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
      label: "account-sync-full-live",
    });
  }

  const frame = await encryptBodyBlob(body, bek);
  const resp = await client.putEncryptedBlobAccount(
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
  return { bek, generation: (resp["generation"] as number) ?? -1 };
}

/** Restore the flat body to a stage dir, reassemble per the manifest, return tn.yaml. */
async function restoreAndReassemble(
  client: VaultClient,
  projectId: string,
  passphrase: string,
  layout: Record<string, string>,
): Promise<string> {
  const stageDir = mkdtempSync(join(tmpdir(), "acctfull-stage-"));
  await restoreViaPassphrase(client, { projectId, passphrase, outDir: stageDir });
  const destDir = mkdtempSync(join(tmpdir(), "acctfull-dest-"));
  for (const [token, rel] of Object.entries(layout)) {
    const target = join(destDir, ...rel.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, readFileSync(join(stageDir, token)));
  }
  return join(destDir, "tn.yaml");
}

// ── The capstone ───────────────────────────────────────────────────────────

test(
  "FULL ACCOUNT SYNC — A inits+binds+2 groups+writes+sync; B connects+pulls (both groups USABLE, A's log readable); round-back G3 union; negatives clean",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    // One dev account; both devices connect to it. `devLogin` ensures the
    // account exists (and gives us its deterministic passphrase).
    const minter = uniqueHandle("acctfull");
    const dev0 = await devLogin(minter);
    const passphrase = dev0.passphrase;
    const projectId = ulidish();

    const A = await setupDevice("A", minter, projectId, passphrase);
    const B = await setupDevice("B", minter, projectId, passphrase);
    const created = [A.dir, B.dir];

    try {
      // ───────────────────────── DEVICE A ─────────────────────────
      // Two groups with routed fields.
      assert.equal(await groupAddCmd({ name: "g1", fields: "s1", yaml: A.yamlPath }), 0);
      assert.equal(await groupAddCmd({ name: "g2", fields: "s2", yaml: A.yamlPath }), 0);
      assert.deepEqual(groupsInYaml(A.yamlPath), ["g1", "g2"], "A must declare G1+G2");

      // Several entries across default + G1 + G2.
      {
        const aTn = await Tn.init(A.yamlPath);
        try {
          aTn.log("acct.default.alpha", { n: 1 }); // default group
          aTn.info("acct.default.beta", "noted", { n: 2 }); // default group
          aTn.info("acct.g1.gamma", { s1: "A-G1-SECRET", who: "A" }); // -> G1
          aTn.info("acct.g2.delta", { s2: "A-G2-SECRET", who: "A" }); // -> G2
        } finally {
          await aTn.close();
        }
      }

      // A's own read sees all four, with the routed secrets decrypted.
      {
        const aEntries = await readEntries(A.yamlPath);
        const g1 = aEntries.find((e) => e.event_type === "acct.g1.gamma");
        const g2 = aEntries.find((e) => e.event_type === "acct.g2.delta");
        assert.equal(g1?.fields["s1"], "A-G1-SECRET", "A reads its own G1 secret");
        assert.equal(g2?.fields["s2"], "A-G2-SECRET", "A reads its own G2 secret");
      }

      // wallet sync: push body + publish G1/G2 key snapshots to the inbox.
      const aOut = await sync(A);
      assert.match(aOut, /published group keys to own inbox/, `A sync must publish group keys:\n${aOut}`);
      assert.match(aOut, /g1/, `A publish must include G1:\n${aOut}`);
      assert.match(aOut, /g2/, `A publish must include G2:\n${aOut}`);

      // Sanity: B does NOT yet know G1/G2.
      assert.deepEqual(groupsInYaml(B.yamlPath), [], "B must start with no extra groups");

      // ───────────────────────── DEVICE B ─────────────────────────
      // wallet sync pull -> absorb installs+registers G1 and G2.
      await sync(B);
      const bGroups = groupsInYaml(B.yamlPath);
      assert.ok(
        bGroups.includes("g1") && bGroups.includes("g2"),
        `B must register BOTH groups after pull; got ${JSON.stringify(bGroups)}`,
      );

      // USABLE: B encrypts to G1 and G2 and reads its own writes back.
      await assertGroupUsable(B.yamlPath, "s1", "B_on_g1");
      await assertGroupUsable(B.yamlPath, "s2", "B_on_g2");

      // ── A's PRIOR log readable on B via the body blob (DID adoption). ──
      // The group-keys path makes the groups USABLE but does NOT carry A's
      // event log; A's prior entries travel in the body blob. A's `wallet
      // sync` already pushed a body to `projectId`, but the verb keys its
      // members `body/keys/<name>` (nested) and the TS restore's traversal
      // guard refuses any name with a separator — the documented TS/Python
      // body-restore divergence (docs/cli-test-plans/wallet_restore.md). So
      // for the TS body leg we push A's body under FLAT tokens to a SEPARATE
      // project id (with a layout manifest) — the shape the TS restore can
      // round-trip — exactly as wallet_two_device_sync_live does, then B
      // restores+reassembles it. (G1/G2 usability above already came via the
      // group-keys snapshot, independent of this body blob.)
      const clientB = devClient((await devLogin(minter)).token);
      const bodyProjectId = ulidish();
      const aCfg = loadConfig(A.yamlPath);
      const aCollect = collectFullBody(A.dir, A.yamlPath, aCfg.keystorePath, aCfg.logPath);
      const aDid = (await (async () => {
        const t = await Tn.init(A.yamlPath);
        try {
          return t.did;
        } finally {
          await t.close();
        }
      })());
      await pushBody(clientB, passphrase, bodyProjectId, aCollect.body, "*");

      const bRestoredYaml = await restoreAndReassemble(clientB, bodyProjectId, passphrase, aCollect.layout);
      created.push(dirname(bRestoredYaml));
      {
        const restored = await Tn.init(bRestoredYaml);
        try {
          assert.equal(restored.did, aDid, "B's body-restored ceremony adopts A's device DID");
          const events = [...restored.read()]
            .filter((e): e is Entry => e instanceof Entry);
          const g1 = events.find((e) => e.event_type === "acct.g1.gamma");
          const g2 = events.find((e) => e.event_type === "acct.g2.delta");
          assert.ok(
            events.some((e) => e.event_type === "acct.default.alpha"),
            "B must read A's default-group prior entry",
          );
          assert.equal(g1?.fields["s1"], "A-G1-SECRET", "B reads A's G1 secret after body restore");
          assert.equal(g2?.fields["s2"], "A-G2-SECRET", "B reads A's G2 secret after body restore");
        } finally {
          await restored.close();
        }
      }
      clientB.close?.();

      // ───────────────────────── ROUND-BACK ─────────────────────────
      // B adds a NEW group G3, writes to it, then syncs (publishes G3).
      assert.equal(await groupAddCmd({ name: "g3", fields: "s3", yaml: B.yamlPath }), 0);
      await writeEntry(B.yamlPath, "acct.g3.fromB", { s3: "B-G3-SECRET", who: "B" });
      const bOut = await sync(B);
      assert.match(bOut, /published group keys to own inbox/, `B sync must publish group keys:\n${bOut}`);
      assert.match(bOut, /g3/, `B publish must include G3:\n${bOut}`);

      // A syncs (pull) -> A now has G3, and it is USABLE on A.
      assert.ok(!groupsInYaml(A.yamlPath).includes("g3"), "A must not know G3 before its pull");
      await sync(A);
      assert.ok(
        groupsInYaml(A.yamlPath).includes("g3"),
        `A must register G3 after pull; got ${JSON.stringify(groupsInYaml(A.yamlPath))}`,
      );
      await assertGroupUsable(A.yamlPath, "s3", "A_on_g3");

      // UNION both directions: A has G1,G2,G3; B has G1,G2,G3.
      assert.deepEqual(groupsInYaml(A.yamlPath), ["g1", "g2", "g3"], "A union must hold G1+G2+G3");
      assert.deepEqual(groupsInYaml(B.yamlPath), ["g1", "g2", "g3"], "B union must hold G1+G2+G3");

      // ───────────────────────── NEGATIVES (in-journey) ─────────────────────────
      const clientNeg = devClient((await devLogin(minter)).token);
      try {
        // N1: wrong passphrase on a body restore fails CLEAN (no partial write).
        const badDir = mkdtempSync(join(tmpdir(), "acctfull-badpass-"));
        created.push(badDir);
        let caught: Error | null = null;
        try {
          await restoreViaPassphrase(clientNeg, {
            projectId: bodyProjectId, // a project with a real pushed body
            passphrase: passphrase + "-WRONG",
            outDir: badDir,
          });
        } catch (e) {
          caught = e as Error;
        }
        assert.ok(caught, "wrong passphrase must throw on restore");
        assert.ok(
          caught instanceof AwkBekError || caught instanceof RestoreError,
          `expected AwkBekError/RestoreError; got ${caught?.constructor.name}: ${caught?.message}`,
        );
        assert.deepEqual(
          readdirSync(badDir),
          [],
          "a failed restore must leave the output dir EMPTY (no partial keystore)",
        );

        // N2: a stale If-Match concurrent body push surfaces the 412 conflict.
        // First push lands a generation; a correct gen-matched push advances
        // it; a writer still holding the STALE generation is rejected with 412.
        const negProject = ulidish();
        const negBody = new Map<string, Uint8Array>([["body/v", new Uint8Array([1])]]);
        const first = await pushBody(clientNeg, passphrase, negProject, negBody, "*");
        assert.ok(first.generation >= 1, `first push should land a generation; got ${first.generation}`);

        const second = await pushBody(
          clientNeg,
          passphrase,
          negProject,
          new Map([["body/v", new Uint8Array([2])]]),
          String(first.generation),
        );
        assert.equal(
          second.generation,
          first.generation + 1,
          "a correct-generation push must advance the body generation",
        );

        let conflict: VaultError | null = null;
        try {
          await pushBody(
            clientNeg,
            passphrase,
            negProject,
            new Map([["body/v", new Uint8Array([3])]]),
            String(first.generation), // STALE
          );
        } catch (e) {
          conflict = e as VaultError;
        }
        assert.ok(conflict, "a stale-generation push must be rejected, not silently applied");
        assert.ok(conflict instanceof VaultError, `expected VaultError; got ${conflict?.constructor.name}`);
        assert.equal(conflict!.status, 412, "stale If-Match must surface as HTTP 412");

        // The losing write must NOT have advanced the body.
        const blob = await clientNeg.getEncryptedBlob(negProject);
        assert.equal(
          blob["generation"],
          second.generation,
          "the rejected push must not have mutated the body (generation unchanged)",
        );
      } finally {
        clientNeg.close?.();
      }
    } finally {
      for (const d of created) rmSync(d, { recursive: true, force: true });
    }
  },
);
