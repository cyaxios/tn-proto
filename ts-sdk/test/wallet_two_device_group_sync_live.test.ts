// LIVE two-device GROUP-sync test against the real dev vault (34987).
//
// This proves the merge-path companion to the last-write-wins body blob:
// a group created on device A becomes USABLE on device B after sync — B can
// ENCRYPT (tn.info) to the group AND READ it back decrypted — WITHOUT relying
// on the body blob (which is overwritten on the next push).
//
// HOW IT WORKS (the piece this test exercises):
//   * `tn wallet sync` push now ALSO publishes a `group_keys` `.tnpkg`
//     (group `.btn.state`/`.btn.mykit` + the yaml `groups.<name>` blocks, NO
//     device secret) to the OWN account inbox via
//     POST /api/v1/inbox/{did}/snapshots/{ceremony}/{ts}.tnpkg.
//   * The other device's `tn wallet sync` pull -> absorb INSTALLS the group
//     key files into its keystore AND REGISTERS each group in its yaml
//     (union-merged, content-addressed, idempotent).
//   * After that, a fresh `Tn.init` over B's yaml routes through the group.
//
// Both devices share ONE account (two connect codes minted by one account),
// so the account-inbox aggregator surfaces A's published snapshot to B and
// vice-versa. Each device has its OWN identity.json (distinct device DID) —
// the group publisher keys are device-independent, so they install on either.
//
// CI-safe: probes the vault first and skips cleanly when unreachable.
//
// Run: node --import tsx --import ./test/_setup_wasm.mjs --test \
//        test/wallet_two_device_group_sync_live.test.ts

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";
import { groupAddCmd } from "../src/cli/group_add.js";
import { walletSyncCmd } from "../src/cli/wallet_sync.js";
import { Identity } from "../src/identity.js";
import { AccountNamespace } from "../src/account/index.ts";

import {
  VAULT_BASE,
  devLogin,
  mintConnectCode,
  ulidish,
  uniqueHandle,
  vaultReachable,
} from "./_vault_live.ts";

const reachable = await vaultReachable();

/** A buffered stdout/stderr sink so we can inspect the verb's output. */
function sink(): { write(s: string): void; text(): string } {
  let buf = "";
  return { write: (s: string) => { buf += s; }, text: () => buf };
}

interface DeviceCtx {
  dir: string;
  yamlPath: string;
  identityDir: string;
  identity: Identity;
  passphrase: string;
}

/**
 * Stand up one device: its own TN_IDENTITY_DIR (distinct device DID), a fresh
 * ceremony flipped to `mode: linked` (linked_vault + the SHARED project id),
 * and an `account connect` binding its identity DID to `account`'s account.
 */
async function setupDevice(
  stem: string,
  minterHandle: string,
  projectId: string,
  passphrase: string,
): Promise<DeviceCtx> {
  const dir = mkdtempSync(join(tmpdir(), `grp-${stem}-`));
  const identityDir = join(dir, "identity");
  mkdirSync(identityDir, { recursive: true });
  const identityPath = join(identityDir, "identity.json");
  const identity = Identity.loadOrMint(identityPath);

  // Fresh ceremony.
  const yamlPath = join(dir, "tn.yaml");
  const seed = await Tn.init(yamlPath);
  await seed.close();

  // Bind THIS device's identity DID to the shared account (own connect code).
  const { code } = await mintConnectCode(minterHandle);
  await AccountNamespace.connect(code, VAULT_BASE, identity.deviceKey(), { yamlPath });

  // Flip the ceremony to linked against the shared project so the verb's push
  // (and the group_keys publish) runs.
  const doc = (parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>) ?? {};
  const ceremony = (doc.ceremony ?? {}) as Record<string, unknown>;
  ceremony.mode = "linked";
  ceremony.linked_vault = VAULT_BASE;
  ceremony.linked_project_id = projectId;
  doc.ceremony = ceremony;
  writeFileSync(yamlPath, stringifyYaml(doc), "utf8");

  return { dir, yamlPath, identityDir, identity, passphrase };
}

/** Run `tn wallet sync` for a device with its identity. Returns stdout text. */
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

/** Group names declared in a ceremony yaml (sans tn.agents). */
function groupsInYaml(yamlPath: string): string[] {
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>;
  const groups = (doc.groups ?? {}) as Record<string, unknown>;
  return Object.keys(groups).filter((g) => g !== "tn.agents").sort();
}

test(
  "two-device GROUP sync — A adds G + syncs; B syncs and can ENCRYPT to G and READ it back (G is USABLE on B)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    // One account minted via dev/login; both devices connect to it.
    const minter = uniqueHandle("grpsync");
    const dev0 = await devLogin(minter); // ensures the account exists + passphrase
    const passphrase = dev0.passphrase;
    const projectId = ulidish();

    const A = await setupDevice("A", minter, projectId, passphrase);
    const B = await setupDevice("B", minter, projectId, passphrase);

    try {
      // ── Device A: add group G, route a secret field, write a G-routed entry. ──
      assert.equal(
        await groupAddCmd({ name: "partners", fields: "secret", yaml: A.yamlPath }),
        0,
      );
      const aTn = await Tn.init(A.yamlPath);
      aTn.info("grp.fromA", { secret: "A-ONLY-SECRET", who: "A" });
      await aTn.close();

      // ── Device A: wallet sync — pushes body + PUBLISHES group_keys to inbox. ──
      const aOut = await sync(A);
      assert.match(
        aOut,
        /published group keys to own inbox.*partners/,
        `A's sync should publish group keys for 'partners'; got:\n${aOut}`,
      );

      // Sanity: B does NOT yet know G.
      assert.ok(
        !groupsInYaml(B.yamlPath).includes("partners"),
        "B should not know group G before its pull",
      );

      // ── Device B: wallet sync — pull + absorb installs G + registers it. ──
      await sync(B);

      // B's yaml now declares G (registered, not just key files on disk).
      assert.ok(
        groupsInYaml(B.yamlPath).includes("partners"),
        `B did not register group G after pull/absorb; B groups=${JSON.stringify(
          groupsInYaml(B.yamlPath),
        )}`,
      );

      // ── B can ENCRYPT to G: a fresh write routes through the group. ──
      const bTn = await Tn.init(B.yamlPath);
      try {
        // USABLE part 1: B writes a NEW G-routed entry (encrypt side works).
        bTn.info("grp.fromB", { secret: "B-WROTE-THIS", who: "B" });

        // USABLE part 2: B reads its own G-routed entry back, DECRYPTED.
        const fromB = [...bTn.read()]
          .filter((e): e is Entry => e instanceof Entry)
          .find((e) => e.event_type === "grp.fromB");
        assert.ok(fromB, "B must read back its own G-routed entry");
        assert.equal(
          fromB!.fields["secret"],
          "B-WROTE-THIS",
          "B's own G-routed secret must decrypt (G is USABLE on B)",
        );
      } finally {
        await bTn.close();
      }
    } finally {
      for (const d of [A, B]) rmSync(d.dir, { recursive: true, force: true });
    }
  },
);

test(
  "two-device GROUP sync — concurrent adds union: A adds G1, B adds G2, both sync both ways -> BOTH groups on BOTH (no clobber)",
  { skip: !reachable && "dev vault not reachable on 34987" },
  async () => {
    const minter = uniqueHandle("grpunion");
    const dev0 = await devLogin(minter);
    const passphrase = dev0.passphrase;
    const projectId = ulidish();

    const A = await setupDevice("A", minter, projectId, passphrase);
    const B = await setupDevice("B", minter, projectId, passphrase);

    try {
      // A adds G1, B adds DIFFERENT group G2 (concurrent, independent).
      assert.equal(await groupAddCmd({ name: "alpha", fields: "fa", yaml: A.yamlPath }), 0);
      assert.equal(await groupAddCmd({ name: "beta", fields: "fb", yaml: B.yamlPath }), 0);

      // Each writes a group-routed entry under its own new group.
      const aTn = await Tn.init(A.yamlPath);
      aTn.info("union.fromA", { fa: "alpha-secret" });
      await aTn.close();
      const bTn = await Tn.init(B.yamlPath);
      bTn.info("union.fromB", { fb: "beta-secret" });
      await bTn.close();

      // Cross-sync both ways. Order: A push, B push (pull A's first), A pull B's.
      await sync(A); // publishes alpha
      await sync(B); // pulls alpha (absorbs G1) THEN publishes beta
      await sync(A); // pulls beta (absorbs G2)

      // UNION: both devices now declare BOTH groups (no clobber).
      const aGroups = groupsInYaml(A.yamlPath);
      const bGroups = groupsInYaml(B.yamlPath);
      assert.ok(
        aGroups.includes("alpha") && aGroups.includes("beta"),
        `A must have BOTH groups; got ${JSON.stringify(aGroups)}`,
      );
      assert.ok(
        bGroups.includes("alpha") && bGroups.includes("beta"),
        `B must have BOTH groups; got ${JSON.stringify(bGroups)}`,
      );

      // USABLE both ways: A can encrypt+read beta (the group it RECEIVED);
      // B can encrypt+read alpha (the group it RECEIVED).
      const aTn2 = await Tn.init(A.yamlPath);
      try {
        aTn2.info("union.A_uses_beta", { fb: "A-on-beta" });
        const e = [...aTn2.read()]
          .filter((x): x is Entry => x instanceof Entry)
          .find((x) => x.event_type === "union.A_uses_beta");
        assert.ok(e, "A must read back its beta-routed entry");
        assert.equal(e!.fields["fb"], "A-on-beta", "A must encrypt+decrypt via RECEIVED group beta");
      } finally {
        await aTn2.close();
      }

      const bTn2 = await Tn.init(B.yamlPath);
      try {
        bTn2.info("union.B_uses_alpha", { fa: "B-on-alpha" });
        const e = [...bTn2.read()]
          .filter((x): x is Entry => x instanceof Entry)
          .find((x) => x.event_type === "union.B_uses_alpha");
        assert.ok(e, "B must read back its alpha-routed entry");
        assert.equal(e!.fields["fa"], "B-on-alpha", "B must encrypt+decrypt via RECEIVED group alpha");
      } finally {
        await bTn2.close();
      }
    } finally {
      for (const d of [A, B]) rmSync(d.dir, { recursive: true, force: true });
    }
  },
);
