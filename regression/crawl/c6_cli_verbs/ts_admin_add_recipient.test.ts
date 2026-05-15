/**
 * SILO: C6 — `tn` CLI verbs
 * TEST: `tn-js admin add-recipient` mints a kit on disk + emits the
 *       `tn.recipient.added` admin event.
 *
 * Python's equivalent: `tn add_recipient <group> <recipient>`. Note the
 * shape difference — Python uses positionals, TS uses `--group / --out
 * / --recipient-did` flags. See `ts_cli_verb_parity.test.ts` for the
 * named-assertion that captures this drift.
 *
 * Flow:
 *   1. Mint a fresh ceremony via `Tn.use("default")` in a tmpdir (no
 *      tn-js init, since tn-js has none).
 *   2. Invoke `node bin/tn-js.mjs admin add-recipient --yaml <yaml>
 *      --group default --out <kit> --recipient-did did:key:zFrank...`.
 *   3. Assert exit 0, kit file landed at --out path, admin log has a
 *      `tn.recipient.added` event with the right recipient_did.
 *
 * Asserts (named):
 *   - "tnjs-admin-add-recipient-exit-0"
 *   - "tnjs-admin-add-recipient-writes-kit"
 *   - "tnjs-admin-add-recipient-emits-event"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";
import { LogQuery } from "../../_shared/log_query.js";

const FRANK_DID = "did:key:zFrank0123456789abcdefghjkmnpqrstuvwx";
const TNJS = "C:/codex/tn/tn_proto/ts-sdk/bin/tn-js.mjs";

test("C6 (TS): tn-js admin add-recipient mints kit + emits event", async () => {
  setTestContext({
    silo: "c6",
    test: "c6_tnjs_admin_add_recipient::happy_path",
  });

  // Mint the ceremony via the SDK (tn-js has no init verb).
  const projectDir = mkdtempSync(join(tmpdir(), "c6-tnjs-add-"));
  const cwdBefore = process.cwd();
  process.chdir(projectDir);

  let alice: Tn | undefined;
  let yamlPath = "";
  try {
    alice = await Tn.use("default");
    yamlPath = alice.yamlPath;
    await alice.close();
    alice = undefined;
  } finally {
    process.chdir(cwdBefore);
  }

  // Invoke the CLI as a subprocess.
  const kitPath = join(projectDir, "frank.btn.mykit");
  const proc = spawnSync(
    "node",
    [
      TNJS,
      "admin",
      "add-recipient",
      "--yaml", yamlPath,
      "--group", "default",
      "--out", kitPath,
      "--recipient-did", FRANK_DID,
    ],
    { encoding: "utf-8", timeout: 30000 },
  );

  assertNamed({
    name: "tnjs-admin-add-recipient-exit-0",
    expected: 0,
    observed: proc.status ?? -1,
    onMiss:
      `tn-js admin add-recipient exited ${proc.status ?? "?"}. ` +
      `stderr=${JSON.stringify(proc.stderr?.slice(0, 400) ?? "")}`,
  });

  assertNamed({
    name: "tnjs-admin-add-recipient-writes-kit",
    expected: true,
    observed: existsSync(kitPath),
    on_miss:
      `Expected kit file at ${kitPath} after tn-js admin add-recipient. ` +
      "Check ts-sdk/bin/tn-js.mjs adminCmd add-recipient handler.",
  } as never);

  // Admin event landed.
  const log = new LogQuery({ ceremonyPath: yamlPath });
  const env = log.assertContains({
    name: "tnjs-admin-add-recipient-emits-event",
    where: { event_type: "tn.recipient.added", group: "default" },
    onMiss:
      "After tn-js admin add-recipient, expected a tn.recipient.added " +
      "admin event with group=default. The CLI wrote the kit but didn't " +
      "attest. Check the adminCmd path in ts-sdk/bin/tn-js.mjs and " +
      "NodeRuntime.addRecipient emit step.",
  });
  assertNamed({
    name: "tnjs-admin-add-recipient-event-has-recipient-did",
    expected: FRANK_DID,
    observed: env.get("recipient_did"),
    onMiss:
      `tn.recipient.added envelope has recipient_did=` +
      `${JSON.stringify(env.get("recipient_did"))}, expected ${FRANK_DID}.`,
  });

  void assert;
});
