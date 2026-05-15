/**
 * SILO: C5 — Local groups + recipients in-process
 * TEST: TS publisher Alice mints kit + writes events; Python recipient Frank
 *       decrypts them.
 *
 * The reverse direction of `ts_cross_language_python_publisher.test.ts`.
 * Proves the wire format is symmetric: TS-encrypted envelopes must
 * decrypt under Python's cipher path, not just TS's own.
 *
 * Why both directions matter: a TS service that writes logs which a
 * Python operator audits with `tn.read` is the OTHER common shape (a
 * browser-side client whose receipts get audited server-side). If only
 * one direction works, the protocol is half-finished.
 *
 * Flow:
 *   1. TS Alice: chdir tmpdir, Tn.use("default"), addRecipient(FRANK),
 *      bundleForRecipient → frank.tnpkg, info() ×2, close.
 *   2. Spawn Python child for Frank:
 *        - hermetic dirs, chdir Frank's tmpdir
 *        - tn.init()  (fresh ceremony)
 *        - tn.pkg.absorb(frank.tnpkg)
 *        - tn.flush_and_close()
 *        - iterate tn.read(log=alice_log, as_recipient=frank_keystore,
 *            group="default"); print decoded count + amounts as JSON.
 *   3. Assert Python decrypted 2 events with amounts 1000 + 250.
 *
 * Asserts (named):
 *   - "ts-alice-bundled-kit"
 *   - "python-frank-decrypted-ts-events"
 *   - "python-frank-fields-round-tripped-from-ts"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const FRANK_DID = "did:key:zFrank0123456789abcdefghjkmnpqrstuvwx";

function pythonAbsorbAndRead(args: {
  frankDir: string;
  aliceLog: string;
  frankTnpkg: string;
}): {
  decrypted_count: number;
  amounts: number[];
} {
  const py = String.raw`
import json, os
os.environ['TN_IDENTITY_DIR'] = r'${args.frankDir.replace(/\\/g, "\\\\")}_id'
os.environ['TN_NO_LINK'] = '1'
os.chdir(r'${args.frankDir.replace(/\\/g, "\\\\")}')

import tn
tn.init()  # Frank's own ceremony
receipt = tn.pkg.absorb(r'${args.frankTnpkg.replace(/\\/g, "\\\\")}')
frank_keystore = tn.current_config().keystore
tn.flush_and_close()

amounts = []
for entry in tn.read(
    log=r'${args.aliceLog.replace(/\\/g, "\\\\")}',
    as_recipient=frank_keystore,
    group="default",
):
    if entry.event_type == "c5.ts.crosslang.payment" and "default" not in entry.hidden_groups:
        a = entry.fields.get("amount")
        if isinstance(a, int):
            amounts.append(a)

print(json.dumps({
    "decrypted_count": len(amounts),
    "amounts": amounts,
}))
`;
  const pythonBin =
    process.env["TN_REGRESSION_PYTHON"] ??
    "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";
  const proc = spawnSync(pythonBin, ["-c", py], {
    encoding: "utf-8",
    timeout: 30000,
  });
  if (proc.status !== 0) {
    throw new Error(
      `pythonAbsorbAndRead: python exit ${proc.status}, ` +
        `stderr=${proc.stderr?.slice(0, 600)}`,
    );
  }
  const last = proc.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(last) as { decrypted_count: number; amounts: number[] };
}

test("C5 (cross-lang): TS publisher, Python Frank decrypts", async () => {
  setTestContext({
    silo: "c5",
    test: "c5_ts_cross_language_ts_publisher::ts_to_py",
  });

  const aliceDir = mkdtempSync(join(tmpdir(), "c5-ts-alice-"));
  const frankDir = mkdtempSync(join(tmpdir(), "c5-py-frank-"));
  const cwdBefore = process.cwd();

  // ── TS Alice publishes ─────────────────────────────────────────
  process.chdir(aliceDir);
  const alice = await Tn.use("default");
  const aliceLog = alice.logPath;

  const aliceBundleDir = join(aliceDir, "alice_bundles");
  mkdirSync(aliceBundleDir, { recursive: true });
  const frankTnpkg = join(aliceBundleDir, "frank.tnpkg");

  await alice.admin.addRecipient("default", { recipientDid: FRANK_DID });
  await alice.pkg.bundleForRecipient({
    recipientDid: FRANK_DID,
    outPath: frankTnpkg,
    groups: ["default"],
  });

  assertNamed({
    name: "ts-alice-bundled-kit",
    expected: true,
    observed: existsSync(frankTnpkg),
    onMiss: `Alice's bundleForRecipient didn't produce ${frankTnpkg}.`,
  });

  alice.info("c5.ts.crosslang.payment", { amount: 1000, currency: "USD" });
  alice.info("c5.ts.crosslang.payment", { amount: 250, currency: "USD" });
  await alice.close();

  // chdir back so the python child gets its own clean cwd parameter.
  process.chdir(cwdBefore);

  // ── Python Frank decrypts ──────────────────────────────────────
  const result = pythonAbsorbAndRead({
    frankDir,
    aliceLog,
    frankTnpkg,
  });

  assertNamed({
    name: "python-frank-decrypted-ts-events",
    expected: 2,
    observed: result.decrypted_count,
    onMiss:
      `Python Frank decrypted ${result.decrypted_count} TS-written ` +
      "events; expected 2. If 0, the Python BTN cipher can't unwrap " +
      "TS-encrypted envelopes — that's the reverse-direction " +
      "cross-language gap. Check python/tn/cipher.py:BtnGroupCipher.",
  });

  assertNamed({
    name: "python-frank-fields-round-tripped-from-ts",
    expected: true,
    observed:
      result.amounts.includes(1000) && result.amounts.includes(250),
    onMiss:
      `Python decoded amounts=${JSON.stringify(result.amounts)}; ` +
      "expected to contain 1000 and 250.",
  });

  void assert;
});
