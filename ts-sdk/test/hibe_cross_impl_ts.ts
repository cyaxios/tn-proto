// TS half of the hibe cross-impl proof (see hibe_cross_impl.sh).
//
//  1. Absorb the kit the PYTHON authority granted, then read/verify the
//     python-written hibe log through readAsRecipient (plaintext + per-row
//     signature + chain).
//  2. Mint a TS hibe authority, seal two entries, and grant a kit for the
//     python side to absorb (verified by hibe_cross_impl_py.py --verify).
//
// Run from ts-sdk/ with `node --import tsx`. argv[2] = the shared
// workspace directory owned by the shell driver.

import { strict as assert } from "node:assert";
import { copyFileSync } from "node:fs";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { readAsRecipient } from "../src/read_as_recipient.js";

const ws = process.argv[2];
if (!ws) throw new Error("usage: hibe_cross_impl_ts.ts <workspace-dir>");

// --- 1. TS reader absorbs the python-granted kit and reads the python log.
const pyLog = join(ws, "py_auth", "log.ndjson");
const kitFromPy = join(ws, "py_to_ts.tnpkg");

const reader = await Tn.init(join(ws, "ts_reader", "tn.yaml"), { stdout: false, link: false });
const readerKeystore = (reader.config() as { keystorePath: string }).keystorePath;
const receipt = await reader.pkg.absorb(kitFromPy);
assert.equal(receipt.rejectedReason, undefined, `absorb rejected: ${receipt.rejectedReason}`);
assert.ok(receipt.acceptedCount >= 3, `expected hibe mpk+idpath+sk installed, got ${receipt.acceptedCount}`);
await reader.close();

const got: Record<string, Record<string, unknown>> = {};
for (const e of readAsRecipient(pyLog, readerKeystore, { group: "default" })) {
  const et = String(e.envelope["event_type"]);
  got[et] = e.plaintext["default"] ?? {};
  assert.ok(e.valid.signature, `bad signature on python entry ${et}`);
  assert.ok(e.valid.chain, `broken chain on python entry ${et}`);
}
assert.equal(got["py.first"]!["note"], "python sealed 1", JSON.stringify(got));
assert.equal(got["py.second"]!["note"], "python sealed 2", JSON.stringify(got));
console.log("ts: opened both python-sealed hibe entries; sig+chain ok");

// --- 2. TS hibe authority seals a log and grants a kit for python.
const auth = await Tn.init(join(ws, "ts_auth", "tn.yaml"), {
  cipher: "hibe",
  stdout: false,
  link: false,
});
assert.equal((auth.config() as { cipher: string }).cipher, "hibe");
auth.info("ts.first", { note: "typescript sealed 1" });
auth.info("ts.second", { note: "typescript sealed 2" });
await auth.admin.grantReader("default", {
  readerDid: "did:key:z6Mk-py-reader",
  outPath: join(ws, "ts_to_py.tnpkg"),
  // Synthetic cross-impl DID with no embedded key: the python side absorbs a
  // plaintext kit, so plaintext delivery is requested explicitly.
  unsafePlaintext: true,
});
const tsLog = (auth.config() as { logPath: string }).logPath;
await auth.close();
// Surface the TS log at a fixed name so the python verifier needn't know
// the ceremony's stem-derived layout.
copyFileSync(tsLog, join(ws, "ts_auth_log.ndjson"));
console.log("ts: sealed 2 hibe entries and granted ts_to_py.tnpkg");
