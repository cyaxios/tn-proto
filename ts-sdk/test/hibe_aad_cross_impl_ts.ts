// TS half of the hibe AAD cross-impl proof (see hibe_aad_cross_impl.sh).
//
//  1. Absorb the kit the PYTHON authority granted, reconstruct the aad from
//     the python-written record's public tn_aad, open the body, verify
//     signature + chain. Prove a tampered tn_aad fails to decrypt.
//  2. Mint a TS hibe authority, seal an entry bound to an aad dict, and grant
//     a kit for the python side to absorb (verified by --verify).
//
// Run from ts-sdk/ with `node --import tsx`. argv[2] = shared workspace dir.

import { strict as assert } from "node:assert";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { readAsRecipient } from "../src/read_as_recipient.js";

const ws = process.argv[2];
if (!ws) throw new Error("usage: hibe_aad_cross_impl_ts.ts <workspace-dir>");

// --- 1. TS reader absorbs the python-granted kit and opens the aad-bound log.
const pyLog = join(ws, "py_auth", "log.ndjson");
const kitFromPy = join(ws, "py_to_ts.tnpkg");

const reader = await Tn.init(join(ws, "ts_reader", "tn.yaml"), { stdout: false, link: false });
const readerKeystore = (reader.config() as { keystorePath: string }).keystorePath;
const receipt = await reader.pkg.absorb(kitFromPy);
assert.equal(receipt.rejectedReason, undefined, `absorb rejected: ${receipt.rejectedReason}`);
await reader.close();

const got: Record<string, Record<string, unknown>> = {};
for (const e of readAsRecipient(pyLog, readerKeystore, { group: "default" })) {
  const et = String(e.envelope["event_type"]);
  got[et] = e.plaintext["default"] ?? {};
  assert.ok(e.valid.signature, `bad signature on python entry ${et}`);
  assert.ok(e.valid.chain, `broken chain on python entry ${et}`);
  assert.deepEqual(
    JSON.parse(e.envelope["tn_aad"] as string),
    { default: { policy: "finra-oba", v: "1" } },
    `unexpected tn_aad on ${et}: ${JSON.stringify(e.envelope["tn_aad"])}`,
  );
}
assert.equal(got["py.aad"]!["note"], "python sealed with aad", JSON.stringify(got));
console.log("ts: reconstructed python aad, opened body; sig+chain ok");

// Tamper the python record's tn_aad on disk -> TS must fail to decrypt.
const pyLines = readFileSync(pyLog, "utf8").split(/\r?\n/).filter((l) => l.length > 0);
const pyTampered = pyLines.map((line) => {
  const obj = JSON.parse(line) as Record<string, unknown>;
  if (obj["event_type"] === "py.aad")
    obj["tn_aad"] = (obj["tn_aad"] as string).replace("finra-oba", "tampered");
  return JSON.stringify(obj);
});
writeFileSync(pyLog, pyTampered.join("\n") + "\n", "utf8");
for (const e of readAsRecipient(pyLog, readerKeystore, { group: "default" })) {
  if (String(e.envelope["event_type"]) === "py.aad") {
    const pt = e.plaintext["default"] ?? {};
    assert.notEqual(pt["note"], "python sealed with aad", "tamper leaked plaintext");
    assert.ok("$decrypt_error" in pt || "$no_read_key" in pt, JSON.stringify(pt));
  }
}
console.log("ts: tampered python tn_aad did NOT decrypt (marker, not plaintext)");

// --- 2. TS hibe authority seals an aad-bound entry and grants a kit.
const auth = await Tn.init(join(ws, "ts_auth", "tn.yaml"), {
  cipher: "hibe",
  stdout: false,
  link: false,
});
assert.equal((auth.config() as { cipher: string }).cipher, "hibe");
auth.info("ts.aad", { note: "typescript sealed with aad" }, { aad: { policy: "sox-404", v: "2" } });
await auth.admin.grantReader("default", {
  readerDid: "did:key:z6Mk-py-reader",
  outPath: join(ws, "ts_to_py.tnpkg"),
  // Synthetic cross-impl DID with no embedded key: the python side absorbs a
  // plaintext kit, so plaintext delivery is requested explicitly.
  unsafePlaintext: true,
});
const tsLog = (auth.config() as { logPath: string }).logPath;
await auth.close();
copyFileSync(tsLog, join(ws, "ts_auth_log.ndjson"));
console.log("ts: sealed aad-bound entry and granted ts_to_py.tnpkg");
