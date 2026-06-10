// Cross-impl ROUND-TRIP test for the contact_update kind (GAP 1).
//
// TS produce contact_update -> Python absorb: the contact lands in the
//   ceremony's contacts.yaml (Python's reducer), and Python reports it.
// Python produce contact_update -> TS absorb: the contact lands in the
//   SAME contacts.yaml via the TS reducer, and TS reads it back.
//
// Both reducers project to the canonical six-field row and key idempotency
// on (account_id, package_did). Using ONE shared ceremony yaml for both
// directions also exercises that the two reducers agree on the contacts.yaml
// location (`<yamlDir>/.tn/<stem>/contacts.yaml`) and the row schema.
//
// Skip policy mirrors admin_state_interop.test.ts: console.warn + return
// WITHOUT asserting when no Python `import tn` is available; assert (and
// fail loudly) when a usable interpreter is present.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";

import { DeviceKey } from "../src/index.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";
import type { ContactUpdateBody } from "../src/runtime/node_runtime.js";
import { BtnPublisher } from "../src/raw.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "..");
const pyHelper = join(here, "contact_update_py_helper.py");

function resolvePython(): string {
  const fromEnv = process.env.TN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    resolve(repoRoot, ".venv_win/Scripts/python.exe"),
    resolve(repoRoot, ".venv/Scripts/python.exe"),
    resolve(repoRoot, ".venv/bin/python"),
    resolve(repoRoot, ".venv_linux/bin/python"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return "python";
}

function probePython(): string | null {
  const py = resolvePython();
  const res = spawnSync(py, ["-c", "import tn"], { encoding: "utf8" });
  if (res.error === undefined && res.status === 0) return py;
  return null;
}

interface Ceremony {
  yamlPath: string;
  contactsPath: string;
  cleanup: () => void;
}

// Deterministic single-file btn ceremony on disk. contacts.yaml lands at
// `<dir>/.tn/tn/contacts.yaml` (per-stem layout; stem of `tn.yaml` is `tn`).
function makeCeremony(): Ceremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-contact-update-interop-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 19 + 13) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 11 + 4) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 7 + 23) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));
  pub.free();

  const yaml = `ceremony:
  id: contact_update_interop
  mode: local
  cipher: btn
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
device:
  device_identity: ${dk.did}
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
fields: {}
`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    contactsPath: join(dir, ".tn", "tn", "contacts.yaml"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

interface ContactsDoc {
  contacts?: Array<Record<string, unknown>>;
}

function readContacts(path: string): Array<Record<string, unknown>> {
  if (!existsSync(path)) return [];
  const doc = parseYaml(readFileSync(path, "utf8")) as ContactsDoc | null;
  if (doc && Array.isArray(doc.contacts)) return doc.contacts;
  return [];
}

function pyRun(py: string, args: string[]): unknown {
  const res = spawnSync(py, [pyHelper, ...args], { encoding: "utf8" });
  if (res.error) throw res.error;
  assert.equal(
    res.status,
    0,
    `python helper exited ${res.status}\nargs: ${JSON.stringify(args)}\n` +
      `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
  );
  try {
    return JSON.parse(res.stdout);
  } catch (e) {
    throw new Error(
      `python helper did not emit valid JSON: ${(e as Error).message}\n` +
        `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
      { cause: e },
    );
  }
}

test("contact_update.interop.round_trip", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] contact_update interop: no Python interpreter with `import tn` " +
        "found. Skipping WITHOUT asserting — Python-less env.",
    );
    return;
  }
  console.warn(`[info] contact_update interop: probe OK; using ${py}`);

  const c = makeCeremony();
  const outDir = mkdtempSync(join(tmpdir(), "tn-contact-update-out-"));
  const rt = NodeRuntime.init(c.yamlPath);
  try {
    // ── Direction 1: TS produces, Python absorbs.
    const tsContact: ContactUpdateBody = {
      account_id: "acct_ts_001",
      label: "Acme Corp (via TS)",
      package_did: "did:key:zPackageFromTs0000000000000000000000000001",
      x25519_pub_b64: "QUJDREVGdHNfeDI1NTE5X3B1Yg==",
      claimed_at: "2026-06-03T12:00:00.000+00:00",
      source_link_id: "link_ts_42",
    };
    const tsTnpkg = join(outDir, "ts_contact.tnpkg");
    rt.exportPkg({ kind: "contact_update", contactUpdate: tsContact }, tsTnpkg);
    assert.ok(existsSync(tsTnpkg), "TS should have written the contact_update tnpkg");

    const pyAbsorb = pyRun(py, ["absorb", tsTnpkg, c.yamlPath]) as {
      kind: string | null;
      status: string | null;
      reason: string | null;
      accepted_count: number | null;
      contacts: Array<Record<string, unknown>>;
    };
    // Two-arg Python absorb returns an AbsorbResult; a successful
    // contact_update reduce maps to status "enrolment_applied" (the
    // reducer's legacy_status). Not "rejected" is the load-bearing check.
    assert.notEqual(pyAbsorb.status, "rejected", `Python rejected the TS bundle: ${pyAbsorb.reason}`);
    assert.equal(
      pyAbsorb.status,
      "enrolment_applied",
      `expected contact_update absorb status enrolment_applied: ${JSON.stringify(pyAbsorb)}`,
    );

    const pyRow = pyAbsorb.contacts.find((r) => r["account_id"] === tsContact.account_id);
    assert.ok(pyRow, `Python contacts.yaml should hold the TS contact: ${JSON.stringify(pyAbsorb.contacts)}`);
    assert.equal(pyRow["label"], tsContact.label, "Python should reflect the TS label");
    assert.equal(pyRow["package_did"], tsContact.package_did, "Python should reflect the TS package_did");
    assert.equal(pyRow["x25519_pub_b64"], tsContact.x25519_pub_b64, "Python should reflect x25519_pub_b64");
    assert.equal(pyRow["claimed_at"], tsContact.claimed_at, "Python should reflect claimed_at");
    assert.equal(pyRow["source_link_id"], tsContact.source_link_id, "Python should reflect source_link_id");
    console.warn(`[info] contact_update ts->py OK; Python reflected ${String(pyRow["account_id"])}`);

    // ── Direction 2: Python produces, TS absorbs.
    const pyContact = {
      account_id: "acct_py_002",
      label: "Globex (via Python)",
      package_did: null, // OAuth-only account, no package yet — exercise null nullable.
      x25519_pub_b64: null,
      claimed_at: "2026-06-03T13:30:00.000+00:00",
      source_link_id: "link_py_77",
    };
    const pyTnpkg = join(outDir, "py_contact.tnpkg");
    const pyProduce = pyRun(py, ["produce", pyTnpkg, c.yamlPath, JSON.stringify(pyContact)]) as {
      ok: boolean;
      publisher_identity: string;
    };
    assert.equal(pyProduce.ok, true, "Python produce should succeed");
    assert.ok(existsSync(pyTnpkg), "Python should have written the contact_update tnpkg");

    const receipt = rt.absorbPkg(pyTnpkg);
    assert.equal(receipt.kind, "contact_update", `unexpected kind: ${JSON.stringify(receipt)}`);
    assert.equal(
      receipt.rejectedReason,
      undefined,
      `TS rejected the Python bundle: ${receipt.rejectedReason}`,
    );
    assert.equal(receipt.acceptedCount, 1, `expected acceptedCount=1: ${JSON.stringify(receipt)}`);

    const tsContacts = readContacts(c.contactsPath);
    const tsRow = tsContacts.find((r) => r["account_id"] === pyContact.account_id);
    assert.ok(tsRow, `TS contacts.yaml should hold the Python contact: ${JSON.stringify(tsContacts)}`);
    assert.equal(tsRow["label"], pyContact.label, "TS should reflect the Python label");
    assert.equal(tsRow["package_did"], null, "TS should preserve the null package_did");
    assert.equal(tsRow["x25519_pub_b64"], null, "TS should preserve the null x25519_pub_b64");
    assert.equal(tsRow["claimed_at"], pyContact.claimed_at, "TS should reflect claimed_at");
    assert.equal(tsRow["source_link_id"], pyContact.source_link_id, "TS should reflect source_link_id");

    // Both directions wrote to the SAME contacts.yaml, so both rows coexist.
    assert.ok(
      tsContacts.some((r) => r["account_id"] === tsContact.account_id),
      "the TS-direction row must still be present after the Python-direction absorb",
    );
    assert.equal(tsContacts.length, 2, `expected 2 distinct contacts, got ${tsContacts.length}`);
    console.warn(`[info] contact_update py->ts OK; TS reflected ${String(tsRow["account_id"])}`);
  } finally {
    await rt.close();
    c.cleanup();
    rmSync(outDir, { recursive: true, force: true });
  }
});
