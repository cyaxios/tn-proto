// In-process coverage for the `tn absorb` CLI verb (src/cli/absorb.ts),
// the TypeScript parity port of Python's `cmd_absorb`. Mirrors the
// behaviour, stdout, and exit codes of `python/tn/cli.py::cmd_absorb`,
// including the 0.4.2a9 self-absorb guard.
//
// These tests call `absorbCmd` directly (no subprocess) with injected
// stdout/stderr sinks so every branch — happy absorb, self-absorb
// refusal, --allow-self-absorb, bad package, the replaced-kit WARN
// block, and the package/yaml not-found dies — is exercised and counted
// by c8.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { absorbCmd } from "../src/cli/absorb.js";
import type { Entry } from "../src/Entry.js";

interface Sinks {
  out: string;
  err: string;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

function sinks(): Sinks {
  const s: Sinks = {
    out: "",
    err: "",
    stdout: (x: string) => {
      s.out += x;
    },
    stderr: (x: string) => {
      s.err += x;
    },
  };
  return s;
}

/** Stand up a fresh btn ceremony in its own temp dir. Returns the dir +
 *  yaml path + the device DID so tests can reason about self/cross. */
async function freshCeremony(prefix: string): Promise<{
  dir: string;
  yamlPath: string;
  did: string;
}> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  const did = tn.did;
  await tn.close();
  return { dir, yamlPath, did };
}

/** Export a kit_bundle `.tnpkg` (fromDid = exporter's DID) bound to
 *  `recipientDid`, written under the exporter's dir. */
async function exportKitBundle(
  yamlPath: string,
  outPath: string,
  recipientDid: string,
): Promise<void> {
  const tn = await Tn.init(yamlPath);
  try {
    await tn.pkg.export({ bundle: { recipientDid, groups: ["default"] } }, outPath);
  } finally {
    await tn.close();
  }
}

test("happy absorb: cross-impl kit_bundle absorbs cleanly (exit 0)", async () => {
  // Ceremony A exports a kit_bundle; Ceremony B (different DID) absorbs it.
  const a = await freshCeremony("ts-absorb-A-");
  const b = await freshCeremony("ts-absorb-B-");
  assert.notEqual(a.did, b.did, "two fresh ceremonies must have distinct DIDs");
  const pkg = join(a.dir, "bundle.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, b.did);
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      yaml: b.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `expected exit 0; stderr=${s.err}`);
    assert.match(s.out, /^\[tn absorb\] kind=kit_bundle accepted=\d+ skipped=\d+\n/);
    assert.equal(s.err, "", "no error output on the happy path");
  } finally {
    rmSync(a.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("self-absorb is refused by default (exit 2)", async () => {
  // Ceremony A absorbs a package A itself minted (from_did == A.did).
  const a = await freshCeremony("ts-absorb-self-");
  const pkg = join(a.dir, "self.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, "did:key:zSomeReader");
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      yaml: a.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 2, `self-absorb must exit 2; stdout=${s.out}`);
    assert.match(s.err, /^tn: error: refusing to absorb a package this ceremony minted/);
    assert.match(s.err, new RegExp(`from_did=${a.did.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(s.err, /--allow-self-absorb/);
    assert.equal(s.out, "", "refusal prints nothing to stdout");
  } finally {
    rmSync(a.dir, { recursive: true, force: true });
  }
});

test("--allow-self-absorb overrides the guard (exit 0)", async () => {
  const a = await freshCeremony("ts-absorb-allow-");
  const pkg = join(a.dir, "self.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, "did:key:zSomeReader");
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      yaml: a.yamlPath,
      allowSelfAbsorb: true,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `--allow-self-absorb must exit 0; stderr=${s.err}`);
    assert.match(s.out, /^\[tn absorb\] kind=kit_bundle accepted=\d+ skipped=\d+\n/);
  } finally {
    rmSync(a.dir, { recursive: true, force: true });
  }
});

test("absorbing a foreign bundle over an existing kit prints the replaced-kit WARN block", async () => {
  // Ceremony B already owns a `default.btn.mykit` (its own self-kit).
  // A kit_bundle exported from ceremony A packs A's `default.btn.mykit`,
  // whose bytes differ from B's. Absorbing it into B overwrites the
  // existing kit file, so the receipt carries replacedKitPaths and the
  // verb prints the WARN block. (Identical bytes would dedupe instead.)
  const a = await freshCeremony("ts-absorb-warnA-");
  const b = await freshCeremony("ts-absorb-warnB-");
  const pkg = join(a.dir, "bundle.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, "did:key:zSomeReader");
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      yaml: b.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `absorb stderr=${s.err}`);
    assert.match(s.out, /\[tn absorb\] WARN: overwrote \d+ existing kit file\(s\):/);
    assert.match(s.out, /\[tn absorb\] prior bytes preserved at <name>\.previous\.<UTC_TS>/);
  } finally {
    rmSync(a.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("bad package: a non-zip file yields kind=unknown accepted=0 (exit 0)", async () => {
  // The manifest peek swallows the parse error and lets absorbPkg produce
  // its own rejected receipt; the verb still prints the receipt line.
  const b = await freshCeremony("ts-absorb-bad-");
  const bad = join(b.dir, "garbage.tnpkg");
  writeFileSync(bad, "this is not a zip file at all");
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: bad,
      yaml: b.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `bad-package absorb stderr=${s.err}`);
    assert.match(s.out, /^\[tn absorb\] kind=unknown accepted=0 skipped=0\n/);
  } finally {
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("package not found dies with exit 1", async () => {
  const b = await freshCeremony("ts-absorb-nopkg-");
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: join(b.dir, "does-not-exist.tnpkg"),
      yaml: b.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^tn: error: package not found:/);
    assert.equal(s.out, "");
  } finally {
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("explicit --yaml that does not exist dies with exit 1", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-absorb-noyaml-"));
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: join(dir, "whatever.tnpkg"),
      yaml: join(dir, "missing.yaml"),
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^tn: error: yaml not found:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("yaml discovery via ./tn.yaml in cwd when --yaml and $TN_YAML are absent", async () => {
  // Exercises the cwd `./tn.yaml` discovery branch: chdir into B's dir,
  // clear $TN_YAML, omit `yaml`.
  const a = await freshCeremony("ts-absorb-cwdA-");
  const b = await freshCeremony("ts-absorb-cwdB-");
  const pkg = join(a.dir, "bundle.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, b.did);
  const prevEnv = process.env["TN_YAML"];
  delete process.env["TN_YAML"];
  const prevCwd = process.cwd();
  process.chdir(b.dir);
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `cwd-discovery absorb stderr=${s.err}`);
    assert.match(s.out, /^\[tn absorb\] kind=kit_bundle accepted=/);
  } finally {
    process.chdir(prevCwd);
    if (prevEnv !== undefined) process.env["TN_YAML"] = prevEnv;
    rmSync(a.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("yaml discovery via $TN_YAML when --yaml is omitted", async () => {
  // Exercises the no-arg discovery branch: set $TN_YAML to a real
  // ceremony, omit `yaml`, and absorb a cross-impl bundle.
  const a = await freshCeremony("ts-absorb-envA-");
  const b = await freshCeremony("ts-absorb-envB-");
  const pkg = join(a.dir, "bundle.tnpkg");
  await exportKitBundle(a.yamlPath, pkg, b.did);
  const prev = process.env["TN_YAML"];
  process.env["TN_YAML"] = b.yamlPath;
  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: pkg,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `discovery absorb stderr=${s.err}`);
    assert.match(s.out, /^\[tn absorb\] kind=kit_bundle accepted=/);
  } finally {
    if (prev === undefined) delete process.env["TN_YAML"];
    else process.env["TN_YAML"] = prev;
    rmSync(a.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Real round-trip: produce -> consume with on-disk install + decrypt read-back.
//
// The tests above stop at the receipt line. The ones below add the two
// load-bearing checks the contract (PASS #3 / #4) calls out and the original
// suite SKIPPED:
//
//   * the kit really lands as `<group>.btn.mykit` in the recipient's
//     keystore with the KIT's bytes (not the recipient's own self-kit), and
//   * after absorb the recipient can `read` + DECRYPT an entry the
//     publisher wrote — the only proof the *correct* key installed.
// ---------------------------------------------------------------------------

interface FullCeremony {
  dir: string;
  yamlPath: string;
  did: string;
  keystore: string;
  logPath: string;
}

/** Like `freshCeremony`, but also captures the keystore + main-log paths
 *  so a test can inspect the on-disk install and do a foreign-log read. */
async function freshCeremonyFull(prefix: string): Promise<FullCeremony> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  const did = tn.did;
  // NodeRuntime config carries keystorePath; reach it the same way the
  // other in-tree tests do (secure_read_tamper.test.ts), via a cast that
  // doesn't trip private-member checks if test/ is ever typechecked.
  const cfg = (tn as unknown as { _rt: { config: { keystorePath: string } } })._rt
    .config;
  const keystore = cfg.keystorePath;
  const logPath = tn.logPath;
  await tn.close();
  return { dir, yamlPath, did, keystore, logPath };
}

/** Publisher writes one `default`-group entry and exports a kit bound to
 *  `recipientDid`. Returns the kit path. */
async function writeEntryAndBundle(
  pub: FullCeremony,
  recipientDid: string,
  fields: Record<string, unknown>,
  kitName = "bundle.tnpkg",
): Promise<string> {
  const tn = await Tn.init(pub.yamlPath);
  try {
    tn.info("payday", fields);
    const kit = join(pub.dir, kitName);
    await tn.pkg.export({ bundle: { recipientDid, groups: ["default"] } }, kit);
    return kit;
  } finally {
    await tn.close();
  }
}

/** Read the publisher's log AS the recipient (foreign-log + the
 *  recipient's keystore). Returns the decoded `Entry[]`. */
async function recipientRead(rec: FullCeremony, publisherLog: string): Promise<Entry[]> {
  const tn = await Tn.init(rec.yamlPath);
  try {
    const out: Entry[] = [];
    for (const e of tn.read({ log: publisherLog, asRecipient: rec.keystore, group: "default" })) {
      out.push(e as Entry);
    }
    return out;
  } finally {
    await tn.close();
  }
}

test("round-trip: kit installs on disk AND the recipient decrypts the publisher's entry", async () => {
  // P writes an entry + mints a kit bound to B.did; B absorbs; B reads
  // back P's entry and decrypts it. (PASS #1-#4.)
  const p = await freshCeremonyFull("ts-rt-P-");
  const b = await freshCeremonyFull("ts-rt-B-");
  assert.notEqual(p.did, b.did, "two fresh ceremonies must have distinct DIDs");

  // Negative complement: before absorbing P's kit, B holds only its own
  // group key and CANNOT decrypt P's payload. event_type is public; the
  // field is hidden.
  const kit = await writeEntryAndBundle(p, b.did, { amount: 4200 });
  const pre = await recipientRead(b, p.logPath);
  assert.equal(pre.length, 1, "B should see P's one entry (envelope is public)");
  assert.equal(pre[0]!.event_type, "payday");
  assert.deepEqual(pre[0]!.fields, {}, "B must NOT decrypt P's payload pre-absorb");
  assert.deepEqual(pre[0]!.hidden_groups, ["default"], "default group should be hidden pre-absorb");

  // Snapshot B's own self-kit so we can prove the absorb replaced it.
  const bSelfKit = join(b.keystore, "default.btn.mykit");
  const bSelfBytes = readFileSync(bSelfKit);

  const s = sinks();
  try {
    const code = await absorbCmd({
      packagePath: kit,
      yaml: b.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `absorb stderr=${s.err}`);
    const m = s.out.match(/\[tn absorb\] kind=kit_bundle accepted=(\d+) skipped=(\d+)/);
    assert.ok(m, `receipt line missing: ${s.out}`);
    assert.ok(Number(m![1]) >= 1, `expected accepted>=1: ${s.out}`);

    // PASS #3: the kit landed with the KIT's bytes, not B's own self-kit.
    assert.ok(existsSync(bSelfKit), "default.btn.mykit missing after absorb");
    const installed = readFileSync(bSelfKit);
    assert.ok(!installed.equals(bSelfBytes), "absorb did not replace B's own self-kit");
    const backups = readdirSync(b.keystore).filter((f) =>
      f.startsWith("default.btn.mykit.previous."),
    );
    assert.equal(backups.length, 1, `expected one .previous backup; got ${backups}`);
    assert.ok(
      readFileSync(join(b.keystore, backups[0]!)).equals(bSelfBytes),
      "backup does not hold B's prior self-kit bytes",
    );

    // PASS #4 (load-bearing): B now decrypts P's entry.
    const post = await recipientRead(b, p.logPath);
    assert.equal(post.length, 1);
    assert.deepEqual(post[0]!.fields, { amount: 4200 }, "read-back failed: B should decrypt P's entry");
    assert.deepEqual(post[0]!.hidden_groups, [], "no hidden groups once the right kit is installed");
  } finally {
    rmSync(p.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("idempotent re-absorb: the second absorb of the same kit dedupes (accepted=0 skipped=1)", async () => {
  // PASS #6.
  const p = await freshCeremonyFull("ts-idem-P-");
  const b = await freshCeremonyFull("ts-idem-B-");
  const kit = await writeEntryAndBundle(p, b.did, { amount: 1 });
  try {
    const s1 = sinks();
    const c1 = await absorbCmd({ packagePath: kit, yaml: b.yamlPath, stdout: s1.stdout, stderr: s1.stderr });
    assert.equal(c1, 0, s1.err);
    assert.match(s1.out, /kind=kit_bundle accepted=1 skipped=0/);

    const s2 = sinks();
    const c2 = await absorbCmd({ packagePath: kit, yaml: b.yamlPath, stdout: s2.stdout, stderr: s2.stderr });
    assert.equal(c2, 0, s2.err);
    assert.match(s2.out, /kind=kit_bundle accepted=0 skipped=1/);
  } finally {
    rmSync(p.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  }
});

test("wrong-recipient unsealed btn kit still decrypts (DOCUMENTED GAP for FAIL #6)", async () => {
  // The contract's FAIL #6 ("a kit minted for a DIFFERENT recipient
  // cannot be decrypted by this one") does NOT hold for the unsealed btn
  // kit_bundle — a genuine protocol property, not a test bug. The kit zip
  // is just {manifest.json, body/default.btn.mykit}; the group read-key
  // ships in the clear and `recipient_identity` is attestation metadata
  // only. Cryptographic recipient-binding requires the sealed-box path
  // (`--seal-for-recipient` / recipient_wrap), a different originate route
  // not exercised here. Per the plan's HARD RULE we do NOT assert a
  // can't-decrypt outcome we know is false; instead we pin the two things
  // that ARE true so the gap is explicit and a future sealing-by-default
  // flip trips this test:
  //
  //   1. A ceremony that absorbed NO kit for P's group cannot decrypt
  //      (the negative that genuinely holds).
  //   2. A kit minted for THIRD, absorbed by W, currently DOES decrypt
  //      P's entry (documents the unsealed reality).
  const p = await freshCeremonyFull("ts-wrong-P-");
  const third = await freshCeremonyFull("ts-wrong-T-");
  const w = await freshCeremonyFull("ts-wrong-W-");
  const kit = await writeEntryAndBundle(p, third.did, { amount: 4200 });
  try {
    // (1) W has no P-kit yet: cannot decrypt.
    const pre = await recipientRead(w, p.logPath);
    assert.equal(pre.length, 1);
    assert.deepEqual(pre[0]!.fields, {}, "fresh ceremony must not decrypt P's payload");

    // (2) W absorbs a kit addressed to THIRD, and (gap) decrypts anyway.
    const s = sinks();
    const code = await absorbCmd({ packagePath: kit, yaml: w.yamlPath, stdout: s.stdout, stderr: s.stderr });
    assert.equal(code, 0, s.err);
    const post = await recipientRead(w, p.logPath);
    assert.deepEqual(
      post[0]!.fields,
      { amount: 4200 },
      "DOCUMENTED GAP changed: an unsealed btn kit minted for a DIFFERENT recipient " +
        "no longer decrypts. FAIL #6 may now be enforceable — revisit " +
        "the absorb contract and add the real can't-decrypt assertion.",
    );
  } finally {
    rmSync(p.dir, { recursive: true, force: true });
    rmSync(third.dir, { recursive: true, force: true });
    rmSync(w.dir, { recursive: true, force: true });
  }
});
