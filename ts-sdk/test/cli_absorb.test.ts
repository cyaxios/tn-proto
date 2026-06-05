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
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { absorbCmd } from "../src/cli/absorb.js";

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
