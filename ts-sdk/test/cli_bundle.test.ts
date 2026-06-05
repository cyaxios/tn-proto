// Tests for the `tn bundle` CLI verb (src/cli/bundle.ts).
//
// Mirrors python/tn/cli.py::cmd_bundle. Exercises every branch of
// `bundleCmd`: happy path, --groups, --yaml (valid + missing),
// $TN_YAML discovery, no-yaml discovery failure, --seal-for-recipient
// guard, and an error thrown inside the bundle try/finally.
//
// Run with coverage:
//   npx c8 --include='src/cli/bundle.ts' --reporter=text \
//     node --import tsx --import ./test/_setup_wasm.mjs \
//     --test test/cli_bundle.test.ts

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { DeviceKey, NodeRuntime, readTnpkg } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";
import { bundleCmd } from "../src/cli/bundle.js";

const RECIPIENT = "did:key:zRecipientReaderBundleTest";

// ---- ceremony fixture -------------------------------------------------

function makeCeremony(): { dir: string; yamlPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-bundle-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 13 + 17) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 7) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 5 + 23) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const kit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(kit));

  const yaml = `ceremony:\n  id: cli_bundle_test\n  mode: local\n  cipher: btn\nlogs:\n  path: ./.tn/logs/tn.ndjson\nkeystore:\n  path: ./.tn/keys\ndevice:\n  device_identity: ${dk.did}\npublic_fields:\n- timestamp\n- event_id\n- event_type\n- level\n- group\n- leaf_index\n- recipient_identity\n- kit_sha256\n- cipher\ndefault_policy: private\ngroups:\n  default:\n    policy: private\n    cipher: btn\n    recipients:\n    - recipient_identity: ${dk.did}\nfields: {}\n`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return { dir, yamlPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---- stdout / stderr capture -----------------------------------------

function captureConsole(): {
  out: string[];
  err: string[];
  restore: () => void;
} {
  const out: string[] = [];
  const err: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a: unknown[]) => out.push(a.join(" "));
  console.error = (...a: unknown[]) => err.push(a.join(" "));
  return {
    out,
    err,
    restore: () => {
      console.log = origLog;
      console.error = origErr;
    },
  };
}

// Track env we mutate so each test restores it.
const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

// ---- tests ------------------------------------------------------------

test("happy path: explicit yaml, no groups -> kit_bundle for recipient", async () => {
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const out = join(dir, "reader.tnpkg");
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({ recipientIdentity: RECIPIENT, out, yaml: yamlPath });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 0);
  // stdout: four [tn bundle] lines.
  assert.equal(cap.out.length, 4);
  assert.match(cap.out[0]!, /^\[tn bundle\] wrote /);
  assert.match(cap.out[1]!, new RegExp(`recipient: ${RECIPIENT}$`));
  assert.match(cap.out[2]!, /ceremony:\s+cli_bundle_test\s+\(cipher=btn\)/);
  assert.match(cap.out[3]!, /groups:\s+\["default"\]/);

  // Behavior assertion: the produced .tnpkg has kit_bundle kind + recipient.
  const { manifest } = readTnpkg(out);
  assert.equal(manifest.kind, "kit_bundle");
  assert.equal(manifest.toDid, RECIPIENT);
});

test("--groups branch: explicit comma list is honored", async () => {
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const out = join(dir, "reader-groups.tnpkg");
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out,
      yaml: yamlPath,
      groups: "default",
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 0);
  // groups summary line reflects the explicit list (not the discovered set).
  assert.match(cap.out[3]!, /groups:\s+\["default"\]/);
  const { manifest } = readTnpkg(out);
  assert.equal(manifest.kind, "kit_bundle");
});

test("$TN_YAML discovery when --yaml omitted", async () => {
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const prev = process.env.TN_YAML;
  process.env.TN_YAML = yamlPath;
  cleanups.push(() => {
    if (prev === undefined) delete process.env.TN_YAML;
    else process.env.TN_YAML = prev;
  });
  const out = join(dir, "reader-env.tnpkg");
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({ recipientIdentity: RECIPIENT, out });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 0);
  const { manifest } = readTnpkg(out);
  assert.equal(manifest.kind, "kit_bundle");
});

test("./tn.yaml cwd discovery when --yaml and $TN_YAML absent", async () => {
  const { dir, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const prevTnYaml = process.env.TN_YAML;
  delete process.env.TN_YAML;
  const origCwd = process.cwd();
  process.chdir(dir); // ./tn.yaml now resolves here
  cleanups.push(() => {
    process.chdir(origCwd);
    if (prevTnYaml !== undefined) process.env.TN_YAML = prevTnYaml;
  });
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(dir, "cwd-reader.tnpkg"),
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 0);
  const { manifest } = readTnpkg(join(dir, "cwd-reader.tnpkg"));
  assert.equal(manifest.kind, "kit_bundle");
});

test("--yaml points at a missing path -> exit 1", async () => {
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(tmpdir(), "never.tnpkg"),
      yaml: join(tmpdir(), "does-not-exist-xyz.yaml"),
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /yaml not found:/.test(l)));
});

/** Redirect `os.homedir()` (and `$TN_YAML`, cwd) to empty temp dirs so
 * discovery is deterministic regardless of the host machine's real
 * ~/.tn/tn.yaml. Returns the fake home dir. */
function isolateDiscoveryEnv(): { fakeHome: string } {
  const prevTnYaml = process.env.TN_YAML;
  delete process.env.TN_YAML;
  const prevHome = process.env.HOME;
  const prevUserProfile = process.env.USERPROFILE;
  const fakeHome = mkdtempSync(join(tmpdir(), "tn-cli-bundle-home-"));
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
  const emptyDir = mkdtempSync(join(tmpdir(), "tn-cli-bundle-cwd-"));
  const origCwd = process.cwd();
  process.chdir(emptyDir);
  cleanups.push(() => {
    process.chdir(origCwd);
    if (prevTnYaml !== undefined) process.env.TN_YAML = prevTnYaml;
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = prevUserProfile;
    rmSync(emptyDir, { recursive: true, force: true });
    rmSync(fakeHome, { recursive: true, force: true });
  });
  // Sanity: homedir() now points at our fake home.
  assert.equal(homedir(), fakeHome);
  return { fakeHome };
}

test("no yaml anywhere -> discovery failure exit 1", async () => {
  const { fakeHome } = isolateDiscoveryEnv();
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(fakeHome, "x.tnpkg"),
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /no yaml found\./.test(l)));
});

test("~/.tn/tn.yaml discovery branch (home fallback)", async () => {
  // Build a real ceremony, then move its yaml under the fake home's
  // ~/.tn/tn.yaml so the home-fallback discovery branch resolves it.
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const { fakeHome } = isolateDiscoveryEnv();
  const homeTn = join(fakeHome, ".tn");
  mkdirSync(homeTn, { recursive: true });
  // The ceremony's keystore/log paths are relative to the yaml dir, so
  // run with cwd at the ceremony dir but yaml resolved via the home copy.
  // Copy the yaml verbatim; relative paths resolve against the loader's
  // yamlDir (the home dir), so instead point home yaml content at the
  // original dir via an absolute keystore/log path is overkill — simpler:
  // copy the whole ceremony into the fake home.
  const homeKeys = join(homeTn, ".tn/keys");
  const homeLogs = join(homeTn, ".tn/logs");
  mkdirSync(homeKeys, { recursive: true });
  mkdirSync(homeLogs, { recursive: true });
  for (const f of [
    "local.private",
    "local.public",
    "index_master.key",
    "default.btn.state",
    "default.btn.mykit",
  ]) {
    writeFileSync(
      join(homeKeys, f),
      Buffer.from(readFileSync(join(dir, ".tn/keys", f))),
    );
  }
  writeFileSync(
    join(homeTn, "tn.yaml"),
    readFileSync(yamlPath).toString("utf8"),
    "utf8",
  );
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(fakeHome, "home-reader.tnpkg"),
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 0);
  const { manifest } = readTnpkg(join(fakeHome, "home-reader.tnpkg"));
  assert.equal(manifest.kind, "kit_bundle");
});

test("--seal-for-recipient (real did:key) is rejected (TS runtime gap) -> exit 1, nothing written", async () => {
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const out = join(dir, "sealed.tnpkg");
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT, // a real did:key:z... shape
      out,
      yaml: yamlPath,
      sealForRecipient: true,
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /seal-for-recipient is not supported/.test(l)));
  // Safety: refusal must not write a (would-be unsealed) bundle to disk, and
  // must not print a success "wrote" line.
  assert.ok(!existsSync(out), "no .tnpkg should be written on seal refusal");
  assert.ok(!cap.out.some((l) => /wrote/.test(l)), "no success line on refusal");
});

test("runtime init failure (malformed yaml) -> exit 1", async () => {
  // A yaml that exists but loadConfig cannot parse into a valid ceremony,
  // so NodeRuntime.init throws before the bundle try-block. Mirrors
  // Python letting tn_init's failure propagate to a non-zero exit.
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-bundle-bad-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const badYaml = join(dir, "tn.yaml");
  writeFileSync(badYaml, "ceremony:\n  mode: local\n", "utf8"); // no id, no device
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(dir, "x.tnpkg"),
      yaml: badYaml,
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /^\[tn bundle\] /.test(l)));
});

test("init throws a non-Error value -> String(e) arm, exit 1", async () => {
  // Cover the `e instanceof Error ? ... : String(e)` false arm in the
  // init catch block by making NodeRuntime.init throw a bare string.
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const origInit = NodeRuntime.init;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (NodeRuntime as any).init = () => {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal
    throw "boom-not-an-error";
  };
  cleanups.push(() => {
    NodeRuntime.init = origInit;
  });
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(dir, "x.tnpkg"),
      yaml: yamlPath,
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /boom-not-an-error/.test(l)));
});

test("bundle throws a non-Error value -> String(e) arm, exit 1", async () => {
  // Cover the false arm of the ternary in the bundle try/catch by making
  // bundleForRecipient throw a bare string. The finally must still close
  // the runtime (no leak).
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const proto = NodeRuntime.prototype as unknown as {
    bundleForRecipient: unknown;
  };
  const origBundle = proto.bundleForRecipient;
  proto.bundleForRecipient = () => {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal
    throw "bundle-boom-not-an-error";
  };
  cleanups.push(() => {
    proto.bundleForRecipient = origBundle;
  });
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(dir, "x.tnpkg"),
      yaml: yamlPath,
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /bundle-boom-not-an-error/.test(l)));
});

test("error inside bundle (unknown group) -> exit 1, runtime closed", async () => {
  const { dir, yamlPath, cleanup } = makeCeremony();
  cleanups.push(cleanup);
  const cap = captureConsole();
  let rc: number;
  try {
    rc = await bundleCmd({
      recipientIdentity: RECIPIENT,
      out: join(dir, "bad.tnpkg"),
      yaml: yamlPath,
      groups: "nope_not_a_group",
    });
  } finally {
    cap.restore();
  }
  assert.equal(rc, 1);
  assert.ok(cap.err.some((l) => /unknown groups/.test(l)));
});
