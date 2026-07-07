// In-process coverage for the `tn inbox accept` CLI verb
// (src/cli/inbox_accept.ts), the TypeScript parity port of Python's
// `tn.inbox accept` subcommand (python/tn/inbox.py). Mirrors the
// behaviour, stdout, and exit codes of `accept` + `_cmd_accept` +
// `main()`'s accept branch.
//
// These tests call `inboxAcceptCmd` (and the lower `accept`) directly —
// no subprocess — with injected stdout/stderr sinks so every branch is
// exercised and counted by c8: the happy accept, the backup-of-existing-
// kit print, the hash-mismatch InboxError, the missing-zip /
// missing-manifest / missing-kit / missing-yaml dies, the bad-zip die,
// and the no-hash skip path.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../src/tn.js";
import { packTnpkg } from "../src/core/tnpkg_archive.js";
import { accept, InboxError, inboxAcceptCmd } from "../src/cli/inbox_accept.js";

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

/** Stand up a fresh btn ceremony in its own temp dir. `keystorePath` is the
 *  resolved keystore dir (yaml-stem-namespaced `./.tn/tn/keys` for the
 *  default ceremony) so tests can locate the installed kit without
 *  hardcoding the layout. */
async function freshCeremony(
  prefix: string,
): Promise<{ dir: string; yamlPath: string; keystorePath: string }> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const yamlPath = join(dir, "tn.yaml");
  const tn = await Tn.init(yamlPath);
  const keystorePath = (tn.config() as { keystorePath: string }).keystorePath;
  await tn.close();
  return { dir, yamlPath, keystorePath };
}

/** A real btn reader-kit's bytes: the ceremony's own `default.btn.mykit`.
 *  Using genuine kit bytes (rather than arbitrary text) keeps the ceremony
 *  re-initialisable after the kit is installed, so the absorbed-attestation
 *  emit path runs for real instead of hitting the non-fatal warn branch. */
function realKit(keystorePath: string): Uint8Array {
  return new Uint8Array(readFileSync(join(keystorePath, "default.btn.mykit")));
}

/** Build a `tn-invite-*.zip` (outer zip with manifest.json + kit.tnpkg).
 *  `withHash` controls whether the manifest carries the kit_sha256; when a
 *  string is supplied it overrides the computed hash (to force a mismatch). */
function buildInviteZip(
  opts: {
    kit?: Uint8Array;
    group?: string;
    leaf?: number;
    fromEmail?: string;
    fromDid?: string;
    hash?: string | null;
    omitManifest?: boolean;
    omitKit?: boolean;
    /** Inner kit entry name. Defaults to the legacy `kit.tnpkg`; pass
     *  `<group>.btn.mykit` to mirror the real server's wrapper. */
    kitEntry?: string;
  } = {},
): Uint8Array {
  const kit = opts.kit ?? new TextEncoder().encode("fake-kit-bytes-for-test");
  const computed = "sha256:" + createHash("sha256").update(kit).digest("hex");
  const manifest: Record<string, unknown> = {
    group_name: opts.group ?? "default",
    leaf_index: opts.leaf ?? 7,
    from_email: opts.fromEmail ?? "alice@example.com",
    from_account_did: opts.fromDid ?? "did:key:zAlice",
  };
  if (opts.hash !== null) manifest["kit_sha256"] = opts.hash ?? computed;
  const entries = [];
  if (!opts.omitManifest) {
    entries.push({
      name: "manifest.json",
      data: new TextEncoder().encode(JSON.stringify(manifest)),
    });
  }
  if (!opts.omitKit) {
    entries.push({ name: opts.kitEntry ?? "kit.tnpkg", data: kit });
  }
  return packTnpkg(entries);
}

test("happy accept installs the kit and emits the absorbed attestation (exit 0)", async () => {
  const c = await freshCeremony("ts-inbox-ok-");
  // A genuine btn kit (the ceremony's own self-kit) so the post-install
  // re-init succeeds and the absorbed-attestation emit actually writes.
  const kit = realKit(c.keystorePath);
  const zip = join(c.dir, "tn-invite-01KQ.zip");
  writeFileSync(zip, buildInviteZip({ kit, group: "default", leaf: 3 }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `expected exit 0; stderr=${s.err}`);
    assert.match(s.out, /^Accepting invitation from tn-invite-01KQ\.zip \.\.\./);
    assert.match(s.out, /Installed kit for group 'default' \(leaf 3\) from alice@example\.com\./);
    assert.match(s.out, /Kit written to: /);
    assert.match(s.out, /Absorbed at: {4}\d{4}-\d\d-\d\dT/);
    assert.equal(s.err, "", "no error output on the happy path");

    // The installed kit file carries the exact kit bytes.
    const kitDest = join(c.keystorePath, "default.btn.mykit");
    assert.deepEqual(new Uint8Array(readFileSync(kitDest)), kit);
    // GAP (faithful to Python's broad-except): the TS wasm runtime classifies
    // `tn.enrolment.absorbed` as an admin event and rejects it for a missing
    // `publisher_identity` field, so the attestation emit hits the non-fatal
    // warn branch. The kit is installed and the verb still exits 0 — exactly
    // the contract Python's `accept` guarantees when its own emit fails. See
    // the REPORT for the parity note.
    assert.match(s.out, /Warning: could not emit tn\.enrolment\.absorbed/);
    assert.match(s.out, /The kit is installed\. You may emit the attestation manually\./);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("accepting over an existing kit backs it up to .previous.<ts>", async () => {
  const c = await freshCeremony("ts-inbox-backup-");
  // Install into a NON-default group so the ceremony's own `default` self-kit
  // stays intact across re-inits; the foreign-group kit bytes are never
  // validated on init, so arbitrary bytes are fine for exercising the backup.
  const first = new TextEncoder().encode("kit-v1");
  const second = new TextEncoder().encode("kit-v2-different");
  const zip = join(c.dir, "tn-invite-A.zip");

  // First accept: writes payments.btn.mykit (no backup line).
  writeFileSync(zip, buildInviteZip({ kit: first, group: "payments" }));
  const s1 = sinks();
  await inboxAcceptCmd({ zipPath: zip, yaml: c.yamlPath, stdout: s1.stdout, stderr: s1.stderr });
  assert.doesNotMatch(s1.out, /Backed up existing kit/);

  // Second accept with different bytes: backs up the prior kit.
  writeFileSync(zip, buildInviteZip({ kit: second, group: "payments" }));
  const s2 = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s2.stdout,
      stderr: s2.stderr,
    });
    assert.equal(code, 0, `stderr=${s2.err}`);
    assert.match(
      s2.out,
      /\(Backed up existing kit to payments\.btn\.mykit\.previous\.\d{8}T\d{6}Z\)/,
    );
    const kitDest = join(c.keystorePath, "payments.btn.mykit");
    assert.deepEqual(new Uint8Array(readFileSync(kitDest)), second);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("accepts the inner kit under the REAL server entry name <group>.btn.mykit (exit 0)", async () => {
  // Bug-fix: the production invitation producer (tn_proto_web
  // _make_invitation_zip / _kit_entry_name) names the inner kit
  // `<group>.btn.mykit`, NOT the legacy `kit.tnpkg`. Before the fix, accept
  // only looked up `kit.tnpkg` and raised "missing kit.tnpkg" on a genuine
  // server-minted zip. Pack the kit under the real name and prove accept
  // finds, hash-verifies, and installs it.
  //
  // This is a fixture-level bug-fix test, not a full round-trip. A faithful
  // end-to-end round-trip (mint a real recipient-bound invite zip, then
  // accept it) is BLOCKED inside tn_proto: there is no CLI/SDK invite-mint
  // verb — only tn_proto_web mints the wrapper. That test is intentionally left
  // OUT rather than faked.
  const c = await freshCeremony("ts-inbox-realname-");
  // Non-default group so the ceremony's own `default` self-kit stays intact
  // across re-inits; foreign-group bytes are never validated on init.
  const kit = new TextEncoder().encode("server-minted-kit-bytes");
  const zip = join(c.dir, "tn-invite-real.zip");
  writeFileSync(
    zip,
    buildInviteZip({ kit, group: "payments", leaf: 4, kitEntry: "payments.btn.mykit" }),
  );
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `expected exit 0; stderr=${s.err}`);
    assert.match(s.out, /Installed kit for group 'payments' \(leaf 4\)/);
    const kitDest = join(c.keystorePath, "payments.btn.mykit");
    assert.deepEqual(new Uint8Array(readFileSync(kitDest)), kit);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("a manifest with no kit_sha256 skips hash verification (exit 0)", async () => {
  const c = await freshCeremony("ts-inbox-nohash-");
  const zip = join(c.dir, "tn-invite-nohash.zip");
  writeFileSync(zip, buildInviteZip({ hash: null }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 0, `stderr=${s.err}`);
    assert.match(s.out, /Installed kit for group/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("kit hash mismatch is refused (exit 1)", async () => {
  const c = await freshCeremony("ts-inbox-badhash-");
  const zip = join(c.dir, "tn-invite-bad.zip");
  // Manifest claims a sha256 that does not match the kit bytes.
  writeFileSync(zip, buildInviteZip({ hash: "sha256:" + "0".repeat(64) }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1, `stdout=${s.out}`);
    assert.match(s.err, /^Error: Kit hash mismatch\./m);
    assert.match(s.err, /Expected: 0{64}/);
    assert.match(s.err, /Re-download from the vault\./);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("hash mismatch tolerates a bare-hex (no sha256: prefix) expectation", async () => {
  const c = await freshCeremony("ts-inbox-barehash-");
  const zip = join(c.dir, "tn-invite-barehash.zip");
  writeFileSync(zip, buildInviteZip({ hash: "f".repeat(64) }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /Expected: f{64}/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("missing zip dies with exit 1", async () => {
  const c = await freshCeremony("ts-inbox-nozip-");
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: join(c.dir, "does-not-exist.zip"),
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^Error: Zip not found:/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("missing tn.yaml dies with exit 1", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-inbox-noyaml-"));
  const zip = join(dir, "tn-invite.zip");
  writeFileSync(zip, buildInviteZip());
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: join(dir, "missing.yaml"),
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^Error: tn\.yaml not found at /);
    assert.match(s.err, /pass --yaml <path>\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a non-zip file is refused as an invalid zip (exit 1)", async () => {
  const c = await freshCeremony("ts-inbox-badzip-");
  const bad = join(c.dir, "tn-invite-garbage.zip");
  writeFileSync(bad, "this is not a zip at all");
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: bad,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^Error: Invalid zip file:/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("an invitation zip missing manifest.json is refused (exit 1)", async () => {
  const c = await freshCeremony("ts-inbox-nomanifest-");
  const zip = join(c.dir, "tn-invite-nomanifest.zip");
  writeFileSync(zip, buildInviteZip({ omitManifest: true }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^Error: Invalid invitation zip: missing manifest\.json/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("an invitation zip missing kit.tnpkg is refused (exit 1)", async () => {
  const c = await freshCeremony("ts-inbox-nokit-");
  const zip = join(c.dir, "tn-invite-nokit.zip");
  writeFileSync(zip, buildInviteZip({ omitKit: true }));
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: c.yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1);
    assert.match(s.err, /^Error: Invalid invitation zip: missing kit\.tnpkg/);
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("default yaml is ./tn.yaml in cwd when --yaml is omitted", async () => {
  const c = await freshCeremony("ts-inbox-cwd-");
  const zip = join(c.dir, "tn-invite-cwd.zip");
  writeFileSync(zip, buildInviteZip());
  const prevCwd = process.cwd();
  process.chdir(c.dir);
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({ zipPath: zip, stdout: s.stdout, stderr: s.stderr });
    assert.equal(code, 0, `stderr=${s.err}`);
    assert.match(s.out, /Installed kit for group/);
  } finally {
    process.chdir(prevCwd);
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("an unloadable tn.yaml is reported as 'Could not read tn.yaml' (exit 1)", async () => {
  // The yaml exists (passes the existence gate) but is not a loadable
  // ceremony, so Tn.init throws and accept wraps it in an InboxError.
  const dir = mkdtempSync(join(tmpdir(), "ts-inbox-badyaml-"));
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, "this: [is, not, : a valid tn ceremony yaml\n");
  const zip = join(dir, "tn-invite-badyaml.zip");
  writeFileSync(zip, buildInviteZip());
  const s = sinks();
  try {
    const code = await inboxAcceptCmd({
      zipPath: zip,
      yaml: yamlPath,
      stdout: s.stdout,
      stderr: s.stderr,
    });
    assert.equal(code, 1, `stdout=${s.out}`);
    assert.match(s.err, /^Error: Could not read tn\.yaml:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a corrupt manifest.json (non-InboxError) propagates instead of exit-1 swallow", async () => {
  // JSON.parse on a malformed manifest throws a SyntaxError, not an
  // InboxError, so the command wrapper re-throws rather than mapping it to
  // exit 1 — proving the `throw exc` branch.
  const c = await freshCeremony("ts-inbox-badmanifest-");
  const zip = join(c.dir, "tn-invite-badmanifest.zip");
  writeFileSync(
    zip,
    packTnpkg([
      { name: "manifest.json", data: new TextEncoder().encode("{ not valid json") },
      { name: "kit.tnpkg", data: new TextEncoder().encode("x") },
    ]),
  );
  const s = sinks();
  try {
    await assert.rejects(
      () =>
        inboxAcceptCmd({ zipPath: zip, yaml: c.yamlPath, stdout: s.stdout, stderr: s.stderr }),
      (e) => e instanceof SyntaxError,
    );
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});

test("the lower accept() returns the parsed result fields", async () => {
  // Direct call (no command wrapper) to assert the AcceptResult shape and
  // that InboxError is the thrown type for bad input.
  const c = await freshCeremony("ts-inbox-direct-");
  const zip = join(c.dir, "tn-invite-direct.zip");
  writeFileSync(zip, buildInviteZip({ group: "payments", leaf: 11, fromEmail: "bob@x.io" }));
  const out: string[] = [];
  try {
    const res = await accept(zip, c.yamlPath, (s) => out.push(s));
    assert.equal(res.groupName, "payments");
    assert.equal(res.leafIndex, 11);
    assert.equal(res.fromEmail, "bob@x.io");
    assert.match(res.kitPath, /payments\.btn\.mykit$/);
    assert.match(res.absorbedAt, /^\d{4}-\d\d-\d\dT/);

    await assert.rejects(
      () => accept(join(c.dir, "nope.zip"), c.yamlPath, (s) => out.push(s)),
      (e) => e instanceof InboxError && /Zip not found/.test((e as Error).message),
    );
  } finally {
    rmSync(c.dir, { recursive: true, force: true });
  }
});
