/**
 * Unit tests for `tn show profiles` (ts-sdk/src/cli/show_profiles.ts).
 *
 * Mirrors Python's `tn.cli.cmd_show_profiles`. Captures stdout from the
 * exported `showProfilesCmd` and asserts the table / json shape against
 * the live SDK catalog (`../src/profiles.js`), exercising every line of
 * the command module.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";

import { showProfilesCmd } from "../src/cli/show_profiles.js";
import {
  allProfileNames,
  getProfile,
  DEFAULT_PROFILE,
} from "../src/profiles.js";

/** Run `showProfilesCmd`, capturing everything written to stdout. */
async function capture(
  opts: Parameters<typeof showProfilesCmd>[0],
): Promise<{ code: number; out: string }> {
  const orig = process.stdout.write.bind(process.stdout);
  let out = "";
  // @ts-expect-error — narrow write override for the duration of the call.
  process.stdout.write = (chunk: string | Uint8Array): boolean => {
    out += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  };
  try {
    const code = await showProfilesCmd(opts);
    return { code, out };
  } finally {
    process.stdout.write = orig;
  }
}

test("show profiles: default format (no --format) renders the human table", async () => {
  // Python: fmt = getattr(args, "format", "human") or "human" — the
  // undefined branch defaults to human.
  const { code, out } = await capture({});
  assert.equal(code, 0);

  // Header + separator rule.
  assert.match(out, /^NAME {10}ENCRYPTS {2}SIGNS {2}CHAINS {2}FLUSH {5}SINK {10}\n/);
  assert.match(out, /\n-{12} {2}-{8} {2}-{5} {2}-{6} {2}-{8} {2}-{14}\n/);

  // Footer marker legend.
  assert.match(
    out,
    /\n\* = catalog default \(used when tn\.init\(\) is called with no profile=\)\.\n\n/,
  );

  // Every catalog profile appears in the table AND as an intended-use blurb.
  for (const name of allProfileNames()) {
    const p = getProfile(name);
    assert.ok(out.includes(name), `table missing profile ${name}`);
    assert.ok(
      out.includes(`${p.name}: ${p.intended_use}\n\n`),
      `blurb missing for ${name}`,
    );
  }
});

test("show profiles: human format marks the default profile with '*'", async () => {
  const { out } = await capture({ format: "human" });

  // The default profile's row carries the '*' marker right after the name.
  assert.ok(
    out.includes(`${DEFAULT_PROFILE}*`),
    `default ${DEFAULT_PROFILE} should be marked with *`,
  );

  // A non-default profile must NOT carry the marker.
  const nonDefault = allProfileNames().find((n) => n !== DEFAULT_PROFILE);
  assert.ok(nonDefault, "catalog needs at least one non-default profile");
  assert.ok(
    !out.includes(`${nonDefault}*`),
    `non-default ${nonDefault} must not be marked`,
  );
});

test("show profiles: human rows render yes/no booleans and flush/sink", async () => {
  const { out } = await capture({ format: "human" });
  const lines = out.split("\n");

  for (const name of allProfileNames()) {
    const p = getProfile(name);
    // Find the table row for this profile (starts with the name).
    const row = lines.find((l) => l.startsWith(name) && l.includes(p.flush));
    assert.ok(row, `no table row for ${name}`);
    assert.ok(row.includes(p.encrypts ? "yes" : "no"));
    assert.ok(row.includes(p.signs ? "yes" : "no"));
    assert.ok(row.includes(p.chains ? "yes" : "no"));
    assert.ok(row.includes(p.flush));
    assert.ok(row.includes(p.default_sink));
  }
});

test("show profiles: --format json emits the full catalog payload", async () => {
  const { code, out } = await capture({ format: "json" });
  assert.equal(code, 0);
  assert.ok(out.endsWith("\n"), "json output ends with a trailing newline");

  const parsed = JSON.parse(out) as {
    profiles: Array<{
      name: string;
      encrypts: boolean;
      signs: boolean;
      chains: boolean;
      flush: string;
      default_sink: string;
      intended_use: string;
      default: boolean;
    }>;
  };

  const names = allProfileNames();
  assert.equal(parsed.profiles.length, names.length);

  for (let i = 0; i < names.length; i++) {
    const p = getProfile(names[i]);
    const j = parsed.profiles[i];
    assert.equal(j.name, p.name);
    assert.equal(j.encrypts, p.encrypts);
    assert.equal(j.signs, p.signs);
    assert.equal(j.chains, p.chains);
    assert.equal(j.flush, p.flush);
    assert.equal(j.default_sink, p.default_sink);
    assert.equal(j.intended_use, p.intended_use);
    assert.equal(j.default, p.name === DEFAULT_PROFILE);
  }

  // Exactly one profile is flagged default, and it is DEFAULT_PROFILE.
  const defaults = parsed.profiles.filter((p) => p.default);
  assert.equal(defaults.length, 1);
  assert.equal(defaults[0].name, DEFAULT_PROFILE);
});
