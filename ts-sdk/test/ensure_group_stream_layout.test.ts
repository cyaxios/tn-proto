/**
 * ``ensureGroup`` / ``rotateGroup`` must persist parent-owned keys
 * AUTHORITATIVELY under the flipped multi-ceremony layout.
 *
 * A named ceremony (``Tn.openCeremony("X")``) is a *stream*: its yaml at
 * ``<project>/.tn/X/tn.yaml`` carries ``extends: ../default/tn.yaml`` and
 * inherits ``device`` / ``keystore`` / ``groups`` / ``fields`` /
 * ``recipients`` from the project root ``.tn/default/tn.yaml``. Those keys
 * are parent-owned — ``config.resolveExtends`` discards a child's copy on
 * the next load ("child sets parent-owned key 'groups'; parent wins").
 *
 * Regression (pre-fix):
 *   - ``rotateGroup`` wrote ``groups.<g>.index_epoch`` into the *stream*
 *     yaml via ``this.config.yamlPath``, where ``groups`` is
 *     non-authoritative — the bump vanished on the next load.
 *   - ``ensureGroup`` was log-only: it emitted ``tn.group.added`` but wrote
 *     no yaml, so a stream-added group never appeared in the resolved yaml
 *     and was never routable.
 *
 * The fix routes both writes through ``authoritativeYamlFor`` so they land
 * in the chain-root ``.tn/default/tn.yaml``. Mirrors the Python suite at
 * python/tests/test_ensure_group_stream_layout.py.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parse as parseYaml } from "yaml";

import { Tn } from "../src/tn.js";

function makeProject(): string {
  return mkdtempSync(join(tmpdir(), "tn-ensure-stream-"));
}

/** Run `fn` with console.warn captured; returns the collected lines. */
async function captureWarnings(fn: () => Promise<void>): Promise<string[]> {
  const warnings: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map((a) => String(a)).join(" "));
  };
  try {
    await fn();
  } finally {
    console.warn = orig;
  }
  return warnings;
}

test("ensureGroup on a stream lands the group in the authoritative root yaml, not the stream", async () => {
  const project = makeProject();
  try {
    let warnings: string[] = [];
    warnings = await captureWarnings(async () => {
      const tn = await Tn.openCeremony("X", { projectDir: project });
      try {
        await tn.admin.ensureGroup("partners");
      } finally {
        await tn.close();
      }
    });

    const rootPath = join(project, ".tn", "default", "tn.yaml");
    const streamPath = join(project, ".tn", "X", "tn.yaml");
    const rootDoc = parseYaml(readFileSync(rootPath, "utf8")) as Record<string, unknown>;
    const streamDoc = parseYaml(readFileSync(streamPath, "utf8")) as Record<string, unknown>;
    const rootGroups = (rootDoc.groups ?? {}) as Record<string, unknown>;

    assert.ok(
      "partners" in rootGroups,
      "group 'partners' did not persist in the authoritative root yaml " +
        ".tn/default/tn.yaml; ensureGroup wrote it to the stream yaml where " +
        "groups are non-authoritative (or did not write yaml at all).",
    );
    assert.ok(
      !("groups" in streamDoc),
      "ensureGroup wrote a `groups:` block into the stream yaml — that is the " +
        "parent-owned key the loader discards on the next load.",
    );
    // The btn key material is minted into the SHARED (default) keystore so the
    // group is genuinely routable, not just declared. Mirrors Python's
    // ensure_group calling _create_group before the yaml write.
    assert.ok(
      existsSync(join(project, ".tn", "default", "keys", "partners.btn.state")),
      "partners.btn.state was not minted in the shared keystore; the group " +
        "would not be routable by a fresh process.",
    );
    const parentOwned = warnings.filter((w) => w.includes("parent-owned"));
    assert.deepEqual(
      parentOwned,
      [],
      `ensureGroup tripped the parent-owned-key warning, meaning it wrote ` +
        `groups into the stream yaml: ${JSON.stringify(parentOwned)}`,
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});

test("rotateGroup on a stream bumps index_epoch in the authoritative root yaml, not the stream", async () => {
  const project = makeProject();
  try {
    const warnings = await captureWarnings(async () => {
      const tn = await Tn.openCeremony("X", { projectDir: project });
      try {
        await tn.admin.rotate("default");
      } finally {
        await tn.close();
      }
    });

    const rootPath = join(project, ".tn", "default", "tn.yaml");
    const streamPath = join(project, ".tn", "X", "tn.yaml");
    const rootDoc = parseYaml(readFileSync(rootPath, "utf8")) as Record<string, unknown>;
    const streamDoc = parseYaml(readFileSync(streamPath, "utf8")) as Record<string, unknown>;
    const rootDefault = ((rootDoc.groups ?? {}) as Record<string, Record<string, unknown>>)
      .default;

    assert.equal(
      rootDefault?.index_epoch,
      1,
      "rotateGroup did not bump groups.default.index_epoch in the authoritative " +
        "root yaml; it wrote to the non-authoritative stream yaml where the " +
        "bump is discarded on the next load.",
    );
    assert.ok(
      !("groups" in streamDoc),
      "rotateGroup wrote a parent-owned `groups:` block into the stream yaml.",
    );
    const parentOwned = warnings.filter((w) => w.includes("parent-owned"));
    assert.deepEqual(
      parentOwned,
      [],
      `rotateGroup tripped the parent-owned-key warning: ${JSON.stringify(parentOwned)}`,
    );
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
});
