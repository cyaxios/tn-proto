// `{event_id}` templated `logs.path`: one ndjson file per event, and
// `read({ log: template })` globs them back into one stream.
//
// Parity with the Python SDK's tests/test_log_path_event_id.py and the
// Rust runtime's tests/event_id_template.rs. The wasm runtime renders
// the `{event_id}` token per emit (open-write-close, no writer pool);
// the TS read path glob-expands the template back.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parse as yamlParse, stringify as yamlStringify } from "yaml";

import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tn-evid-"));
}

function setLogsPath(yamlPath: string, newPath: string): void {
  const doc = yamlParse(readFileSync(yamlPath, "utf8")) as Record<string, unknown>;
  doc["logs"] = { path: newPath };
  const handlers = doc["handlers"];
  if (Array.isArray(handlers)) {
    for (const h of handlers) {
      if (h && typeof h === "object" && String((h as Record<string, unknown>)["kind"] ?? "").startsWith("file")) {
        (h as Record<string, unknown>)["path"] = newPath;
        break;
      }
    }
  }
  writeFileSync(yamlPath, yamlStringify(doc), "utf8");
}

function ndjsonFiles(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries.filter((e) => e.endsWith(".ndjson")).map((e) => join(dir, e)).sort();
}

test("{event_id} logs.path writes one file per event, one row each", async () => {
  const dir = tmp();
  try {
    const yamlPath = join(dir, "tn.yaml");
    let tn = await Tn.init(yamlPath, { stdout: false });
    await tn.close();

    setLogsPath(yamlPath, "./logs/{event_id}.ndjson");

    tn = await Tn.init(yamlPath, { stdout: false });
    const n = 5;
    for (let i = 0; i < n; i++) tn.info("order.created", { seq: i });
    await tn.close();

    const logDir = join(dir, "logs");
    const files = ndjsonFiles(logDir);

    const businessIds = new Set<string>();
    for (const f of files) {
      const lines = readFileSync(f, "utf8").split(/\r?\n/).filter((l) => l.trim());
      assert.equal(lines.length, 1, `${f} should hold exactly one row, got ${lines.length}`);
      const env = JSON.parse(lines[0]!) as Record<string, unknown>;
      const stem = f.slice(f.lastIndexOf("/") + 1).replace(/\.ndjson$/, "").split(/[\\/]/).pop();
      assert.equal(env["event_id"], stem, `${f}: stem != event_id`);
      if (env["event_type"] === "order.created") businessIds.add(env["event_id"] as string);
    }
    assert.equal(businessIds.size, n, `expected ${n} distinct business files, saw ${businessIds.size}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("read({ log: '{event_id}' template }) merges per-event files back", async () => {
  const dir = tmp();
  try {
    const yamlPath = join(dir, "tn.yaml");
    let tn = await Tn.init(yamlPath, { stdout: false });
    await tn.close();

    const template = "./logs/{event_id}.ndjson";
    setLogsPath(yamlPath, template);

    tn = await Tn.init(yamlPath, { stdout: false });
    tn.info("order.created", { marker: "A" });
    tn.info("order.created", { marker: "B" });
    tn.info("order.created", { marker: "C" });
    await tn.close();

    tn = await Tn.init(yamlPath, { stdout: false });
    const markers = new Set<unknown>();
    for (const e of tn.read({ log: template, allRuns: true })) {
      const fields = e instanceof Entry ? e.fields : ((e as Record<string, unknown>) ?? {});
      const m = (fields as Record<string, unknown>)["marker"];
      if (m !== undefined) markers.add(m);
    }
    await tn.close();
    assert.deepEqual([...markers].sort(), ["A", "B", "C"], `merged markers wrong: ${[...markers]}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
