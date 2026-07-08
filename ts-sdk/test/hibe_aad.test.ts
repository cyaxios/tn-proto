// Per-emit and per-group additional-authenticated-data (AAD) on the hibe
// ceremony surface, mirroring python/tests/test_hibe_aad.py case for case:
//
//   a  emit a hibe record with info(..., { aad }); read it back and confirm
//      plaintext recovered AND the public section carries tn_aad
//   b  a granted reader reconstructs the aad from the public echo and opens it
//   c  tamper the on-disk tn_aad -> read fails row_hash AND no decrypt (marker)
//   d  a yaml group aad default is applied with no per-emit arg
//   e  a per-emit aad overrides the yaml default (merge semantics)
//   f  a record emitted with NO aad has no tn_aad key and reads normally
//   g  aad binds on a btn ceremony too, via the native wasm runtime
//
// The aad dict is bound (authenticated, not encrypted) to the group seal via
// the same canonical-bytes routine that feeds row_hash, and echoed into the
// public tn_aad block so any reader reconstructs byte-identical binding data.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { readAsRecipient } from "../src/read_as_recipient.js";
import type { NodeRuntime } from "../src/runtime/node_runtime.js";
import type { ReadEntry } from "../src/runtime/node_runtime.js";

function rt(a: Tn): NodeRuntime {
  return (a as unknown as { _rt: NodeRuntime })._rt;
}

function byType(a: Tn, log: string): Record<string, ReadEntry> {
  const out: Record<string, ReadEntry> = {};
  for (const e of rt(a).read(log)) out[String(e.envelope["event_type"])] = e;
  return out;
}

function injectGroupAad(yamlPath: string, group: string, aad: Record<string, unknown>): void {
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as {
    groups: Record<string, { aad?: Record<string, unknown> }>;
  };
  doc.groups[group]!.aad = aad;
  writeFileSync(yamlPath, stringifyYaml(doc), "utf8");
}

test("hibe aad: per-emit + config default binding, tamper detection, btn limitation", async () => {
  const ws = mkdtempSync(join(tmpdir(), "ts-hibe-aad-"));
  const aYaml = join(ws, "authority", "tn.yaml");
  const kit = join(ws, "reader.tnpkg");
  try {
    // --- (a) emit with a per-emit aad; authority reads it back.
    let a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    const aLog = (a.config() as { logPath: string }).logPath;
    a.info("oba.filed", { note: "quarterly OBA" }, { aad: { policy: "finra-oba", v: "1" } });
    await a.admin.grantReader("default", { readerDid: "did:key:z6Mk-aad-r1", outPath: kit });
    await a.close();

    a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    let by = byType(a, aLog);
    let rec = by["oba.filed"];
    assert.equal(rec.plaintext["default"]["note"], "quarterly OBA");
    // tn_aad is the canonical JSON STRING of the {group: dict} map.
    assert.deepEqual(JSON.parse(rec.envelope["tn_aad"] as string), {
      default: { policy: "finra-oba", v: "1" },
    });
    assert.ok(rec.valid.rowHash, "row_hash must verify on an aad record");
    assert.ok(rec.valid.signature, "signature must verify on an aad record");
    await a.close();

    // --- (b) a granted reader reconstructs the aad from the public echo.
    const r = await Tn.init(join(ws, "reader", "tn.yaml"), { stdout: false, link: false });
    const rKeystore = (r.config() as { keystorePath: string }).keystorePath;
    await r.pkg.absorb(kit);
    await r.close();
    const got: Record<string, Record<string, unknown>> = {};
    for (const e of readAsRecipient(aLog, rKeystore, { group: "default" })) {
      got[String(e.envelope["event_type"])] = e.plaintext["default"] ?? {};
    }
    assert.equal(got["oba.filed"]!["note"], "quarterly OBA");

    // --- (c) tamper the on-disk tn_aad -> row_hash fails AND no decrypt.
    const lines = readFileSync(aLog, "utf8").split(/\r?\n/).filter((l) => l.length > 0);
    const tampered = lines.map((line) => {
      const obj = JSON.parse(line) as Record<string, unknown>;
      // tn_aad is a canonical JSON STRING; flip a bound value inside it so
      // the reader reconstructs different bytes and the string public field
      // changes (breaking row_hash too).
      if (obj["event_type"] === "oba.filed")
        obj["tn_aad"] = (obj["tn_aad"] as string).replace("finra-oba", "tampered");
      return JSON.stringify(obj);
    });
    writeFileSync(aLog, tampered.join("\n") + "\n", "utf8");

    a = await Tn.init(aYaml, { cipher: "hibe", stdout: false, link: false });
    by = byType(a, aLog);
    rec = by["oba.filed"];
    assert.equal(rec.valid.rowHash, false, "tampered tn_aad must break row_hash");
    const pt = rec.plaintext["default"];
    assert.notEqual(pt["note"], "quarterly OBA", "tampered record must NOT yield real plaintext");
    assert.ok(
      "$decrypt_error" in pt || "$no_read_key" in pt,
      `expected a decrypt marker, got ${JSON.stringify(pt)}`,
    );
    await a.close();

    // --- (d) yaml group aad default, no per-emit arg.
    const dYaml = join(ws, "cfgdefault", "tn.yaml");
    let d = await Tn.init(dYaml, { cipher: "hibe", stdout: false, link: false });
    const dLog = (d.config() as { logPath: string }).logPath;
    await d.close();
    injectGroupAad(dYaml, "default", { tenant: "acme", region: "us" });
    d = await Tn.init(dYaml, { cipher: "hibe", stdout: false, link: false });
    const dGroups = (d.config() as { groups: Map<string, { aadDefault: Record<string, unknown> }> })
      .groups;
    assert.deepEqual(dGroups.get("default")!.aadDefault, { tenant: "acme", region: "us" });
    d.info("cfg.first", { note: "uses yaml aad default" });
    await d.close();

    d = await Tn.init(dYaml, { cipher: "hibe", stdout: false, link: false });
    by = byType(d, dLog);
    rec = by["cfg.first"];
    assert.equal(rec.plaintext["default"]["note"], "uses yaml aad default");
    assert.deepEqual(JSON.parse(rec.envelope["tn_aad"] as string), {
      default: { tenant: "acme", region: "us" },
    });
    assert.ok(rec.valid.rowHash && rec.valid.signature);
    await d.close();

    // --- (e) per-emit aad overrides the yaml default (merge semantics).
    d = await Tn.init(dYaml, { cipher: "hibe", stdout: false, link: false });
    d.info("cfg.override", { note: "override" }, { aad: { region: "eu", extra: "1" } });
    await d.close();
    d = await Tn.init(dYaml, { cipher: "hibe", stdout: false, link: false });
    by = byType(d, dLog);
    rec = by["cfg.override"];
    // config {tenant: acme, region: us} merged UNDER per-emit {region: eu, extra: 1}.
    assert.deepEqual(JSON.parse(rec.envelope["tn_aad"] as string), {
      default: { tenant: "acme", region: "eu", extra: "1" },
    });
    assert.equal(rec.plaintext["default"]["note"], "override");
    assert.ok(rec.valid.rowHash && rec.valid.signature);
    await d.close();

    // --- (f) a no-aad record has no tn_aad key and reads normally.
    const nYaml = join(ws, "noaad", "tn.yaml");
    let n = await Tn.init(nYaml, { cipher: "hibe", stdout: false, link: false });
    const nLog = (n.config() as { logPath: string }).logPath;
    n.info("plain.first", { note: "no aad here" });
    await n.close();
    const rawObj = JSON.parse(
      readFileSync(nLog, "utf8").split(/\r?\n/).filter((l) => l.length > 0)[0]!,
    ) as Record<string, unknown>;
    assert.ok(!("tn_aad" in rawObj), "aad-free record must not carry tn_aad");
    n = await Tn.init(nYaml, { cipher: "hibe", stdout: false, link: false });
    by = byType(n, nLog);
    rec = by["plain.first"];
    assert.equal(rec.plaintext["default"]["note"], "no aad here");
    assert.ok(rec.valid.rowHash && rec.valid.signature);
    await n.close();

    // --- (g) aad now binds on a btn ceremony too (native wasm runtime).
    const bYaml = join(ws, "btn", "tn.yaml");
    let b = await Tn.init(bYaml, { cipher: "btn", stdout: false, link: false });
    const bLog = (b.config() as { logPath: string }).logPath;
    b.info("btn.governed", { note: "btn body" }, { aad: { policy: "sox-404" } });
    await b.close();
    b = await Tn.init(bYaml, { cipher: "btn", stdout: false, link: false });
    const brec = byType(b, bLog)["btn.governed"];
    assert.equal(brec.plaintext["default"]["note"], "btn body");
    assert.deepEqual(JSON.parse(brec.envelope["tn_aad"] as string), {
      default: { policy: "sox-404" },
    });
    assert.ok(brec.valid.rowHash && brec.valid.signature);
    await b.close();
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});
