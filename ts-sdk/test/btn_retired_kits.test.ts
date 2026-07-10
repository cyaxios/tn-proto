// The keystore's btn kit walk must include MODERN `.retired.<epoch>` archives.
//
// Python's tn.admin.rotate (and the Rust runtime) have archived the
// superseded self-kit as `<group>.btn.mykit.retired.<epoch>` since 0.4.3a1;
// the legacy `<group>.btn.mykit.revoked.<unix_ts>` shape is what 0.4.2-line
// keystores (and TS's own rotateGroup, via commitGroupKeys) produce. A TS
// reader that only walks the legacy family loses every pre-rotation row of a
// Python-rotated ceremony. These tests pin the collection order of the Rust
// reference (crypto/tn-core/src/runtime/cipher_build.rs
// collect_btn_kit_bytes_with_storage) and Python's BtnGroupCipher.load
// (python/tn/cipher.py):
//
//   [current, retired epoch-DESC, legacy revoked ts-DESC]
//
// plus the real-world scenario end to end: Python rotates, TS still reads.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Tn } from "../src/tn.js";
import { loadBtnKits } from "../src/runtime/keystore.js";
import type { Entry } from "../src/Entry.js";

// ---------------------------------------------------------------------------
// Unit: collection order off a bare directory
// ---------------------------------------------------------------------------

/** Read every order-relevant fixture back as its content tag, in walk order.
 *  loadBtnKits never parses kit bytes (the decrypt walk does, per kit), so
 *  distinct content tags make the filename-to-position mapping assertable. */
function kitTags(dir: string, group: string): string[] {
  return loadBtnKits(dir, group).map((k) => Buffer.from(k).toString("utf8"));
}

test("loadBtnKits walks current, then retired epoch-desc, then legacy revoked ts-desc", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-retired-kits-"));
  try {
    const write = (name: string, tag: string) => writeFileSync(join(dir, name), Buffer.from(tag));
    write("default.btn.mykit", "CURRENT");
    // Modern archives: epoch 10 must sort before epoch 3 (numeric, not
    // lexical — a lexical sort would order "10" < "3" and flip them).
    write("default.btn.mykit.retired.3", "RETIRED_3");
    write("default.btn.mykit.retired.10", "RETIRED_10");
    // Legacy archives: newest timestamp first (readdir order is not enough).
    write("default.btn.mykit.revoked.1600000000", "REVOKED_OLD");
    write("default.btn.mykit.revoked.1700000000", "REVOKED_NEW");
    // Must NOT leak into the kit list: another group's archive, the retired
    // STATE sibling (decrypt needs kits only), and the active state.
    write("other.btn.mykit.retired.5", "OTHER_GROUP");
    write("default.btn.state.retired.3", "STATE_ARCHIVE");
    write("default.btn.state", "STATE_ACTIVE");

    assert.deepEqual(kitTags(dir, "default"), [
      "CURRENT",
      "RETIRED_10",
      "RETIRED_3",
      "REVOKED_NEW",
      "REVOKED_OLD",
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a non-numeric archive suffix sorts last in its family and never crashes the load", () => {
  const dir = mkdtempSync(join(tmpdir(), "ts-retired-junk-"));
  try {
    const write = (name: string, tag: string) => writeFileSync(join(dir, name), Buffer.from(tag));
    write("default.btn.mykit", "CURRENT");
    write("default.btn.mykit.retired.2", "RETIRED_2");
    // A torn atomic-write leftover: still offered (the decrypt walk skips a
    // kit that fails to parse) but only after every real epoch.
    write("default.btn.mykit.retired.9.tmp", "TORN_TMP");
    write("default.btn.mykit.revoked.1700000000", "REVOKED");

    assert.deepEqual(kitTags(dir, "default"), ["CURRENT", "RETIRED_2", "TORN_TMP", "REVOKED"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadBtnKits handles a retired-only keystore (no current kit, archives still load)", () => {
  // After a Python-side revocation flow a holder can be left with archives
  // only; the walk must still offer them rather than returning empty.
  const dir = mkdtempSync(join(tmpdir(), "ts-retired-only-"));
  try {
    writeFileSync(join(dir, "default.btn.mykit.retired.1"), Buffer.from("RETIRED_1"));
    assert.deepEqual(kitTags(dir, "default"), ["RETIRED_1"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Behavioral: a modern `.retired.<epoch>` keystore spans the rotation boundary
// ---------------------------------------------------------------------------

function orderIds(tn: Tn): Set<string> {
  const ids = new Set<string>();
  for (const e of tn.read({ allRuns: true })) {
    const ent = e as {
      event_type?: string;
      eventType?: string;
      fields?: Record<string, unknown>;
    };
    if ((ent.event_type ?? ent.eventType) === "order.created") {
      ids.add(String(ent.fields?.order_id));
    }
  }
  return ids;
}

test("btn read spans a rotation archived under the modern .retired.<epoch> name", async () => {
  // TS's own rotate still archives under the legacy `.revoked.<ts>` name, so
  // simulate the modern layout honestly: run a REAL rotation, then rename its
  // archives to the exact names Python's tn.admin.rotate writes. Only the
  // filename shape differs — which is precisely the thing under test.
  const dir = mkdtempSync(join(tmpdir(), "ts-rot-retired-"));
  const yaml = join(dir, "tn.yaml");
  try {
    let tn = await Tn.init(yaml, { stdout: false });
    tn.info("order.created", { order_id: "OLD" });
    await tn.admin.rotate("default");
    tn.info("order.created", { order_id: "NEW" });
    const ks = (tn.config() as { keystorePath: string }).keystorePath;
    await tn.close();

    // Rename the legacy archives to the modern shape Python produces
    // (first rotation retires epoch 1 there; any numeric epoch must load).
    let renamed = 0;
    for (const f of readdirSync(ks)) {
      const m = f.match(/^default\.btn\.(state|mykit)\.revoked\.\d+$/);
      if (m) {
        renameSync(join(ks, f), join(ks, `default.btn.${m[1]}.retired.1`));
        renamed += 1;
      }
    }
    assert.equal(renamed, 2, "precondition: rotation archived a state+kit pair");
    assert.ok(
      !readdirSync(ks).some((f) => f.includes(".btn.mykit.revoked.")),
      "precondition: no legacy kit archive left — the read below can only succeed via .retired",
    );

    tn = await Tn.init(yaml, { stdout: false });
    const ids = orderIds(tn);
    await tn.close();
    assert.ok(ids.has("NEW"), `post-rotation entry should read; saw ${[...ids]}`);
    assert.ok(
      ids.has("OLD"),
      `pre-rotation entry should read via the .retired.<epoch> kit; saw ${[...ids]}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Cross-impl (the real-world scenario): Python rotates, TS reads + unseals.
// Same subprocess pattern as seal_unseal_cross_impl.test.ts.
// ---------------------------------------------------------------------------

function pickPython(): string | null {
  const candidates = [process.env["TN_PYTHON"], "python3", "python"].filter(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  for (const bin of candidates) {
    try {
      const result = spawnSync(bin, ["-c", "import tn.admin; print('ok')"], {
        encoding: "utf8",
        timeout: 10_000,
      });
      if (result.status === 0 && result.stdout.trim() === "ok") return bin;
    } catch {
      /* try next */
    }
  }
  return null;
}

// Resolve once and reuse (a second probe under load can flip to null and
// crash the body instead of skipping).
const PYTHON = pickPython();
const SKIP = PYTHON === null ? "Python tn-proto not available locally; runs in CI" : false;

function pyEnv(base: string, proj: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    TN_IDENTITY_DIR: join(base, "ident"),
    XDG_DATA_HOME: join(base, "xdg"),
    TN_PROJ: proj,
    TN_NO_STDOUT: "1",
    TN_NO_LINK: "1",
  };
}

function runPython(python: string, script: string, env: NodeJS.ProcessEnv): string {
  const r = spawnSync(python, ["-c", script], { encoding: "utf8", timeout: 120_000, env });
  if (r.status !== 0) {
    throw new Error(`python failed (${r.status}): ${r.stderr || r.stdout}`);
  }
  const lastLine = r.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
  assert.ok(lastLine, `python printed no output: ${r.stdout}`);
  return lastLine;
}

// Python: btn ceremony -> pre-rotation row + sealed object -> tn.admin.rotate
// (writes the modern .retired.<epoch> archive) -> post-rotation row.
const PY_ROTATOR = `
import os, json
from pathlib import Path
proj = os.environ["TN_PROJ"]
os.chdir(proj)
import tn
import tn.admin
tn.init(str(Path(proj) / "tn.yaml"), cipher="btn", link=False)
tn.info("order.created", order_id="OLD")
sealed = tn.seal("obj.case.v1", receipt=False, secret="pre-rotation")
tn.admin.rotate("default")
tn.info("order.created", order_id="NEW")
tn.flush_and_close()
print(json.dumps({"yaml": str(Path(proj) / "tn.yaml"), "wire": str(sealed)}))
`;

test(
  "live interop: Python rotates a btn ceremony, TS still opens pre-rotation content",
  { skip: SKIP },
  async () => {
    const python = PYTHON!;
    const base = mkdtempSync(join(tmpdir(), "tn-rot-py2ts-"));
    const proj = join(base, "proj");
    mkdirSync(proj, { recursive: true });
    mkdirSync(join(base, "ident"), { recursive: true });
    mkdirSync(join(base, "xdg"), { recursive: true });
    let client: Tn | null = null;
    try {
      const out = JSON.parse(runPython(python, PY_ROTATOR, pyEnv(base, proj))) as {
        yaml: string;
        wire: string;
      };

      client = await Tn.init(out.yaml, { stdout: false });
      const ks = (client.config() as { keystorePath: string }).keystorePath;
      // Honesty guard: the rotation must have produced the MODERN archive
      // shape and none of the legacy one — otherwise this test would pass
      // through the `.revoked` walk without exercising the fix.
      const names = readdirSync(ks);
      assert.ok(
        names.some((f) => /^default\.btn\.mykit\.retired\.\d+$/.test(f)),
        `expected a .btn.mykit.retired.<epoch> archive; keystore holds ${names.join(", ")}`,
      );
      assert.ok(
        !names.some((f) => f.includes(".btn.mykit.revoked.")),
        "expected no legacy .revoked kit archive in a Python-rotated keystore",
      );

      // The log read spans the rotation boundary...
      const ids = orderIds(client);
      assert.ok(ids.has("NEW"), `post-rotation row should read; saw ${[...ids]}`);
      assert.ok(
        ids.has("OLD"),
        `TS lost pre-rotation read access to a Python-rotated btn ceremony; saw ${[...ids]}`,
      );
      // ...and the sealed-object walk opens the pre-rotation object (this
      // path re-reads kits from disk via loadBtnKits, not the init keystore).
      const entry = (await client.unseal(out.wire)) as Entry;
      assert.deepEqual(entry.fields, { secret: "pre-rotation" });
    } finally {
      if (client) await client.close();
      rmSync(base, { recursive: true, force: true });
    }
  },
);
