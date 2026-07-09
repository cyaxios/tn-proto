// tn.seal — sealed-object build tests.
//
// TS port of the seal half of python/tests/test_seal_unseal.py (the
// normative suite): wire shape + standalone conventions, reserved-name
// guard, chain isolation, receipt surface, and the fragile-public-value
// guard.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { Tn } from "../src/tn.js";
import { SealedObject } from "../src/seal.js";
import { Entry } from "../src/Entry.js";
import { resolveAdminLogPath } from "../src/admin/log.js";
import { ZERO_HASH } from "../src/core/chain.js";
import { verify as verifySignature, signatureFromB64 } from "../src/core/signing.js";
import { asDid } from "../src/core/types.js";
import { computeRowHash } from "../src/raw.js";
import type { CeremonyConfig } from "../src/runtime/config.js";

function makeBase(): string {
  return mkdtempSync(join(tmpdir(), "tn-seal-unseal-"));
}

async function initClient(
  dir: string,
  cipher: "btn" | "jwe" | "hibe" = "jwe",
): Promise<Tn> {
  return Tn.init(join(dir, "tn.yaml"), { cipher, stdout: false });
}

function cfgOf(client: Tn): CeremonyConfig {
  return client.config() as CeremonyConfig;
}

/** Collect an async iterator (readAsync) into an array. */
async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of it) out.push(v);
  return out;
}

test("seal returns a SealedObject with the standalone wire conventions", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.invoice.v1", { amount: 9800, customer: "acme" });

    assert.ok(sealed instanceof SealedObject);
    // toString() renders the verbatim compact wire JSON (the log's line
    // format, no trailing newline), and it re-parses to the envelope.
    assert.ok(!String(sealed).endsWith("\n"));
    assert.deepEqual(JSON.parse(String(sealed)), sealed.envelope);

    // standalone conventions
    const env = sealed.envelope;
    assert.equal(env["sequence"], 0);
    assert.equal(env["prev_hash"], "");
    assert.equal(env["level"], "");
    assert.equal(env["tn_sealed"], 1);
    assert.equal(env["event_type"], "obj.invoice.v1");
    assert.equal(sealed.eventType, "obj.invoice.v1");
    assert.equal(sealed.rowHash, env["row_hash"]);
    assert.equal(sealed.deviceIdentity, env["device_identity"]);

    // fields are encrypted, not in the clear
    assert.ok(!("amount" in env));
    assert.ok(!("customer" in env));
    const block = env["default"] as Record<string, unknown>;
    assert.equal(typeof block["ciphertext"], "string");

    // always signed, and the signature verifies
    assert.ok(
      verifySignature(
        asDid(String(env["device_identity"])),
        new Uint8Array(Buffer.from(String(env["row_hash"]), "ascii")),
        signatureFromB64(String(env["signature"])),
      ),
    );

    // row_hash is honestly derived from the envelope contents: the
    // standalone preimage hashes prev_hash "" (not ZERO_HASH), excludes
    // sequence, and binds the tn_sealed marker as a public field
    const expected = computeRowHash({
      device_identity: env["device_identity"],
      timestamp: env["timestamp"],
      event_id: env["event_id"],
      event_type: env["event_type"],
      level: env["level"],
      prev_hash: env["prev_hash"],
      public_fields: { tn_sealed: env["tn_sealed"] },
      groups: {
        default: {
          ciphertext_b64: block["ciphertext"],
          field_hashes: block["field_hashes"],
        },
      },
    });
    assert.equal(env["row_hash"], expected);
    // no aad passed -> no tn_aad echo; aad-free wire shape stays minimal
    assert.ok(!("tn_aad" in env));
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal rejects the reserved tn_sealed field name", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    await assert.rejects(client.seal("obj.test.v1", { tn_sealed: 1 }), /tn_sealed/);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal does not disturb the per-event_type chain", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    // chains are per-event_type: write the SAME type the seal used. If
    // seal had advanced that chain, this row would be sequence 2 with a
    // real prev_hash instead of the genesis link.
    const receipt = await client.emitAsync("", "obj.test.v1", { y: 2 });
    assert.equal(receipt.sequence, 1);
    const rows = [...client.read({ selector: "obj.test.v1", raw: true })] as Record<
      string,
      unknown
    >[];
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!["prev_hash"], String(ZERO_HASH()));
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal writes a tn.object.sealed receipt row by default", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.invoice.v1", { amount: 1 });
    // tn.* events route to the admin/protocol-events log (a dedicated
    // file, not the main ceremony log) — read that surface.
    const adminLog = resolveAdminLogPath(cfgOf(client));
    const receipts = (await collect(
      client.readAsync({ selector: "tn.object.sealed", log: adminLog }),
    )) as Entry[];
    assert.equal(receipts.length, 1);
    const r = receipts[0]!;
    assert.equal(r.fields["object_id"], sealed.rowHash);
    assert.equal(r.fields["object_type"], "obj.invoice.v1");
    assert.deepEqual(r.fields["groups"], ["default"]);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal with receipt: false writes nothing", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    await client.seal("obj.invoice.v1", { amount: 1 }, { receipt: false });
    const adminLog = resolveAdminLogPath(cfgOf(client));
    const receipts = await collect(
      client.readAsync({ selector: "tn.object.sealed", log: adminLog }),
    );
    assert.deepEqual(receipts, []);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

/** Init a jwe ceremony that routes `fieldNames` to public_fields.
 *
 * Public field values feed the row_hash as str(value); group fields do
 * not. These tests need values in PUBLIC position to exercise that path.
 */
async function ceremonyWithPublic(base: string, ...fieldNames: string[]): Promise<Tn> {
  const yamlPath = join(base, "tn.yaml");
  const first = await Tn.init(yamlPath, { cipher: "jwe", stdout: false });
  await first.close();
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown>;
  doc["public_fields"] = [...((doc["public_fields"] as string[]) ?? []), ...fieldNames];
  writeFileSync(yamlPath, stringifyYaml(doc));
  return Tn.init(yamlPath, { stdout: false });
}

test("seal rejects fragile public values up front", async () => {
  const base = makeBase();
  const client = await ceremonyWithPublic(base, "pv");
  try {
    // A public value a foreign JSON runtime would silently reformat must
    // be refused at seal time, not fail at a remote unseal. (JS cannot
    // express Python's 1.0 / -0.0 cases: the language itself collapses
    // them to the integer — see the collapse test below.)
    const fragile: unknown[] = [
      3.14, // non-integral float
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 2, // integer beyond 2**53-1
      -(Number.MAX_SAFE_INTEGER + 2),
      [1.5, 2], // float in list
      { amt: 5.5 }, // float in dict
    ];
    for (const pv of fragile) {
      await assert.rejects(
        client.seal("obj.rt.v1", { pv }, { receipt: false }),
        /public field/,
        `expected fragile-value rejection for ${String(pv)}`,
      );
    }
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("JS integral floats collapse to safe integers before the guard", async () => {
  const base = makeBase();
  const client = await ceremonyWithPublic(base, "pv");
  try {
    // The documented asymmetry vs Python: 1.0 IS 1 in JS (one number
    // type), so the value that reaches the wire is already the safe
    // integer form a foreign runtime cannot reformat.
    const sealed = await client.seal("obj.rt.v1", { pv: 1.0 }, { receipt: false });
    assert.equal(sealed.envelope["pv"], 1);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a ciphertext-shaped public field is refused at seal time", async () => {
  const base = makeBase();
  const client = await ceremonyWithPublic(base, "pv");
  try {
    await assert.rejects(
      client.seal("obj.rt.v1", { pv: { ciphertext: "zzz" } }, { receipt: false }),
      /ciphertext/,
    );
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});
