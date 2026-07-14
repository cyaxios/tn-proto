// tn.seal / tn.unseal round-trip and verification tests.
//
// TS port of python/tests/test_seal_unseal.py (the normative suite).
// Same substance: wire shape + standalone conventions, source shapes,
// raw triple, verify honesty, tamper matrix, malformed matrix, aad
// binding, receipt surface, chain isolation, cross-ceremony opens
// (enrolled peer / unenrolled peer / asRecipient), rotation walks, and
// the fragile-public-value guard.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { x25519 } from "@noble/curves/ed25519";

import { Tn, VerifyError } from "../src/tn.js";
import {
  SealedObject,
  SealedObjectError,
  unsealWithRuntime,
  type SealedTriple,
  type UnsealSource,
} from "../src/seal.js";
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

test("unseal round-trips a sealed object in the sealing ceremony", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal(
      "obj.invoice.v1",
      { amount: 9800, customer: "acme" },
      { receipt: false },
    );
    const entry = (await client.unseal(sealed)) as Entry;
    assert.equal(entry.event_type, "obj.invoice.v1");
    // exact: the tn_sealed wire marker must NOT leak into user fields
    assert.deepEqual(entry.fields, { amount: 9800, customer: "acme" });
    assert.equal(entry.sequence, 0);
    assert.equal(entry.prev_hash, "");
    assert.equal(entry.device_identity, sealed.deviceIdentity);
    assert.deepEqual(entry.hidden_groups, []);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal accepts every source shape (SealedObject / string / object)", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const asSealed = (await client.unseal(sealed)) as Entry;
    const asString = (await client.unseal(String(sealed))) as Entry;
    const asObject = (await client.unseal(
      JSON.parse(String(sealed)) as Record<string, unknown>,
    )) as Entry;
    for (const e of [asSealed, asString, asObject]) {
      assert.equal(e.fields["x"], 1);
    }
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal raw: true returns the {envelope, plaintext, valid} triple", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const triple = (await client.unseal(sealed, { raw: true })) as SealedTriple;
    assert.deepEqual(Object.keys(triple).sort(), ["envelope", "plaintext", "valid"]);
    assert.equal(triple.envelope["row_hash"], sealed.rowHash);
    // the raw envelope stays wire-faithful (keeps the tn_sealed marker)
    assert.equal(triple.envelope["tn_sealed"], 1);
    assert.deepEqual(triple.plaintext["default"], { x: 1 });
    assert.equal(triple.valid.signature, true);
    assert.equal(triple.valid.row_hash, true);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal verify: false honestly reports both checks unverified", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const triple = (await client.unseal(sealed, { verify: false, raw: true })) as SealedTriple;
    assert.deepEqual(triple.valid, { signature: false, row_hash: false });
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal raises VerifyError on a tampered public field", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const tampered = { ...sealed.envelope, tn_sealed: 2 };
    await assert.rejects(client.unseal(tampered), VerifyError);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal raises VerifyError on tampered ciphertext", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const tampered = JSON.parse(String(sealed)) as Record<string, unknown>;
    const block = tampered["default"] as Record<string, unknown>;
    const ct = String(block["ciphertext"]);
    block["ciphertext"] = ct.slice(0, -4) + (ct.endsWith("AAAA") ? "BBBB" : "AAAA");
    await assert.rejects(client.unseal(tampered), VerifyError);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal on a swapped signature fails only the signature check", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const other = await client.seal("obj.other.v1", { y: 2 }, { receipt: false });
    // a validly-encoded signature from a different object: row_hash still
    // recomputes, so only the signature check trips
    const tampered = { ...sealed.envelope, signature: other.envelope["signature"] };
    await assert.rejects(
      client.unseal(tampered),
      (e: unknown) =>
        e instanceof VerifyError &&
        e.failed_checks.includes("signature") &&
        !e.failed_checks.includes("row_hash"),
    );
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal verify: false returns an Entry despite tamper", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    const tampered = { ...sealed.envelope, tn_sealed: 2 };
    const entry = (await client.unseal(tampered, { verify: false })) as Entry;
    assert.equal(entry.event_type, "obj.test.v1");
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal aad binds into the row hash and round-trips", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const sealed = await client.seal(
      "obj.test.v1",
      { x: 1 },
      { receipt: false, aad: { case: "A-17" } },
    );
    assert.ok("tn_aad" in sealed.envelope); // authenticated public echo present
    const entry = (await client.unseal(sealed)) as Entry; // aadBytesFor reconstructs binding
    assert.equal(entry.fields["x"], 1);
    const tampered = {
      ...sealed.envelope,
      tn_aad: String(sealed.envelope["tn_aad"]).replace("A-17", "B-99"),
    };
    await assert.rejects(client.unseal(tampered), VerifyError); // echo is bound into row_hash
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("unseal raises SealedObjectError for every malformed source shape", async () => {
  const base = makeBase();
  const client = await initClient(base);
  try {
    const badSources: UnsealSource[] = [
      "not json at all", // not-json
      "[1,2,3]", // json-array
      "{}", // empty-object
      { event_type: "x" }, // missing-most-keys
      // four original keys present but timestamp/event_id/sequence
      // missing — the strict shape requires all seven.
      { device_identity: "d", event_type: "x", row_hash: "h", signature: "s" },
      42 as unknown as UnsealSource, // unsupported source type
      null as unknown as UnsealSource, // unsupported source type
    ];
    for (const bad of badSources) {
      await assert.rejects(
        client.unseal(bad),
        SealedObjectError,
        `expected SealedObjectError for ${JSON.stringify(bad)}`,
      );
    }
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Cross-ceremony opens (enrolled peer / unenrolled peer / asRecipient)
// ---------------------------------------------------------------------------

/** Alice seals into 'partners'; Bob holds a reader key for that group only.
 *
 * Bob's own ceremony has NO 'partners' group, so unseal's pass 1
 * (own-ceremony group ciphers) structurally cannot open that block —
 * only the pass-2 keystore key-bag can. The sealed object also carries
 * an Alice-only 'default' block ('note'), making the enrolled-peer
 * open a real partial open.
 *
 * JWE decrypt needs only partners.jwe.mykey in Bob's keystore (the
 * ECDH-ES ephemeral travels in the envelope header), which is exactly
 * the file the real enrolment flow's mykey mint lands there.
 *
 * Returns `{sealed, bob, bobKeystore}` with Bob's ceremony ACTIVE.
 * `group` defaults to "partners"; the Object.prototype-named regression
 * below passes "toString".
 */
async function twoPeer(
  base: string,
  group = "partners",
): Promise<{
  sealed: SealedObject;
  bob: Tn;
  bobKeystore: string;
}> {
  const aliceDir = join(base, "alice");
  const bobDir = join(base, "bob");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(bobDir, { recursive: true });

  let alice = await initClient(aliceDir, "jwe");
  await alice.admin.ensureGroup(group, { cipher: "jwe", fields: ["body"] });
  // Re-open so the freshly-persisted group + field routing load from yaml.
  await alice.close();
  alice = await Tn.init(join(aliceDir, "tn.yaml"), { stdout: false });

  const bob = await initClient(bobDir, "jwe");
  const bobKeystore = cfgOf(bob).keystorePath;
  // Bob's reader key for the group — the mykey mint of the enrolment flow.
  const bobPriv = x25519.utils.randomPrivateKey();
  writeFileSync(join(bobKeystore, `${group}.jwe.mykey`), Buffer.from(bobPriv));
  await alice.admin.addRecipient(group, {
    recipientDid: bob.did,
    publicKey: x25519.getPublicKey(bobPriv),
    unsafeUnverified: true, // raw DID-plus-key path (no enrollment proof)
  });

  // body -> the named group (routed), note -> default (unrouted fallback)
  const sealed = await alice.seal(
    "obj.memo.v1",
    { body: "for bob's eyes", note: "alice private" },
    { receipt: false },
  );
  await alice.close();
  assert.ok(
    group in sealed.envelope && "default" in sealed.envelope,
    `setup must seal two group blocks, got: ${Object.keys(sealed.envelope).sort()}`,
  );
  return { sealed, bob, bobKeystore };
}

test("an enrolled peer opens exactly their slice (keystore key-bag walk)", async () => {
  const base = makeBase();
  const { sealed, bob } = await twoPeer(base);
  try {
    // Structural guard: Bob's ceremony has no 'partners' group, so pass 1
    // (own-ceremony group ciphers) cannot fire for that block; an open
    // below proves the pass-2 keystore key-bag walk did it.
    assert.ok(!cfgOf(bob).groups.has("partners"));
    const entry = (await bob.unseal(sealed)) as Entry;
    // partial open: exactly Bob's slice; Alice's private block stays sealed
    assert.deepEqual(entry.fields, { body: "for bob's eyes" });
    assert.ok(entry.hidden_groups.includes("default"));
  } finally {
    await bob.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a group named like an Object.prototype member still opens (pass-2 walk)", async () => {
  const base = makeBase();
  const { sealed, bob, bobKeystore } = await twoPeer(base);
  try {
    // "toString" is inherited by every plain object, so a naive `gname in
    // plaintext` check would misread such a block as already open and
    // skip the key-bag walk entirely. The TS runtime cannot author a
    // group with that name today (its yaml persistence chokes on
    // prototype-named keys), but a foreign SDK can — simulate the wire by
    // renaming the block and Bob's reader-key file. The rename breaks the
    // row-hash binding by design, so open with verify off: the walk under
    // test runs regardless of verification.
    const env = JSON.parse(sealed.rawJson) as Record<string, unknown>;
    env["toString"] = env["partners"];
    delete env["partners"];
    writeFileSync(
      join(bobKeystore, "toString.jwe.mykey"),
      readFileSync(join(bobKeystore, "partners.jwe.mykey")),
    );
    const entry = (await bob.unseal(env, { verify: false })) as Entry;
    assert.deepEqual(entry.fields, { body: "for bob's eyes" });
    assert.ok(entry.hidden_groups.includes("default"));
  } finally {
    await bob.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("an unenrolled peer gets the verified public frame, not an error", async () => {
  const base = makeBase();
  const aliceDir = join(base, "alice");
  const carolDir = join(base, "carol");
  mkdirSync(aliceDir, { recursive: true });
  mkdirSync(carolDir, { recursive: true });
  const alice = await initClient(aliceDir, "jwe");
  const sealed = await alice.seal("obj.memo.v1", { body: "private" }, { receipt: false });
  await alice.close();

  const carol = await initClient(carolDir, "jwe");
  try {
    const entry = (await carol.unseal(sealed)) as Entry; // no fitting key -> no exception
    assert.equal(entry.event_type, "obj.memo.v1");
    assert.ok(!("body" in entry.fields));
    assert.ok(entry.hidden_groups.includes("default"));
  } finally {
    await carol.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("asRecipient opens a single kit directory without an active ceremony", async () => {
  const base = makeBase();
  const { sealed, bob, bobKeystore } = await twoPeer(base);
  await bob.close();
  try {
    // no active ceremony needed: bring-your-own-kit against Bob's
    // keystore, opening only the named group
    const entry = (await unsealWithRuntime(null, sealed, {
      asRecipient: bobKeystore,
      group: "partners",
    })) as Entry;
    assert.deepEqual(entry.fields, { body: "for bob's eyes" });
    assert.ok(entry.hidden_groups.includes("default"));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("asRecipient over a directory with no key for the group throws", async () => {
  const base = makeBase();
  const { sealed, bob, bobKeystore } = await twoPeer(base);
  await bob.close();
  try {
    await assert.rejects(
      unsealWithRuntime(null, sealed, { asRecipient: join(base, "alice"), group: "partners" }),
      /no recipient key found/,
    );
    // ...and a group absent from the envelope opens nothing, loads nothing.
    const entry = (await unsealWithRuntime(null, sealed, {
      asRecipient: bobKeystore,
      group: "absent-group",
    })) as Entry;
    assert.deepEqual(entry.fields, {});
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Cipher coverage + rotation walks
// ---------------------------------------------------------------------------

test("seal fails closed when a jwe group has no publisher recipients", async () => {
  const base = makeBase();
  const client = await initClient(base, "jwe");
  try {
    rmSync(join(cfgOf(client).keystorePath, "default.jwe.recipients"));

    await assert.rejects(
      client.seal("obj.test.v1", { x: 1 }, { receipt: false }),
      /jwe: no recipients file for group "default"/,
    );
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal fails closed when a btn group has no publisher state", async () => {
  const base = makeBase();
  const client = await initClient(base, "btn");
  try {
    const group = (
      client as unknown as {
        _rt: { keystore: { groups: Map<string, { stateBytes?: Uint8Array }> } };
      }
    )._rt.keystore.groups.get("default");
    assert.ok(group);
    group.stateBytes = undefined;

    await assert.rejects(
      client.seal("obj.test.v1", { x: 1 }, { receipt: false }),
      /btn: no state file in this keystore/,
    );
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal/unseal round-trips on a btn ceremony alongside the wasm log path", async () => {
  const base = makeBase();
  const client = await initClient(base, "btn");
  try {
    const sealed = await client.seal("obj.test.v1", { x: 1 }); // receipt on: TS-side write
    const row = client.log("probe.v1", { y: 2 }); // the wasm-dispatched log path
    assert.ok(row.sequence >= 1);
    const entry = (await client.unseal(sealed)) as Entry;
    assert.equal(entry.fields["x"], 1);
    // both log surfaces still verify after the TS-side btn seal:
    // the probe row chains into the main ceremony log...
    const main = [...client.read({ verify: "raise" })] as Entry[];
    assert.ok(main.some((e) => e.event_type === "probe.v1"));
    // ...and the seal receipt chains into the admin/protocol-events log.
    const adminLog = resolveAdminLogPath(cfgOf(client));
    const receipts = [
      ...client.read({ selector: "tn.object.sealed", log: adminLog, verify: "raise" }),
    ] as Entry[];
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0]!.fields["object_id"], sealed.rowHash);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("seal/unseal round-trips on a hibe ceremony", async () => {
  const base = makeBase();
  const client = await initClient(base, "hibe");
  try {
    const sealed = await client.seal("obj.gov.v1", { secret: "s3" }, { receipt: false });
    const entry = (await client.unseal(sealed)) as Entry;
    assert.deepEqual(entry.fields, { secret: "s3" });
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a pre-rotation object still opens after a jwe rotation", async () => {
  const base = makeBase();
  const client = await initClient(base, "jwe");
  try {
    // rotation archives the old reader key as <group>.jwe.mykey.revoked.<ts>,
    // and the decrypt walk trials those priors (active key first, then each
    // revoked key), so a pre-rotation object still opens.
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    await client.admin.rotate("default");
    const entry = (await client.unseal(sealed)) as Entry;
    assert.equal(entry.fields["x"], 1);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a pre-rotation object still opens after a btn rotation", async () => {
  const base = makeBase();
  const client = await initClient(base, "btn");
  try {
    // btn sibling: rotation archives the prior self-kit as
    // <group>.btn.mykit.revoked.<ts>, and the decrypt walk trials
    // [active, ...archived] kits.
    const sealed = await client.seal("obj.test.v1", { x: 1 }, { receipt: false });
    await client.admin.rotate("default");
    const entry = (await client.unseal(sealed)) as Entry;
    assert.equal(entry.fields["x"], 1);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Client JSON round-trip integrity (row_hash across transports)
// ---------------------------------------------------------------------------

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

test("public field values survive object and string transport", async () => {
  const base = makeBase();
  const client = await ceremonyWithPublic(base, "pv");
  try {
    const values: unknown[] = [
      42,
      "hello",
      true,
      null,
      [1, 2, 3],
      { a: 1, b: 2 },
      "café — naïve",
      "",
      Number.MAX_SAFE_INTEGER, // 2**53 - 1
    ];
    for (const value of values) {
      const sealed = await client.seal("obj.rt.v1", { pv: value }, { receipt: false });
      const fromObject = (await client.unseal(
        JSON.parse(JSON.stringify(sealed.envelope)) as Record<string, unknown>,
      )) as Entry;
      const fromString = (await client.unseal(String(sealed))) as Entry;
      assert.deepEqual(fromObject.fields["pv"], value);
      assert.deepEqual(fromString.fields["pv"], value);
    }
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

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
    const entry = (await client.unseal(String(sealed))) as Entry;
    assert.equal(entry.fields["pv"], 1);
  } finally {
    await client.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("a fragile value is safe inside an encrypted group", async () => {
  const base = makeBase();
  const client = await initClient(base, "jwe");
  try {
    // The escape hatch the guard points to: a non-integral float carried
    // in an ENCRYPTED group (the default) round-trips fine, because group
    // fields are hashed as opaque ciphertext, not as str(value).
    const sealed = await client.seal("obj.rt.v1", { price: 19.5 }, { receipt: false });
    const fromObject = (await client.unseal(
      JSON.parse(JSON.stringify(sealed.envelope)) as Record<string, unknown>,
    )) as Entry;
    assert.equal(fromObject.fields["price"], 19.5);
    const fromString = (await client.unseal(String(sealed))) as Entry;
    assert.equal(fromString.fields["price"], 19.5);
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
