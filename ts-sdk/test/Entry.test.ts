// Entry class — shape, attributes, dunders, round-trip.
//
// Mirrors python/tests/test_entry.py case-for-case.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { inspect } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";

import { Tn } from "../src/tn.js";
import { Entry, VerifyError } from "../src/Entry.js";

async function setup(): Promise<{ tn: Tn; close: () => Promise<void> }> {
  const tn = await Tn.ephemeral({ stdout: false });
  return { tn, close: () => tn.close() };
}

// ---------------------------------------------------------------------
// Default Tn.read() yields Entry instances with typed attribute access
// ---------------------------------------------------------------------

test("read yields Entry instances with typed attribute access", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("order.created", { amount: 100, note: "first", currency: "USD" });

    const entries: Entry[] = [];
    for (const e of tn.read()) {
      if (e instanceof Entry && e.event_type === "order.created") {
        entries.push(e);
      }
    }
    assert.equal(entries.length, 1);
    const e = entries[0]!;

    assert.ok(e instanceof Entry);
    assert.equal(e.event_type, "order.created");
    assert.ok(e.timestamp instanceof Date);
    assert.equal(e.level, "info");
    assert.equal(e.message, null);
    assert.ok(e.sequence >= 1);
    assert.ok(e.did.startsWith("did:key:z"));
    assert.equal(e.event_id.length, 36);
    assert.ok(e.run_id);
    assert.ok(e.prev_hash.startsWith("sha256:"));
    assert.ok(e.row_hash.startsWith("sha256:"));
    assert.ok(e.signature);
  } finally {
    await close();
  }
});

test("user kwargs land in fields", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("order.created", { amount: 100, note: "first", currency: "USD" });

    let e: Entry | undefined;
    for (const x of tn.read()) {
      if (x instanceof Entry && x.event_type === "order.created") {
        e = x;
        break;
      }
    }
    assert.ok(e);
    assert.deepEqual(e!.fields, { amount: 100, note: "first", currency: "USD" });
    assert.equal("default" in e!.fields, false);
    assert.equal("signature" in e!.fields, false);
  } finally {
    await close();
  }
});

test("message is null when no positional message given", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("session.opened", {});
    let e: Entry | undefined;
    for (const x of tn.read()) {
      if (x instanceof Entry && x.event_type === "session.opened") {
        e = x;
        break;
      }
    }
    assert.ok(e);
    assert.equal(e!.message, null);
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// Human-readable dunders
// ---------------------------------------------------------------------

test("toString one-line format mirrors Python __str__", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("order.created", { amount: 100 });
    let e: Entry | undefined;
    for (const x of tn.read()) {
      if (x instanceof Entry && x.event_type === "order.created") {
        e = x;
        break;
      }
    }
    assert.ok(e);
    const s = e!.toString();
    assert.ok(s.includes("INFO"));
    assert.ok(s.includes("order.created"));
    assert.ok(s.includes("amount=100"));
    // millisecond precision (one period in the timestamp segment)
    const head = s.split(" ", 1)[0]!;
    assert.equal((head.match(/:/g) ?? []).length, 2);
    assert.equal((head.match(/\./g) ?? []).length, 1);
  } finally {
    await close();
  }
});

test("inspect output truncates long DIDs", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("x.y", {});
    let e: Entry | undefined;
    for (const x of tn.read()) {
      if (x instanceof Entry) {
        e = x;
        break;
      }
    }
    assert.ok(e);
    const r = inspect(e);
    assert.ok(r.startsWith("Entry("));
    assert.ok(r.includes("event_type="));
    // DID truncation: long DIDs get a "..." marker.
    if (e!.did.length > 30) {
      assert.ok(r.includes("..."));
    }
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// JSON round-trip
// ---------------------------------------------------------------------

test("toJSON round-trips through JSON.stringify", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("rt.event", { x: 1, y: "hi" });
    let e: Entry | undefined;
    for (const x of tn.read()) {
      if (x instanceof Entry && x.event_type === "rt.event") {
        e = x;
        break;
      }
    }
    assert.ok(e);
    const raw = JSON.stringify(e);
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(parsed["event_type"], "rt.event");
    const fields = parsed["fields"] as Record<string, unknown>;
    assert.equal(fields["x"], 1);
    assert.equal(fields["y"], "hi");
    assert.ok("row_hash" in parsed);
    assert.ok("did" in parsed);
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// raw=true returns the on-disk envelope dict (not Entry)
// ---------------------------------------------------------------------

test("raw=true yields envelope dict", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("evt.x", { k: 1 });
    const envs: Record<string, unknown>[] = [];
    for (const env of tn.read({ raw: true })) {
      const e = env as Record<string, unknown>;
      if (e["event_type"] === "evt.x") envs.push(e);
    }
    assert.equal(envs.length, 1);
    const env = envs[0]!;
    assert.equal(env instanceof Entry, false);
    // Envelope has the group-keyed ciphertext block intact.
    assert.ok("default" in env);
    const grp = env["default"] as Record<string, unknown>;
    assert.ok("ciphertext" in grp);
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// verify=true raises on tamper; verify="skip" handles validation
// failures.
// ---------------------------------------------------------------------

test("verify=true passes a clean log", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("a.x", {});
    tn.info("b.x", {});
    let n = 0;
    for (const _ of tn.read({ verify: true })) {
      n += 1;
    }
    assert.ok(n >= 2);
  } finally {
    await close();
  }
});

test("verify=true raises on tampered ciphertext", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("v.x", { payload: "orig" });
    const path = tn.logPath;
    const text = readFileSync(path, "utf8");
    const lines = text.split("\n");
    // Find and tamper the v.x line by mutating its row_hash.
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]!.includes('"v.x"')) continue;
      const obj = JSON.parse(lines[i]!) as Record<string, unknown>;
      obj["row_hash"] = "sha256:" + "0".repeat(64);
      lines[i] = JSON.stringify(obj);
      break;
    }
    writeFileSync(path, lines.join("\n"), "utf8");

    assert.throws(
      () => {
        for (const _ of tn.read({ verify: true })) {
          // consume
          void _;
        }
      },
      (e: unknown) => e instanceof VerifyError,
    );
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// where filter receives Entry by default; envelope dict with raw=true
// ---------------------------------------------------------------------

test("where receives Entry instances by default", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("filter.match", { n: 1 });
    tn.info("filter.skip", { n: 2 });
    const seen: Entry[] = [];
    for (const e of tn.read({
      where: (x) => (x instanceof Entry ? x.event_type === "filter.match" : false),
    })) {
      if (e instanceof Entry) seen.push(e);
    }
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.event_type, "filter.match");
  } finally {
    await close();
  }
});

test("where receives envelope dict when raw=true", async () => {
  const { tn, close } = await setup();
  try {
    tn.info("raw.match", { n: 1 });
    tn.info("raw.skip", { n: 2 });
    const seen: Record<string, unknown>[] = [];
    for (const env of tn.read({
      raw: true,
      where: (x) => {
        const r = x as Record<string, unknown>;
        return r["event_type"] === "raw.match";
      },
    })) {
      seen.push(env as Record<string, unknown>);
    }
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!["event_type"], "raw.match");
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------
// Entry.fromRaw constructs from {envelope, plaintext, valid}
// ---------------------------------------------------------------------

test("Entry.fromRaw constructor", () => {
  const raw = {
    envelope: {
      event_type: "x.y",
      timestamp: "2026-05-08T03:30:20.184000Z",
      level: "info",
      did: "did:key:zABC123",
      event_id: "abc-123",
      sequence: 1,
      prev_hash: "sha256:000",
      row_hash: "sha256:111",
      signature: "sig",
      default: { ciphertext: "...", field_hashes: {} },
    },
    plaintext: {
      default: { amount: 100, run_id: "rid-1" },
    },
    valid: { signature: true, row_hash: true, chain: true },
  };
  const e = Entry.fromRaw(raw);
  assert.equal(e.event_type, "x.y");
  assert.deepEqual(e.fields, { amount: 100 }); // run_id hoisted to top
  assert.equal(e.run_id, "rid-1");
  assert.equal(e.did, "did:key:zABC123");
  assert.equal(e.row_hash, "sha256:111");
});
