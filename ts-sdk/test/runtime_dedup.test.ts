/**
 * Per-emit address dedup tests — mirrors python/tests/test_runtime_dedup.py.
 *
 * Contract: per emit, each unique resolved sink address is written
 * at most once. Handlers that return null from resolved_address opt
 * out of dedup and always fire.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { FileHandler } from "../src/handlers/file.js";
import { StdoutHandler } from "../src/handlers/stdout.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tn-ts-dedup-"));
}

class CountingHandler {
  readonly name: string;
  private readonly _addr: string | null;
  calls = 0;

  constructor(name: string, address: string | null) {
    this.name = name;
    this._addr = address;
  }

  accepts(): boolean {
    return true;
  }

  resolved_address(): string | null {
    return this._addr;
  }

  emit(): void {
    this.calls++;
  }

  close(): void {}
}

// ---------------------------------------------------------------------------
// resolved_address() on shipping handlers
// ---------------------------------------------------------------------------

test("FileHandler.resolved_address is the absolute resolved path", () => {
  const td = tmp();
  try {
    const h = new FileHandler("h", join(td, "log.ndjson"));
    const addr = h.resolved_address();
    assert.ok(addr, "resolved_address should be a non-empty string");
    // Absolute path. Cross-platform check: starts with / or drive letter.
    assert.ok(addr.startsWith("/") || /^[A-Za-z]:/.test(addr));
    assert.ok(addr.endsWith("log.ndjson"));
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("two FileHandlers at same path share an address", () => {
  const td = tmp();
  try {
    const a = new FileHandler("a", join(td, "shared.ndjson"));
    const b = new FileHandler("b", join(td, "shared.ndjson"));
    assert.equal(a.resolved_address(), b.resolved_address());
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("two FileHandlers at different paths have different addresses", () => {
  const td = tmp();
  try {
    const a = new FileHandler("a", join(td, "x.ndjson"));
    const b = new FileHandler("b", join(td, "y.ndjson"));
    assert.notEqual(a.resolved_address(), b.resolved_address());
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("StdoutHandler default has the bare sentinel", () => {
  const h = new StdoutHandler();
  assert.equal(h.resolved_address(), "<stdout>");
});

test("StdoutHandler with custom write uses an id-keyed sentinel", () => {
  const buf: string[] = [];
  const sink = (s: string) => {
    buf.push(s);
  };
  const h = new StdoutHandler({ write: sink });
  const addr = h.resolved_address();
  assert.match(addr, /^<stream:\d+>$/);
});

test("two StdoutHandlers sharing one custom write share an address", () => {
  const sink = (_s: string) => {};
  const a = new StdoutHandler({ write: sink });
  const b = new StdoutHandler({ write: sink });
  assert.equal(a.resolved_address(), b.resolved_address());
});

// ---------------------------------------------------------------------------
// Per-emit dedup loop behavior
// ---------------------------------------------------------------------------

function fanout(handlers: { accepts(): boolean; resolved_address(): string | null; emit(env: Record<string, unknown>, line: string): void }[]) {
  const env = { event_id: "e1", event_type: "x", level: "info" };
  const seen = new Set<string>();
  for (const h of handlers) {
    if (!h.accepts()) continue;
    const addr = h.resolved_address();
    if (addr !== null) {
      if (seen.has(addr)) continue;
      seen.add(addr);
    }
    h.emit(env, '{"x":1}\n');
  }
}

test("two handlers at same address — only first writes", () => {
  const a = new CountingHandler("a", "/tmp/log");
  const b = new CountingHandler("b", "/tmp/log");
  fanout([a, b]);
  assert.equal(a.calls, 1);
  assert.equal(b.calls, 0);
});

test("two handlers at different addresses both write", () => {
  const a = new CountingHandler("a", "/tmp/a");
  const b = new CountingHandler("b", "/tmp/b");
  fanout([a, b]);
  assert.equal(a.calls, 1);
  assert.equal(b.calls, 1);
});

test("three handlers, two at same address", () => {
  const a = new CountingHandler("a", "/tmp/x");
  const b = new CountingHandler("b", "/tmp/y");
  const c = new CountingHandler("c", "/tmp/x");
  fanout([a, b, c]);
  assert.equal(a.calls, 1);
  assert.equal(b.calls, 1);
  assert.equal(c.calls, 0);
});

test("handlers with null address always write", () => {
  const a = new CountingHandler("a", "/tmp/x");
  const b = new CountingHandler("b", null);
  const c = new CountingHandler("c", null);
  const d = new CountingHandler("d", "/tmp/x");
  fanout([a, b, c, d]);
  assert.equal(a.calls, 1);
  assert.equal(b.calls, 1);
  assert.equal(c.calls, 1);
  assert.equal(d.calls, 0);
});

test("dedup state resets per emit", () => {
  const a = new CountingHandler("a", "/tmp/x");
  const b = new CountingHandler("b", "/tmp/x");
  fanout([a, b]); // emit 1
  fanout([a, b]); // emit 2 — fresh dedup state
  assert.equal(a.calls, 2);
  assert.equal(b.calls, 0);
});

test("two stdout handlers sharing a custom sink dedup to one write", () => {
  const buf: string[] = [];
  const sink = (s: string) => {
    buf.push(s);
  };
  const a = new StdoutHandler({ name: "a", write: sink });
  const b = new StdoutHandler({ name: "b", write: sink });
  fanout([a, b]);
  // Only one write landed in buf.
  assert.equal(buf.length, 1);
});
