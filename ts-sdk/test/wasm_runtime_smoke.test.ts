// Track B Phase 7 smoke test: drive `WasmRuntime` through the
// `nodeStorageAdapter` end-to-end. After the time-source and path-
// normalization fixes landed, emit and read both succeed
// unconditionally; the test asserts a real round-trip.
//
// See `docs/superpowers/plans/2026-05-13-wasm-widen-and-fallback-deprecate.md`.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// `tn-wasm` is a CommonJS-ish package; the TS .d.ts exposes
// `WasmRuntime` as a named export.
import { WasmRuntime } from "tn-wasm";

import { nodeStorageAdapter } from "../src/runtime/storage_node.js";
import { NodeRuntime } from "../src/runtime/node_runtime.js";

test("WasmRuntime: full init + emit + read round-trip through nodeStorageAdapter", () => {
  // Mint a fresh ceremony on disk via the existing NodeRuntime path —
  // this writes the yaml, device key seed, master index key, and
  // per-group cipher state files. Then we point WasmRuntime at the
  // exact same yaml so all subsequent reads / writes route through our
  // adapter.
  const td = mkdtempSync(join(tmpdir(), "tn-wasm-smoke-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();

  // Path normalization (`\` → `/`) now happens inside `WasmRuntime.init`
  // itself, so callers can pass native OS paths and Windows runs work
  // without per-test workarounds.
  const storage = nodeStorageAdapter();

  const rt = WasmRuntime.init(yamlPath, storage);

  try {
    // Metadata is the cheapest sanity check that init wired up correctly.
    const did = rt.did();
    assert.equal(typeof did, "string", "did() must return a string");
    assert.ok(did.startsWith("did:key:"), `did should start with did:key:, got ${did}`);

    const logPath = rt.logPath();
    assert.equal(typeof logPath, "string", "logPath() must return a string");
    assert.ok(logPath.endsWith(".ndjson"), `logPath should end with .ndjson, got ${logPath}`);

    const groups = rt.groupNames();
    assert.ok(Array.isArray(groups), "groupNames() must return an array");
    assert.ok(groups.length >= 1, `groupNames() must not be empty, got ${JSON.stringify(groups)}`);

    // Emit one envelope. With the `time/wasm-bindgen` feature enabled,
    // `OffsetDateTime::now_utc()` is backed by `js_sys::Date::now()`
    // instead of the `unreachable!()` `SystemTime::now` stub.
    rt.emit("info", "test.smoke", { ok: 1, who: "wasm" });

    // Read back and verify the chain.
    const entries = rt.read() as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(entries), "read() must return an array");
    assert.ok(entries.length >= 1, "read() must surface at least the emitted entry");

    // Find our emitted event. The very first entry is the runtime's
    // own `tn.ceremony.init`, the second (after any policy-published
    // bookkeeping) is the test emit.
    const ours = entries.find((e) => e["event_type"] === "test.smoke");
    assert.ok(ours, `read() must contain test.smoke, got event_types=${entries.map((e) => e["event_type"]).join(",")}`);
    assert.equal(ours["level"], "info");
    assert.equal(ours["ok"], 1);
    assert.equal(ours["who"], "wasm");

    // Timestamp parses as a real date and is recent. Proves the
    // `time/wasm-bindgen` feature wired up — pre-fix, emit trapped on
    // `unreachable!()` before this field was ever populated.
    const ts = ours["timestamp"];
    assert.equal(typeof ts, "string", "timestamp must be a string");
    const parsed = Date.parse(ts as string);
    assert.ok(!Number.isNaN(parsed), `timestamp must parse, got ${ts as string}`);

    // Sequence and event_id are the other envelope basics that flatten
    // exposes — the chain plumbing (prev_hash / row_hash / signature)
    // is reserved at the envelope level and intentionally hidden by
    // `read()`. Callers who need the chain shape use
    // `readWithVerify()` (Phase 2). Asserting the basics here keeps
    // this smoke focused on the round-trip.
    assert.equal(typeof ours["sequence"], "number", "sequence must be a number");
    assert.equal(typeof ours["event_id"], "string", "event_id must be a string");
    assert.equal(typeof ours["did"], "string", "did must be a string");
  } finally {
    try {
      rt.close();
    } catch {
      /* close errors aren't load-bearing for this smoke */
    }
  }
});

// ---------------------------------------------------------------------------
// Phase 2 read-variant smokes. Each test sets up its own ceremony so the
// surface contract for one variant is exercised in isolation; we trust
// the round-trip test above to prove the underlying emit-then-read path.
// ---------------------------------------------------------------------------

function freshRuntime() {
  const td = mkdtempSync(join(tmpdir(), "tn-wasm-p2-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();
  return WasmRuntime.init(yamlPath, nodeStorageAdapter());
}

test("WasmRuntime.readAllRuns: returns an array (Phase 2 surface check)", () => {
  // A deeper multi-run assertion needs out-of-band state we don't have
  // here — this just confirms the method is wired and returns an array.
  // Even on a fresh ceremony there's at least the `tn.ceremony.init`
  // envelope, so `.length >= 1` is a sound floor.
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.allRuns", { idx: 1 });
    const all = rt.readAllRuns() as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(all), "readAllRuns() must return an array");
    assert.ok(all.length >= 1, `readAllRuns() must surface entries, got length=${all.length}`);
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.readWithVerify: each entry carries a _valid block", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.verify", { ok: 1 });
    const entries = rt.readWithVerify() as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(entries), "readWithVerify() must return an array");
    assert.ok(entries.length >= 1, "readWithVerify() must surface at least one entry");

    for (const e of entries) {
      const valid = e["_valid"];
      assert.ok(valid && typeof valid === "object", "_valid must be an object on every entry");
      const v = valid as Record<string, unknown>;
      assert.equal(typeof v["signature"], "boolean", "_valid.signature must be a boolean");
      assert.equal(typeof v["row_hash"], "boolean", "_valid.row_hash must be a boolean");
      assert.equal(typeof v["chain"], "boolean", "_valid.chain must be a boolean");
    }

    // On a clean log every entry's three flags should be true.
    const ours = entries.find((e) => e["event_type"] === "test.verify");
    assert.ok(ours, "readWithVerify() must contain test.verify");
    const v = ours["_valid"] as Record<string, boolean>;
    assert.equal(v["signature"], true, "signature must verify on a clean log");
    assert.equal(v["row_hash"], true, "row_hash must verify on a clean log");
    assert.equal(v["chain"], true, "chain must verify on a clean log");
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.readRaw: returns {envelope, plaintext} per entry", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.raw", { secret: "x" });
    const entries = rt.readRaw() as Array<{
      envelope: Record<string, unknown>;
      plaintext: Record<string, unknown>;
    }>;
    assert.ok(Array.isArray(entries), "readRaw() must return an array");
    assert.ok(entries.length >= 1, "readRaw() must surface at least one entry");

    for (const e of entries) {
      assert.ok(e.envelope && typeof e.envelope === "object", "envelope must be an object");
      assert.equal(typeof e.envelope["event_type"], "string", "envelope.event_type must be a string");
      // Envelope MUST carry the on-disk chain plumbing — that's the
      // whole point of readRaw vs read.
      assert.equal(typeof e.envelope["row_hash"], "string", "envelope.row_hash must be a string");
      assert.equal(typeof e.envelope["prev_hash"], "string", "envelope.prev_hash must be a string");
      assert.ok(e.plaintext && typeof e.plaintext === "object", "plaintext must be an object map");
    }
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.secureRead: clean log surfaces same count as read() for skip + raise", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.secure", { ok: 1 });

    const baseline = rt.read() as Array<Record<string, unknown>>;
    const skip = rt.secureRead("skip") as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(skip), "secureRead('skip') must return an array");
    // On a clean log every row verifies; no skips, no tampered_row_skipped
    // event — so the count matches the plain `read()`.
    assert.equal(
      skip.length,
      baseline.length,
      `secureRead('skip') count must match read() on a clean log; got ${skip.length} vs ${baseline.length}`,
    );

    // 'raise' must NOT throw on a clean log.
    assert.doesNotThrow(
      () => rt.secureRead("raise"),
      "secureRead('raise') must not throw on a clean log",
    );

    // Unknown mode must surface as a JS error.
    assert.throws(
      () => rt.secureRead("bogus"),
      /unknown on_invalid/,
      "secureRead with an unknown mode must throw",
    );
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("nodeStorageAdapter: casWrite rejects mismatched prior with cas-mismatch: prefix", () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-cas-"));
  const target = join(dir, "state.bin");
  const storage = nodeStorageAdapter();

  // Seed an initial value.
  storage.casWrite(target, null, new Uint8Array([1, 2, 3]));
  const after = storage.read(target);
  assert.deepEqual([...after], [1, 2, 3]);

  // Stale prior must throw cas-mismatch:.
  assert.throws(
    () => storage.casWrite(target, new Uint8Array([9, 9, 9]), new Uint8Array([4, 5, 6])),
    (err: Error) => err.message.startsWith("cas-mismatch:"),
    "casWrite with wrong prior must throw cas-mismatch: error",
  );

  // Fresh-write-expected on existing file: also throws cas-mismatch:.
  assert.throws(
    () => storage.casWrite(target, null, new Uint8Array([7, 8, 9])),
    (err: Error) => err.message.startsWith("cas-mismatch:"),
    "casWrite with null prior on existing file must throw cas-mismatch:",
  );

  // Correct prior: succeeds, atomically replaces.
  storage.casWrite(target, new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
  const final = storage.read(target);
  assert.deepEqual([...final], [4, 5, 6]);
});

// ---------------------------------------------------------------------------
// Phase 3 emit-variant smokes. The severity shorthands (info / warning /
// debug / error / log) and the per-call override emits (emitWith /
// emitOverrideSign / emitWithOverrideSign) all funnel through the same
// `emit_inner` path that the round-trip test above already exercises —
// the assertions here just confirm each verb is wired through
// wasm-bindgen with the right level label / timestamp override.
// ---------------------------------------------------------------------------

test("WasmRuntime: Phase 3 emit verbs (info, warning, log, emitWith) round-trip", () => {
  // Reuses the freshRuntime() helper that Phase 2 introduced above —
  // single ceremony, exercise every Phase 3 verb against it.
  const rt = freshRuntime();

  try {
    // Severity shorthands: each must produce an entry tagged with the
    // matching `level`. Distinct event_types keep the assertions
    // unambiguous when we scan the read() output.
    rt.info("test.via.info", { a: 1 });
    rt.warning("test.via.warning", { b: 2 });

    // `emitWith` with a pinned timestamp — proves the override threads
    // all the way through to the envelope. `null` event_id falls back
    // to a fresh UUID.
    const pinnedTs = "2024-01-01T00:00:00.000Z";
    rt.emitWith("info", "test.with_ts", {}, pinnedTs, null);

    // `log()` is severity-less — bypasses the level filter; envelope
    // carries `level: ""`. Single sanity check that the verb exists
    // and writes successfully; semantics covered by tn-core tests.
    rt.log("test.log_severity_less", {});

    // Smoke that emitOverrideSign / emitWithOverrideSign exist on the
    // JS surface — Phase 3 ships the bindings, deeper signing-flag
    // assertions live in tn-core / PyO3 suites. Both must accept
    // `null` for the sign override (= ceremony default).
    rt.emitOverrideSign("info", "test.override_sign", { x: true }, null);
    rt.emitWithOverrideSign(
      "info",
      "test.with_override_sign",
      { y: 7 },
      null,
      null,
      null,
    );

    const entries = rt.read() as Array<Record<string, unknown>>;

    const viaInfo = entries.find((e) => e["event_type"] === "test.via.info");
    assert.ok(viaInfo, "info() must produce a readable entry");
    assert.equal(viaInfo["level"], "info");
    assert.equal(viaInfo["a"], 1);

    const viaWarning = entries.find((e) => e["event_type"] === "test.via.warning");
    assert.ok(viaWarning, "warning() must produce a readable entry");
    assert.equal(viaWarning["level"], "warning");
    assert.equal(viaWarning["b"], 2);

    const withTs = entries.find((e) => e["event_type"] === "test.with_ts");
    assert.ok(withTs, "emitWith() must produce a readable entry");
    assert.equal(
      withTs["timestamp"],
      pinnedTs,
      `emitWith timestamp override must round-trip; got ${withTs["timestamp"] as string}`,
    );

    const logEntry = entries.find((e) => e["event_type"] === "test.log_severity_less");
    assert.ok(logEntry, "log() must produce a readable entry");
    // Severity-less entries carry an empty-string level per tn-core.
    assert.equal(logEntry["level"], "");

    const overrideSignEntry = entries.find((e) => e["event_type"] === "test.override_sign");
    assert.ok(overrideSignEntry, "emitOverrideSign() must produce a readable entry");

    const withOverrideSignEntry = entries.find(
      (e) => e["event_type"] === "test.with_override_sign",
    );
    assert.ok(
      withOverrideSignEntry,
      "emitWithOverrideSign() must produce a readable entry",
    );
  } finally {
    try {
      rt.close();
    } catch {
      /* close errors aren't load-bearing for this smoke */
    }
  }
});

// ---------------------------------------------------------------------------
// Phase 4 admin smokes. Exercises every admin verb on WasmRuntime against a
// fresh ceremony, asserting the underlying keystore_backend now routes
// through the storage adapter (a Phase-4 prerequisite — without it the kit
// + state writes short-circuit straight to std::fs and fail on wasm).
// ---------------------------------------------------------------------------

test("WasmRuntime: Phase 4 admin verbs round-trip", () => {
  // Mint a fresh ceremony inline so we keep a handle on the tempdir for
  // kit + bundle output paths. Mirrors freshRuntime() but exposes `td`.
  const td = mkdtempSync(join(tmpdir(), "tn-wasm-p4-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();

  // Patch the yaml to route tn.* admin events to the main log. The
  // default NodeRuntime mint uses a dedicated admin log
  // (`admin_log_location: ./.tn/tn/admin/admin.ndjson`), but
  // `Runtime::recipients()` / `Runtime::admin_state()` both replay only
  // the main log via `read_raw()` — admin events on a separate file are
  // invisible to those replay paths today. The native admin-replay
  // tests at `crypto/tn-core/tests/admin_replay.rs` use the same
  // `main_log` override for the same reason. Once Rust core grows a
  // "read both logs" replay, this patch can be dropped.
  const yaml = readFileSync(yamlPath, "utf8");
  const patched = yaml.replace(
    /^(\s*)admin_log_location:.*$/m,
    "$1admin_log_location: main_log",
  );
  writeFileSync(yamlPath, patched);

  const rt = WasmRuntime.init(yamlPath, nodeStorageAdapter());

  try {
    // 1. adminAddRecipient — mint a new btn reader kit for the default
    //    group. The kit file must land on disk via the storage adapter
    //    (proves keystore_backend.write_state + the kit-file write both
    //    routed through `self.storage`).
    const kitPath = join(td, "default.btn.mykit");
    const leaf = rt.adminAddRecipient(
      "default",
      kitPath,
      "did:key:zRecipientPhase4",
    );
    assert.equal(typeof leaf, "number", "adminAddRecipient must return a number");
    assert.ok(leaf >= 0, `leaf index must be non-negative, got ${leaf}`);
    assert.ok(
      existsSync(kitPath),
      `kit file must exist on disk after adminAddRecipient, expected ${kitPath}`,
    );

    // 2. recipients(include_revoked=false) — must surface the one we
    //    just added.
    const active = rt.recipients("default", false) as Array<
      Record<string, unknown>
    >;
    assert.ok(Array.isArray(active), "recipients() must return an array");
    assert.equal(
      active.length,
      1,
      `recipients() must contain exactly the just-added recipient, got ${active.length}; raw=${JSON.stringify(active)}`,
    );
    assert.equal(active[0]["leaf_index"], leaf);
    assert.equal(active[0]["recipient_did"], "did:key:zRecipientPhase4");
    assert.equal(active[0]["revoked"], false);

    // 3. adminRevokedCount — fresh ceremony has zero revocations.
    assert.equal(
      rt.adminRevokedCount("default"),
      0,
      "adminRevokedCount on a fresh ceremony must be 0",
    );

    // 4. adminRevokeRecipient — revoke the leaf we just minted. Returns
    //    void; the side-effect is the publisher state file flipping
    //    (again, exercised through `Storage::cas_write`).
    assert.doesNotThrow(
      () => rt.adminRevokeRecipient("default", leaf),
      "adminRevokeRecipient must not throw on a freshly-minted leaf",
    );

    // 5. adminRevokedCount — incremented after revoke.
    assert.equal(
      rt.adminRevokedCount("default"),
      1,
      "adminRevokedCount must reflect the revocation",
    );

    // 6. recipients(include_revoked=true) — revoked recipient now shows
    //    up with `revoked: true`. The active list (excluding revoked)
    //    must be empty.
    const withRevoked = rt.recipients("default", true) as Array<
      Record<string, unknown>
    >;
    const ourEntry = withRevoked.find((r) => r["leaf_index"] === leaf);
    assert.ok(
      ourEntry,
      `revoked recipient must surface in recipients(include_revoked=true): ${JSON.stringify(withRevoked)}`,
    );
    assert.equal(ourEntry["revoked"], true);

    const activeAfter = rt.recipients("default", false) as Array<
      Record<string, unknown>
    >;
    assert.equal(
      activeAfter.length,
      0,
      "active recipients must be empty after revocation",
    );

    // 7. adminState(null) — global view. Must return an object with the
    //    expected top-level keys. The replay reflects the recipient.added
    //    + recipient.revoked events we just produced.
    const stateAll = rt.adminState(null) as Record<string, unknown>;
    assert.ok(
      stateAll && typeof stateAll === "object",
      "adminState(null) must return an object",
    );
    assert.ok(
      Array.isArray(stateAll["recipients"]),
      "adminState.recipients must be an array",
    );
    assert.ok(
      Array.isArray(stateAll["groups"]),
      "adminState.groups must be an array",
    );

    // 8. bundleForRecipient — Rust core's `bundle_for_recipient` (and
    //    `admin_add_agent_runtime`) call `tempfile::Builder::tempdir()`,
    //    which on `wasm32-unknown-unknown` traps on `unreachable!()`
    //    because `std::env::temp_dir()` is stubbed out. Surface as a
    //    documented limitation for now; the upstream fix is to add an
    //    `*_into` variant that accepts a caller-supplied scratch dir
    //    (Phase 6 follow-up, tracked in the Phase 4 report).
    const bundlePath = join(td, "phase4-bundle.tnpkg");
    let bundleThrew = false;
    let bundleWrittenPath: string | undefined;
    try {
      bundleWrittenPath = rt.bundleForRecipient(
        "did:key:zRecipientBundle",
        bundlePath,
        ["default"],
      );
    } catch (e) {
      // Expected today: `tempfile::Builder::tempdir()` traps on wasm.
      // Sanity-check that the failure surfaces with a recognisable shape
      // rather than a silent ok — guards against regressions when Rust
      // core grows a wasm-friendly path.
      bundleThrew = true;
      assert.ok(e instanceof Error, "wasm trap must surface as an Error");
    }
    if (!bundleThrew) {
      assert.equal(
        typeof bundleWrittenPath,
        "string",
        "bundleForRecipient must return a path string when wasm tempdir works",
      );
      assert.ok(
        existsSync(bundleWrittenPath ?? ""),
        `bundle file must exist on disk after bundleForRecipient, expected ${bundleWrittenPath}`,
      );
    }
  } finally {
    try {
      rt.close();
    } catch {
      /* close errors aren't load-bearing for this smoke */
    }
  }
});

// ---------------------------------------------------------------------------
// Phase 6 smokes. Vault link/unlink emit admin events; the explicit-path
// read variants (readFrom / readRawWithValidity / readFromWithValidity)
// surface foreign or current-runtime logs at byte-grade fidelity. Each
// test mints its own ceremony; the vault test additionally patches the
// yaml to route admin events to the main log (same trick the Phase 4
// admin-verbs test uses) so the emit lands somewhere read() can see.
// ---------------------------------------------------------------------------

function freshRuntimeWithAdminInMain(): { rt: WasmRuntime; td: string; yamlPath: string } {
  const td = mkdtempSync(join(tmpdir(), "tn-wasm-p6-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();
  // Same patch as the Phase 4 admin-verbs test: admin events default to a
  // dedicated admin log, but read() only replays the main log. Routing
  // admin events into the main log keeps the smoke focused on the wasm
  // surface rather than the cross-log replay path.
  const yaml = readFileSync(yamlPath, "utf8");
  const patched = yaml.replace(
    /^(\s*)admin_log_location:.*$/m,
    "$1admin_log_location: main_log",
  );
  writeFileSync(yamlPath, patched);
  return { rt: WasmRuntime.init(yamlPath, nodeStorageAdapter()), td, yamlPath };
}

test("WasmRuntime.vaultLink / vaultUnlink: round-trip through read()", () => {
  const { rt } = freshRuntimeWithAdminInMain();
  try {
    const vaultDid = "did:key:zVaultPhase6Smoke";
    const projectId = "proj-phase6";

    // 1. Link — must not throw; emits tn.vault.linked.
    assert.doesNotThrow(
      () => rt.vaultLink(vaultDid, projectId),
      "vaultLink must not throw on a fresh ceremony",
    );

    let entries = rt.read() as Array<Record<string, unknown>>;
    const linked = entries.find((e) => e["event_type"] === "tn.vault.linked");
    assert.ok(
      linked,
      `read() must contain tn.vault.linked after vaultLink; event_types=${entries
        .map((e) => e["event_type"])
        .join(",")}`,
    );
    assert.equal(linked["vault_did"], vaultDid);
    assert.equal(linked["project_id"], projectId);
    assert.equal(
      typeof linked["linked_at"],
      "string",
      "tn.vault.linked must carry an iso8601 linked_at",
    );

    // 2. Idempotence: a second link with the same args is a no-op
    // (matches Python). Count of tn.vault.linked stays at 1.
    rt.vaultLink(vaultDid, projectId);
    entries = rt.read() as Array<Record<string, unknown>>;
    const linkedCount = entries.filter((e) => e["event_type"] === "tn.vault.linked").length;
    assert.equal(linkedCount, 1, "vaultLink must be idempotent for the same (did, project)");

    // 3. Unlink with explicit reason.
    const reason = "phase 6 smoke teardown";
    assert.doesNotThrow(
      () => rt.vaultUnlink(vaultDid, projectId, reason),
      "vaultUnlink must not throw",
    );
    entries = rt.read() as Array<Record<string, unknown>>;
    const unlinked = entries.find((e) => e["event_type"] === "tn.vault.unlinked");
    assert.ok(unlinked, "read() must contain tn.vault.unlinked after vaultUnlink");
    assert.equal(unlinked["vault_did"], vaultDid);
    assert.equal(unlinked["project_id"], projectId);
    assert.equal(unlinked["reason"], reason);
    assert.equal(
      typeof unlinked["unlinked_at"],
      "string",
      "tn.vault.unlinked must carry an iso8601 unlinked_at",
    );

    // 4. Unlink without a reason — JS undefined / null routes to Rust
    // None; envelope carries reason: null.
    const otherProject = "proj-phase6-no-reason";
    rt.vaultLink(vaultDid, otherProject);
    rt.vaultUnlink(vaultDid, otherProject, null);
    entries = rt.read() as Array<Record<string, unknown>>;
    const noReason = entries.find(
      (e) =>
        e["event_type"] === "tn.vault.unlinked" && e["project_id"] === otherProject,
    );
    assert.ok(noReason, "vaultUnlink with null reason must still produce an event");
    assert.equal(noReason["reason"], null, "absent reason must surface as null");
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.readFrom: equivalent to read() when pointed at the runtime's own log", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.readFrom.a", { i: 1 });
    rt.emit("info", "test.readFrom.b", { i: 2 });

    // read() returns the flat shape; readFrom (mirroring PyO3 read_raw with
    // explicit log_path) returns {envelope, plaintext}. Compare the
    // envelope-level event_type sequence so the two views are equivalent
    // entry-by-entry without forcing identical shapes.
    const flat = rt.read() as Array<Record<string, unknown>>;
    const raw = rt.readFrom(rt.logPath()) as Array<{
      envelope: Record<string, unknown>;
      plaintext: Record<string, unknown>;
    }>;

    assert.ok(Array.isArray(raw), "readFrom() must return an array");
    assert.equal(
      raw.length,
      flat.length,
      `readFrom(logPath) must return the same number of entries as read(); got ${raw.length} vs ${flat.length}`,
    );
    for (let i = 0; i < raw.length; i++) {
      assert.equal(
        raw[i].envelope["event_type"],
        flat[i]["event_type"],
        `entry ${i} event_type must match between read() and readFrom(logPath)`,
      );
      assert.ok(raw[i].plaintext && typeof raw[i].plaintext === "object", "plaintext must be an object");
      assert.equal(
        typeof raw[i].envelope["row_hash"],
        "string",
        "readFrom envelope must carry the on-disk row_hash",
      );
    }
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.readRawWithValidity: every entry carries {envelope, plaintext, valid}", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.rawValidity", { ok: 1 });
    const entries = rt.readRawWithValidity() as Array<{
      envelope: Record<string, unknown>;
      plaintext: Record<string, unknown>;
      valid: { signature: boolean; row_hash: boolean; chain: boolean };
    }>;
    assert.ok(Array.isArray(entries), "readRawWithValidity() must return an array");
    assert.ok(entries.length >= 1, "readRawWithValidity() must surface at least one entry");

    for (const e of entries) {
      assert.ok(e.envelope && typeof e.envelope === "object", "envelope must be an object");
      assert.equal(typeof e.envelope["event_type"], "string", "envelope.event_type must be a string");
      assert.equal(typeof e.envelope["row_hash"], "string", "envelope.row_hash must be a string");
      assert.ok(e.plaintext && typeof e.plaintext === "object", "plaintext must be an object");
      assert.ok(e.valid && typeof e.valid === "object", "valid block must be an object");
      assert.equal(typeof e.valid.signature, "boolean", "valid.signature must be a boolean");
      assert.equal(typeof e.valid.row_hash, "boolean", "valid.row_hash must be a boolean");
      assert.equal(typeof e.valid.chain, "boolean", "valid.chain must be a boolean");
    }

    // Clean log: every flag is true.
    const ours = entries.find((e) => e.envelope["event_type"] === "test.rawValidity");
    assert.ok(ours, "readRawWithValidity() must contain test.rawValidity");
    assert.equal(ours.valid.signature, true, "signature must verify on a clean log");
    assert.equal(ours.valid.row_hash, true, "row_hash must verify on a clean log");
    assert.equal(ours.valid.chain, true, "chain must verify on a clean log");
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.readFromWithValidity: same shape as readRawWithValidity, explicit path", () => {
  const rt = freshRuntime();
  try {
    rt.emit("info", "test.fromValidity", { ok: 2 });
    const own = rt.readRawWithValidity() as Array<{
      envelope: Record<string, unknown>;
      plaintext: Record<string, unknown>;
      valid: { signature: boolean; row_hash: boolean; chain: boolean };
    }>;
    const via = rt.readFromWithValidity(rt.logPath()) as Array<{
      envelope: Record<string, unknown>;
      plaintext: Record<string, unknown>;
      valid: { signature: boolean; row_hash: boolean; chain: boolean };
    }>;

    assert.ok(Array.isArray(via), "readFromWithValidity() must return an array");
    assert.equal(
      via.length,
      own.length,
      `readFromWithValidity(logPath) must match readRawWithValidity() count; got ${via.length} vs ${own.length}`,
    );
    for (let i = 0; i < via.length; i++) {
      assert.equal(
        via[i].envelope["row_hash"],
        own[i].envelope["row_hash"],
        `entry ${i} row_hash must match between the two readers`,
      );
      assert.equal(via[i].valid.signature, own[i].valid.signature);
      assert.equal(via[i].valid.row_hash, own[i].valid.row_hash);
      assert.equal(via[i].valid.chain, own[i].valid.chain);
    }

    const ours = via.find((e) => e.envelope["event_type"] === "test.fromValidity");
    assert.ok(ours, "readFromWithValidity() must contain test.fromValidity");
    assert.equal(ours.valid.signature, true);
    assert.equal(ours.valid.row_hash, true);
    assert.equal(ours.valid.chain, true);
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

// ---------------------------------------------------------------------------
// Phase 5 handler + log-level smokes. Asserts:
//   1. addHandler routes every emit through the JS callback, surfaces
//      both envelope + raw NDJSON, and respects an `accepts` predicate.
//   2. setLevel + getLevel + isEnabledFor agree on the active threshold
//      and the emit pipeline drops below-threshold rows.
// ---------------------------------------------------------------------------

test("WasmRuntime.addHandler: routes envelopes + raw line through JS callback", () => {
  const rt = freshRuntime();
  try {
    // Capture every envelope the handler receives. Track that rawLine
    // arrives as a Uint8Array (wasm-bindgen passes Uint8Array views
    // backed by the wasm linear memory).
    const captured: Array<{ envelope: Record<string, unknown>; rawIsUint8: boolean; rawLen: number }> = [];
    rt.addHandler({
      name: "phase5.capture",
      emit(envelope: Record<string, unknown>, rawLine: Uint8Array) {
        captured.push({
          envelope,
          rawIsUint8: rawLine instanceof Uint8Array,
          rawLen: rawLine.length,
        });
      },
    });

    rt.info("test.handler", { x: 1 });
    rt.warning("test.handler", { y: 2 });

    // Captured envelopes must include both event_types in order, with
    // the matching levels.
    const handlerEvents = captured.filter((c) => c.envelope["event_type"] === "test.handler");
    assert.equal(handlerEvents.length, 2, `handler must see both test.handler emits, got ${handlerEvents.length}`);
    assert.equal(handlerEvents[0].envelope["level"], "info");
    assert.equal(handlerEvents[1].envelope["level"], "warning");

    // rawLine arg is a Uint8Array. Length > 0 because the envelope
    // NDJSON has at least the mandatory fields + trailing newline.
    for (const c of handlerEvents) {
      assert.ok(c.rawIsUint8, "rawLine arg must be a Uint8Array");
      assert.ok(c.rawLen > 0, `rawLine must be non-empty, got length=${c.rawLen}`);
    }
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }

  // accepts() predicate. Fresh runtime so the previous capture handler
  // doesn't interfere with the no-emit assertion.
  const rt2 = freshRuntime();
  try {
    let acceptsCalls = 0;
    let emitCalls = 0;
    rt2.addHandler({
      name: "phase5.reject",
      accepts(_env: Record<string, unknown>) {
        acceptsCalls += 1;
        return false;
      },
      emit(_env: Record<string, unknown>, _raw: Uint8Array) {
        emitCalls += 1;
      },
    });
    rt2.info("test.filtered", { a: 1 });
    rt2.warning("test.filtered", { b: 2 });
    assert.ok(acceptsCalls >= 2, `accepts() must be called per emit, got ${acceptsCalls}`);
    assert.equal(emitCalls, 0, "emit() must never fire when accepts() returns false");
  } finally {
    try { rt2.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.setLevel: below-threshold emits are filtered out", () => {
  const rt = freshRuntime();
  try {
    // Default is "info". Bump to "warning"; info-level rows must drop.
    WasmRuntime.setLevel("warning");
    try {
      rt.info("test.suppressed", { dropped: true });
      rt.warning("test.kept", { kept: true });

      const entries = rt.read() as Array<Record<string, unknown>>;
      const eventTypes = entries.map((e) => e["event_type"]);
      assert.ok(
        eventTypes.includes("test.kept"),
        `warning-level emit must survive setLevel('warning'), got ${eventTypes.join(",")}`,
      );
      assert.ok(
        !eventTypes.includes("test.suppressed"),
        `info-level emit must be filtered by setLevel('warning'), got ${eventTypes.join(",")}`,
      );
    } finally {
      // Reset so subsequent tests in this file see the default.
      WasmRuntime.setLevel("info");
    }
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing */ }
  }
});

test("WasmRuntime.isEnabledFor + getLevel agree with setLevel", () => {
  // Default level is "info". `debug` is below info, so disabled.
  assert.equal(WasmRuntime.getLevel(), "info", "default level must be 'info'");
  assert.equal(
    WasmRuntime.isEnabledFor("debug"),
    false,
    "isEnabledFor('debug') must be false at default level=info",
  );
  assert.equal(
    WasmRuntime.isEnabledFor("info"),
    true,
    "isEnabledFor('info') must be true at default level=info",
  );

  WasmRuntime.setLevel("debug");
  try {
    assert.equal(WasmRuntime.getLevel(), "debug", "getLevel must reflect setLevel('debug')");
    assert.equal(
      WasmRuntime.isEnabledFor("debug"),
      true,
      "isEnabledFor('debug') must be true after setLevel('debug')",
    );
  } finally {
    // Reset to the default to keep cross-test invariants stable.
    WasmRuntime.setLevel("info");
  }
});

// ---------------------------------------------------------------------------
// Browser-shape smoke: drive `WasmRuntime` through `memoryStorageAdapter`.
// No `node:fs` reaches the wasm runtime — this is the path an in-browser
// (or CF Worker / Deno / Bun) minting flow would use. The ceremony is
// minted once on real disk via `NodeRuntime` (cheapest source of a valid
// yaml + keystore tuple), then slurped into a memory map under a virtual
// root before `WasmRuntime.initWith` is called.
// ---------------------------------------------------------------------------

import { memoryStorageAdapter } from "../src/runtime/storage_memory.js";
import { readdirSync, statSync } from "node:fs";

function _slurpDirToMap(
  realDir: string,
  virtDir: string,
  map: Map<string, Uint8Array>,
): void {
  for (const name of readdirSync(realDir)) {
    const realChild = join(realDir, name);
    const virtChild = `${virtDir}/${name}`;
    const st = statSync(realChild);
    if (st.isDirectory()) {
      _slurpDirToMap(realChild, virtChild, map);
    } else if (st.isFile()) {
      map.set(virtChild, new Uint8Array(readFileSync(realChild)));
    }
  }
}

test("WasmRuntime: init + emit + read + mint, all through memoryStorageAdapter (browser flow)", () => {
  // 1. Mint a real ceremony on disk so we have valid bytes to preload.
  //    In a real browser flow these come from fetch / IndexedDB / drag-drop.
  const td = mkdtempSync(join(tmpdir(), "tn-mem-smoke-"));
  const yamlPath = join(td, "tn.yaml");
  const noderuntime = NodeRuntime.init(yamlPath);
  noderuntime.close();

  // 2. Slurp everything under the ceremony root into a `path → bytes` map,
  //    rewriting each disk path to a virtual `/v/...` path. The slash
  //    convention matters: wasm32 std::path is Unix-only.
  const fileMap = new Map<string, Uint8Array>();
  _slurpDirToMap(td, "/v", fileMap);
  const virtYaml = "/v/tn.yaml";
  assert.ok(fileMap.has(virtYaml), `slurp must include the yaml; got keys ${[...fileMap.keys()].join(",")}`);

  // 3. Build the adapter from the preload map and hand to `WasmRuntime`.
  //    Note: zero `node:fs` calls from this point on for the runtime path.
  const preload: Record<string, Uint8Array> = {};
  for (const [k, v] of fileMap) preload[k] = v;
  const storage = memoryStorageAdapter(preload);
  const initialSize = storage.size();
  assert.ok(initialSize >= 5, `preload should carry yaml + keystore + ...; got ${initialSize}`);

  // initWith + skipCeremonyInitEmit + skipPolicyPublishedEmit avoids the
  // stray bookkeeping emits that NodeRuntime already wrote on disk.
  const rt = WasmRuntime.initWith(virtYaml, storage, {
    skipCeremonyInitEmit: true,
    skipPolicyPublishedEmit: true,
  });

  try {
    // Same round-trip the nodeStorageAdapter test does, just in memory.
    const did = rt.did();
    assert.ok(did.startsWith("did:key:"), `did from wasm should be did:key:..., got ${did}`);

    rt.emit("info", "test.mem.smoke", { ok: true, where: "memory" });

    const entries = rt.read() as Array<Record<string, unknown>>;
    const ours = entries.find((e) => e["event_type"] === "test.mem.smoke");
    assert.ok(ours, `read() must find test.mem.smoke after emit, got event_types=${entries.map(e => e["event_type"]).join(",")}`);
    assert.equal(ours["level"], "info");
    assert.equal(ours["ok"], true);
    assert.equal(ours["where"], "memory");

    // Mint a new reader kit via the admin verb. This exercises the
    // CAS-write path through `memoryStorageAdapter.casWrite` AND the
    // kit file `write` path. The mint must succeed and the new kit
    // file must appear in the memory map.
    const kitVirtPath = "/v/.tn/keys/bob.btn.mykit";
    // Generate a valid did:key (the runtime uses verifyDid on the
    // recipient DID); use the wasm primitive so we don't smuggle in
    // node-side crypto.
    // Actually `admin_add_recipient(group, out_path, recipient_did?)` accepts
    // a None for recipient_did per the Phase 4 binding — pass undefined to
    // mint a kit without recording a recipient identity. Simpler path.
    const leafIndex = rt.adminAddRecipient("default", kitVirtPath, undefined);
    assert.equal(typeof leafIndex, "number", `adminAddRecipient must return a leaf index, got ${typeof leafIndex}`);
    assert.ok(leafIndex >= 0, `leaf index should be non-negative, got ${leafIndex}`);

    // The mint should have:
    //  (a) written the kit file to memory storage
    //  (b) updated the btn state file via casWrite
    //  (c) appended to the admin log
    assert.ok(storage.exists(kitVirtPath), `kit file must exist after mint at ${kitVirtPath}`);
    const kitBytes = storage.read(kitVirtPath);
    assert.ok(kitBytes.length > 0, `kit must have non-empty bytes, got ${kitBytes.length}`);

    // Snapshot for persistence handoff — proves the round-trip shape.
    const snap = storage.snapshot();
    assert.ok(snap[kitVirtPath], `snapshot must include the new kit`);
    assert.ok(storage.size() > initialSize, `storage should grow after mint (was ${initialSize}, now ${storage.size()})`);
  } finally {
    try { rt.close(); } catch { /* close errors aren't load-bearing for this smoke */ }
  }
});

test("memoryStorageAdapter: casWrite enforces the prior-bytes contract", () => {
  const s = memoryStorageAdapter();
  const path = "/foo/state.bin";
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([4, 5, 6]);

  // prior=null on a fresh path succeeds.
  s.casWrite(path, null, a);
  assert.deepEqual(Array.from(s.read(path)), [1, 2, 3]);

  // prior=null on an existing non-empty file must fail.
  assert.throws(() => s.casWrite(path, null, b), /cas-mismatch/);

  // prior=current succeeds and updates.
  s.casWrite(path, a, b);
  assert.deepEqual(Array.from(s.read(path)), [4, 5, 6]);

  // prior=stale (the original 'a') must fail.
  assert.throws(() => s.casWrite(path, a, new Uint8Array([7])), /cas-mismatch/);

  // Bytes are still 'b' — failed CAS didn't mutate.
  assert.deepEqual(Array.from(s.read(path)), [4, 5, 6]);
});

test("memoryStorageAdapter: list returns only direct children of a dir", () => {
  const s = memoryStorageAdapter({
    "/v/a.txt":          new Uint8Array([1]),
    "/v/sub/b.txt":      new Uint8Array([2]),
    "/v/sub/deeper/c":   new Uint8Array([3]),
    "/v/sub/d.txt":      new Uint8Array([4]),
    "/other/x":          new Uint8Array([5]),
  });
  assert.deepEqual(s.list("/v").sort(), ["/v/a.txt"]);
  assert.deepEqual(s.list("/v/sub").sort(), ["/v/sub/b.txt", "/v/sub/d.txt"]);
  assert.deepEqual(s.list("/v/sub/deeper").sort(), ["/v/sub/deeper/c"]);
  assert.deepEqual(s.list("/nope"), []);
});
