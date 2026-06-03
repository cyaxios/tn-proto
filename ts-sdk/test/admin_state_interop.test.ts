// Cross-impl GOLDEN test: prove Python `tn.admin.state()` / `tn.admin.recipients()`
// equals TypeScript `tn.admin.state()` / `tn.admin.recipients()` for the SAME
// ceremony.
//
// This is the first end-to-end increment of the SDK-unification pilot. It pins
// TODAY's parity as a runnable test BEFORE any core change, so a later
// unification refactor that drifts one side from the other fails here loudly.
//
// Shape of the test:
//
//   1. Build ONE deterministic btn ceremony on disk (fixed seeds) with two
//      recipients beyond self (Alice + Bob) declared in the yaml, provisioned
//      the same way init_idempotence.test.ts does (NodeRuntime.init reconcile,
//      via Tn.init). Then revoke ONE of them (Bob) through the public
//      `tn.admin.revokeRecipient` surface. The resulting attested log carries a
//      ceremony, a group row, an active recipient (Alice), and a revoked
//      recipient (Bob).
//   2. TS side: capture `tn.admin.state("default")` and
//      `tn.admin.recipients("default", { includeRevoked: true })`.
//   3. Python side: spawn the resolved interpreter on admin_state_py_helper.py
//      against the SAME yaml. It loads the ceremony (`tn.init(yaml)`) and prints
//      `{ state, recipients }` as JSON. Because both sides replay the SAME
//      on-disk log, this is a true apples-to-apples comparison.
//   4. Normalize TS camelCase -> Python snake_case, sort the list members by
//      (group, leaf_index), then assert deep equality on the STABLE projection
//      of both outputs.
//
// Skip policy: if no Python interpreter with `import tn` is available, the test
// console.warns and returns WITHOUT asserting (Python-less envs stay green). It
// does NOT skip when a usable interpreter (e.g. .venv_win) is present.
//
// ── Result today (2026-06): the golden FAILS, by design, surfacing the first
//    real unification findings (see the GOLDEN FINDINGS block near the end). The
//    surfaces that ARE at parity are asserted green above the findings, so this
//    test simultaneously (a) pins today's real parity as a regression baseline
//    and (b) fails loudly on the genuine TS-vs-Python divergences. The two
//    findings are:
//      #1 tn.admin.state().groups — Python synthesizes a tn.group.added for the
//         yaml-declared `default` group during reconcile; TS does not (TS=[]).
//      #2 tn.admin.state().ceremony.created_at — Python fills a config-derived
//         wall-clock string; TS leaves it null.
//
// ── Compared vs type-checked fields ──────────────────────────────────────────
//
// COMPARED for equality (proven parity TODAY — asserted as the green baseline):
//   ceremony:           ceremony_id, cipher, device_identity
//   state.recipients[]: group, leaf_index, recipient_identity, kit_sha256,
//                       active_status
//   recipients()[]:     leaf_index, recipient_identity, kit_sha256, revoked
//
// TYPE-CHECKED only (present + same JS type on both sides, value NOT compared):
//   state.recipients[].minted_at / revoked_at / retired_at
//   recipients()[].minted_at / revoked_at
//
// ASSERTED-AS-FINDING (currently diverges — fails the test, reported explicitly):
//   state().groups          (#1: row exists on PY, absent on TS)
//   ceremony.created_at      (#2: string on PY, null on TS — type compared)
//
// Why type-check rather than equality-compare the recipient timestamps: they are
// envelope timestamps (mintedAt = the row's `timestamp`). Although in THIS test both
// sides read the very same envelopes off disk so the values happen to be equal,
// pinning their exact value would make the GOLDEN brittle against a future impl
// that legitimately re-derives or reformats a timestamp. Asserting presence +
// type catches a field going missing or flipping null<->string (a real schema
// regression) without coupling the test to wall-clock content.

import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { DeviceKey, Tn } from "../src/index.js";
import { BtnPublisher } from "../src/raw.js";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "..");
const pyHelper = join(here, "admin_state_py_helper.py");

const GROUP = "default";
const ALICE_DID = "did:key:z6MkAliceForAdminStateInteropGolden00000001";
const BOB_DID = "did:key:z6MkBobForAdminStateInteropGolden000000002";

// ── Python resolution (mirrors interop_driver.mjs, extended with the venv
//    layout this worktree actually uses: .venv_win / .venv / .venv_linux). ─────
function resolvePython(): string {
  const fromEnv = process.env.TN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    resolve(repoRoot, ".venv_win/Scripts/python.exe"),
    resolve(repoRoot, ".venv/Scripts/python.exe"),
    resolve(repoRoot, ".venv/bin/python"),
    resolve(repoRoot, ".venv_linux/bin/python"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return "python";
}

/** Probe that the resolved interpreter can `import tn`. Returns the working
 * interpreter path, or null if none can import the package (graceful skip). */
function probePython(): string | null {
  const py = resolvePython();
  const res = spawnSync(py, ["-c", "import tn"], { encoding: "utf8" });
  if (res.error === undefined && res.status === 0) return py;
  return null;
}

// ── Deterministic ceremony on disk (canonical schema, mirrors
//    init_idempotence.test.ts makeCeremony, with two extra recipients). ────────
interface Ceremony {
  yamlPath: string;
  yamlDir: string;
  cleanup: () => void;
  dk: DeviceKey;
}

function makeCeremony(): Ceremony {
  const dir = mkdtempSync(join(tmpdir(), "tn-admin-state-interop-"));
  const keys = join(dir, ".tn/keys");
  const logs = join(dir, ".tn/logs");
  mkdirSync(keys, { recursive: true });
  mkdirSync(logs, { recursive: true });

  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) seed[i] = (i * 11 + 3) & 0xff;
  const dk = DeviceKey.fromSeed(seed);
  writeFileSync(join(keys, "local.private"), Buffer.from(seed));
  writeFileSync(join(keys, "local.public"), dk.did, "utf8");
  const indexMaster = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) indexMaster[i] = (i * 5) & 0xff;
  writeFileSync(join(keys, "index_master.key"), Buffer.from(indexMaster));

  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 7 + 19) & 0xff;
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  writeFileSync(join(keys, "default.btn.state"), Buffer.from(pub.toBytes()));
  writeFileSync(join(keys, "default.btn.mykit"), Buffer.from(selfKit));
  pub.free();

  // Self + Alice + Bob. init reconcile mints kits for Alice and Bob and emits
  // tn.recipient.added for each (leaf 1 and leaf 2; self is leaf 0).
  //
  // Deliberately NO `protocol_events_location` template here. With a templated
  // `{event_type}` PEL the wasm runtime writes admin events to a per-type file,
  // but AdminStateCache.resolveAdminLogPath bails on templated PELs and falls
  // back to the default admin log — so the TS reducer would never see the
  // reconcile's tn.recipient.added rows. Omitting the override routes admin
  // events to the default `<yamlDir>/.tn/admin/admin.ndjson`, which BOTH the TS
  // cache and Python's admin-aware reader consume. (The templated-PEL gap is a
  // real cross-impl wrinkle, but orthogonal to this state/recipients parity
  // golden.)
  const yaml = `ceremony:
  id: admin_state_interop
  mode: local
  cipher: btn
logs:
  path: ./.tn/logs/tn.ndjson
keystore:
  path: ./.tn/keys
device:
  device_identity: ${dk.did}
public_fields:
- timestamp
- event_id
- event_type
- level
- group
- leaf_index
- recipient_identity
- kit_sha256
- cipher
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
    - recipient_identity: ${ALICE_DID}
    - recipient_identity: ${BOB_DID}
fields: {}
`;
  const yamlPath = join(dir, "tn.yaml");
  writeFileSync(yamlPath, yaml, "utf8");

  return {
    yamlPath,
    yamlDir: dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
    dk,
  };
}

// ── Normalization: camelCase (TS) -> snake_case (Python reference shape). ─────
type Json = Record<string, unknown>;

// Volatile timestamp fields excluded from equality (type-checked separately).
const VOLATILE = new Set([
  "minted_at",
  "revoked_at",
  "retired_at",
  "added_at",
  "created_at",
]);

const KEY_MAP: Record<string, string> = {
  recipientDid: "recipient_identity",
  kitSha256: "kit_sha256",
  mintedAt: "minted_at",
  activeStatus: "active_status",
  revokedAt: "revoked_at",
  retiredAt: "retired_at",
  ceremonyId: "ceremony_id",
  deviceDid: "device_identity",
  publisherDid: "publisher_identity",
  leafIndex: "leaf_index",
  addedAt: "added_at",
  createdAt: "created_at",
  vaultLinks: "vault_links",
  // previous_kit_sha256 etc. are already snake_case in both shapes; map the
  // camelCase variants so rotations[] (if ever present) also normalize.
  previousKitSha256: "previous_kit_sha256",
  rotatedAt: "rotated_at",
};

function snakeKey(k: string): string {
  return KEY_MAP[k] ?? k;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value !== null && typeof value === "object") {
    const out: Json = {};
    for (const [k, v] of Object.entries(value as Json)) {
      out[snakeKey(k)] = normalize(v);
    }
    return out;
  }
  return value;
}

/** Split a normalized object into { stable, volatile } where volatile holds the
 * timestamp fields (kept for type-checking) and stable holds the rest. */
function splitVolatile(obj: Json): { stable: Json; volatile: Json } {
  const stable: Json = {};
  const volatile: Json = {};
  for (const [k, v] of Object.entries(obj)) {
    if (VOLATILE.has(k)) volatile[k] = v;
    else stable[k] = v;
  }
  return { stable, volatile };
}

function sortRows(rows: Json[]): Json[] {
  return rows.slice().sort((a, b) => {
    const ga = String(a["group"] ?? "");
    const gb = String(b["group"] ?? "");
    if (ga !== gb) return ga < gb ? -1 : 1;
    return Number(a["leaf_index"] ?? 0) - Number(b["leaf_index"] ?? 0);
  });
}

/** Stable projection of a (nullable) ceremony object: snake-cased, with
 * volatile timestamps (created_at) stripped. Returns null if absent. */
function stableCeremony(cer: unknown): Json | null {
  if (cer === null || typeof cer !== "object") return null;
  return splitVolatile(cer as Json).stable;
}

/** Stable projection of a recipient list (state.recipients OR the recipients()
 * roster): each row snake-cased, volatile timestamps stripped, sorted. */
function stableRecipients(rows: Json[]): Json[] {
  return sortRows(rows.map((r) => splitVolatile(r).stable));
}

/** Stable projection of the state.groups list. */
function stableGroups(rows: Json[]): Json[] {
  return sortRows(rows.map((g) => splitVolatile(g).stable));
}

/** Extract the (volatile) created_at off a normalized ceremony object, or null
 * if the ceremony is absent / has no created_at. Used only by the findings
 * reporter, which compares its TYPE across sides. */
function createdAtOf(cer: unknown): unknown {
  if (cer === null || typeof cer !== "object") return null;
  const v = (cer as Json)["created_at"];
  return v ?? null;
}

/** Assert each volatile timestamp field is present on both sides with the same
 * JS type ("string" | "null"), without comparing its value. A null/absent
 * object on both sides is a no-op (parity); a one-sided object fails. */
function assertTimestampParity(label: string, tsObj: unknown, pyObj: unknown): void {
  const tsIsObj = tsObj !== null && typeof tsObj === "object";
  const pyIsObj = pyObj !== null && typeof pyObj === "object";
  if (!tsIsObj && !pyIsObj) return;
  assert.ok(tsIsObj, `${label}: TS side is null/absent but Python side is present`);
  assert.ok(pyIsObj, `${label}: Python side is null/absent but TS side is present`);
  const tsV = splitVolatile(tsObj as Json).volatile;
  const pyV = splitVolatile(pyObj as Json).volatile;
  const keys = new Set([...Object.keys(tsV), ...Object.keys(pyV)]);
  for (const k of keys) {
    assert.ok(k in tsV, `${label}: TS missing timestamp field ${k}`);
    assert.ok(k in pyV, `${label}: Python missing timestamp field ${k}`);
    const tt = tsV[k] === null ? "null" : typeof tsV[k];
    const pt = pyV[k] === null ? "null" : typeof pyV[k];
    assert.equal(
      tt,
      pt,
      `${label}: timestamp ${k} type differs ` +
        `(ts=${tt} ${JSON.stringify(tsV[k])}, py=${pt} ${JSON.stringify(pyV[k])})`,
    );
  }
}

/** Row-wise timestamp parity for two lists, matched by sorted (group,
 * leaf_index) order. Asserts equal length first. */
function assertRowTimestampParity(label: string, tsRows: Json[], pyRows: Json[]): void {
  const ts = sortRows(tsRows);
  const py = sortRows(pyRows);
  assert.equal(ts.length, py.length, `${label}: row count differs`);
  for (let i = 0; i < ts.length; i += 1) {
    assertTimestampParity(`${label}[${i}]`, ts[i]!, py[i]!);
  }
}

test("admin_state.interop.golden_python_equals_typescript", async () => {
  const py = probePython();
  if (py === null) {
    console.warn(
      "[skip] admin_state interop: no Python interpreter with `import tn` " +
        "found (set TN_PYTHON or provide a venv with tn installed). " +
        "Skipping WITHOUT asserting — this env is not broken, just Python-less.",
    );
    return;
  }
  console.warn(`[info] admin_state interop: probe OK; using interpreter ${py}`);

  const c = makeCeremony();
  try {
    // ── TS side: build the ceremony state through the public tn.admin surface.
    const tn = await Tn.init(c.yamlPath);
    try {
      // Sanity: init reconcile provisioned Alice (leaf 1) and Bob (leaf 2).
      // Self (leaf 0) is the publisher's own self-kit and emits no
      // tn.recipient.added event, so it is NOT part of the recipient roster on
      // either side — the roster holds exactly the two externally-added DIDs.
      const before = tn.admin.recipients(GROUP, { includeRevoked: true });
      assert.equal(
        before.length,
        2,
        `expected Alice+Bob = 2 recipients after init (self is not a roster ` +
          `entry), got ${before.length}: ${JSON.stringify(before)}`,
      );
      // Revoke Bob through the public admin verb (resolves DID -> leaf via the
      // attested log, then emits tn.recipient.revoked).
      await tn.admin.revokeRecipient(GROUP, { recipientDid: BOB_DID });

      const tsStateRaw = tn.admin.state(GROUP) as unknown as Json;
      const tsRecipientsRaw = tn.admin.recipients(GROUP, {
        includeRevoked: true,
      }) as unknown as Json[];

      // ── Python side: same ceremony, same log, read through tn.admin.*.
      const res = spawnSync(py, [pyHelper, c.yamlPath, GROUP], {
        encoding: "utf8",
      });
      if (res.error) throw res.error;
      assert.equal(
        res.status,
        0,
        `python helper exited ${res.status}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
      );
      let pyParsed: { state: Json; recipients: Json[] };
      try {
        pyParsed = JSON.parse(res.stdout) as { state: Json; recipients: Json[] };
      } catch (e) {
        throw new Error(
          `python helper did not emit valid JSON: ${(e as Error).message}\n` +
            `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
          { cause: e },
        );
      }

      // ── Normalize both sides to the Python snake_case reference shape.
      const tsState = normalize(tsStateRaw) as Json;
      const tsRecipients = normalize(tsRecipientsRaw) as Json[];
      const pyState = normalize(pyParsed.state) as Json;
      const pyRecipients = normalize(pyParsed.recipients) as Json[];

      // ── Per-surface stable projections (volatile timestamps stripped,
      //    lists sorted by (group, leaf_index)).
      const tsCerStable = stableCeremony(tsState["ceremony"]);
      const pyCerStable = stableCeremony(pyState["ceremony"]);
      const tsStateRecsStable = stableRecipients(tsState["recipients"] as Json[]);
      const pyStateRecsStable = stableRecipients(pyState["recipients"] as Json[]);
      const tsRecStable = stableRecipients(tsRecipients);
      const pyRecStable = stableRecipients(pyRecipients);
      const tsGroupsStable = stableGroups(tsState["groups"] as Json[]);
      const pyGroupsStable = stableGroups(pyState["groups"] as Json[]);

      // Print every normalized projection so it is evident the two sides were
      // really compared (not skipped), and so any mismatch is debuggable from
      // CI logs.
      const dump = (label: string, v: unknown): void => {
        console.warn(`── ${label} ──`);
        console.warn(JSON.stringify(v, null, 2));
      };
      dump("normalized TS ceremony (stable)", tsCerStable);
      dump("normalized PY ceremony (stable)", pyCerStable);
      dump("normalized TS state.recipients (stable)", tsStateRecsStable);
      dump("normalized PY state.recipients (stable)", pyStateRecsStable);
      dump("normalized TS recipients() (stable)", tsRecStable);
      dump("normalized PY recipients() (stable)", pyRecStable);
      dump("normalized TS state.groups (stable)", tsGroupsStable);
      dump("normalized PY state.groups (stable)", pyGroupsStable);

      // ── Timestamp parity for the RECIPIENT rows (present + same JS type on
      //    both sides, value NOT compared). These hold today: minted_at is a
      //    string and revoked_at is string|null on both sides, driven by the
      //    SAME shared-log envelopes. A field going missing / flipping
      //    null<->string here would be a real schema regression.
      //
      //    NOTE: ceremony.created_at is deliberately NOT type-asserted here —
      //    it is a known divergence (finding #2 below): TS leaves it null,
      //    Python's config-derived ceremony fallback fills a fresh wall-clock
      //    string. Asserting it would mask the recipient-row checks behind a
      //    pre-existing gap.
      assertRowTimestampParity(
        "state.recipients",
        tsState["recipients"] as Json[],
        pyState["recipients"] as Json[],
      );
      assertRowTimestampParity("recipients()", tsRecipients, pyRecipients);

      // ── GREEN baseline: surfaces that are at parity TODAY. These pin the
      //    agreed behaviour so any future core change that drifts one side is
      //    caught here.
      assert.deepEqual(
        tsCerStable,
        pyCerStable,
        "GOLDEN: tn.admin.state().ceremony stable fields differ between TS and Python",
      );
      assert.deepEqual(
        tsStateRecsStable,
        pyStateRecsStable,
        "GOLDEN: tn.admin.state().recipients stable rows differ between TS and Python",
      );
      assert.deepEqual(
        tsRecStable,
        pyRecStable,
        "GOLDEN: tn.admin.recipients() stable rows differ between TS and Python",
      );

      // ── Sanity: the scenario genuinely exercised an active + a revoked
      //    recipient on the agreed surface.
      assert.ok(
        pyRecStable.some((r) => r["revoked"] === true),
        "expected >=1 revoked recipient in the roster",
      );
      assert.ok(
        pyRecStable.some((r) => r["revoked"] === false),
        "expected >=1 active recipient in the roster",
      );

      // ── UNIFICATION FINDINGS (asserted last so the green baseline above is
      //    independently visible). Two surfaces are NOT at parity today; both
      //    trace to the same root cause — Python's reconcile, run inside the
      //    helper's `tn.init`, manufactures state during init that the TS
      //    NodeRuntime reconcile does not:
      //
      //    Finding #1 — state().groups. Python emits a synthetic
      //      `tn.group.added` for the yaml-declared `default` group during
      //      reconcile (its `added_at` is the Python-run wall clock, proving it
      //      is freshly minted at reconcile, not replayed from the shared log),
      //      so Python reports one group row. The TS reconcile does NOT emit
      //      `tn.group.added` for a pre-existing yaml group, so the TS reducer
      //      reports `groups: []`.
      //      (Aside, observed but not exercised here: when a `tn.group.added`
      //      event IS present, the TS reducer records `publisher_identity` as
      //      the empty string rather than the publisher DID — a separate,
      //      narrower gap to fold into the same fix.)
      //
      //    Finding #2 — ceremony.created_at. Neither side has a
      //      `tn.ceremony.init` event, so both derive ceremony from config.
      //      Python's fallback fills `created_at` with a fresh wall-clock
      //      string; TS leaves it `null`.
      //
      //    Both are asserted below so the failure enumerates them. The
      //    unification work must reconcile both (most cleanly: make the two
      //    reconcile paths agree on whether init synthesizes group/ceremony
      //    state, and on the config-derived `created_at`).
      const findings: string[] = [];
      try {
        assert.deepEqual(tsGroupsStable, pyGroupsStable);
      } catch {
        findings.push(
          "#1 state().groups differs: TS=" +
            JSON.stringify(tsGroupsStable) +
            " PY=" +
            JSON.stringify(pyGroupsStable),
        );
      }
      const tsCreatedAt = createdAtOf(tsState["ceremony"]);
      const pyCreatedAt = createdAtOf(pyState["ceremony"]);
      const tsCreatedType = tsCreatedAt === null ? "null" : typeof tsCreatedAt;
      const pyCreatedType = pyCreatedAt === null ? "null" : typeof pyCreatedAt;
      if (tsCreatedType !== pyCreatedType) {
        findings.push(
          `#2 ceremony.created_at type differs: TS=${tsCreatedType} ` +
            `PY=${pyCreatedType}`,
        );
      }
      assert.equal(
        findings.length,
        0,
        "GOLDEN FINDINGS (TS vs Python tn.admin.state divergences the " +
          "unification must reconcile):\n  " +
          findings.join("\n  ") +
          "\n(See the dumped per-surface projections above for full context.)",
      );
    } finally {
      await tn.close();
    }
  } finally {
    c.cleanup();
  }
});
