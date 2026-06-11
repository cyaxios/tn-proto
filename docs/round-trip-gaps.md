# Python <-> TypeScript round-trip gaps

The only bar here: does a Python<->TS round trip actually work end to end, or
is there an UNIMPLEMENTED surface (missing verb, throw-stub, or a `.tnpkg`
kind one side can produce but the other can't consume) that breaks it? Not
"is it Rust-backed", not perf - just interop that works vs doesn't.

## STATUS (updated, commit 1992093)

- FIXED + cross-impl-proven both directions against real Python: #1
  contact_update, #2 identity_seed (produce), #3 vault.setLinkState. Tests:
  contact_update_interop / identity_seed_interop / vault_set_link_state_interop.
- PROVEN already working (no code change needed): #5 project_seed
  (backup/restore). Test: project_seed_interop.
- REMAINING unproven: #4 full_keystore (no cross-impl round-trip test yet).
- Out of scope: browser tier (throw-stubs), JWE (offer / enrolment /
  recipient_invite).

The detailed sections below are the original evidence trail; the status
block above is current.

Ground truth (verified against `ts-sdk/src/runtime/node_runtime.ts`):
- TS **export** produces: `admin_log_snapshot`, `offer`/`enrolment`,
  `kit_bundle`/`full_keystore`, `project_seed` (`:1290-1315`). Does NOT
  produce `identity_seed` or `contact_update`. `recipient_invite` throws.
- TS **absorb** consumes: `admin_log_snapshot`, `kit_bundle`/`full_keystore`,
  `identity_seed`, `project_seed`, `offer`/`enrolment` (no-op). Everything
  else -> `"unsupported manifest kind"` (`:1443-1469`).

Method to close any of these: write the cross-impl round-trip test first
(Python produce -> TS consume, and reverse; pattern:
`ts-sdk/test/admin_state_interop.test.ts`), watch it fail, then implement
until green.

---

## 1. CONFIRMED breaks - Node TS <-> Python (code-proven)

### 1.1 `contact_update` - TS can neither produce nor consume
- Direction: **Py -> TS broken** (and TS -> Py impossible).
- Evidence: TS export has no `contact_update` branch (`node_runtime.ts:1290-1315`);
  TS absorb rejects it with `"unsupported manifest kind"` (`:1460-1469`).
  Python produces + absorbs it (`python/tn/absorb.py` `_absorb_contact_update`
  + `_apply_contact_update`).
- Impact: a Python/vault-emitted `contact_update` tnpkg is rejected by a TS
  absorber. Contact-roster updates do not propagate Py -> TS.
- Fix: add a TS export branch + a TS absorb handler mirroring Python's
  `_apply_contact_update` (yaml mutation). + round-trip test.

### 1.2 `identity_seed` - TS cannot produce it
- Direction: **TS -> Py cannot start** (Py -> TS implemented but untested).
- Evidence: TS export dispatch has no `identity_seed` branch
  (`node_runtime.ts:1290-1315`); TS absorb DOES (`:1447-1448`
  `_absorbIdentitySeed`). Python produces (`python/tn/export.py`
  `export_identity_seed`) + consumes.
- Impact: a TS-created identity cannot be exported as an `identity_seed` for
  Python to bootstrap from.
- Fix: add the `identity_seed` branch to TS `exportPkg` (build the seed body);
  + round-trip test both directions.

### 1.3 `vault.setLinkState` - TS throws
- Direction: **broken on TS** (Python works).
- Evidence: `ts-sdk/src/vault/index.ts:47` throws "not yet ported from
  Python"; Python `set_link_state` mutates `ceremony.mode` in the yaml.
- Impact: TS cannot flip a ceremony local<->linked; only Python can.
- Fix: implement in TS (it already writes yaml via `persistBtnGroup`, so the
  yaml-mutation objection no longer holds). + round-trip test asserting the
  yaml `ceremony.mode` matches Python's.

## 2. UNPROVEN - implemented both sides, NO cross-impl test (could silently break)

### 2.1 `full_keystore`
- Both produce + absorb (TS `:1302-1309` export, `:1445-1446` absorb via
  `_absorbKitBundle`). Absorb key-placement is untested cross-language.
- Risk: keys may not land in the right keystore slots when produced by the
  other SDK; a restored ceremony might not decrypt/sign.
- Fix: round-trip test (Py produce full_keystore -> TS absorb -> TS can
  read+emit; and reverse), asserting every private key is placed + usable.

### 2.2 `project_seed`
- Both produce + absorb (TS `:1310-1314` export, `:1449-1450` absorb). No
  cross-impl test; reportedly browser-leaning for production.
- Risk: a full-ceremony backup from one SDK may not fully restore on the other.
- Fix: round-trip test (produce -> absorb -> ceremony fully operable), both
  directions.

## 3. Scope-flagged - browser tier (only if browser<->Python interop matters)

- `ts-sdk/src/browser/tn.ts`: `admin`/`pkg`/`vault`/`agents`/`handlers`
  namespaces are `_stubNamespace(...)` -> throw `NotYetWiredForBrowserError`;
  static `Tn.absorb` throws too.
- Impact: browser-TS cannot do admin / pkg.export / pkg.absorb / vault ops, so
  any browser<->Python round trip for those is broken. Node TS is unaffected.
- Fix (if in scope): wire the browser namespaces (or a documented subset) onto
  the browser runtime. Larger - whole namespaces are stubbed.

## 4. Out of scope - JWE

- `offer` / `enrolment`: TS absorb is a no-op (counts `body/package.json`,
  never applies the package - `node_runtime.ts:1451-1459`); Python applies it.
  These are the JWE recipient/group bootstrap. Out of scope per the standing
  JWE decision.
- `recipient_invite`: reserved in the schema; both SDKs throw on export and
  reject on absorb. By design, not a regression.

## PROVEN-WORKING (ignore - they round-trip with passing tests)

- `admin_log_snapshot` (tnpkg_interop + crypto/tn-core tests).
- Log emit/read both directions (watch_interop, full_runtime_interop).
- `tn.admin.state()` / `recipients()` (admin_state_interop, green).
- `kit_bundle` (admin_interop; recipient mint + absorb).
