# tn.yaml canonical schema and restore contract

Status: Phase 0 baseline (yaml-identity-ironout)
Branch: `fix/yaml-identity-ironout`
Date: 2026-05-29

This document fixes the canonical `tn.yaml` schema and the restore
contract that all four TN surfaces (Python SDK, ts-sdk core, tn-js CLI,
browser dashboard JS) must converge on. Every claim below is backed by a
quoted line from code read on 2026-05-29 against the branch above.

The empirical baseline was produced by running the real `tn init`
(`python/tn/cli.py:cmd_init` → `_multi.create_fresh`) and capturing the
exact `tn.yaml` it writes. The golden fixture derived from it lives at
`tests/golden/canonical_tn.yaml`; its load proof is
`tests/golden/load_check_canonical.py`.

---

## 1. Canonical `tn.yaml` schema

What the loader (`python/tn/config.py:load`, line 1401) actually reads.
Top-level keys it consults: `ceremony`, `logs`, `keystore`, `device`
(via the structural validator), `groups`, `public_fields`,
`default_policy`, `handlers`, `fields`, `llm_classifier`, `extends`
(`config.py:1416-1455`, `1472-1475`).

### 1.1 Top-level keys

| Key | Required | Read at | Notes |
|-----|----------|---------|-------|
| `ceremony` | yes (block; `ceremony.id` required) | `config.py:1424-1425`, `1233-1235` | scalars packed by `_resolve_ceremony_settings` |
| `device` | **yes** | validator `config.py:1202-1204` | must carry `device_identity` |
| `groups` | **yes** | validator `config.py:1202-1204`; loaded `config.py:1438-1449` | at least the `default` group |
| `keystore` | optional (default `./.tn/keys`) | `config.py:1328` | `keystore.path`; the real key files live here |
| `logs` | optional (default `./.tn/logs/tn.ndjson`) | `config.py:1428-1429` | `logs.path` |
| `handlers` | optional (`None` if absent) | `config.py:1475` | list; `[]` is valid (browser uses it) |
| `public_fields` | optional (ADDITIVE to defaults) | `config.py:1467-1471` | union with `DEFAULT_PUBLIC_FIELDS` |
| `default_policy` | optional (default `"private"`) | `config.py:1472` | |
| `fields` | optional (legacy flat map; deprecated) | `config.py:845-855` | prefer per-group `groups.<g>.fields` |
| `llm_classifier` | optional | `config.py:1455` | stub config; `_classifier._configure` |
| `extends` | optional | `config.py:1018`, `1135`, `1421` | stream yamls only; resolved before validation |

### 1.2 The `device:` block (required)

```yaml
device:
  device_identity: did:key:z6Mk...
```

The validator rejects any doc lacking `device` (and lacking `groups`):

> `config.py:1202` — `for required in ("device", "groups"):`
> `config.py:1203-1204` — `if required not in doc: raise ValueError(f"{yaml_path}: missing required key {required!r}")`

The device key material is loaded from the keystore, not from the DID
string in the yaml:

> `config.py:1329` — `device = DeviceKey.from_private_bytes(_read_bytes(keystore / "local.private"))`

### 1.3 `ceremony.*` keys (which the loader reads)

All packed by `_resolve_ceremony_settings` (`config.py:1224-1269`):

| `ceremony.*` key | Required | Read at | Default |
|------------------|----------|---------|---------|
| `id` | **yes** (non-empty) | `config.py:1233-1235` | — (raises if empty) |
| `cipher` | optional | `config.py:1236-1241` | `"btn"`; only `jwe`/`btn` accepted |
| `mode` | optional | `config.py:1242-1244` | `"local"`; only `local`/`linked` |
| `linked_vault` | required iff `mode=linked` | `config.py:1245`, `1247-1250` | `None` |
| `linked_project_id` | optional | `config.py:1246` | `None` |
| `sync_logs` | optional | `config.py:1257` | `False` |
| `sign` | optional | `config.py:1260` | `True` |
| `chain` | optional | `config.py:1264` | `True` |
| `project_name` | optional | `config.py:1267` | `None` |
| `version_name` | optional | `config.py:1268` | `None` |
| `admin_log_location` | optional | `config.py:1296`, `1311` | `./.tn/admin/admin.ndjson` |
| `protocol_events_location` | optional (legacy alias; `DeprecationWarning`) | `config.py:1297`, `1300-1309` | — |

`log_level` and `profile` appear in the emitted yaml but are not consumed
by `config.load`'s ceremony resolver (profile is honored at mint time via
the profile catalog / `_multi`, and stamped into `sign`/`chain`).

### 1.4 `groups` block

```yaml
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: did:key:z6Mk...
  tn.agents:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: did:key:z6Mk...
    fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]
    auto_populated_by_policy: true
```

Per-group keys read by `_load_group` (`config.py:1361-1398`):
`pool_size` (`:1377`), `index_epoch` (`:1378`), `cipher` (`:1379-1384`).
Per-group `fields` are read by `_build_field_to_groups`
(`config.py:816-834`).

`recipients: [{recipient_identity: ...}]` is **metadata only** — the
loader does not parse the recipient DID into crypto; group key material
comes from the keystore (`_instantiate_group_cipher`, `config.py:1335-1358`,
e.g. `BtnGroupCipher.load(keystore, name)` at `:1345`). The
`recipients`/`recipient_identity` shape is authoritative-source metadata
written by `create_fresh` (`config.py:628`, `:650`).

Reserved namespace: group names starting with `tn.` are rejected except
`tn.agents` (`config.py:1216-1221`).

### 1.5 `public_fields`

`DEFAULT_PUBLIC_FIELDS` (`config.py:173-...`) is the always-present base
set; the yaml's list is ADDITIVE (`config.py:1467-1471`). `project_id`
and `recipient_identity` are members of this list (`config.py:212`,
`:198`) — they are publishable field *names*, NOT top-level config keys.

---

## 2. FORBIDDEN / dead keys

### 2.1 Top-level `me:` — REJECTED by the loader

> `config.py:1195` — `if "me" in doc and "device" not in doc:`
> `config.py:1196-1201` — raises: "legacy `me:` top-level block is no longer supported (0.4.3a1 renamed it to `device:`)."

No back-compat shim. A yaml with top-level `me:` and no `device:` fails
to load. (0.4.3a1 me:→device: flip.)

### 2.2 Top-level `project_id:` — DEAD (never read)

`project_id` appears in the source **only** as a member of
`DEFAULT_PUBLIC_FIELDS`:

> `config.py:212` — `"project_id",`  (inside the `DEFAULT_PUBLIC_FIELDS` list, `config.py:173`+)

There is no `doc.get("project_id")` / `doc["project_id"]` anywhere in
`config.py` (verified by grep over all `doc.get`/`doc[` reads,
`config.py:804,811,845,1018,1135,1210,1246,1328,1424,1428,1448,1455,1469,1472,1475`).
A top-level `project_id:` in a yaml is silently ignored. The browser
still emits it (see §5) — it is dead weight to be removed.

### 2.3 Top-level `label:` — browser legacy, never read

No `doc.get("label")` exists in `config.py`. The browser's `buildTnYaml`
emits a top-level `label:` (`static/account/yaml_profile.js:125`) — it is
ignored by every loader and must be dropped. The canonical human label is
`ceremony.project_name` (`config.py:1267`).

---

## 3. The id vocabulary (disambiguated)

- **`ceremony.id`** — the *local* project/ceremony id (e.g.
  `local_4228a04f`), minted at init; the chain-disambiguation prefix.
  Required (`config.py:1233-1235`).
- **`ceremony.linked_project_id`** — the *vault-side* project id (e.g.
  `01KSVE...` ULID) set on `tn.vault.link()`; empty until linked
  (`config.py:1246`; `create_fresh` writes `""` at `config.py:689`).
- **`ceremony.project_name`** — the *human label* the operator chose;
  becomes the `X-Project-Name` header and the vault link name
  (`config.py:1265-1267`; CLI stamps it via `_stamp_project_labels`,
  `cli.py:360-362`).

---

## 4. RESTORE CONTRACT (decided — law, not open for re-litigation)

1. **One artifact across all four surfaces: `project_seed`.** The single
   user-facing backup/restore bundle is the `project_seed` tnpkg
   (manifest-signed, self-addressed `from_did == to_did`).

2. **Backup scope = KEYS + CONFIG (`tn.yaml`) ONLY.** The event
   `.ndjson` log is device-local and is NOT in the seed. Restore-then-read
   the OLD events is explicitly OUT of scope. (Matches the existing
   `_absorb_project_seed` contract: it installs `keys/local.private` +
   the tn.yaml, not the log — `absorb.py:1577-1726`.)

3. **Python `export()` and ts-sdk export MUST gain the ability to MINT
   `project_seed`.** Today **neither can**:
   - Python: `project_seed` is NOT in `KNOWN_KINDS`
     (`tnpkg.py:74-95`) nor in `ExportKind` (`export.py:68-76`).
     `export()` raises on any kind outside `KNOWN_KINDS`
     (`export.py:445-446`). Python export today mints
     `admin_log_snapshot`, `offer`, `enrolment`, `kit_bundle`,
     `full_keystore`, `identity_seed` (and reserves `recipient_invite`,
     `contact_update`).
   - ts-sdk: no `export(kind="project_seed")` producer in `ts-sdk/src`
     (only smoke scripts under `ts-sdk/scripts/` build a project_seed by
     hand for absorb tests). Phase 2 must add a real producer.

4. **A new `tn import` verb and `tn-js import` verb consume it.** Today
   the consuming verb is **`tn absorb`** (`cli.py:1421` `cmd_absorb`,
   registered at `cli.py:3161`); there is no `import` verb in the Python
   CLI, and tn-js has no `import`/`absorb`/`export` subcommand at all
   (its cases: init, vault, wallet, account, show, seal, verify,
   canonical, info, read, admin, compile, watch, streams, validate —
   `tn-js.mjs:1282-1324`). **Decision: `import` is a thin user-facing
   alias/wrapper over the existing `absorb` dispatch** — it does not
   introduce a second restore path. `absorb` already routes
   `project_seed` → `_absorb_project_seed` (`absorb.py:378-379`), so
   `import` is a rename of the entry point only; the absorb dispatcher
   and `_absorb_project_seed` body stay authoritative. Keep `absorb` as
   a hidden/deprecated alias for back-compat with shipped scripts.

5. **Browser already mints `project_seed`.** `project_minter.js` calls
   `buildSignedTnpkg({ kind: "project_seed", ... })`
   (`static/account/project_minter.js:355-356`) over the yaml that
   `buildTnYaml` produces (`:266`).

6. **NO back-compat shims for already-shipped legacy `me:` seeds.** A
   seed carrying top-level `me:` will fail to load (`config.py:1195`) and
   that is intended.

---

## 5. SURFACES INVENTORY

Producer = the function that writes the `tn.yaml` for a fresh ceremony.

| Surface | Producer (file:func) | emits canonical `device:`? | emits `recipient_identity`? | emits dead `project_id`/`label`? | can EXPORT `project_seed` today? | can ABSORB/import `project_seed` today? |
|---------|----------------------|----------------------------|-----------------------------|----------------------------------|----------------------------------|------------------------------------------|
| Python SDK | `config.py:create_fresh` (doc built at `config.py:673`+; device at the `device:` block; recipients at `:628`,`:650`), driven by `cli.py:cmd_init` / `_multi.init` | YES — `device.device_identity` | YES — `recipients: [{recipient_identity}]` (`config.py:628`,`:650`) | NO project_id, NO label | **NO** — not in `KNOWN_KINDS` (`tnpkg.py:74-95`) / `ExportKind` (`export.py:68-76`) | YES — `absorb.py:378-379` → `_absorb_project_seed` (`absorb.py:1577`); verb is `absorb` (`cli.py:3161`) |
| ts-sdk core | `runtime/node_runtime.ts:createFreshCeremony` (yaml literal `node_runtime.ts:2798-2899`); browser mirror `browser/create_fresh.ts:createFreshCeremony` (`:257-337`) | YES — `device_identity` (`node_runtime.ts:2829`; `create_fresh.ts:270`) | YES (`node_runtime.ts:2881`,`:2886`; `create_fresh.ts:322`,`:327`) | NO project_id, NO label | **NO** — no `project_seed` producer in `ts-sdk/src` (only `ts-sdk/scripts/*_smoke.mjs` hand-build for tests) | YES — `runtime/absorb_bootstrap.ts` `_absorb_project_seed` (referenced `_sealed_absorb_smoke.mjs:89`) |
| tn-js CLI | `tn-js.mjs:initCmd` (`:800`) → `createFreshCeremony` (`node_runtime.ts`, same producer as ts-sdk core, `tn-js.mjs:268`) | YES (inherits node_runtime producer) | YES (inherits) | NO project_id, NO label | **NO** — no `export` subcommand (`tn-js.mjs:1282-1324`) | **NO** — no `import`/`absorb` subcommand (`tn-js.mjs:1282-1324`) |
| browser JS | `static/account/yaml_profile.js:buildTnYaml` (`:109`), invoked by `static/account/project_minter.js:266` | YES — `device.device_identity` (`yaml_profile.js:147`) | YES — `recipient_identity` (`yaml_profile.js:168`,`:173`) | **YES — emits dead top-level `project_id:` (`yaml_profile.js:124`) AND `label:` (`:125`)** | YES — `project_minter.js:355-356` `buildSignedTnpkg({kind:"project_seed"})` | (consume) N/A on browser; restore is device-side. Browser is the canonical project_seed MINTER. |

Notes:
- The browser also includes `device_did`, `publisher_did`,
  `recipient_did`, etc. legacy aliases in its `DEFAULT_PUBLIC_FIELDS`
  mirror (`yaml_profile.js:39-77`) that the Python list no longer carries
  — cosmetic public-field drift, harmless (additive set), but worth a
  Phase 2 sweep for lockstep.
- ts-sdk Node producer emits the full `llm_classifier` block
  (`node_runtime.ts:2896-2899`); the ts-sdk browser producer
  (`create_fresh.ts`) OMITS `llm_classifier` and uses `handlers: []`.
  Both load fine (block is optional, `config.py:1455`).

---

## 6. Phase blockers / drift summary

- **DRIFT (browser):** `buildTnYaml` emits dead `project_id:` and `label:`
  top-level keys. Phase 2 must remove both; canonical label is
  `ceremony.project_name`. (`yaml_profile.js:124-125`,`:133`.)
- **DRIFT (Python API `link=False`):** `tn.init(yaml, link=False)` via the
  Python API still wrote `mode: linked` in this session's mint — the
  `link=False` knob is only honored on the path that reaches
  `create_fresh`'s `_is_unlinked` branch (`config.py:669-671`), and the
  `tn.init` high-level wrapper did not thread it through. The CLI
  `cmd_init` (which passes `link=False` to `_ensure_ceremony_on_disk`) is
  the path that produces a true `mode: local` yaml. Not a Phase-0
  blocker, but Phase 3 restore tests must mint via the CLI path (or fix
  the API thread-through) to get a self-contained `mode: local` seed.
- **GAP (Phase 2):** neither Python nor ts-sdk can MINT `project_seed`
  today. Both producers must be added. This is the central Phase 2 task.
- **GAP (Phase 2):** tn-js has no `import`/`export`/`absorb` subcommand;
  the `import` verb (alias of absorb) must be added to both the Python
  CLI and tn-js.
- **CONFIRMED (no blocker):** absorb-side `project_seed` consumption
  exists in Python (`absorb.py:378-379`) and ts-sdk
  (`absorb_bootstrap.ts`), and the browser already mints `project_seed`.
  So Phases 2/3 are additive (producers + verb rename), not a rewrite of
  the consume path.

---

## 7. Golden fixture

`tests/golden/canonical_tn.yaml` — a loader-valid `mode: local` canonical
yaml with placeholder DIDs (`did:key:z6GOLDENdevice...`). Proven to load
via `tests/golden/load_check_canonical.py`, which mints a real keystore,
substitutes the placeholder for the real minted DID, and runs
`config.load`. Captured output:

```
LOADED_OK
project_name= GoldenProj
device_identity= did:key:z6Mk... (substituted)
ceremony_id= local_90lde9a1
mode= local
cipher= btn
group_count= 2
groups= ['default', 'tn.agents']
```

---

## 8. Phase-0 design-review addendum (orchestrator, 2026-05-29)

Reviewed the spec above against the code; the schema + restore contract are
accepted. Four amendments are now **law** for Phases 1-3:

1. **`project_seed` is a SECRET-bearing artifact.** The seed installs
   `keys/local.private` (`absorb.py:1577`+), i.e. it carries private key
   material. Therefore the new `export(kind="project_seed")` MUST be gated
   the same way `full_keystore` is — `confirm_includes_secrets=True`
   (`export.py:447`) — and the tn-js/`tn import` UX must make the
   secrets nature explicit (it is a full identity+keys backup, not a public
   manifest). Restore on a fresh device needs those private keys, so the
   secrets ARE the point — but minting must never be silent/accidental.

2. **`link=False` gets FIXED, not worked around.** Per the standing
   "honor declared config at runtime" rule: `tn.init(yaml, link=False)`
   must thread `link=False` through to `create_fresh`'s `_is_unlinked`
   branch (`config.py:669-671`) and produce `mode: local`. Phase 3 fixes
   the API thread-through; restore tests then mint self-contained local
   seeds via the public API, not only via the CLI side-door.

3. **Conformance (Phase 1) is SHAPE-based, not byte-equal.** Golden carries
   placeholder DIDs/ids/paths. The conformance test normalizes volatile
   values (every `did:key:...`, `ceremony.id`, `linked_*`, `*.path`,
   timestamps) before comparing. It asserts: (a) all REQUIRED canonical
   keys present with canonical *shape* — top-level `device.device_identity`,
   `groups.<g>.recipients[].recipient_identity`, required `ceremony.*`;
   (b) FORBIDDEN keys ABSENT — top-level `me:`, `project_id:`, `label:`;
   (c) the doc loads through `config.load`. `llm_classifier` and `handlers`
   are OPTIONAL (loader treats them optional, `config.py:1455`/`:1475`);
   the two ts-sdk producers legitimately differ there, so conformance must
   not require them.

4. **Public-fields lockstep.** Phase 2 aligns the browser
   `DEFAULT_PUBLIC_FIELDS` mirror (`yaml_profile.js:39-77`) to the Python
   list — drop the legacy `*_did` aliases (`device_did`, `publisher_did`,
   `recipient_did`, `to_did`, `peer_did`, `from_did`, `envelope_did`). The
   set is additive so this is non-breaking, but the user wants consistency.

Everything else in §1-§7 is approved as the Phase 1+ baseline.
