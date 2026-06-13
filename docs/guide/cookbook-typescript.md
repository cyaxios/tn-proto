# TN TypeScript SDK + CLI Cookbook

Recipes for the TN protocol TypeScript SDK and its `tn-js` CLI.

Two ways to drive TN from TypeScript:

- The CLI: `node bin/tn-js.mjs <command> ...` (run from `ts-sdk/`).
- The code API: `import * as tn from "tn-proto"` — the module-level
  surface (`tn.init` / `tn.log` / `tn.info` / `tn.read` / ...) mirrors Python.
  For multiple ceremonies in one process, use the `Tn` class directly.

`tn-js init` is the universal entry point. There is no separate enroll step.

The code snippets in this guide were run with:

```bash
node --import tsx --import ./test/_setup_wasm.mjs <file.mts>
```

The `_setup_wasm.mjs` import loads the Rust core compiled to wasm and is required
for any script that touches the runtime.

## Basics

### Initialize in code

`tn.use(name)` mints (or attaches to) a named ceremony on disk under
`<projectDir>/.tn/<name>/`. `tn.init(yamlPath)` makes a ceremony the
process-level default so the bare verbs (`tn.log`, `tn.info`, `tn.read`) act on
it. Both return the underlying `Tn` instance.

```typescript
import * as tn from "tn-proto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Entry } from "tn-proto";

const dir = mkdtempSync(join(tmpdir(), "tncook-"));

// Mint/attach a named ceremony on disk under <dir>/.tn/cookbook/
const t = await tn.use("cookbook", { projectDir: dir });
const cfg = t.config();
console.log("ceremony id:", cfg.ceremonyId);
console.log("device did :", cfg.device.device_identity);

// Make it the process-default, then log against it
await tn.init(cfg.yamlPath);

// tn.log: severity-less attested event (fields only)
const r1 = tn.log("order.placed", { sku: "A-100", qty: 2 });
console.log("log    -> seq", r1.sequence, "eventId", r1.eventId);

// tn.info: severity INFO, message + fields
const r2 = tn.info("user.login", "login ok", { user: "alice" });
console.log("info   -> seq", r2.sequence, "eventId", r2.eventId);

// tn.read: typed Entry by default
for (const e of tn.read()) {
  const entry = e as Entry;
  console.log("read   ->", entry.sequence, entry.level, entry.event_type, JSON.stringify(entry.fields));
}
await tn.close();
```

Output (the `LOG` / `INFO` lines come from the ceremony's configured stdout
handler; the `->` lines are the script's own `console.log`):

```text
ceremony id: stream_cookbook_8301db
device did : did:key:z6Mkk5mb9qEpN3eggJqn8FZbGaet9Je7GHqJwywuS2QdNLSa
15:26:26.982 LOG    seq=1  order.placed  id=019ea7d7…  did=did:key:z6Mkk5mb…
log    -> seq 1 eventId 019ea7d7-a0a6-72b2-8ed8-0eb06449bc5a
15:26:26.992 INFO   seq=1  user.login  id=019ea7d7…  did=did:key:z6Mkk5mb…
info   -> seq 1 eventId 019ea7d7-a0b1-7252-9cc4-e038136a1f33
read   -> 1  order.placed {"qty":2,"sku":"A-100"}
read   -> 1 info user.login {"user":"alice"}
```

Notes on shapes:

- The receipt returned by `tn.log` / `tn.info` has `{ eventId, rowHash, sequence }`.
- A typed `Entry` from `tn.read()` carries `event_type`, `timestamp`, `level`,
  `message`, `fields`, `device_identity`, `event_id`, `sequence`, `run_id`,
  `prev_hash`, `row_hash`, `signature`, `hidden_groups`.
- `tn.log` records no severity (the `level` column is empty); `tn.info` sets
  `level: info`.

### Logging with fields

`tn.log(eventType, fields)` and `tn.info(eventType, message, fields)`. Each call
appends one attested, signed, hash-chained entry. The first positional after the
event type may be either a fields object or a message string:

```typescript
tn.log("order.placed", { sku: "A-100", qty: 2 });   // fields only
tn.info("user.login", "login ok", { user: "alice" }); // message + fields
tn.warning("quota.near", { used: 0.92 });             // severity WARNING
tn.error("charge.failed", "gateway timeout", { txn: "t_42" });
```

Severity verbs available on the module surface: `tn.debug`, `tn.info`,
`tn.warning`, `tn.error`, plus severity-less `tn.log`.

### Read back in code (typed)

`tn.read()` yields a typed `Entry` by default. Pass `{ raw: true }` only when you
want the raw envelope dict instead.

```typescript
for (const e of tn.read()) {
  const entry = e as Entry;
  console.log(entry.sequence, entry.event_type, entry.fields);
}
```

### Read from the CLI

```bash
node bin/tn-js.mjs read --yaml .tn/demo/tn.yaml --compact
```

Output (one JSON line per entry; `--compact` collapses the pretty-print).
Each line carries the decoded per-group `plaintext` and the `valid` block proving
signature, row-hash, and chain integrity:

```json
{"event_type":"order.placed","sequence":1,"timestamp":"2026-06-08T15:26:50.619000Z","device_identity":"did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS","row_hash":"sha256:7c1059fcd4a3996f32ec5d7693e2937bdafe7877047a1b516e2d237915b596d6","plaintext":{"default":{"qty":"2","run_id":"62963acd5e4e475a951ea53b6b8535a3","sku":"A-100"}},"valid":{"signature":true,"rowHash":true,"chain":true}}
{"event_type":"user.login","sequence":1,"timestamp":"2026-06-08T15:26:51.051000Z","device_identity":"did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS","row_hash":"sha256:afddf5316e103e43261462039e223edace2dd94225847e9a4f015279ada8e8cb","plaintext":{"default":{"run_id":"df56ae5e259249278f476a300ab71438","user":"alice"}},"valid":{"signature":true,"rowHash":true,"chain":true}}
```

## CLI commands

The ceremony used in the examples below was minted once with:

```bash
node bin/tn-js.mjs init demo --no-link
```

```json
{"ok":true,"yaml_path":"...\\.tn\\demo\\tn.yaml","ceremony_id":"local_1375be14","did":"did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS"}
```

### init

```text
tn-js init [<project-name>] [--yaml <yaml-path>] [--no-link] [--link <url>]
  Mint or attach to a TN ceremony. A <project-name> mints a root
  ceremony at <cwd>/.tn/<name>/ (own keystore + admin + logs) and,
  unless --no-link, backs it up to the vault and prints a claim URL.
  --link <url> overrides the vault base URL (default: TN_VAULT_URL
  or the hosted vault). --yaml attaches to an explicit yaml; no arg
  runs discovery (./tn.yaml -> ./.tn/default/tn.yaml).
```

`--no-link` skips the vault backup so init runs fully offline:

```bash
node bin/tn-js.mjs init demo --no-link
```

```json
{"ok":true,"yaml_path":"...\\.tn\\demo\\tn.yaml","ceremony_id":"local_1375be14","did":"did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS"}
```

Code-API equivalent: `await tn.use("demo", { projectDir })` mints the same
on-disk ceremony; `await tn.init(yamlPath)` attaches to an existing yaml.

### wallet status

```text
tn-js wallet status [<yaml>]
  print identity + optional ceremony details
```

```bash
node bin/tn-js.mjs wallet status --yaml .tn/demo/tn.yaml
```

```text
Identity: did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS
  file:    ...\tn\identity.json
  linked:  https://vault.tn-proto.org
  prefs:   default_new_ceremony_mode=local
           prefs_version=0
Ceremony: local_1375be14
  yaml:            ...\.tn\demo\tn.yaml
  mode:            local
  cipher:          btn
  linked_vault:    (none)
  linked_project:  (none)
  groups:          ["default","tn.agents","finance"]
  pending_sync:    (queue empty)
```

### wallet sync

```text
tn-js wallet sync [<yaml>] [--pull] [--push-only] [--drain-queue] [--passphrase <p>] [--vault <url>]
  two-way sync: pull account inbox + absorb, then push the body backup
  (--pull stages only; --push-only / --drain-queue skip the pull/absorb)
```

The pull stage runs against the live vault and stages snapshots for `tn absorb`:

```bash
node bin/tn-js.mjs wallet sync .tn/demo/tn.yaml --pull --vault https://vault.tn-proto.org
```

```text
Pulled 0 snapshot(s); run `tn absorb <path>` on each to materialize.
```

The push stage wraps the project BEK with the account key derived from your
passphrase, so a full two-way sync needs `--passphrase` and a ceremony that has
been linked (`wallet link`). Without a linked ceremony:

```text
tn: error: ceremony local_1375be14 is not linked; nothing to push
```

### wallet link

```text
tn-js wallet link <vault-url> --yaml <path> [--name <project>]
  create vault project + flip ceremony.mode to linked
```

```bash
node bin/tn-js.mjs wallet link https://vault.tn-proto.org --yaml .tn/demo/tn.yaml --name cookbook-demo
```

```json
{"ok":true,"verb":"wallet.link","project_id":"01KTKXN7GWT21PPNVFS04695JJ","project_name":"cookbook-demo","vault_base_url":"https://vault.tn-proto.org","newly_linked":true}
```

### wallet unlink

```text
tn-js wallet unlink --yaml <path>
  flip ceremony.mode back to local (yaml-only; vault project untouched)
```

```bash
node bin/tn-js.mjs wallet unlink --yaml .tn/demo/tn.yaml
```

```json
{"ok":true,"verb":"wallet.unlink","yaml":".tn/demo/tn.yaml"}
```

### wallet pull-prefs

```text
tn-js wallet pull-prefs [--vault <url>]
  refresh the global identity's account prefs from the vault
```

```bash
node bin/tn-js.mjs wallet pull-prefs --vault https://vault.tn-proto.org
```

```text
Pulled prefs from https://vault.tn-proto.org:
  default_new_ceremony_mode: local
  prefs_version: 0
```

### wallet export-mnemonic

```text
tn-js wallet export-mnemonic [--yes]
  re-display the stored BIP-39 recovery phrase (--yes to confirm)
```

This only works if `identity.json` was created with `--keep-mnemonic`. On the
default (safer) path the phrase was shown once at init and never stored:

```bash
node bin/tn-js.mjs wallet export-mnemonic
```

```text
tn: error: no mnemonic stored on this machine. identity.json was created without --keep-mnemonic (the default and safer path), so the recovery phrase was only shown once at `tn init` time. Record it elsewhere when you first see it.

If you want future `tn wallet export-mnemonic` calls to work, re-run `tn init <new-project> --keep-mnemonic` on a fresh project — this stores the phrase in identity.json (trades some security for recovery convenience).
```

There is also a `wallet restore --vault <url> --out <dir>` subcommand (listed in
`wallet` help) that pulls a ceremony backup down from the vault.

### account connect

```text
tn-js account connect <code> --yaml <path> [--vault <url>] [--identity <path>]
  redeem a vault connect code; binds device DID to the account
  and persists account_id into ceremony sync state
```

Requires a vault-minted connect code. With a placeholder code the request
reaches the live vault and is rejected as not found:

```bash
node bin/tn-js.mjs account connect DEMO-CODE-0000 --yaml .tn/demo/tn.yaml --vault https://vault.tn-proto.org
```

```text
tn-js: account connect: POST /api/v1/account/connect-codes/redeem returned 404 (status=404)
```

### vault link

```text
tn-js vault link <vault-did> <project-id> [--yaml <path>]
  emit tn.vault.linked event into the ceremony's log
```

Appends a `tn.vault.linked` attested event to the log (this is a log entry, not a
mode flip — that is `wallet link`):

```bash
node bin/tn-js.mjs vault link did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH proj_demo --yaml .tn/demo/tn.yaml
```

```json
{"ok":true,"verb":"vault.link","event_id":"019ea7da-444e-7f82-9139-da4501dd73dc","row_hash":"sha256:2a599a7a9cc2975a2f9b2fbdca63a433131a0206d6589dbca1042c71abe53849","vault_did":"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH","project_id":"proj_demo"}
```

### vault unlink

```text
tn-js vault unlink <vault-did> <project-id> [--reason <text>] [--yaml <path>]
  emit tn.vault.unlinked event into the ceremony's log
```

```bash
node bin/tn-js.mjs vault unlink did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH proj_demo --reason "rotating" --yaml .tn/demo/tn.yaml
```

```json
{"ok":true,"verb":"vault.unlink","event_id":"019ea7da-459f-7b63-8ca6-8a173ed10833","row_hash":"sha256:dd9a62ef1bf3bbee4f0b1ed5d80ed12ae480781bc8485f537292e27d66df4152","vault_did":"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH","project_id":"proj_demo"}
```

#### Reading vault events back

Vault link state lives in the admin log, and `tn.read()` includes admin
events by default, so no extra option is needed. Do not hardcode an
admin-log filename; the path is recorded in the yaml.

```typescript
import { Tn } from "tn-proto";
import type { Entry } from "tn-proto";

const tn = await Tn.init("./tn.yaml");
await tn.vault.link("did:web:vault.example.org", "proj_demo123");
await tn.vault.unlink("did:web:vault.example.org", "proj_demo123");

for (const e of tn.read()) {
  const entry = e as Entry;
  if (entry.event_type.startsWith("tn.vault.")) {
    console.log(entry.event_type, entry.fields.vault_identity, entry.fields.project_id);
  }
}
await tn.close();
```

```text
tn.vault.linked did:web:vault.example.org proj_demo123
tn.vault.unlinked did:web:vault.example.org proj_demo123
```

### show env

```text
tn-js show env [--yaml <path>]
  print resolved ceremony config as JSON
```

```bash
node bin/tn-js.mjs show env --yaml .tn/demo/tn.yaml
```

```json
{
  "ok": true,
  "me": { "did": "did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS" },
  "ceremony": { "id": "local_1375be14", "cipher": "btn", "mode": "local" },
  "keystore": { "path": "...\\.tn\\demo\\keys" },
  "logs": { "path": "...\\.tn\\demo\\logs\\tn.ndjson" },
  "handlers_count": 2,
  "public_fields_count": 0
}
```

Code-API equivalent: `t.config()`.

### show profiles

```text
tn-js show profiles [--format human|json]
  print the curated profile catalog
```

```bash
node bin/tn-js.mjs show profiles
```

```text
NAME          ENCRYPTS  SIGNS  CHAINS  FLUSH     SINK
------------  --------  -----  ------  --------  --------------
transaction*  yes       yes    yes     fsync     file_rotating
audit         yes       yes    yes     buffered  file_rotating
secure_log    yes       yes    no      buffered  file_rotating
telemetry     yes       no     no      async     stdout

* = catalog default (used when tn.init() is called with no profile=).
```

`--format json` prints the same catalog with each profile's `intended_use`:

```json
{
  "profiles": [
    {
      "name": "transaction",
      "encrypts": true,
      "signs": true,
      "chains": true,
      "flush": "fsync",
      "default_sink": "file_rotating",
      "intended_use": "Grants, revokes, payments, agent actions, security events. Maximum evidence: signed, chained, durable. Use when reconstruction and non-repudiation matter.",
      "default": true
    }
  ]
}
```

### seal

```text
tn-js seal   stdin JSON -> ndjson envelope line on stdout
```

Signs a single envelope from a JSON object on stdin. Required input fields:
`seed_b64`, `event_type`, `level`, `sequence`, `prev_hash`, `timestamp`,
`event_id` (optional `public_fields`).

```bash
echo '{"seed_b64":"<32-byte-seed-base64>","event_type":"order.placed","level":"info","sequence":1,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","timestamp":"2026-06-08T15:27:39.309000Z","event_id":"b2f7be39-f870-43c8-97de-59feb8294961","public_fields":{"region":"us"}}' | node bin/tn-js.mjs seal
```

```json
{"device_identity":"did:key:z6MknAanj5BGGiS6vcyuuKTjwuKpFnmve5icaLmG1BoSVgXA","timestamp":"2026-06-08T15:27:39.309000Z","event_id":"b2f7be39-f870-43c8-97de-59feb8294961","event_type":"order.placed","level":"info","sequence":1,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","row_hash":"sha256:898762c1712ed873635c45b427810c95c4f20ee262ca0dd176dc82ea79ae4492","signature":"Tu4rjFmOMyEAl1EYmXIbXGB7-u8jU3RxEu_i00Z_EaI-A6StDxfoH9LwrGrsY7M-pGgeUMWWbJxJOPYd5HkVCg","region":"us"}
```

### verify

```text
tn-js verify   ndjson envelope line -> {ok, ...} on stdout
```

Recomputes the row hash from public envelope fields and checks the signature.
Feeding it the `seal` output above:

```bash
cat env.ndjson | node bin/tn-js.mjs verify
```

```json
{"ok":true,"did":"did:key:z6MknAanj5BGGiS6vcyuuKTjwuKpFnmve5icaLmG1BoSVgXA","event_type":"order.placed","event_id":"b2f7be39-f870-43c8-97de-59feb8294961","row_hash":"sha256:898762c1712ed873635c45b427810c95c4f20ee262ca0dd176dc82ea79ae4492","sequence":1}
```

This is a public-only verify path; envelopes carrying encrypted group payloads
return `{ok:false, reason:"group payload ... present; public-only verify"}`.

### canonical

```text
tn-js canonical   stdin JSON -> canonical UTF-8 line on stdout
```

Emits the deterministic canonical form (sorted keys, recursively):

```bash
echo '{"b":2,"a":1,"nested":{"z":9,"y":8}}' | node bin/tn-js.mjs canonical
```

```json
{"a":1,"b":2,"nested":{"y":8,"z":9}}
```

### info

```text
tn-js info --yaml <path> --event <type> [--level info] --field k=v ...
  Append one attested entry to the log defined in yaml.
```

```bash
node bin/tn-js.mjs info --yaml .tn/demo/tn.yaml --event order.placed --field sku=A-100 --field qty=2
```

```json
{"event_id":"019ea7d7-fcfb-7793-bdad-b3793c28b7e4","row_hash":"sha256:7c1059fcd4a3996f32ec5d7693e2937bdafe7877047a1b516e2d237915b596d6","sequence":1}
```

Code-API equivalent: `tn.info("order.placed", { sku: "A-100", qty: 2 })`.

### read

```text
tn-js read --yaml <path> [--log <path>] [--compact]
  Iterate decoded entries as pretty JSON on stdout.
  Includes plaintext (per-group) and valid {signature,rowHash,chain}.
  --compact: one JSON line per entry instead of pretty-print.
```

See "Read from the CLI" under Basics for output. Code-API equivalent:
`for (const e of tn.read()) { ... }`.

### watch

```text
tn-js watch --yaml <path> [--since start|now|<seq>|<iso-ts>] [--verify] [--poll <ms>] [--once]
  Tail the log and write one decoded entry per line to stdout.
  --since controls the starting point (default: now, only new appends).
  --once: snapshot mode — dump matching entries and exit.
  --verify: include signature/rowHash/chain validity in output.
  --poll <ms>: polling interval in ms (default: 300).
```

`--once --since start` dumps everything currently in the log and exits:

```bash
node bin/tn-js.mjs watch --yaml .tn/demo/tn.yaml --since start --once
```

```json
{"event_type":"order.placed","timestamp":"2026-06-08T15:26:50.619Z","level":"info","message":null,"fields":{"qty":"2","sku":"A-100"},"device_identity":"did:key:z6MksPsDhwFCy8Cho6xM83iE2b21oqutKef2KmBdWDAbnSQS","event_id":"019ea7d7-fcfb-7793-bdad-b3793c28b7e4","sequence":1,"run_id":"62963acd5e4e475a951ea53b6b8535a3","prev_hash":"sha256:0000...0000","row_hash":"sha256:7c1059...","signature":"TdsSe...","hidden_groups":[]}
```

Code-API equivalent (the `--once` snapshot is a one-shot read, not a live tail): `for (const e of tn.read({ allRuns: true })) { ... }`. (`tn.watch({ since: "start" })` is the live-tail form and never returns.)

### streams

```text
tn-js streams
  list the ceremonies discovered under ./.tn
```

```bash
node bin/tn-js.mjs streams
```

```text
NAME  PROFILE      YAML
----  -----------  ----
demo  transaction  ...\.tn\demo\tn.yaml
```

Code-API equivalent: `tn.listCeremonies()`.

### validate

```text
tn-js validate
  load every ceremony under ./.tn and report validity
```

```bash
node bin/tn-js.mjs validate
```

```text
WARNING: no 'default' ceremony at .tn/default/. The project's identity should live there; named streams normally extend from it.
OK: 1 ceremony valid.
```

### compile

```text
tn-js compile --keystore <dir> --out <file.tnpkg> [--kit <group>]... [--label <text>] [--full]
  Package *.btn.mykit files into a .tnpkg (zip w/ manifest.json + kits) that the
  Chrome extension, Python SDK, and tn-js can all import.
  --kit filters to named groups; --full also writes publisher state + signing seed.
  --yaml <path> may be used in place of --keystore to infer the keystore dir.
```

```bash
node bin/tn-js.mjs compile --yaml .tn/demo/tn.yaml --out compiled.tnpkg
```

```json
{"ok":true,"out":"...\\compiled.tnpkg","kits":["default.btn.mykit","default.btn.mykit.revoked.1780932479","default.btn.mykit.revoked.1780932490","tn.agents.btn.mykit"],"kind":"readers-only","label":null}
```

Code-API equivalent: `compileKitBundleToFile(...)` (exported from `tn-proto`).

### admin add-recipient

```text
tn-js admin add-recipient --yaml <path> [--group default] --out <kit-path> [--recipient-did did:key:...]
```

Mints a reader kit for a new recipient leaf and writes the `.btn.mykit` to
`--out`. With no `--recipient-did`, a fresh recipient identity is minted:

```bash
node bin/tn-js.mjs admin add-recipient --yaml .tn/demo/tn.yaml --group default --out reader.kit
```

```json
{"ok":true,"group":"default","leaf_index":1,"kit_path":"./reader.kit","recipient_did":null}
```

Code-API equivalent: `await t.admin.addRecipient("default", { outKitPath })`.

### admin revoke-recipient

```text
tn-js admin revoke-recipient --yaml <path> [--group default] --leaf <index> [--recipient-did did:key:...]
```

```bash
node bin/tn-js.mjs admin revoke-recipient --yaml .tn/demo/tn.yaml --group default --leaf 1
```

```json
{"ok":true,"group":"default","leaf_index":1}
```

Code-API equivalent: `await t.admin.revokeRecipient("default", { leafIndex: 1 })`.

### admin revoked-count

```text
tn-js admin revoked-count --yaml <path> [--group default]
```

```bash
node bin/tn-js.mjs admin revoked-count --yaml .tn/demo/tn.yaml --group default
```

```json
{"ok":true,"group":"default","count":1}
```

Code-API equivalent: `t.admin.revokedCount("default")`.

### admin rotate

```text
tn-js admin rotate --yaml <path> [--group <g> | --groups a,b,c] [--out <dir>|<file.tnpkg>]
  The deploy primitive — rotates each target group (default: every
  non-internal group), bumps index_epoch in the yaml, and emits one
  .tnpkg per surviving recipient under ./rotated_<UTC_TS>/ (or --out).
```

```bash
node bin/tn-js.mjs admin rotate --yaml .tn/demo/tn.yaml --group default --out rotated
```

When the group has no surviving (non-revoked, non-self) recipients, the rotation
is recorded but produces no per-recipient artifact:

```json
{"ok":true,"rotated":[{"group":"default","generation":1}],"artifacts":[],"note":"no surviving recipients to bundle for; rotation recorded"}
```

With surviving recipients, `artifacts` lists one `.tnpkg` per recipient under the
output directory. Code-API equivalent: `await t.admin.rotate("default")`.

### bundle

```text
tn-js bundle <recipient> <out> [--yaml <path>] [--groups a,b] [--seal-for-recipient]
  Mint a kit_bundle .tnpkg for one recipient DID.
```

```bash
node bin/tn-js.mjs bundle did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH bundle2.tnpkg --yaml .tn/demo/tn.yaml --groups default
```

```text
[tn bundle] wrote ...\bundle2.tnpkg
[tn bundle]   recipient: did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
[tn bundle]   ceremony:  local_1375be14  (cipher=btn)
[tn bundle]   groups:    ["default"]
```

### add_recipient

```text
tn-js add_recipient <group> <recipient> [--out <path>] [--yaml <path>] [--seal-for-recipient]
  One-shot mint + bundle a reader kit for a group/recipient.
```

Combines `admin add-recipient` and `bundle` in one step for an explicit DID:

```bash
node bin/tn-js.mjs add_recipient default did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH --out bundle1.tnpkg --yaml .tn/demo/tn.yaml
```

```text
[tn add_recipient] wrote ...\bundle1.tnpkg
[tn add_recipient]   group:     default
[tn add_recipient]   recipient: did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
```

### absorb

```text
tn-js absorb <package> [--yaml <path>] [--allow-self-absorb]
  Install a .tnpkg (kit bundle, enrolment) into the active ceremony.
```

Installs a `.tnpkg` into the active ceremony's keystore. Absorbing a package the
same ceremony minted is refused unless `--allow-self-absorb` is passed (used in
tests and recovery flows):

```bash
node bin/tn-js.mjs absorb for_rcpt.tnpkg --yaml .tn/rcpt/tn.yaml --allow-self-absorb
```

```text
[tn absorb] kind=kit_bundle accepted=1 skipped=0
[tn absorb] WARN: overwrote 1 existing kit file(s):
             ...\.tn\rcpt\keys\default.btn.mykit
[tn absorb] prior bytes preserved at <name>.previous.<UTC_TS> in the same directory.
```

Code-API equivalent: `await Tn.absorb(packagePath, { ... })`.

### group add

```text
tn-js group add <name> [--fields a,b,c] [--cipher btn|jwe] [--yaml <path>]
  Add a group to an existing ceremony post-init.
```

```bash
node bin/tn-js.mjs group add finance --fields amount,currency --cipher btn --yaml .tn/demo/tn.yaml
```

```text
[tn group add] added group 'finance'
[tn group add]   fields: amount, currency
[tn group add]   cipher: btn
```

This appends a `tn.group.added` attested event to the log. Code-API equivalent:
`await t.admin.ensureGroup("finance", { fields: ["amount", "currency"] })`.

### firehose stats | list | get

```text
tn-js firehose stats <tenant>
tn-js firehose list  <tenant> [--did <did>]
tn-js firehose get   <tenant> <ceremony> <name> [--did <did>] [--out <path>]
```

Gated on `TN_FIREHOSE_URL` (plus a token). Without it set:

```bash
node bin/tn-js.mjs firehose stats acme
```

```text
tn: error: TN_FIREHOSE_URL is not set. Point it at the firehose-worker base URL (e.g. https://firehose-worker.<account>.workers.dev).
```

`firehose list` and `firehose get` report the same precondition.

### inbox accept

```text
tn-js inbox accept <zip> [--yaml <path>]
  accept an invitation zip locally and install the kit it carries.
```

Takes a downloaded `tn-invite-*.zip`. With a missing path it reports the lookup:

```bash
node bin/tn-js.mjs inbox accept invite.zip --yaml .tn/demo/tn.yaml
```

```text
Accepting invitation from invite.zip ...
Error: Zip not found: ...\invite.zip
```

### inbox list-local

```text
tn-js inbox list-local [--dir <path>]
  list downloaded tn-invite-*.zip files (default ~/Downloads); no vault contact.
```

```bash
node bin/tn-js.mjs inbox list-local --dir /tmp
```

```text
No tn-invite-*.zip files found in ...\Temp
```
