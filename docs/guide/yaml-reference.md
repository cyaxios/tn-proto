# tn.yaml reference

`tn.yaml` is a project's configuration file: identity, keystore, groups,
recipients, log destinations, and field routing.

You normally never write this file by hand. `tn init` generates it, and the
CLI and SDK keep it in sync as you add groups, recipients, fields, or a vault
link. You can hand-edit it whenever you want finer control; the tools read
whatever is in the file.

This page documents every field. The file is standard YAML, with
Compose-style environment-variable substitution applied to the text first
(see [Environment variables](#environment-variables)).

## Example

The block below is what `tn init demoproj --no-link` writes for an offline btn
project. The comments here are explanatory; the emitted file has none.

```yaml
ceremony:
  id: local_f2bb8224              # ceremony identifier (required)
  mode: local                    # local | linked
  linked_vault: ''               # vault URL; empty when offline
  linked_project_id: ''          # vault-side project id; filled by `tn vault link`
  sync_logs: false               # also sync ndjson logs to the vault
  cipher: btn                    # btn | jwe  (ceremony-wide cipher)
  sign: true                     # Ed25519-sign every row_hash
  admin_log_location: ./admin/admin.ndjson   # where tn.* admin events land
  log_level: debug               # debug | info | warning | error
  profile: transaction           # evidence profile (see profiles.md)
  chain: true                    # maintain per-event_type hash chain
  project_name: demoproj         # human label; sent as X-Project-Name on vault push

logs:
  path: ./logs/tn.ndjson         # main user-log ndjson destination

keystore:
  path: ./keys                   # directory holding local.private, *.btn.state, etc.

device:
  device_identity: did:key:z6MknGoAJ9ncLTQ7t1mDXh1Lph7d9D5hc65XyKdDuvecTEEM

handlers:                        # output sinks; replaces the implicit default sink
- kind: file.rotating
  name: main
  path: ./logs/tn.ndjson
  max_bytes: 5242880
  backup_count: 5
  rotate_on_init: false
- kind: stdout

public_fields:                   # fields always emitted in the clear (ADDITIVE to defaults)
- timestamp
- event_id
# ... (init writes the full default catalog; see public_fields below)

default_policy: private          # policy for fields not routed to any group

groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: did:key:z6MknGoAJ9ncLTQ7t1mDXh1Lph7d9D5hc65XyKdDuvecTEEM
  tn.agents:                     # reserved protocol group (auto-injected)
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: did:key:z6MknGoAJ9ncLTQ7t1mDXh1Lph7d9D5hc65XyKdDuvecTEEM
    fields:                      # canonical multi-group routing: these fields go to tn.agents
    - instruction
    - use_for
    - do_not_use_for
    - consequences
    - on_violation_or_error
    - policy
    auto_populated_by_policy: true

fields: {}                       # field routing overrides; groups carry their own

llm_classifier:
  enabled: false
  provider: ''
  model: ''
```

A minimal ephemeral ceremony (the shape `Runtime::ephemeral` mints in
`crypto/tn-core/src/runtime/helpers.rs::write_fresh_btn_ceremony`) carries
far less:

```yaml
ceremony: {id: cer_eph_0a1b2c3d4e5f, mode: local, cipher: btn, protocol_events_location: main_log}
keystore: {path: ./.tn/keys}
device: {device_identity: "did:key:z6Mk..."}
public_fields: []
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
      - {recipient_identity: "did:key:z6Mk..."}
    index_epoch: 0
  "tn.agents":
    policy: private
    cipher: btn
    recipients:
      - {recipient_identity: "did:key:z6Mk..."}
    index_epoch: 0
    fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]
fields: {}
llm_classifier: {enabled: false, provider: "", model: ""}
```

## Top-level keys

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `ceremony` | mapping | yes | — | Ceremony metadata. See [ceremony](#ceremony). |
| `keystore` | mapping | yes | — | Keystore location. `keystore.path` is required. |
| `device` | mapping | yes | — | Publisher device identity. See [device](#device). |
| `groups` | mapping | yes | — | Named groups keyed by group name. See [groups](#groups). |
| `logs` | mapping | no | `{path: ./.tn/logs/tn.ndjson}` | Main user-log destination. See [logs](#logs). |
| `public_fields` | list of string | no | a 47-field catalog | Fields emitted in the clear. See [public_fields](#public_fields). |
| `default_policy` | string | no | `private` | Policy for fields not routed to any group. |
| `llm_classifier` | mapping | no | `{enabled: false, provider: "", model: ""}` | Classifier stub config. See [llm_classifier](#llm_classifier). |
| `handlers` | list of mapping | no | implicit default file sink | Output sinks. See [handlers](#handlers). |
| `extends` | string | no | — | Relative path to a parent yaml to inherit from. See [extends](#extends). |

`ceremony`, `keystore`, `device`, and `groups` are required; loading fails if
any is missing.

### ceremony

`ceremony` is a mapping of scalar settings.

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `ceremony.id` | string | yes | — | Ceremony identifier (e.g. `local_f2bb8224`, `cer_...`). Python raises if empty. |
| `ceremony.mode` | string | no | `local` | `local` (offline) or `linked` (vault-bound). `linked` requires `linked_vault`. |
| `ceremony.cipher` | string | yes | `btn` | Ceremony-wide cipher: `btn` or `jwe`. |
| `ceremony.linked_vault` | string | no | `null` / `""` | Vault URL for linked mode. Required when `mode: linked`. |
| `ceremony.linked_project_id` | string | no | `null` / `""` | Vault-side project id. Empty until `tn vault link` claims one. |
| `ceremony.sync_logs` | bool | no | `false` | Whether wallet-linked ceremonies also sync ndjson logs. |
| `ceremony.sign` | bool | no | `true` | Sign each row's `row_hash` with the device Ed25519 key. `false` = chain-only (still `prev_hash`/`row_hash` tamper-evidence, no identity attestation). |
| `ceremony.chain` | bool | no | `true` | Maintain a per-`event_type` hash chain (sequence + prev_hash + cross-process tip refresh). `false` emits `sequence: 1`, `prev_hash: ""`, and skips the per-emit advisory lock. |
| `ceremony.admin_log_location` | string | no | `./.tn/admin/admin.ndjson` | Where `tn.*` admin envelopes are written. Literal `main_log` folds them into the main log. Otherwise a path template (see [path templates](#path-templates)). |
| `ceremony.log_level` | string | no | `debug` | Active log-level threshold: `debug` / `info` / `warning` / `error`. |
| `ceremony.project_name` | string | no | `null` | Operator-chosen human label. Sent as the `X-Project-Name` header on vault push so the vault shows a name instead of the random `ceremony_id`. |
| `ceremony.version_name` | string | no | `null` | Per-instance nickname inside the project (e.g. `laptop-dev`, `ci`, `prod`). Falls back to `project_name` when unset. |
| `ceremony.profile` | string | no | `transaction` | Evidence profile (`transaction` / `audit` / `secure_log` / `telemetry` / `stdout`). Sets `sign` / `chain` / sink at init. See [profiles.md](profiles.md). |

### keystore

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `keystore.path` | string | yes | — | Directory holding key material (`local.private`, `local.public`, `index_master.key`, `<group>.btn.state`, `<group>.btn.mykit`, JWE sidecars). Relative paths resolve against the yaml directory; absolute paths are used as-is. |

### device

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `device.device_identity` | string | yes | — | This party's `did:key:z…` device DID. |

### logs

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `logs.path` | string | no | `./.tn/logs/tn.ndjson` | Main user-log ndjson destination. Single path. May contain path-template tokens (validated to resolve under the ceremony directory). For event-type splitting use `handlers:` or `admin_log_location`. |

### public_fields

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `public_fields` | list of string | no | see below | Field names always emitted as plaintext on the envelope root. A field listed here cannot also appear in a group's `fields:` list (that overlap is a load error). |

Defaulting differs across loaders, and this is intentional:

- Rust `Config.public_fields` defaults to `[]`.
- Python merges the yaml list **additively** on top of a built-in
  `DEFAULT_PUBLIC_FIELDS` catalog (47 envelope-routing and admin-catalog
  field names such as `timestamp`, `event_id`, `event_type`, `level`,
  `ceremony_id`, `recipient_identity`, `policy_uri`, ...). `tn init` writes
  that full catalog into the file, so the on-disk default is the 47-field
  list, de-duplicated, with any yaml additions appended in order.

The `DEFAULT_PUBLIC_FIELDS` catalog includes the string `project_id`, but
that is a **payload field name** kept public so the vault reducer can read
it without a reader kit. It is unrelated to the top-level `project_id` key,
which no loader reads.

### groups

`groups` is a mapping from group name to a group spec. At least the
`default` group is expected; the TS loader synthesizes a `default` group
(recipient = the device) when none is declared.

Group names starting with `tn.` are **reserved**. The only allowed reserved
name is `tn.agents` (auto-injected). Any other `tn.*` group name is rejected
at load by all three loaders.

Per-group fields:

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `groups.<name>.cipher` | string | no | ceremony cipher | Cipher for this group: `btn` or `jwe`. Defaults to the ceremony cipher. |
| `groups.<name>.policy` | string | no | `private` | `private` or `public`. |
| `groups.<name>.recipients` | list of mapping | no | `[]` | Declared recipients (used at ceremony setup; the runtime cipher loads its own state files). See [recipient entries](#recipient-entries). |
| `groups.<name>.fields` | list of string | no | `[]` | Field names this group encrypts. Canonical multi-group routing source of truth: a field listed under N groups is encrypted into all N groups' payloads. Omitted-when-empty on serialize (round-trip stable). |
| `groups.<name>.index_epoch` | integer (u64) | no | `0` | Incremented when keys rotate; feeds HKDF info for index-key derivation. |
| `groups.<name>.pool_size` | integer | no | `4` | BGW pool size. Ignored by `btn`/`jwe` ciphers. |
| `groups.<name>.auto_populated_by_policy` | bool | no | — | Marker on the `tn.agents` group recording that its fields are policy-driven. Informational. |

#### recipient entries

Each entry in `recipients` is a mapping:

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `recipient_identity` | string | yes | — | Recipient device DID (`did:key:z…`). |
| `key` | string | no | `null` | BGW reader-key file path (relative to keystore). |
| `pub_b64` | string | no | `null` | JWE X25519 public key, standard base64. |

### Field routing validation

A field routed to an unknown group is an error, and a field cannot appear in
both `public_fields` and a group's `fields:` list.

### llm_classifier

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `llm_classifier.enabled` | bool | no | `false` | Whether the classifier is on. Currently a stub; classification stays Python-side. |
| `llm_classifier.provider` | string | no | `""` | Provider identifier. |
| `llm_classifier.model` | string | no | `""` | Model identifier. |

### handlers

`handlers` is a list of output-sink specs. If the key is absent, the runtime
synthesizes a single default rotating file sink. If the key is present but
the list is **empty**, that is treated as an explicit opt-out (no log output;
Python logs a warning).

Common per-entry fields:

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `handlers[].kind` | string | yes | — | Sink type (see catalog below). |
| `handlers[].name` | string | no | `kind` | Handler name; used for dedupe across an `extends:` merge. |
| `handlers[].filter` | mapping | no | — | Filter spec (field/op dict, or shorthand keys `event_type_prefix`, `not_event_type_prefix`, `event_type_in`, `level_in`, `sync`). |

The Rust loader treats each handler entry as an opaque `serde_yml::Value` and
leaves interpretation to the host. The Python registry
(`python/tn/handlers/registry.py`) is the authority for handler kinds and
their per-kind options:

| `kind` | key options |
|--------|-------------|
| `file.rotating` / `file` | `path` (required; may be a template), `max_bytes` (default `5242880`), `backup_count` (default `5`), `rotate_on_init` (default `false`) |
| `file.timed_rotating` | `path` (required), `when` (default `midnight`), `backup_count` (default `30`) |
| `stdout` | `format`, `include_admin` (default consults `TN_STDOUT_INCLUDE_ADMIN`) |
| `kafka` | `bootstrap`, `topic` (required), `sasl`, `client_id`, `compression_type` (default `zstd`), `acks` (default `all`) |
| `s3` / `aws.s3` | `bucket` (required), `prefix`, `region`, `access_key`, `secret_key`, `session_token`, `endpoint_url`, `sse`, `sse_kms_key_id`, `batch_max_rows`, `batch_max_bytes`, `batch_window_sec` |
| `delta` / `delta_table` / `databricks` | `host`, `token` (required), `warehouse_id`, `catalog`, `schema`, `table`, `partition_by`, `batch_max_rows`, `batch_max_bytes`, `batch_window_sec`, `one_table_per_event_type` |
| `vault.sync` / `vault` | `vault_identity`, `project_id` (required), `keystore_path`, `batch_interval_ms`, `batch_max_events` |
| `vault.push` | `endpoint`, `project_id` (required), `trigger`, `poll_interval`, `scope` |
| `vault.pull` | `endpoint`, `project_id` (required), `poll_interval`, `on_absorb_error` |
| `tn.firehose` | `endpoint`, `project_id` (required), `key_id` |
| `fs.drop` | `out_dir`, `on`, `scope`, `trigger`, `filename_template` |
| `fs.scan` | `in_dir` (required), `archive_dir`, `poll_interval`, `on_processed` |
| `otel` / `opentelemetry` | wired programmatically via `extra_handlers`; YAML-only declares a no-op logger |

`poll_interval` and similar duration fields accept a number (seconds) or a
string like `"60s"`, `"5m"`, `"1h"`, `"500ms"`.

## extends

A child yaml may declare `extends: <relpath>` to inherit from a parent. Used
by per-stream yamls (the multi-ceremony layer), which carry only their own
overrides and pull identity, keystore, groups, and recipients from the chain
root.

| path | type | required | default | description |
|------|------|----------|---------|-------------|
| `extends` | string | no | — | Relative path (against the child's directory) to the parent yaml. |

Merge rules (identical across Rust, Python, TS):

- **Parent-owned keys** — `device`, `keystore`, `groups`, `fields`,
  `public_fields`, `default_policy`, `llm_classifier`: parent wins. A child
  override is dropped (Python/TS warn; Rust is silent). These belong at the
  chain root only.
- `ceremony`: shallow-merged per subfield, child wins.
- `handlers`: additive, deduped by `name` (falling back to `kind`); child
  entries win on a name collision.
- All other top-level keys (`logs`, etc.): child wins if set, else parent's.

Parent relative paths (`keystore.path`, `logs.path`, `handlers[].path`,
`ceremony.admin_log_location`) are absolutized against the parent's directory
before merging into the child's coordinate system. The chain has a maximum
depth of 8 and a cycle check; both surface as a clean error.

## Environment variables

Before YAML parsing, every loader runs Compose-style substitution over the
raw file text (not the parsed structure):

- `${NAME}` — required; load fails if `NAME` is unset.
- `${NAME:-default}` — falls back to `default` (which may be empty).
- `$${literal}` — escape; emits the literal `${literal}`.

Variable names match `[A-Za-z_][A-Za-z0-9_]*`. There is no recursive
expansion. Malformed references (e.g. `${1FOO}`, `${FOO BAR}`) raise a
path- and line-prefixed error.

## Path templates

`ceremony.admin_log_location` and `logs.path` may contain template tokens,
rendered per-envelope by the runtime. Recognized tokens (Python
`_KNOWN_PEL_TOKENS`): `{event_type}`, `{event_class}`, `{event_id}`,
`{date}`, `{yaml_dir}`, `{ceremony_id}`, `{did}`. An unknown token, or a
template that resolves outside the ceremony directory, is rejected at load.
The literal `main_log` (only valid for `admin_log_location`) is an escape
hatch that folds admin events back into the main log instead of a separate
file.
