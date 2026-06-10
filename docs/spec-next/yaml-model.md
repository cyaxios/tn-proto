# YAML Model

This document captures the next YAML contract we are converging on. It is
based on the active Python implementation, then locked with TS/Rust parity
tests.

## Shape

TN YAML is project-scoped at the root, with stream YAML files as overlays.

The root project YAML owns identity and security state:

- `device`
- `keystore`
- `groups`
- `fields`
- `public_fields`
- `default_policy`
- `llm_classifier`
- project/vault metadata

Stream YAML files may point at the project root with:

```yaml
extends: ../tn.yaml
```

Stream YAMLs should remain small. They may override stream-local behavior:

- `ceremony` subfields such as `id`, `profile`, `sign`, `chain`,
  `admin_log_location`, and `log_level`
- `logs`
- `handlers`

## Extends Merge

When a child YAML declares `extends`, the loader reads the parent, resolves the
parent first, then merges the child over it.

Rules:

- Parent-owned keys are inherited from the parent. If the child also declares
  them, the parent wins.
- `ceremony` is shallow-merged by subfield. Child subfields win.
- `logs` is child-owned. Child wins outright.
- `handlers` is child-owned. If the child declares `handlers`, its list replaces
  the parent list, including `handlers: []`.
- Other top-level keys use normal child-wins behavior.

Parent relative paths are absolutized against the parent YAML directory before
the merge. This prevents a child stream from accidentally resolving the
parent's `keystore.path`, `logs.path`, handler paths, or
`ceremony.admin_log_location` against the child directory.

## Handler Rationale

Handler inheritance is intentionally replacement-based, not additive. A stream
that declares:

```yaml
handlers:
  - kind: stdout
    name: stdout
```

means "stdout only." It must not silently inherit the parent file sink and
dual-write. Shared default handler behavior should be created explicitly by the
stream writer, not by implicit loader merge.

## Vault Block

Vault state is explicit. If a YAML file has no vault block and no vault handler,
vault sync is off.

Fresh project init should write an explicit vault block unless the caller opts
out:

```yaml
vault:
  enabled: true
  url: https://vault.tn-proto.org
  linked_project_id: ""
  autosync: true
  sync_interval_seconds: 600
```

Rules:

- `vault.enabled: false` disables vault behavior even if other vault metadata or
  legacy `ceremony.linked_*` fields are present.
- `linked_project_id: ""` means "not linked yet." `wallet link` may populate it.
- Absorb may populate `url` and `linked_project_id` from a root-authoritative
  `project_seed` package only when the corresponding local value is empty. It
  must not overwrite a non-empty local value. Kit bundles and admin snapshots do
  not establish project/vault authority.
- `autosync: true` means the project should have a conceptual `vault.sync`
  handler. The handler sleeps quietly until link/auth material exists.
- `sync_interval_seconds` defaults to `600` when omitted.
- Wallet sync reads the normalized project-level vault view first, using legacy
  `ceremony.linked_*` fields only for YAMLs that do not declare `vault:`.
- Vault sync backs up project control state only. It never includes application
  log files or stream output history.

Legacy `ceremony.linked_vault`, `ceremony.linked_project_id`, and
handler-specific `vault.push`/`vault.pull` fields remain compatibility inputs
while implementations move to the project-level block.

## Current Contract Tests

- Python: `python/tests/test_extends_loader.py`
- Python vault block: `python/tests/test_vault_yaml_model.py`
- Python fresh init / link-state vault block: `python/tests/test_ceremony_link_state.py`
- Python project-seed vault adoption: `python/tests/test_project_seed.py`
- Python wallet sync vault view: `python/tests/test_wallet_backup_scope.py`
- TS: `ts-sdk/test/extends_loader.test.ts`
- TS vault block: `ts-sdk/test/yaml_vault_model.test.ts`
- TS fresh init vault block: `ts-sdk/test/create_fresh_vault_yaml.test.ts`
- TS wallet link vault block: `ts-sdk/test/wallet_link.test.ts`
- TS project-seed vault adoption: `ts-sdk/test/tnpkg_export_absorb.test.ts`
- Rust: `crypto/tn-core/tests/extends_loader.rs`
- Rust vault block: `crypto/tn-core/tests/config_parse.rs`

These tests assert parent-owned key behavior, `ceremony` shallow merge, path
absolutization, cycle detection, handler replacement, and vault block
normalization and the rule that an explicit disabled vault block suppresses
legacy ceremony link fields. The fresh-init and wallet-link tests additionally
assert that Python and TS write the explicit project-level `vault:` block with
`sync_interval_seconds: 600`.
