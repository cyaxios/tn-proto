# Project Backup Scope

Vault backup/sync is for project continuity, not application log storage.

The package communication unit is `.tnpkg`. For current project backup this is
`kind: "project_seed"`; future names may split initial seed from derived project
snapshot, but the inclusion rule is the same.

## Include

Project backup packages may include:

- root project YAML, currently `body/tn.yaml`
- device public/private key material required for restore
- group key state and reader kits required for restore
- project/vault linkage metadata in the manifest state
- admin/control state during the migration period

## Exclude

Project backup packages must not include application logs:

- no `logs/*.ndjson`
- no rotated application log files
- no stdout history
- no Kafka/S3/Firehose/external sink history
- no raw user-emitted stream history

Admin/control events are not application logs. During the migration period they
may be represented as admin snapshots or control-state package content. The
longer-term target is derived/signed project-state snapshots rather than raw
admin log transport.

## Legacy `sync_logs`

Older YAML may contain `ceremony.sync_logs`. It is ignored for vault backup
scope. Fresh Python YAML no longer writes it.

## Current Contract Tests

- `python/tests/test_wallet_backup_scope.py`
- `python/tests/test_project_seed_roundtrip.py`
- `ts-sdk/test/tnpkg_export_absorb.test.ts`
- `crypto/tn-core/tests/tnpkg_export_absorb.rs`
