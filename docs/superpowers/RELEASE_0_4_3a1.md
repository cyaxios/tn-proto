# 0.4.3a1 — release runbook

Single coordinated release covering:

- **Identity-naming flip** (originally queued as 0.4.2a11): `did` →
  `device_identity` across envelope wire format, yaml schema, admin
  event payloads, tnpkg manifest, Python + Rust + TS SDKs, and the
  `tn_proto_web` Mongo schema.
- **btn cipher rotation** (originally queued as 0.4.3): forward-secret
  rotation with retired-state archive and per-recipient kit renewal.
  Replaces the 0.4.2a10 `LooseRotationWarning` stopgap.

See:

- `docs/superpowers/specs/2026-05-20-identity-and-key-naming.md`
- `docs/superpowers/specs/2026-05-20-btn-cipher-rotation.md`

## Deploy order — LOAD-BEARING

The Mongo migration on `tn_proto_web` MUST run BEFORE the tn-protocol
0.4.3a1 release is tagged. The publisher-binding flow in tn_proto_web
looks up by `publishers.device_identity`; if the migration hasn't run,
legacy docs with `publishers.did` won't be found and connect-binding
will silently double-insert publisher records.

### 1. Mongo migration on prod

```bash
cd C:/codex/tn/tn_proto_web
# Match the env-var names src/config.py uses (NOT MONGO_URL /
# MONGO_DB_NAME — those defaults silently fall through to localhost,
# which produces a no-op rewrite that *looks* successful).
export VAULT_MONGO_URI=<prod>
export VAULT_MONGO_DB=<prod-db>
python scripts/migrate_0_4_3a1_identity_naming.py --require-non-localhost
```

The script is idempotent. It walks `account_projects` and rewrites
each `publishers[*].did` → `publishers[*].device_identity`, then
recreates the supporting index. Re-running is a no-op on already-
migrated documents.

`--require-non-localhost` refuses to run against `mongodb://localhost`
or `mongodb://127.*` — guards against the silent no-op above. First
line of script output is `migration target: uri=<creds-redacted> db=<name>`
so the operator can sanity-check the destination before any writes.

Verify:

```bash
mongosh --eval 'db.account_projects.findOne({"publishers.device_identity":{$exists:1}})'
```

### 2. Deploy tn_proto_web

The branch `feat/first-time-user-pass` carries the matching API + reducer
changes. Merge + deploy via the existing tn_proto_web pipeline.

### 3. Build + publish tn-protocol wheels

```bash
cd C:/codex/tn/tn_proto
nox -s build_btn build_core build_protocol
nox -s test_install          # smoke-import in a fresh venv
nox -s verify_version        # confirm 0.4.3a1 isn't already on TestPyPI
nox -s publish_test          # uploads dist/* to TestPyPI
```

### 4. Tag

```bash
cd C:/codex/tn/tn_proto
git tag -a v0.4.3a1 -m "0.4.3a1 — identity-naming flip + btn cipher rotation"
git push origin v0.4.3a1
```

The release-python GitHub workflow on the v* tag publishes the wheels to
TestPyPI (and PyPI on a real v0.4.3 tag).

### 5. Verify TestPyPI

```bash
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  'tn-protocol==0.4.3a1'
python -c "import tn, tn_btn, tn_core; s = tn_btn.PublisherState(bytes([1]*32)); o = s.rotate(); print(o.active.epoch)"
```

Expected output: `1` (post-rotation epoch).

## Wire-format compatibility

- **Envelope row_hash is byte-identical across the rename.** The
  hasher operates on field *values* with null-byte separators, not
  field *names*. Pre-rename signed log rows remain signature-verifiable.
  Only the envelope JSON shape changes (`"did":` → `"device_identity":`).
- **tnpkg manifest signatures DO change.** The manifest canonicalizes
  with field names. Frozen `.tnpkg` files signed under the legacy
  schema can no longer be verified. Regenerate via each SDK's
  `build_*_fixture.py` / `.ts` after this release lands.
- **yaml schema is breaking.** Legacy `me: {did: ...}` is rejected
  at load time with a pointed migration error. The `tn_proto_web`
  service yaml has been migrated; downstream services that consume
  TN configs need to flip their own yamls.

## Mapping reference

```
did              → device_identity       (envelope root + DeviceKey)
device_did       → device_identity       (admin events)
publisher_did    → publisher_identity    (admin events + manifest)
recipient_did    → recipient_identity    (admin events + yaml recipients + manifest)
peer_did         → peer_identity         (admin events)
vault_did        → vault_identity        (admin events)
to_did           → recipient_identity    (collapsed; manifest + admin)
from_did         → publisher_identity    (collapsed; manifest + admin)
signer_did       → device_identity       (collapsed; Package + admin)
envelope_did     → envelope_device_identity (tampered-row event)
me: (yaml top)   → device:                (yaml schema)
publishers[].did → publishers[].device_identity (tn_proto_web Mongo)
```

Back-compat shims (still work indefinitely):

- `DeviceKey.did` / `Identity.did` — `@property` returning the new
  `device_identity` field.
- Operator-facing yaml template tokens (e.g. fs.drop's `{from_did}`
  placeholder) — intentionally kept on legacy spelling so existing
  yaml handler templates don't break.

## btn cipher rotation surface

After 0.4.3a1, `tn.admin.rotate("default")` on btn is forward-secret:

- Fresh `master_seed` + new `publisher_id` + cipher `epoch` bump.
- Prior state archived under `<group>.btn.state.retired.<N>` (the
  lightweight `RetiredPublisherState` wire format, kind byte `0x04`).
- Prior self-kit archived under `<group>.btn.mykit.retired.<N>`.
- Per-recipient `.tnpkg` bundles minted under
  `<keystore>/rotations/<group>/<new_epoch>/<safe_did>.tnpkg`. Operators
  distribute out-of-band; recipients absorb via `tn.absorb(<path>)`.
- `tn.rotation.completed` event carries new truth-telling fields:
  `cipher_actually_rotated: True`, `prior_publisher_id_hex`,
  `new_publisher_id_hex`, `prior_epoch`, `new_epoch`,
  `renewed_recipients`, `renewal_output_dir`.
- `RotateGroupResult.cipher_actually_rotated` is now `True` for btn
  (was hardcoded `False` in 0.4.2a10).

Removed in 0.4.3a1:

- `tn.LooseRotationWarning` class.
- `tn.admin.rotate(..., acknowledge_loose=True)` kwarg.

Both were the truth-telling stopgap from 0.4.2a10 before the cipher
work actually landed. They're gone now; btn rotation is real.

## Test state at release

- `cargo test --workspace --no-fail-fast`: 46/46 suites green
  (306 tests pass, 6 ignored perf-matrix opt-in).
- `pytest python/tests/` (excluding integration suite, which exercises
  external Mongo / vault deployment): see CI status; remaining failures
  are scoped to specific SDK-rebuild-dependent fixtures and will clear
  once the wheel-rebuild step (`nox -s build_*`) is part of the CI
  workflow on this branch.

End of runbook.
