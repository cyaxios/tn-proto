### Task 3: Bind every package body member into the signed manifest

**Files:**
- Modify: `python/tn/tnpkg.py`
- Modify: `python/tn/export.py`
- Modify: `python/tn/cli_compile.py`
- Modify (approved verified no-runtime bootstrap remediation): `python/tn/absorb.py`
- Modify (approved public-wrapper manifest-only routing remediation): `python/tn/_pkg_impl.py`
- Modify: `python/tests/test_manifest_contract.py`
- Modify: `python/tests/test_tnpkg_container_contract.py`
- Modify (approved producer/earlier-failure regressions): `python/tests/test_admin_log.py`
- Modify (approved producer/earlier-failure regressions): `python/tests/test_project_seed.py`
- Modify (approved producer regression): `python/tests/test_contact_update_tnpkg.py`
- Modify (approved earlier body-digest failure): `python/tests/test_identity_seed.py`
- Modify (approved earlier body-digest failure): `python/tests/test_kit_bundle_sealed.py`
- Modify (approved earlier body-digest failure): `python/tests/test_absorb.py`
- Modify (approved legacy absent-index golden): `python/tests/test_tnpkg_interop.py`
- Modify: `crypto/tn-core/src/tnpkg/mod.rs`
- Modify: `crypto/tn-core/src/tnpkg/zip_write.rs`
- Modify: `crypto/tn-core/src/tnpkg/zip_read.rs`
- Modify: `crypto/tn-core/src/tnpkg/sign.rs`
- Modify: `crypto/tn-core/src/runtime_export/mod.rs`
- Modify: `crypto/tn-core/tests/manifest_contract.rs`
- Modify: `crypto/tn-core/tests/tnpkg_container_contract.rs`
- Modify (approved public-field initializer/golden expansion): `crypto/tn-core/tests/tnpkg_interop.rs`
- Modify (approved public-field initializer expansion): `crypto/tn-wasm/src/lib.rs`
- Modify (approved cross-crate strict-writer producer regression): `rust-sdk/tests/pkg.rs`
- Modify (approved strict-writer regression expansion): `rust-sdk/tests/pkg.rs`
- Modify: `ts-sdk/src/core/tnpkg.ts`
- Modify: `ts-sdk/src/tnpkg_io.ts`
- Modify: `ts-sdk/src/compile.ts`
- Modify: `ts-sdk/src/seal_bundle_producer.ts`
- Modify: `ts-sdk/src/cli/export.ts`
- Modify: `ts-sdk/src/runtime/node_runtime.ts`
- Modify (approved verified absorb-path migration): `ts-sdk/src/runtime/absorb_bootstrap.ts`
- Modify (approved public-root export expansion): `ts-sdk/src/index.ts`
- Modify: `ts-sdk/test/manifest_contract.test.ts`
- Modify: `ts-sdk/test/tnpkg_container_contract.test.ts`
- Modify (approved verified absorb regressions): `ts-sdk/test/absorb_sealed_bootstrap.test.ts`
- Modify (approved producer/fail-closed regressions): `ts-sdk/test/identity_project_seed.test.ts`
- Modify (approved producer/fail-closed regressions): `ts-sdk/test/dirt_easy_flow.test.ts`
- Modify (approved producer/tamper regressions): `ts-sdk/test/tnpkg_export_absorb.test.ts`
- Modify (approved cross-language strict-writer helper regression): `ts-sdk/test/contact_update_py_helper.py`
- Modify (approved explicit legacy absent-index fixture generator): `ts-sdk/test/fixtures/build_agentic20_project_seed.ts`
- Consume: `tests/fixtures/trust/v1/package_body_index.json`

**Interfaces:**

```text
TnpkgManifest.body_sha256: dict[str, str]
compute_body_sha256(body_files: Mapping[str, bytes]) -> dict[str, str]
prepare_manifest_body_index(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
) -> TnpkgManifest
sign_manifest_with_body(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
  signing_key: Ed25519PrivateKey,
) -> TnpkgManifest
verify_manifest_body_index(
  manifest: TnpkgManifest,
  body_files: Mapping[str, bytes],
  require_index: bool,
) -> None
```

Rust uses `Manifest.body_sha256: BTreeMap<String, String>`,
`sign_manifest_with_body(manifest, body, key)`, and
`read_tnpkg_verified(source)`. TypeScript uses
`body_sha256: Record<string, string>`, `signManifestWithBody`, and
`readTnpkgVerified` with the same snake-case wire name.

- [ ] **Step 1: Write failing cross-SDK body-index tests**

For the shared fixture, assert exact lowercase `sha256:` values, signing bytes,
and signature. Add one-property failures for a substituted body, missing indexed
member, extra archive member, malformed digest, and missing index. Prove the
manifest signature is checked before body bytes are loaded and the digest index
is checked before any kind-specific body parser or mutation.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_manifest_contract.py python/tests/test_tnpkg_container_contract.py -q`

Run: `cargo test -p tn-core --test manifest_contract --test tnpkg_container_contract`

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/manifest_contract.test.ts test/tnpkg_container_contract.test.ts` from `ts-sdk/`.

Expected: manifests do not expose or verify `body_sha256`.

- [ ] **Step 3: Implement the additive v1 field and strict writer/reader checks**

Compute the map from final stored bytes before signing through the central
builder, then migrate every producer listed above to that builder. `_write_tnpkg`,
Rust `write_tnpkg`/`write_tnpkg_bytes`, and TS writers reject an unsigned
manifest or a map that differs from their supplied body. Refactor Rust's current
body-first `read_tnpkg` path: `read_tnpkg_verified` enforces central-directory
limits, reads the bounded manifest alone, verifies its complete-DID signature,
then reads bounded members and checks the exact digest map before returning any
body. Secure absorb uses only that API. Low-level inspection may parse a legacy
manifest only when it does not apply body state; security-sensitive absorb
requires the index unless its caller selects the named unsafe legacy migration
in Task 5.

Representative Python check:

```python
actual = compute_body_sha256(body_files)
if manifest.body_sha256 != actual:
    raise TrustError(TrustReason.BODY_DIGEST_MISMATCH, "body index mismatch")
```

- [ ] **Step 4: Run GREEN and targeted format checks**

Run all three Step 2 commands.

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/tnpkg/mod.rs crypto/tn-core/src/tnpkg/zip_write.rs crypto/tn-core/src/tnpkg/zip_read.rs crypto/tn-core/src/tnpkg/sign.rs crypto/tn-core/src/runtime_export/mod.rs crypto/tn-core/tests/manifest_contract.rs crypto/tn-core/tests/tnpkg_container_contract.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit only baseline-clean paths as `feat(tnpkg): sign package body digests`.

## Independent-review remediation

- Expand to `python/tn/absorb.py` and existing bootstrap regressions: the
  no-runtime bootstrap path may perform only a bounded manifest kind peek
  before trust; recognized bootstrap bodies must be verified once, reused for
  config derivation and dispatch, and trust failures must not autoinit or
  create files.
- Expand narrowly to the existing dirty `python/tn/_pkg_impl.py`: the public
  `tn.absorb` wrapper must perform only the manifest-only bootstrap routing
  peek, leaving the single verified body read and rejection handling to the
  raw absorb path. Preserve its pre-existing BTN-only bundler changes.
- Rust ZIP preflight must identify a structurally valid EOCD (including its
  comment length and archive end), reject inconsistent metadata and
  unsupported ZIP64, and enforce entry-count/central-directory caps before
  constructing `ZipArchive` for both path and byte sources.
- Cross-SDK test producers must follow the same strict writer contract. The
  Rust SDK package helpers and Python contact-update interop helper index final
  body bytes before signing/writing. The Agentic20 fixture generator is the
  sole explicit exception: it uses a clearly named test-only raw ZIP path to
  preserve the committed legacy absent-index fixture used by fail-closed tests.
- Writer documentation and unsigned-manifest errors must direct callers to the
  body-aware signing helpers rather than the now-insufficient signature-only
  helpers.

---
