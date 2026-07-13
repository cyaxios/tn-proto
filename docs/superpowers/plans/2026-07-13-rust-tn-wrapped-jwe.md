# Rust TN-Wrapped JWE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make configured Rust runtimes emit and read `cipher: jwe` groups using Biscuit direct A256GCM bodies and TN per-DID content-key wraps.

**Architecture:** `cipher/jwe.rs` owns a strict `tn-jwe-v1` frame and implements the existing `GroupCipher` boundary. `recipient_seal.rs` exposes its key-wrap primitive inside `tn-core`, and runtime construction passes the already-authenticated device key plus configured recipient DIDs into the cipher. The read scanner, policy, and projections remain unchanged.

**Tech Stack:** Rust 2021, Biscuit 0.8 compact JWE, AES-256-GCM, X25519, HKDF-SHA256, serde, zeroize

## Global Constraints

- This is a clean replacement; do not implement the legacy General JSON JWE format.
- Do not create, read, or export `.jwe.mykey` material in the configured-runtime slice.
- Use complete canonical Ed25519 `did:key` recipients and the runtime's existing `local.private` seed.
- Pin body algorithms to `alg=dir` and `enc=A256GCM` during decryption.
- Reject more than 1,024 recipient wraps.
- Do not change `Tn::read`, read policy, scanner, or projection APIs.
- Every affected production Rust file must remain at most 609 lines; changed functions target at most 50 lines and must never exceed 200 lines.
- Never stage or modify the unrelated dirty Python and TypeScript worktree files.

---

### Task 1: Reuse TN recipient key wrapping

**Files:**
- Modify: `crypto/tn-core/src/recipient_seal.rs`

**Interfaces:**
- Produces: `seal_key_for_recipient(key: &[u8; 32], recipient_did: &str, aad: &[u8]) -> Result<Value>`
- Produces: `unseal_key_from_wrap(wrap: &Map<String, Value>, device_seed: &[u8; 32], aad: &[u8]) -> Result<[u8; 32]>`
- Preserves: existing `.tnpkg` manifest wrapping behavior byte-for-byte apart from required randomness

- [ ] **Step 1: Add a focused round-trip unit test**

```rust
#[test]
fn generic_recipient_wrap_opens_only_for_the_named_device() {
    let reader = crate::DeviceKey::from_private_bytes(&[7_u8; 32]).unwrap();
    let stranger = crate::DeviceKey::from_private_bytes(&[8_u8; 32]).unwrap();
    let key = [9_u8; 32];
    let aad = b"tn-jwe-frame";
    let value = seal_key_for_recipient(&key, reader.did(), aad).unwrap();
    let wrap = value.as_object().unwrap();
    assert_eq!(
        unseal_key_from_wrap(wrap, &reader.private_bytes(), aad).unwrap(),
        key
    );
    assert!(unseal_key_from_wrap(wrap, &stranger.private_bytes(), aad).is_err());
}
```

- [ ] **Step 2: Run the unit test and confirm the reusable names do not exist yet**

Run: `cargo test -p tn-core recipient_seal::tests::generic_recipient_wrap_opens_only_for_the_named_device --no-default-features --features fs`

Expected: compile failure naming `seal_key_for_recipient` or `unseal_key_from_wrap`.

- [ ] **Step 3: Generalize the existing package-only functions**

```rust
pub(crate) fn seal_key_for_recipient(
    key: &[u8; 32],
    recipient_did: &str,
    aad: &[u8],
) -> Result<Value> {
    // Existing ephemeral-X25519, HKDF, and AES-GCM implementation.
}

pub(crate) fn unseal_key_from_wrap(
    wrap: &Map<String, Value>,
    device_seed: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 32]> {
    // Existing inverse implementation.
}
```

Update `build_recipient_wraps` and `maybe_unseal_recipient_body` to call these names. Do not change `tn-sealed-box-v1`, its field names, padded-base64 encoding, HKDF salt/info, or manifest AAD construction.

- [ ] **Step 4: Verify the focused test and package contract**

Run: `cargo test -p tn-core recipient_seal::tests::generic_recipient_wrap_opens_only_for_the_named_device --no-default-features --features fs`

Run: `cargo test -p tn-core --test tnpkg_container_contract --no-default-features --features fs`

Expected: both pass.

- [ ] **Step 5: Commit only the generalized wrapper**

```text
git add crypto/tn-core/src/recipient_seal.rs
git commit -m "refactor(core): reuse recipient key wrapping"
```

### Task 2: Implement the strict `tn-jwe-v1` cipher

**Files:**
- Modify: `crypto/tn-core/Cargo.toml`
- Modify: `Cargo.lock`
- Replace: `crypto/tn-core/src/cipher/jwe.rs`

**Interfaces:**
- Consumes: the two Task 1 recipient-wrap functions
- Produces: `JweCipher::new(recipient_dids: &[String], device: &DeviceKey) -> Result<JweCipher>`
- Produces: a normal `GroupCipher` implementation with AAD support

- [ ] **Step 1: Add cipher tests beside the implementation**

```rust
#[test]
fn named_recipient_round_trips_and_stranger_is_not_entitled() {
    let writer = DeviceKey::from_private_bytes(&[1_u8; 32]).unwrap();
    let reader = DeviceKey::from_private_bytes(&[2_u8; 32]).unwrap();
    let stranger = DeviceKey::from_private_bytes(&[3_u8; 32]).unwrap();
    let recipients = vec![reader.did().to_owned()];
    let sealer = JweCipher::new(&recipients, &writer).unwrap();
    let opener = JweCipher::new(&recipients, &reader).unwrap();
    let denied = JweCipher::new(&recipients, &stranger).unwrap();
    let ciphertext = sealer.encrypt_with_aad(b"secret", b"marker").unwrap();
    assert_eq!(opener.decrypt_with_aad(&ciphertext, b"marker").unwrap(), b"secret");
    assert!(matches!(
        denied.decrypt_with_aad(&ciphertext, b"marker"),
        Err(Error::NotEntitled { .. })
    ));
    assert!(opener.decrypt_with_aad(&ciphertext, b"wrong").is_err());
}
```

Also assert the serialized frame has exactly `frame`, `body`, and `recipient_wraps`; the protected header pins `dir`, `A256GCM`, `tn_frame`, and `tn_aad`; and 1,025 wraps are rejected before an unwrap attempt.

- [ ] **Step 2: Run the cipher test and observe the placeholder failure**

Run: `cargo test -p tn-core cipher::jwe::tests --no-default-features --features fs`

Expected: compile failure because `JweCipher` does not exist.

- [ ] **Step 3: Add Biscuit and define the strict frame**

```toml
biscuit = "0.8.0"
```

```rust
const FRAME: &str = "tn-jwe-v1";
const MAX_RECIPIENT_WRAPS: usize = 1_024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JweFrame {
    frame: String,
    body: String,
    recipient_wraps: Vec<Value>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct TnProtectedHeader {
    tn_frame: String,
    tn_aad: String,
}
```

- [ ] **Step 4: Implement body encryption and decryption**

Use `Compact<Vec<u8>, TnProtectedHeader>`, `JWK::new_octet_key`, a fresh 12-byte nonce, `DirectSymmetricKey`, and `A256GCM`. During decryption, pass the expected algorithms to Biscuit and compare both private protected-header fields before returning the payload.

```rust
fn encrypt_body(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<String>;
fn decrypt_body(body: &str, key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>>;
```

- [ ] **Step 5: Implement content-key wrapping and `GroupCipher`**

Generate a fresh zeroizing 32-byte content key per call. Encrypt the body first, compute canonical wrap AAD from only `{ "frame": FRAME, "body": body }`, and seal the same key once per normalized recipient DID. On open, parse strictly, enforce the wrap limit, select the wrap whose `recipient_identity` equals the local DID, unwrap with the local seed, then decrypt the body.

```rust
impl GroupCipher for JweCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(plaintext, &[])
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(ciphertext, &[])
    }

    fn kind(&self) -> &'static str { "jwe" }
}
```

- [ ] **Step 6: Run tests and review code shape**

Run: `cargo test -p tn-core cipher::jwe::tests --no-default-features --features fs`

Run: `cargo fmt --all -- --check`

Run: `Get-Content crypto/tn-core/src/cipher/jwe.rs | Measure-Object -Line`

Expected: tests pass, formatting is clean, and the file is at most 609 lines with no changed function over 50 lines.

- [ ] **Step 7: Commit the standalone cipher**

```text
git add Cargo.lock crypto/tn-core/Cargo.toml crypto/tn-core/src/cipher/jwe.rs
git commit -m "feat(core): add TN-wrapped JWE cipher"
```

### Task 3: Wire JWE into configured Rust runtimes

**Files:**
- Modify: `crypto/tn-core/src/runtime/cipher_build.rs`
- Modify: `crypto/tn-core/src/runtime/init.rs`
- Modify: `crypto/tn-core/src/runtime/admin.rs`
- Add: `crypto/tn-core/tests/cipher_jwe.rs`

**Interfaces:**
- Consumes: `JweCipher::new`
- Preserves: `Runtime::read`, `Tn::read`, and `GroupCipher`
- Produces: native runtime construction for `cipher: jwe` and alias `bearer`

- [ ] **Step 1: Add a configured-runtime integration test**

Create a normal filesystem ceremony with a real device seed, a JWE group whose recipient list contains that device DID, and no `.jwe.mykey` files. Initialize `Runtime`, emit one private field with non-empty AAD, and assert `Runtime::read()` returns the plaintext. Assert the keystore still contains no `.jwe.mykey`.

- [ ] **Step 2: Run it and observe the existing `NotImplemented` error**

Run: `cargo test -p tn-core --test cipher_jwe --no-default-features --features fs`

Expected: failure from `build_cipher_with_admin_with_storage` saying JWE runs through Python.

- [ ] **Step 3: Pass the authenticated device into cipher construction**

Change the builder boundary consistently:

```rust
pub(crate) fn build_group_states(
    cfg: &Config,
    master_index_key: &[u8; 32],
    keystore: &Path,
    storage: &Arc<dyn Storage>,
    device: &DeviceKey,
) -> Result<GroupTables>;
```

Pass `&device` from `Runtime::init_with_options` and `&self.device` from `reload_group_cipher`. Apply the same parameter to both storage and non-storage cipher builders so their behavior stays aligned.

- [ ] **Step 4: Build JWE from configured DIDs**

```rust
fn build_jwe_cipher(spec: &GroupSpec, device: &DeviceKey) -> Result<BuildCipherResult> {
    let recipients = spec
        .recipients
        .iter()
        .map(|recipient| recipient.recipient_identity.clone())
        .collect::<Vec<_>>();
    let cipher = crate::cipher::jwe::JweCipher::new(&recipients, device)?;
    Ok((Arc::new(cipher), None, None))
}
```

Route both `"jwe"` and the compatibility cipher name `"bearer"` to this builder. Do not read `pub_b64` or any JWE key file.

- [ ] **Step 5: Verify the integration and adjacent runtime paths**

Run: `cargo test -p tn-core --test cipher_jwe --no-default-features --features fs`

Run: `cargo test -p tn-core --test runtime_read --no-default-features --features fs`

Run: `cargo test -p tn-core --test secure_default_read --no-default-features --features fs`

Expected: all pass.

- [ ] **Step 6: Commit runtime wiring only**

```text
git add crypto/tn-core/src/runtime/admin.rs crypto/tn-core/src/runtime/cipher_build.rs crypto/tn-core/src/runtime/init.rs crypto/tn-core/tests/cipher_jwe.rs
git commit -m "feat(core): enable JWE runtime reads"
```

### Task 4: Final Rust verification

**Files:**
- Verify only; no planned production edits

**Interfaces:**
- Confirms: the existing secure read pipeline consumes JWE through `GroupCipher`

- [ ] **Step 1: Inspect only the slice diff**

Run: `git diff 780e57f..HEAD -- crypto/tn-core Cargo.toml Cargo.lock`

Expected: no read scanner, policy, projection, Python, or TypeScript changes.

- [ ] **Step 2: Run scoped Rust verification**

Run: `cargo test -p tn-core --no-default-features --features fs`

Run: `cargo check -p tn-core`

Run: `cargo clippy -p tn-core --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Expected: all commands succeed.

- [ ] **Step 3: Check production source shape**

Run: `cargo test -p tn-core --test read_source_shape --no-default-features --features fs`

Expected: pass, with the read files still under their enforced limits.
