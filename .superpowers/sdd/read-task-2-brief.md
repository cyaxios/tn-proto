### Task 2: Make Rust core produce complete validity and stable rejection metadata

**Files:**
- Modify: `crypto/tn-core/src/runtime/types.rs`
- Modify: `crypto/tn-core/src/runtime/read.rs`
- Modify: `crypto/tn-core/src/runtime/mod.rs`
- Create: `crypto/tn-core/tests/secure_default_read.rs`
- Modify: `crypto/tn-core/tests/secure_read.rs`
- Modify: `crypto/tn-core/tests/secure_read_interop.rs`
- Review-remediation expansion: `crypto/tn-core/src/storage.rs`
- Consume: `tests/fixtures/trust/v1/read_policy_matrix.json`
- Consume: `tests/fixtures/trust/v1/read_cursor_vectors.json`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode { Auto, Raise, Skip, Disabled }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReadTrustPolicy {
    pub verify: VerifyMode,
    pub require_signature: Option<bool>,
    pub allow_unauthenticated: Option<bool>,
    pub trusted_writers: BTreeSet<String>,
    pub trusted_writers_supplied: bool,
    pub allow_unknown_writers: bool,
}

pub struct ReadContext {
    pub active: bool,
    pub local_log: bool,
    pub detached: bool,
    pub writable: bool,
    pub profile_sign: Option<bool>,
    pub profile_chain: Option<bool>,
    pub local_device_did: Option<String>,
    pub required_group: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadRejectReason {
    RecordInvalid, RowHashInvalid, ChainInvalid, SignatureRequired,
    SignatureInvalid, WriterUntrusted, AadInvalid, NotARecipient,
}

pub enum CursorKind { ByteOffset, Sequence, Opaque }
pub struct SourceCursorV1 { pub kind: CursorKind, pub value: String }
pub struct ReadCursorV1 {
    pub version: u8,
    pub sources: BTreeMap<String, SourceCursorV1>,
}
pub struct ReadReport<T> {
    pub entries: Vec<T>,
    pub scanned: usize,
    pub yielded: usize,
    pub skipped: usize,
    pub cursor: ReadCursorV1,
}

impl Runtime {
    pub fn read_with_policy(
        &self,
        options: &SecureReadOptions,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<FlatEntry>>;
}
```

Extend validity metadata with `writer_authenticated`, `writer_authorized`, and an ordered de-duplicated `reasons` array. Keep existing `signature`, `row_hash`, and `chain` fields for compatibility. Define `ReadDecision { accepted: bool, reasons: Vec<ReadRejectReason>, writer_authenticated: bool, writer_authorized: bool }`.

- [ ] **Step 1: Write failing fixture/core tests**

Load the top-level matrix and assert exact accept/reject/reason/authenticated/authorized outcomes. Add tests proving missing validity data is not silently `true`, local `sign:false` does not excuse a foreign unsigned row, policy rejection happens before plaintext is returned, and skip mode remains bounded streaming. Assert multi-source reports emit sorted canonical source IDs and lossless byte-offset/sequence/opaque cursor strings.

- [ ] **Step 2: Run RED**

Run: `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop`

Expected: missing policy/reason types and default-policy failures.

- [ ] **Step 3: Implement one core gate**

Construct `ReadContext` once from the bound runtime/config and call source, then refactor `Runtime::secure_read` and ordinary validity reads through `read_with_policy`. Perform parse/shape, row hash, chain, signature presence/DID verification, writer authorization, then decryption/AAD. Map decryption authentication failures to `aad_invalid`. Map absent recipient blocks/keys to `not_a_recipient` only when `required_group` or recipient mode demands that group; preserve optional `_hidden_groups`. Do not expose library error strings as reason codes.

Representative evaluator shape:

```rust
let mut reasons = Vec::new();
push_once(&mut reasons, parse_reason);
push_once(&mut reasons, row_hash_reason);
push_once(&mut reasons, chain_reason);
push_once(&mut reasons, signature_reason);
push_once(&mut reasons, authorization_reason);
push_once(&mut reasons, decryption_reason);
let transport_fatal = reasons.iter().any(|reason| matches!(
    reason,
    ReadRejectReason::RecordInvalid
        | ReadRejectReason::AadInvalid
        | ReadRejectReason::NotARecipient
));
let policy_rejected = policy.verify != VerifyMode::Disabled
    && reasons.iter().any(|reason| !matches!(
        reason,
        ReadRejectReason::RecordInvalid
            | ReadRejectReason::AadInvalid
            | ReadRejectReason::NotARecipient
    ));
let accepted = !transport_fatal && !policy_rejected;
ReadDecision { accepted, reasons, writer_authenticated, writer_authorized }
```

- [ ] **Step 4: Run GREEN and format**

Run: `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop --test runtime_read`

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/runtime/types.rs crypto/tn-core/src/runtime/read.rs crypto/tn-core/src/runtime/mod.rs crypto/tn-core/tests/secure_default_read.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit baseline-clean Rust paths as `feat(core): enforce read trust policy`.

## Independent-review remediation

- Bind file-source context inside `Runtime`; caller-provided context may not
  label a foreign source as the local unsigned/unchained profile.
- Preserve the prior explicit fail-closed error for policy-aware foreign BTN
  reads until recipient-kit verification/decryption is implemented.
- Scan a fixed-length storage snapshot incrementally with bounded line state;
  native filesystem reads must not call whole-source `read_bytes`, and source
  appends caused by skip auditing must not enter the same snapshot.

---
