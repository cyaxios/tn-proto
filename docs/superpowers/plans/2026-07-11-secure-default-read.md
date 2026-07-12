# Secure-Default Read Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Use superpowers:test-driven-development for every behavior change and superpowers:verification-before-completion before reporting completion. Steps use checkbox (`- [ ]`) syntax for tracking.

## Status ledger (reconciled 2026-07-12 against local main, ahead of origin by 9)

Evidence: 246-test Python arc suite green on the dirty working tree (2026-07-12); commit hashes below are local-main checkpoints.

| Task | State | Evidence |
|---|---|---|
| 1 Policy model + decision table | DONE | 87ad1fd (read_policy.py + matrix fixture) |
| 2 Rust core validity/rejection metadata | DONE | 4a3384d |
| 3 Python read() secure default | DONE | 2324cc9 |
| 4 Python watch/MCP/weakening audit | PARTIAL | code in 2324cc9; gate confirmation pending |
| 5 rust-sdk read/watch defaults | NOT STARTED | |
| 6 TypeScript read equivalence (node/local/browser/CLI) | NOT STARTED | |
| 7 C# ReadAsync secure default | NOT STARTED | |
| 8 Perf gate + joint docs handoff | NOT STARTED | |

Per-SDK: Python in-tree through T3/T4; Rust core done (T2); rust-sdk, TypeScript, C#, browser all NOT STARTED - the parity tail is entirely open.

**Goal:** Keep `read()` as TN's main surface while making its default policy verify integrity, authenticate signatures where required, and authorize writers, with explicit parameters for intentional weakening and equivalent watch behavior.

**Architecture:** A receiver-local `ReadTrustPolicy` resolves call parameters plus ceremony/log context into one decision engine. Rust core defines stable validity/rejection metadata; Python, Rust SDK, TypeScript, and C# preserve their existing result/iterator shapes while adopting the same policy matrix. Existing `secure_read()` delegates to strict `read()` parameters. A versioned JSON FFI entry point carries the richer C# policy without breaking the legacy native symbol.

**Tech Stack:** Python 3.10+/pytest, Rust 1.85/serde, TypeScript/Node, C#/.NET/xUnit, shared JSON fixtures.

## Global Constraints

- The approved contract is `docs/superpowers/specs/2026-07-11-trusted-enrollment-secure-read-design.md`; use only its stable read reasons.
- `read()` remains the primary public surface. Do not change its iterator, entry, callback, stats, log-selection, or filtering shapes except by adding policy parameters and validity metadata.
- Default mode is `"auto"`. `True` remains an alias for `"raise"`; explicit `False` disables integrity verification and must never claim authentication or authorization.
- Workstream B depends only on the frozen strict Ed25519 DID verifier/reason contract, not on Workstream A's pending offers, enrollment store, or `VerifiedPrincipal` type. Publisher trust enters through a receiver-local trust-provider interface.
- The companion plan's Foundation task owns `tests/fixtures/trust/v1/read_policy_matrix.json`; this plan consumes but never edits it. Begin Track B immediately after that short contract-freeze task passes `--check`; Track B does not wait for enrollment state or package APIs.
- Preserve unrelated changes. Record `git status --short` and `git diff -- <owned paths>` before each task. Never reset, checkout, stash, or use `git add .`. One worker owns each path at a time.
- Verification must happen before plaintext is returned. Decryption/AAD validation may be the final check, but no rejected plaintext reaches the caller, callback, or watcher.
- Explicit weakening emits a structured warning and best-effort admin audit event. Audit is recursion guarded and cannot alter read results.
- Commit checkpoints are conditional: commit only new or baseline-clean paths. For pre-dirty files, retain and review a scoped diff rather than staging them.
- Every cursor implementation uses the design's `source:sha256:` descriptor rules; no SDK may hash its platform-native path string directly.
- The companion Foundation owns the admin catalog and warning payload/event surfaces before tracks start. Companion Task 9 solely owns `crypto/tn-core-ffi/src/lib.rs`, C# `NativeMethods.cs`/`NativeBridge.cs`, and TS `src/index.ts`; companion Task 11 solely owns shared readmes/guides. Track workers do not edit those paths.

---

### Task 1: Freeze the read policy model and Python decision table

> **Status (2026-07-12):** DONE - checkpoint 87ad1fd.

**Files:**
- Create: `python/tn/read_policy.py`
- Create: `python/tn/read_trust.py`
- Create: `python/tests/test_read_trust_policy.py`
- Create: `python/tests/test_read_trust_provider.py`
- Consume: `tests/fixtures/trust/v1/read_policy_matrix.json`

**Interfaces:**

```text
VerifyMode = Literal["auto", "raise", "skip"] | bool

class ReadRejectReason(str, Enum):
    RECORD_INVALID = "record_invalid"
    ROW_HASH_INVALID = "row_hash_invalid"
    CHAIN_INVALID = "chain_invalid"
    SIGNATURE_REQUIRED = "signature_required"
    SIGNATURE_INVALID = "signature_invalid"
    WRITER_UNTRUSTED = "writer_untrusted"
    AAD_INVALID = "aad_invalid"
    NOT_A_RECIPIENT = "not_a_recipient"

@dataclass(frozen=True)
class ReadTrustPolicy:
    mode: Literal["raise", "skip", "disabled"]
    require_signature: bool
    allow_unauthenticated: bool
    trusted_writers: frozenset[str]
    allow_unknown_writers: bool

  resolve(
    verify: VerifyMode,
    require_signature: bool | None,
    allow_unauthenticated: bool | None,
    trusted_writers: Collection[str] | None,
    allow_unknown_writers: bool,
    context: ReadContext,
  ) -> ReadTrustPolicy

ReadTrustProvider protocol:
  trusted_writer_dids(context: ReadContext) -> frozenset[str]
  source_for(did: str) -> Literal[
    "local-device", "verified-package", "explicit-config"
  ] | None

InMemoryReadTrustProvider(entries: Mapping[str, str])
LocalReadTrustProvider(cfg: LoadedConfig, state_root: Path)

ReadContext fields:
  active: bool
  local_log: bool
  detached: bool
  writable: bool
  profile_sign: bool | None
  profile_chain: bool | None
  local_device_did: str | None
  required_group: str | None
  trust_provider: ReadTrustProvider
```

The default private record path is
`<keystore>/trust/verified_publishers.v1.json`. Explicit configuration is:

```yaml
trust:
  writers:
    - did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Both sources reject invalid/non-Ed25519 DIDs; the provider caches an exact-key
map for constant-time lookup.

Policy resolution freezes `verify="auto"` to `mode="raise"`; only explicit
`verify="skip"` drops and continues.

- [x] **Step 1: Write the failing matrix test**

```python
@pytest.mark.parametrize("case", load_read_policy_cases(), ids=lambda c: c["id"])
def test_read_policy_matrix(case: dict[str, object]) -> None:
    if case["expected"].get("parameter_error"):
        with pytest.raises(ValueError):
            resolve_case(case)
        return
    decision = evaluate_case(case)
    assert decision.accepted is case["expected"]["accepted"]
    assert decision.reasons == case["expected"].get("reasons", [])
    assert decision.writer_authenticated is case["expected"]["writer_authenticated"]
    assert decision.writer_authorized is case["expected"]["writer_authorized"]
```

Include local signed, local explicitly unsigned, foreign unsigned, context-free unsigned, trusted/unknown valid DID, malformed record, row/chain/signature failures, AAD failure, non-recipient, every verify mode, and invalid `verify=False` plus `trusted_writers` combinations. Assert auto resolves to raise rather than silently skipping. Explicitly prove disabled mode may ignore integrity/authentication/authorization failures but still rejects `record_invalid`, `aad_invalid`, and required-group `not_a_recipient`.

- [x] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py -q`

Expected: import failure for `tn.read_policy`.

- [x] **Step 3: Implement pure policy resolution/evaluation**

Do not read global config inside the policy object. `ReadContext` supplies active/detached, local/foreign, profile signing/chaining, local device DID, requested/required group, and trust-provider output. Treat unsigned envelopes as unauthenticated even when accepted. Return an ordered de-duplicated reason array; callbacks/exceptions use its first element. `not_a_recipient` applies only to an explicitly required group/recipient mode, never to an optional hidden group. Reject impossible combinations before reading the log.

- [x] **Step 4: Run GREEN**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py python/tests/test_read_trust_provider.py -q`

Expected: every fixture case passes with exact reasons.

- [x] **Step 5: Checkpoint**

If both files were new, stage only them and commit `feat(read): define secure default trust policy`.

---

### Task 2: Make Rust core produce complete validity and stable rejection metadata

> **Status (2026-07-12):** DONE - checkpoint 4a3384d.

**Files:**
- Modify: `crypto/tn-core/src/runtime/types.rs`
- Modify: `crypto/tn-core/src/runtime/read.rs`
- Modify: `crypto/tn-core/src/runtime/mod.rs`
- Create: `crypto/tn-core/tests/secure_default_read.rs`
- Modify: `crypto/tn-core/tests/secure_read.rs`
- Modify: `crypto/tn-core/tests/secure_read_interop.rs`
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

- [x] **Step 1: Write failing fixture/core tests**

Load the top-level matrix and assert exact accept/reject/reason/authenticated/authorized outcomes. Add tests proving missing validity data is not silently `true`, local `sign:false` does not excuse a foreign unsigned row, policy rejection happens before plaintext is returned, and skip mode remains bounded streaming. Assert multi-source reports emit sorted canonical source IDs and lossless byte-offset/sequence/opaque cursor strings.

- [x] **Step 2: Run RED**

Run: `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop`

Expected: missing policy/reason types and default-policy failures.

- [x] **Step 3: Implement one core gate**

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

- [x] **Step 4: Run GREEN and format**

Run: `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop --test runtime_read`

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/runtime/types.rs crypto/tn-core/src/runtime/read.rs crypto/tn-core/src/runtime/mod.rs crypto/tn-core/tests/secure_default_read.rs`

Expected: pass.

- [x] **Step 5: Checkpoint**

Commit baseline-clean Rust paths as `feat(core): enforce read trust policy`.

---

### Task 3: Make Python `read()` secure by default without changing its shape

> **Status (2026-07-12):** DONE - checkpoint 2324cc9.

**Files:**
- Modify: `python/tn/read.py`
- Modify: `python/tn/_read_impl.py`
- Modify: `python/tn/_entry.py`
- Modify: `python/tn/reader.py`
- Modify: `python/tn/config.py`
- Modify: `python/tn/_handle.py`
- Modify: `python/tn/__init__.py`
- Modify: `python/tn/cli.py`
- Modify: `python/tn/cli_read.py`
- Create: `python/tests/test_read_secure_default.py`
- Create: `python/tests/test_handle_read_policy.py`
- Create: `python/tests/test_cli_read_security.py`
- Modify: `python/tests/test_secure_read_tamper.py`
- Modify: `python/tests/test_read_skip_observability.py`
- Modify: `python/tests/test_verify_respects_sign_setting.py`
- Modify: `python/tests/test_verify_roundtrip.py`
- Modify: `python/tests/test_read_parse_resilience.py`

**Interfaces:**

```text
read(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    verify: VerifyMode = "auto",
    require_signature: bool | None = None,
    allow_unauthenticated: bool | None = None,
    trusted_writers: Collection[str] | None = None,
    allow_unknown_writers: bool = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
    on_skip: Callable[[dict[str, Any], str], None] | None = None,
) -> _ReadIterator

secure_read(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    trusted_writers: Collection[str] | None = None,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
) -> _ReadIterator
```

`secure_read` always calls `read` with `verify="raise"`,
`require_signature=True`, `allow_unauthenticated=False`, and
`allow_unknown_writers=False`; it exposes no weakening keywords.

- [x] **Step 1: Write failing public-surface tests**

Assert `tn.read()` raises on the first tampered/unsigned-when-required/unknown-writer row by default, still returns `_ReadIterator` with unchanged entry shape before iteration, honors explicit `skip` stats/callbacks, accepts a local explicitly unsigned profile without claiming writer authentication, requires both unsigned overrides for foreign input, and treats `True`/`False` as compatibility aliases. Assert raw rows include stable reasons and authentication/authorization flags. Prove two simultaneous `TN` handles resolve their own DID/profile/trust state, and CLI reads use auto unless the operator passes an explicit weakening flag.

- [x] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_secure_default.py python/tests/test_handle_read_policy.py python/tests/test_cli_read_security.py python/tests/test_secure_read_tamper.py python/tests/test_read_skip_observability.py python/tests/test_verify_respects_sign_setting.py python/tests/test_verify_roundtrip.py python/tests/test_read_parse_resilience.py -q`

Expected: default `verify=False` returns rows that the new tests reject.

- [x] **Step 3: Resolve context and trust once per iterator**

Build `ReadContext` at iterator creation from the bound `TN` handle, never the process-global singleton when a handle exists. `LocalReadTrustProvider` reads the active device DID, private-state verified publisher records, and exact DIDs from `trust.writers` in that ceremony's config. Cache the exact-DID set once per iterator. Never infer signature optionality for foreign logs from the active ceremony's `sign:false`. Replace fabricated missing validity values with explicit unknown/failure handling. CLI omission calls `read()` without a `verify` keyword; `--verify`, `--verify skip`, and `--no-verify` map to raise, skip, and explicit false respectively.

- [x] **Step 4: Route all rows through the shared gate**

Preserve parse resilience and skip callbacks. In raise mode, throw the existing public `VerifyError` carrying primary stable `reason`, full `reasons`, sequence, and event type. In skip mode, increment existing counters and call `on_skip` with the first stable reason while retaining the full array in raw metadata. In disabled mode, set authentication/authorization metadata false or unknown; do not populate it from envelope claims.

- [x] **Step 5: Run GREEN**

Run the Step 2 command.

Expected: pass.

- [x] **Step 6: Checkpoint**

Review every hunk in the pre-existing `read.py` diff before any staging; use a scoped diff checkpoint if it was dirty.

---

### Task 4: Apply the same policy to Python watch, MCP, and weakening audit

> **Status (2026-07-12):** PARTIAL - code committed in 2324cc9; gate confirmation pending.

**Files:**
- Consume Foundation-owned: `python/tn/security_audit.py`
- Modify: `python/tn/_watch_impl.py`
- Modify: `python/tn/read.py`
- Modify: `python/tn/mcp/schemas.py`
- Modify: `python/tn/mcp/tools_core.py`
- Consume: `tests/fixtures/trust/v1/read_cursor_vectors.json`
- Create: `python/tests/test_read_security_audit.py`
- Modify: `python/tests/test_watch.py`
- Modify: `python/tests/test_watch_bugs_w5_w6.py`
- Modify: `python/tn/mcp/tests/test_schemas.py`
- Modify: `python/tn/mcp/tests/test_tools_core.py`

**Interfaces:**

```text
UnsafeOperationNotice fields:
  operation: Literal["read", "watch"]
  relaxations: Sequence[Literal[
    "verification_disabled", "signature_not_required",
    "unauthenticated_allowed", "unknown_writer_allowed"
  ]]
  group: str | None
  subject_did: str | None
  artifact_digest: None

TnSecurityWarning(UserWarning): notice: UnsafeOperationNotice

SourceCursorV1 fields:
  kind: Literal["byte_offset", "sequence", "opaque"]
  value: str
ReadCursorV1 fields:
  version: Literal[1]
  sources: Mapping[str, SourceCursorV1]

record_policy_weakening(
    operation: Literal["read", "watch"],
    policy: ReadTrustPolicy,
    context: ReadContext,
) -> None

watch(
    *,
    where: Callable[[Any], bool] | None = None,
    verify: VerifyMode = "auto",
    require_signature: bool | None = None,
    allow_unauthenticated: bool | None = None,
    trusted_writers: Collection[str] | None = None,
    allow_unknown_writers: bool = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    since: str | int = "now",
    poll_interval: float = 0.3,
) -> AsyncIterator[Entry] | AsyncIterator[dict[str, Any]]
```

- [ ] **Step 1: Add failing parity/audit tests**

Prove watch has the same decisions/reasons as read across initial drain and later polls; its cursor advances by scanned byte offset/source sequence rather than accepted-row count, so skipped rows advance exactly once. Prove explicit weakening emits one `TnSecurityWarning` and one `tn.security.unsafe_operation` event with the exact spec payload when writable, emits no audit when detached/read-only, and a thread/task-local recursion guard prevents audit reads/emits from warning again. Prove audit failure never changes requested results. Assert MCP default schema is `"auto"` and forwards every policy parameter.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_security_audit.py python/tests/test_watch.py python/tests/test_watch_bugs_w5_w6.py python/tn/mcp/tests/test_schemas.py python/tn/mcp/tests/test_tools_core.py -q`

Expected: watch currently forces `verify=False`; schema defaults false; no audit helper exists.

- [ ] **Step 3: Implement parity and observability**

Make `_watch_impl` preserve raw validity/reasons and invoke the same gate as read; remove its verification no-op path. Persist scanned byte offset/source sequence independently of yielded entries. Emit the exact notice for `verify=False`, unsigned overrides outside their automatic local context, or `allow_unknown_writers=True`. Use a `ContextVar[bool]` recursion guard and best-effort audit emission.

Representative guard:

```python
token = _AUDIT_RECURSION.set(True)
try:
    warnings.warn(TnSecurityWarning(notice), stacklevel=3)
    if context.writable:
        context.emit_admin("tn.security.unsafe_operation", notice.to_fields())
finally:
    _AUDIT_RECURSION.reset(token)
```

- [ ] **Step 4: Run GREEN**

Run the Step 2 command.

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit new clean paths only; retain scoped diffs for any pre-dirty file.

---

### Task 5: Add Rust SDK/watch defaults and report/cursor plumbing

> **Status (2026-07-12):** NOT STARTED.

**Files:**
- Modify: `crypto/tn-core/src/config.rs`
- Modify: `rust-sdk/src/tn.rs`
- Modify: `rust-sdk/src/watch.rs`
- Modify: `rust-sdk/Cargo.toml`
- Create: `rust-sdk/src/read_trust.rs`
- Create: `rust-sdk/src/security_warning.rs`
- Create: `rust-sdk/tests/secure_default_read.rs`
- Modify: `rust-sdk/tests/verify.rs`
- Modify: `rust-sdk/tests/watch.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug)]
pub struct ReadOptions {
    pub all_runs: bool,
    pub verify: VerifyMode,
    pub require_signature: Option<bool>,
    pub allow_unauthenticated: Option<bool>,
    pub trusted_writers: Option<BTreeSet<String>>,
    pub allow_unknown_writers: bool,
}

pub trait ReadTrustProvider: Send + Sync {
    fn trusted_writer_dids(&self, context: &ReadContext) -> BTreeSet<String>;
    fn source_for(&self, did: &str) -> Option<TrustSource>;
}

pub type ReadReport = tn_core::ReadReport<Entry>;
```

`ConfigReadTrustProvider` loads the local device, `trust.writers`, and optional
verified-publisher records once. `Tn` owns `Arc<dyn ReadTrustProvider>` and adds
`set_read_trust_provider` for injected tests/app policy. The joint bridge task
serializes `ReadRequestV1`/`ReadResponseV1`; this task does not edit FFI.

Config schema addition:

```yaml
trust:
  writers:
    - did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Config parsing rejects non-list values, invalid/non-Ed25519 DIDs, and duplicate
entries after exact-string normalization.

- [ ] **Step 1: Write failing SDK/ABI tests**

Assert `ReadOptions::default().verify == VerifyMode::Auto` and auto raises on the first rejection, `ConfigReadTrustProvider` loads exact-DID config entries and injected providers override it per `Tn`, and watch clones/forwards all fields. Insert a rejected row between accepted rows and prove every poll persists the fixture-defined `ReadCursorV1` whose source position advances. Capture exactly one `log` warning plus one admin audit event for each weakening.

- [ ] **Step 2: Run RED**

Run: `cargo test -p tn-proto --test secure_default_read --test verify --test watch`

Expected: missing mode/report/provider fields and old false defaults.

- [ ] **Step 3: Implement SDK and v2 adapter**

Keep the existing by-value `Tn::read(ReadOptions)` API and delegate internally to a borrowed `read_with_options(&ReadOptions)` helper returning `ReadReport`; watchers clone options at construction and borrow them on every poll. Track the exact cross-SDK cursor token independently from returned entry count. Load receiver-local trust through `ConfigReadTrustProvider`. Add direct `log = "0.4"`; the SDK emits the serialized `log::warn!` once and the runtime emits one best-effort `tn.security.unsafe_operation`, guarded by a thread-local boolean.

Representative compatibility adapter:

```rust
pub fn read(&self, options: ReadOptions) -> Result<Vec<Entry>> {
    self.read_with_options(&options).map(|report| report.entries)
}
```

- [ ] **Step 4: Run GREEN**

Run the Step 2 command.

Run: `rustfmt --edition 2021 --check crypto/tn-core/src/config.rs rust-sdk/src/tn.rs rust-sdk/src/watch.rs rust-sdk/src/read_trust.rs rust-sdk/src/security_warning.rs`

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit baseline-clean paths as `feat(rust): make read verification automatic`.

---

### Task 6: Make TypeScript Node, local, browser, watch, and CLI reads equivalent

> **Status (2026-07-12):** NOT STARTED.

**Files:**
- Create: `ts-sdk/src/core/read_policy.ts`
- Create: `ts-sdk/src/core/read_trust.ts`
- Consume Foundation-owned: `ts-sdk/src/core/unsafe_operation.ts`
- Create: `ts-sdk/src/runtime/node_unsafe_guard.ts`
- Create: `ts-sdk/src/browser/unsafe_guard.ts`
- Modify: `ts-sdk/src/tn.ts`
- Modify: `ts-sdk/src/runtime/config.ts`
- Consume joint Task 9: `ts-sdk/src/index.ts`
- Modify: `ts-sdk/src/watch.ts`
- Modify: `ts-sdk/src/local/read.ts`
- Modify: `ts-sdk/src/local/watch.ts`
- Modify: `ts-sdk/src/local/index.ts`
- Modify: `ts-sdk/src/browser/tn.ts`
- Modify: `ts-sdk/src/browser/runtime.ts`
- Modify: `ts-sdk/src/cli/read.ts`
- Modify: `ts-sdk/src/cli/watch.ts`
- Create: `ts-sdk/test/secure_default_read.test.ts`
- Modify: `ts-sdk/test/secure_read.test.ts`
- Modify: `ts-sdk/test/watch.test.ts`
- Modify: `ts-sdk/test/local_read.test.ts`
- Modify: `ts-sdk/test/local_watch.test.ts`
- Modify: `ts-sdk/test/core_browser_contract.test.ts`
- Consume: `tests/fixtures/trust/v1/read_cursor_vectors.json`

**Interfaces:**

```ts
export type VerifyMode = "auto" | "raise" | "skip" | boolean;
export interface ReadContext {
  active: boolean;
  localLog: boolean;
  detached: boolean;
  writable: boolean;
  profileSign: boolean | null;
  profileChain: boolean | null;
  localDeviceDid: string | null;
  requiredGroup: string | null;
}
export interface ReadTrustProvider {
  trustedWriterDids(context: ReadContext): ReadonlySet<string>;
  sourceFor(did: string): "local-device" | "verified-package" | "explicit-config" | null;
}
export class ConfigReadTrustProvider implements ReadTrustProvider {
  constructor(config: CeremonyConfig, verifiedPublisherStatePath?: string);
  trustedWriterDids(context: ReadContext): ReadonlySet<string>;
  sourceFor(did: string): "local-device" | "verified-package" | "explicit-config" | null;
}
export interface ReadOptions {
  selector?: string | null;
  filter?: ReadFilter;
  where?: (entry: Entry | Record<string, unknown>) => boolean;
  verify?: VerifyMode;
  requireSignature?: boolean;
  allowUnauthenticated?: boolean;
  trustedWriters?: readonly string[];
  allowUnknownWriters?: boolean;
  raw?: boolean;
  log?: string;
  asRecipient?: string;
  group?: string;
  allRuns?: boolean;
  expectGenesis?: boolean;
}
export interface ReadCursorV1 {
  version: 1;
  sources: Record<string, {
    kind: "byte_offset" | "sequence" | "opaque";
    value: string;
  }>;
}
interface ReadReport {
  entries: Entry[];
  scanned: number;
  yielded: number;
  skipped: number;
  cursor: ReadCursorV1;
}
```

- [ ] **Step 1: Add failing matrix and surface-parity tests**

Consume the shared matrix. Until joint Task 9, import new policy types from track-local modules; Task 9 tests root exports. Assert omitted `verify` resolves to raise-on-rejection auto, true/false aliases work, result shapes remain the same, watch equals read, CLI defaults secure, and Node/local/browser make identical decisions. Assert `trust.writers` parsing, default `ConfigReadTrustProvider`, and per-`Tn` injected provider isolation. Insert a rejected row between accepted rows and prove watch persists the exact multi-source `ReadCursorV1` rather than returned-array length. Browser `read()` must accept `ReadOptions`; browser watch may remain unsupported but must not create a policy mismatch in its advertised types. Capture exactly one Node/browser language warning and one writable admin audit for the unsafe-operation payload.

- [ ] **Step 2: Run RED**

Run from `ts-sdk/`: `node --import tsx --import ./test/_setup_wasm.mjs --test test/secure_default_read.test.ts test/secure_read.test.ts test/watch.test.ts test/local_read.test.ts test/local_watch.test.ts test/core_browser_contract.test.ts`

Expected: old default false and browser/Node option mismatch failures.

- [ ] **Step 3: Implement one TypeScript policy adapter**

Normalize camelCase public options to the stable wire object once. Use nullish defaulting, not truthiness, so explicit false remains disabled. Route secure-read helpers, Node/local reads, and watch through the same evaluator and stable reasons. `Tn` constructs `ConfigReadTrustProvider` and exposes `setReadTrustProvider(provider)` for exact per-instance injection; the verified-package state source is optional until Workstream A integration. Persist the cross-SDK cursor token returned by the scanner. On weakening, call `process.emitWarning(JSON.stringify(notice), { code: "TN_SECURITY_UNSAFE_OPERATION" })` in Node or a structured browser warning, then let the pure runtime emit one best-effort audit. The Node-only adapter uses `AsyncLocalStorage`; it is never imported by browser bundles. The browser adapter threads a per-call `{ inUnsafeAudit: true }` token through the synchronous audit emit and keeps no module-global recursion flag.

CLI omission leaves `verify` undefined (therefore auto); `--verify` maps to
`"raise"`, `--verify=skip` to `"skip"`, and `--no-verify` to explicit false.

Representative normalization:

```ts
const verify = opts.verify ?? "auto";
const normalized = Object.assign({}, opts, { verify });
const policy = resolveReadPolicy(normalized, context, trustProvider);
const report = evaluateRows(rows, policy, { cursor: scannedSourceCursor });
```

- [ ] **Step 4: Run GREEN and static checks**

Run the Step 2 command, then `npm run typecheck` and `npm run lint`.

Expected: pass.

- [ ] **Step 5: Checkpoint**

Because `core_browser_contract.test.ts` is pre-dirty, review its complete diff and do not stage it without explicit ownership confirmation.

---

### Task 7: Make C# `ReadAsync` and polling watch secure by default

> **Status (2026-07-12):** NOT STARTED.

**Prerequisite:** Companion enrollment plan Task 9 (joint native/SDK bridge) is
GREEN. This task consumes those native declarations and does not edit them.

**Files:**
- Create: `csharp-sdk/src/TnProto/ReadVerificationMode.cs`
- Create: `csharp-sdk/src/TnProto/ReadContext.cs`
- Create: `csharp-sdk/src/TnProto/ReadTrustProvider.cs`
- Create: `csharp-sdk/src/TnProto/NativeReadTrustProvider.cs`
- Create: `csharp-sdk/src/TnProto/ReadCursorV1.cs`
- Create: `csharp-sdk/src/TnProto/ReadReport.cs`
- Consume Foundation-owned: `csharp-sdk/src/TnProto/TnSecurityWarningEventArgs.cs`
- Modify: `csharp-sdk/src/TnProto/ReadOptions.cs`
- Modify: `csharp-sdk/src/TnProto/Entry.cs`
- Modify: `csharp-sdk/src/TnProto/Tn.cs`
- Modify: `csharp-sdk/src/TnProto/WatchOptions.cs`
- Modify: `csharp-sdk/src/TnProto/PollingWatch.cs`
- Consume joint Task 9: `csharp-sdk/src/TnProto/Native/NativeMethods.cs`
- Consume joint Task 9: `csharp-sdk/src/TnProto/Native/NativeBridge.cs`
- Create: `csharp-sdk/tests/TnProto.Tests/ReadTrustPolicyTests.cs`
- Modify: `csharp-sdk/tests/TnProto.Tests/EmitReadTests.cs`
- Modify: `csharp-sdk/tests/TnProto.Tests/WatchTests.cs`
- Modify: `csharp-sdk/src/TnProto.Cli/CliApp.cs`
- Modify: `csharp-sdk/tests/TnProto.Cli.Tests/CliReadTests.cs`
- Consume: `tests/fixtures/trust/v1/read_cursor_vectors.json`

**Interfaces:**

```csharp
public enum ReadVerificationMode { Auto, Raise, Skip, Disabled }

public sealed record ReadContext(
    bool Active,
    bool LocalLog,
    bool Detached,
    bool Writable,
    bool? ProfileSign,
    bool? ProfileChain,
    string? LocalDeviceDid,
    string? RequiredGroup);

public interface IReadTrustProvider
{
    IReadOnlySet<string> TrustedWriterDids(ReadContext context);
    string? SourceFor(string did);
}

public sealed record SourceCursorV1(string Kind, string Value);
public sealed record ReadCursorV1(
    int Version,
    IReadOnlyDictionary<string, SourceCursorV1> Sources);
internal sealed record ReadReport(
    IReadOnlyList<Entry> Entries,
    ulong Scanned,
    ulong Yielded,
    ulong Skipped,
    ReadCursorV1 Cursor);

public sealed class ReadOptions
{
    public bool AllRuns { get; init; }
    public ReadVerificationMode Verification { get; init; } = ReadVerificationMode.Auto;
    public bool? RequireSignature { get; init; }
    public bool? AllowUnauthenticated { get; init; }
    public IReadOnlyCollection<string>? TrustedWriters { get; init; }
    public bool AllowUnknownWriters { get; init; }

    // Preserve the existing public bool property/binary signature.
    public bool Verify { get => _legacyVerify ?? false; init => _legacyVerify = value; }
    internal bool HasLegacyVerify => _legacyVerify.HasValue;
    private bool? _legacyVerify;
}
```

If `HasLegacyVerify`, explicit `true` maps to Raise and explicit `false` to Disabled; otherwise `Verification` controls the default Auto behavior.

`Tn` owns a settable `IReadTrustProvider ReadTrustProvider`. Its default
`NativeReadTrustProvider` consumes the joint bridge's receiver-local trust
snapshot; tests/applications may inject an in-memory provider. Public
`ReadAsync` returns `report.Entries`; internal `ReadReportAsync` returns the
complete report for `PollingWatch`.

The CLI parser stores verification as nullable/enum state: omission maps to
`Auto`, `--verify` maps to `Raise`, `--verify skip` maps to `Skip`, and explicit
`--no-verify` maps to `Disabled`. It must not always assign the legacy bool
property from a default-false parser field.

- [ ] **Step 1: Write failing public/fixture tests**

Consume the shared policy and cursor fixtures through `Tn.ReadAsync`. Assert omitted options use raise-on-rejection auto, existing object initializers `{ Verify = true/false }` retain meaning, validity exposes stable reasons/authentication/authorization, polling watch forwards options on every poll, and CLI defaults secure. Insert a rejected row between accepted rows and prove `PollingWatch` persists the exact multi-source cursor rather than `entries.Count`. Capture one `Tn.SecurityWarning` plus one admin audit event and assert the exact payload; prove its async-local recursion guard and best-effort failure behavior.

- [ ] **Step 2: Run RED**

Run: `dotnet test csharp-sdk/TnProto.sln --filter "FullyQualifiedName~ReadTrustPolicyTests|FullyQualifiedName~EmitReadTests|FullyQualifiedName~WatchTests|FullyQualifiedName~CliReadTests"`

Expected: old `bool Verify` defaults false and the C# public/report/watch wrappers do not yet consume the Task 9 bridge.

- [ ] **Step 3: Implement v2 JSON bridge**

P/Invoke `tn_runtime_read_v2` and `tn_runtime_read_trust_snapshot_v1` while preserving the old `RuntimeRead` declaration. Serialize the exact `ReadRequestV1` snake_case object from joint Task 9 and reject duplicate/unknown options before native invocation. Deserialize `ReadResponseV1` into `ReadReport` without removing existing entry fields. Public `ReadAsync` returns entries; `PollingWatch` calls internal `ReadReportAsync` and persists `report.Cursor`. Resolve local/config trust through `IReadTrustProvider`; the verified-package adapter remains optional until Workstream A integration. On weakening, raise the Foundation-owned `Tn.SecurityWarning` exactly once behind an `AsyncLocal<bool>` recursion guard; the native read runtime owns the single best-effort `tn.security.unsafe_operation` audit.

Representative compatibility resolution:

```csharp
var mode = options.HasLegacyVerify
    ? (options.Verify ? ReadVerificationMode.Raise : ReadVerificationMode.Disabled)
    : options.Verification;
```

- [ ] **Step 4: Run GREEN and full solution**

Run the Step 2 command, then `dotnet test csharp-sdk/TnProto.sln`.

Expected: pass.

- [ ] **Step 5: Checkpoint**

Commit exact clean C# paths as `feat(csharp): secure read by default`.

---

### Task 8: Verify read performance and hand off joint docs/integration

> **Status (2026-07-12):** NOT STARTED.

**Files:**
- Consume joint bridge integration from companion plan Task 9: `crypto/tn-core-ffi/src/lib.rs`
- Consume joint bridge integration from companion plan Task 9: `ts-sdk/src/index.ts`
- Consume joint bridge integration from companion plan Task 9: `csharp-sdk/src/TnProto/Native/NativeMethods.cs`
- Consume joint bridge integration from companion plan Task 9: `csharp-sdk/src/TnProto/Native/NativeBridge.cs`
- Consume joint documentation from companion plan Task 11: `docs/guide/protocol.md`
- Consume joint documentation from companion plan Task 11: `docs/guide/getting-started.md`
- Consume joint documentation from companion plan Task 11: `README.md`
- Consume joint documentation from companion plan Task 11: `python/README.md`
- Consume joint documentation from companion plan Task 11: `ts-sdk/README.md`
- Consume joint documentation from companion plan Task 11: `python/tests/test_key_ceremony_docs.py`
- Modify: `python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py`

- [ ] **Step 1: Add the failing performance contract**

Extend the existing verified-read performance test to compare throughput and bounded per-row verification working memory against the current verified path rather than insecure disabled mode. Rust/C# APIs may still accumulate their explicitly materialized result arrays; the gate itself must not retain prior row plaintext/verification scratch state. Provide the companion Task 11 owner with the read documentation assertions listed in the approved design; do not edit shared docs in this track.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py -q`

Expected: the new secure-default comparison fails before instrumentation/gating is updated.

- [ ] **Step 3: Implement and run the performance gate**

Measure the secure-default path against the pre-existing verified path using the same fixture/log size and stage instrumentation. Assert bounded per-row scratch growth and document any platform variance in the test threshold. Do not compare against intentionally disabled verification.

- [ ] **Step 4: Run all Workstream B suites**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py python/tests/test_read_trust_provider.py python/tests/test_read_secure_default.py python/tests/test_handle_read_policy.py python/tests/test_cli_read_security.py python/tests/test_read_security_audit.py python/tests/test_secure_read_tamper.py python/tests/test_read_skip_observability.py python/tests/test_verify_respects_sign_setting.py python/tests/test_watch.py python/tn/mcp/tests/test_schemas.py python/tn/mcp/tests/test_tools_core.py python/tests/perf_smoke/instrumentation/test_verified_read_perf_stages.py -q`

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_key_ceremony_docs.py -q` after companion Task 11.

Run: `cargo test -p tn-core --test secure_default_read --test secure_read --test secure_read_interop --test runtime_read`

Run: `cargo test -p tn-proto --test secure_default_read --test verify --test watch`

Run: `cargo test -p tn-core-ffi --test read_options_v2`

Run: `npm run typecheck` from `ts-sdk/`.

Run: `npm run lint` from `ts-sdk/`.

Run: `node --import tsx --import ./test/_setup_wasm.mjs --test test/secure_default_read.test.ts test/secure_read.test.ts test/watch.test.ts test/local_read.test.ts test/local_watch.test.ts test/core_browser_contract.test.ts` from `ts-sdk/`.

Run: `dotnet test csharp-sdk/TnProto.sln`

Expected: all pass.

- [ ] **Step 5: Prove fixture parity and worktree safety**

Run: `.\.venv\Scripts\python.exe tools/fixtures/build_trust_v1.py --check`

Run: `git diff --check`

Run: `git status --short`

Expected: fixture check and diff check exit 0. Review owned paths against recorded baselines; do not stage or alter unrelated changes.

- [ ] **Step 6: Independent review and final verification**

Invoke superpowers:requesting-code-review. Resolve every correctness/security finding in its owning task, rerun affected RED/GREEN tests, then invoke superpowers:verification-before-completion and rerun the complete Step 4 command set before claiming completion.
