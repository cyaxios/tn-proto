### Task 1: Freeze the read policy model and Python decision table

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

- [ ] **Step 1: Write the failing matrix test**

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

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py -q`

Expected: import failure for `tn.read_policy`.

- [ ] **Step 3: Implement pure policy resolution/evaluation**

Do not read global config inside the policy object. `ReadContext` supplies active/detached, local/foreign, profile signing/chaining, local device DID, requested/required group, and trust-provider output. Treat unsigned envelopes as unauthenticated even when accepted. Return an ordered de-duplicated reason array; callbacks/exceptions use its first element. `not_a_recipient` applies only to an explicitly required group/recipient mode, never to an optional hidden group. Reject impossible combinations before reading the log.

- [ ] **Step 4: Run GREEN**

Run: `.\.venv\Scripts\python.exe -m pytest python/tests/test_read_trust_policy.py python/tests/test_read_trust_provider.py -q`

Expected: every fixture case passes with exact reasons.

- [ ] **Step 5: Checkpoint**

If both files were new, stage only them and commit `feat(read): define secure default trust policy`.

---

