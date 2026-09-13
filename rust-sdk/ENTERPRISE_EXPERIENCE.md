# Enterprise consumer experience

This note records consumer findings from the separate `tn-enterprise-patterns` corpus, which evaluates the governed-object API through fifteen enterprise architecture patterns. The corpus contains running code, fault tests, and consumer feedback, with separate source pins and evidence for the mutable API and its subsequent complaint remedies. It is not bundled with this SDK; reproducing its baseline requires a separately supplied checkout. The SDK includes [application examples](../python/examples/enterprise/README.md) that can be run from this repository.

The original six-pattern consumer check remains a historical baseline: corpus commit `9e8a0d2`, original SDK commit `243b3d2bd1b6f55ad1149c562b7bdbf6be8e77d3`, fourteen complaints, and 72 compatibility checks. The baseline harness below takes that corpus version. The fifteen-pattern rounds use the corpus's `scripts/evaluate_round.py` and separate `rounds/01` and `rounds/02` records.

## Consumer operations preserve the governed workflow

| Observed consumer task | Rust and Python convenience | Application decision |
|---|---|---|
| Originate several business groups together (P01, P03, P09) | `create_obj_with_groups` validates the collection and creates one complete initial signed snapshot. | Select the origin's applicable policy and group routing. |
| Associate a result with an exact accepted source revision (P02) | `SourceReference.references_with_policy` compares object identity and the accepted authority, policy reference and revision. | Admit that source policy; check groups, operation and business correlation. |
| Inspect edits after a refused or pending release (P05, P08) | `has_unreleased_changes` is available on working data and Python callback snapshots. | Persist the explicit successful release; track database commit and delivery separately. |
| Publish an explicit reduced group set (P07, P09) | `retain_groups` selects plaintext and opaque groups atomically while retaining policies and historical snapshots. Python `DataState.hidden_groups` supports release inspection. | Approve the resulting representation and its permitted destination/use. |
| Read an authority-issued policy publication (P10) | A policy adapter verifies, admits, opens `policy_revision`, then calls `PolicyRevision::from_opened` on the immutable source. | Admit every DAG parent/edge, scope and exact revision applicability. |

The mutable path is `create_obj` or `create_obj_with_groups`, `receive`, ordinary
data changes, optional policy attachment or input inclusion, and `release`.
Callers retain policy automatically. The following recipes place business
transactions and recovery around that path. The [Rust workflow guide](GOVERNED_OBJECTS.md)
and [Python workflow guide](../python/GOVERNED_WORKFLOW.md) document the convenience
methods; the native Python example [governed_data.py](../python/examples/governed_data.py)
executes them together.

## Reproduce the six-pattern baseline

With a separate `tn-enterprise-patterns` checkout at commit `9e8a0d2`, run from the SDK repository with Python 3.11 or later, Cargo, and a populated Cargo dependency cache:

```text
python scripts/check_enterprise_patterns.py --corpus /path/to/tn-enterprise-patterns --target-dir /path/to/cargo-target --report /path/to/enterprise-sdk-regression.json
```

The script creates a temporary consumer crate containing shared fixture code, the six completed binaries, and the two fixture tests. It points `tn-proto`, `tn-core`, and `tn-btn` at this checkout. Dependency features are retained from the corpus manifest. It copies the original lockfile, refreshes local workspace dependency records with `cargo update --offline --workspace`, and runs each test target with `cargo test --offline --locked`. Missing cached dependencies cause a failure; the script does not fetch them. The report includes the generated manifest, effective lockfile, source hashes, compiler versions, command output, and exact test counts. It verifies the frozen vendor manifest before and after execution and refuses a clean result if corpus inputs or SDK sources change during the run. The temporary crate is removed when the run finishes. Cargo output and the report must be outside the original corpus.

The one deliberate adaptation is confined to the temporary copy of P05-C01, `accepted_policy_reference_does_not_admit_altered_carried_rules`. The old test constructs a modified public policy template, seals it, and expects application admission to refuse it. `Governance::from_template` now rejects a modified parsed template immediately. The copied test asserts that earlier rejection and retains its checks for zero inbox/effect rows and subsequent acceptance of the trusted sale. The script prints a unified diff, records before/after hashes, and refuses to patch if the expected test block changes. The original source and frozen vendor dependency are neither retargeted nor edited.

Expected coverage is 70 pattern tests plus 2 shared-fixture tests: P01 13, P02 10, P03 12, P04 16, P05 11, P06 8, and fixture authority 2. The script requires every target to report its exact count with no failed, ignored, or filtered tests. These are compatibility tests of the existing consumers with the documented P05 adaptation. The new mutable-object workflow has its own SDK/core tests; this harness does not migrate the six applications to that workflow or run the nine unfinished patterns.

Observed on 2026-09-07 with Rust/Cargo 1.94.0: all 72 tests passed offline with the exact counts above. SDK/core/BTN source hashes stayed unchanged during the final run. Corpus input hashes stayed unchanged, and all 1,587 frozen vendor files matched baseline commit `243b3d2bd1b6f55ad1149c562b7bdbf6be8e77d3` before and after execution. The evidence report contains the source hashes, copied-test patch, compiler output, and effective lockfile for that run.

## The fourteen baseline complaints

| Complaint | Current API or application recipe | Responsibility that remains with the application |
|---|---|---|
| P01-C01: admission callback lacks source context | `GovernanceView::authorize_with` and `GovernedReader::receive` pass `AdmissionContext`, including verified `object()`, `governance()`, `operation()`, `policies()`, and `sources()`. | Decide accepted writer, object type, authority, every applicable contract, and requested use. |
| P01-C02: missing output groups fail during sealing | `GovernedWriter::check_groups` reports all required groups, including `tn.agents`; `require_groups` rejects incomplete or unsupported configuration. Configured `Objects` exposes both. | Declare output groups at startup and stage fallible sealing before committing effects. Preflight cannot guarantee that later I/O or encryption succeeds. |
| P01-C03: invoice uniqueness and receipt reuse need state | The transaction recipe below stores business identity, accepted source identity, and exact sealed reply together. `GovernedObject::wire()` and `DataObject::snapshot()` expose retained signed bytes. | Set business-key scope, uniqueness, retention, and conflict handling. |
| P02-C01: replies need request association | `SourceReference`, `Governance::source_references`, and `AdmissionContext::sources` replace manually assembled lineage JSON; `SourceReference::references` checks source object identity/type/writer and the governance marker. | Compare the pending request, expected reply writer and contract, signed correlation ID, business ID, selected groups, and admitted operation. A lineage match alone does not establish all of these. |
| P02-C02: lost replies and bounded retry caches need durable state | Persist the committed result and original reply bytes in the same local transaction as the effect. Retain the caller's original request for retry. | Define capacity, expiry, restart recovery, cancellation, and cross-replica consistency. |
| P03-C01: retained envelopes do not restore inbox state | Persist the inbox identity, business effect, and any response/outbox row together; acknowledge after commit. | Restore the durable inbox and its retained results before consuming. A cold subscriber with only envelopes can repeat effects. |
| P03-C02: carrier sequence is not business order | The ordering recipe below uses authenticated stream, ordinal, and predecessor fields in a business group. | Validate gaps, duplicates, conflicts, and bounded buffering. The historical envelope `sequence` is excluded from the old row-hash preimage. |
| P04-C01: exact saga retries need a transaction ledger | Store the canonical command/business ID, accepted request hash, exact response, effect, and coordinator's pending command at their local transaction boundaries. | Keep saga transitions, compensation, recovery policy, and semantic conflict decisions in the saga. Resealing the same payload creates a new object. |
| P04-C02: a reader cipher can be configured as a writer | `PublicationCapability` distinguishes supported, unsupported, and unknown publication. Preflight reports a known reader-only cipher as unavailable without trial encryption. | Use separate publisher/reader provisioning. Unknown custom ciphers remain supported by the legacy sealing path, but do not pass strict `require_groups`. |
| P04-C03: compensation has two causal inputs | `DataObject::include` combines admitted inputs' source references and carried policies; `SourceReference` exposes typed identity, authority, groups, and operation. | Confirm that the reservation is the effect being undone. Keep an explicit signed `compensates` business field when the command schema requires it. |
| P05-C01: altered template can retain an accepted reference | Parsed templates carry an immutable validation binding checked by `Governance::from_template`. `Governance::matches_contract` compares authority, policy reference, selected revision, and the five effective rule fields. | Admit the signer and authority separately. Evaluate all attached policies and any application-specific extensions; `matches_contract` intentionally ignores lineage and other extensions. |
| P05-C02: a new signature can reuse a business operation ID | Enforce both object-ID inbox uniqueness and business-operation uniqueness in the same receiver transaction. Preserve the exact first wire for dispatch retries. | Define whether a second source for the same business ID is refused, reconciled, or explicitly treated as a new revision. |
| P06-C01: projection derivation has several inputs | Receive each input through admission, then use `DataObject::include` before releasing the aggregate. `policies()` keeps the primary and attached contracts inspectable. | Choose the computation and approve release under every carried contract. Keep ordered reducer inputs and reducer version in the application schema when order matters. |
| P06-C02: standalone events need application ordering | Validate signed stream/ordinal/predecessor against a durable accepted prefix and checkpoint it with projection state. | Obtain an independently trusted expected head or count to detect a missing tail; a valid prefix does not prove completeness. |

## Admit, mutate, and release

`GovernedWriter::create_obj` originates a mutable `DataObject` with a required policy and an initial signed snapshot. `GovernedReader::receive` verifies the source, opens governance, asks the application to admit the use, and opens only selected business groups. The returned object supports group/field/path edits while retaining policy and prior snapshots. `GovernedWriter::attach` adds an explicitly approved policy. `release` asks a callback about the current result, output type, purpose, and destination before producing another signed snapshot. Configured `Objects` provides the same flow over loaded identity and group material.

Admission should inspect `ctx.object().writer()` and `object_type()`, the intended `operation()`, and the complete `ctx.policies()?` set. For each carried contract, compare the approved effective contract and check applicability. `matches_contract` provides that field comparison; it is not a policy interpreter or a substitute for accepting the governing authority. At release, inspect the current `ctx.data()`, its carried policies and sources, and the resolved destination. English policy text needs application interpretation.

Unopened groups remain ciphertext unless the application explicitly removes them from the next version. Old signed snapshots retain their original data and contract. A service can enable separate creation/release metadata registers through `ObjectRegisters`. Register output is separate from a business transaction: a failed optional register write leaves a successfully sealed snapshot available and exposes `DataObject::register_error()`. An application that requires durable registration must arrange that requirement around its own commit and dispatch rules.

## Exact retries and a SQLite transaction

The new [Python SQLite example](../python/examples/governed_outbox.py) uses
`create_obj`, `receive`, data mutation, and `release` directly. Its three tests
cover exact receipt reuse after reopening the service, rollback of inbox/effect/
outbox after a pre-commit failure, and a newly sealed request reusing a business
sale ID. These complement the frozen P05 compatibility tests with a consumer of
the new convenience API.

Three identities serve different purposes. The signed object ID identifies an authenticated TN object. A business ID such as `(tenant, operation, sale_id)` identifies the application operation. A broker delivery ID identifies a transport attempt. Carry the business ID inside a signed, encrypted business group. Treat the envelope's legacy `sequence` as carrier metadata, not an authenticated business ID or ordering claim.

Seal once, persist `object.id()` and `object.wire().as_bytes()`, and send those stored bytes on every transport retry. Calling `seal` or `release` again produces a fresh event identity, timestamp, ciphertext, and signature. It is a new object even when the business fields have not changed. `DataObject::snapshot()` is an in-memory retained version; copy it into durable storage before relying on it across a restart. A mutated working object can still retain its earlier snapshot, so choose the intended committed version explicitly.

The P05 application uses actual SQLite transactions and process exits. Its producer transaction inserts the sale and exact outbox BLOB together. Its receiver transaction inserts an inbox row keyed by object ID and a credit row with a separately unique sale ID. A competing sale ID causes the receiver transaction, including its tentative inbox insert, to roll back. The durable broker in this example is another SQLite file representing broker acceptance.

For a service that also returns a signed receipt, extend that local schema with a receipt/outbox row. One possible application schema is:

```sql
CREATE TABLE inbox (
    object_id TEXT PRIMARY KEY,
    wire BLOB NOT NULL
);
CREATE TABLE effects (
    tenant TEXT NOT NULL,
    operation TEXT NOT NULL,
    business_id TEXT NOT NULL,
    source_id TEXT NOT NULL UNIQUE REFERENCES inbox(object_id),
    result_id TEXT NOT NULL UNIQUE,
    result_wire BLOB NOT NULL,
    PRIMARY KEY (tenant, operation, business_id)
);
CREATE TABLE outbox (
    result_id TEXT PRIMARY KEY,
    wire BLOB NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1))
);
```

This is an application recipe; the receipt extension above is not part of P05's executed schema. Enable foreign keys. After TN verification, application admission, selected opening, and domain validation, use `BEGIN IMMEDIATE` to read the accepted business record. If the business key already maps to the same source ID, return its stored result bytes. If it maps to another source, follow the conflict policy without applying a new effect. For a new key, compute against the transaction's state and prepare the signed result, then insert the inbox, effect/result, and outbox rows and commit them together. A sealing failure rolls the transaction back. For work too expensive to perform while holding the write lock, compute speculatively and use an explicit version check/retry before commit. SQLite cannot roll back an external payment or broker operation; represent such operations as durable outgoing commands.

The dispatcher publishes committed outbox bytes and then marks the row sent. A crash between those steps causes duplicate delivery, which the receiver suppresses using durable application state. Acknowledge a received message only after the receiver transaction commits. Retain results long enough to satisfy the promised retry window; do not silently evict evidence while continuing to promise deduplication.

| Failure boundary | Required recovery |
|---|---|
| Before producer commit | No committed sale or dispatchable outbox row; retry the application transaction. |
| After publication, before marking sent | Republish the exact stored wire. |
| After inbox insertion, before receiver commit | SQLite rolls back inbox and effect together. |
| After receiver commit, before reply/acknowledgement | Recognize the stored source ID and return the retained result without repeating the effect. |
| A freshly sealed object reuses the business ID | Apply the explicit business conflict rule; object-ID deduplication alone is insufficient. |

P05 tests cover real SQLite worker exits before and after commit, including duplicate dispatch through a SQLite broker stub. P01/P02/P03 use process-local state; P04 models transactional state and restart.

## Signed stream order and projection recovery

Put `stream`, a positive `ordinal`, and `predecessor` inside each independently readable business group that needs ordering. The first event has ordinal 1 and no predecessor; later events name the accepted predecessor's signed object ID. Authenticate and admit the source and policy before trusting those values.

For each stream, retain the accepted object ID at each ordinal and the current projection/checkpoint. Accept the next event only when its ordinal is the next expected ordinal and its predecessor equals the accepted head. An existing ordinal with the same object ID is an exact duplicate. An existing ordinal with a different object ID is a conflict. A gap or wrong predecessor must leave the accepted prefix unchanged. If buffering gaps, bound the buffer while reserving a path for the missing predecessor to enter; a full buffer must not permanently prevent progress.

Commit the new accepted prefix, inbox/deduplication state, projection, and any output outbox together. On recovery, verify and admit retained sources again under the application's chosen historical/current policy rules. Check their signed order and schema before applying the deterministic reducer. Keep the reducer version and any ordered input list with the signed projection. To detect an omitted final event, compare against an independently obtained expected head or count; predecessor links alone validate only the supplied prefix.

P03 and P06 explicitly alter the legacy envelope `sequence` while retaining valid TN object identity. Their consumers rely on signed business order instead. The SDK does not change historical row hashing to retrofit authentication into that field.

## Source lineage and policy ancestry

`SourceReference` describes a causal data input: signed object ID, type, writer, governing authority, policy reference, selected groups, and admitted operation. `source_lineage` is carried inside encrypted governance. `DataObject::include` combines sources and policies from additional admitted working objects without copying their business values implicitly. After a release, the next working version refers to that released snapshot; deeper history remains in retained signed objects. A typed reference validates its shape and association, but resolving and independently admitting the referenced source still requires that source and the application's trust rules.

`PolicyDag` records immutable signed policy revisions and their declared parent relations. Applications admit parents before children and select an exact revision and scope. A compensation command's reservation and decline are data inputs, not policy parents. A projection's input events are computation history, not an instruction to merge or select a newer policy. Combining data must keep the carried policy set visible and leave policy compatibility and release approval explicit.
