# Rust carries data and its use contract as one governed object

TN-Proto moves data and a use contract together. Group keys control which data
opens. A signature authenticates the complete envelope. The application checks
the contract, performs the permitted operation, and signs its output with the
continuing policy and a reference to its source.

The application surface follows the data's lifetime:

```text
create_obj(data, policy) → receive → mutate / attach / include → release
                       → retain or forward the exact signed snapshot
```

`DataObject` owns mutable data and retained contracts. `GovernedObject` owns an
immutable signed version. Edits preserve earlier versions through `history()`
and `snapshot()`. Callers never copy policies or invoke `derive()` in this flow.

## Application sessions configure receipt once

`tn_proto::Session` wraps an object context with receiving purposes configured
at startup. `session.policy(name)` selects a contract, and
`session.create_obj(fields, policy)` infers its object type.
`session.receive(&object, "greeting")` verifies and opens the publication through
the evaluator and groups registered for that purpose. The Python session calls
the same Rust implementation.

`configure_receive(UseContext::new("hello", "greeting", "read")?, ["default"], admit)`
registers the application decision once. A purpose must be configured before it
can be used. The evaluator sees the complete carried contract set before data
opens. Working changes require release before another receipt.

The executable Rust example is `crypto/tn-core/examples/governed_hello.rs`.
Use `session.objects()` for the explicit integration operations below.

## Applications mutate data and release signed versions

```rust,no_run
use serde_json::json;
use tn_proto::{Governance, Objects};

fn aggregate(objects: &Objects<'_>, incoming: &str, accepted_writer: &str,
             expected: &Governance) -> tn_core::Result<String> {
    objects.require_groups(["observations"])?;
    let mut data = objects.receive(incoming, "aggregate", ["observations"], |ctx| {
        Ok(ctx.object().writer() == accepted_writer
            && ctx.object().object_type() == "research.sample"
            && ctx.policies()?.len() == 1
            && ctx.governance().matches_contract(expected))
    })?;
    // The application computes and assigns the result.
    data.set_group("observations", json!({"total": 30}))?;
    let result = objects.release(&mut data, "research.aggregate", "aggregate", "llm", |ctx| {
        Ok(ctx.destination() == "llm"
            && ctx.data().policies()?.iter().all(|p| p.matches_contract(expected)))
    })?;
    Ok(result.wire().to_owned())
}
```

Origination calls `create_obj(object_type, policy, group, fields)` with the
contract selected by its policy authority. It retains the first signed snapshot.
For an origin with several groups, `create_obj_with_groups` validates and signs
the whole collection at once:

```rust,no_run
# use tn_proto::{Governance, Objects};
# use serde_json::json;
# fn origin(objects: &Objects<'_>, policy: Governance) -> tn_core::Result<()> {
let account = objects.create_obj_with_groups("finance.account", policy, [
    ("balances", json!({"balance": 1200})),
    ("identities", json!({"owner": "Ada"})),
])?;
assert_eq!(account.history().len(), 1);
assert!(!account.has_unreleased_changes());
# Ok(()) }
```

Its first snapshot contains all supplied groups and `tn.agents`, without an
intermediate partial object. Empty collections, duplicate or reserved group
names, non-object fields, and missing publication material are refused. The
configured context records one optional creation entry after successful sealing.

`Objects` loads configured material; `GovernedWriter` and `GovernedReader` expose
the same workflow with supplied ciphers. `tn-proto` with
`default-features = false` supports that direct workflow without a filesystem
runtime. The runnable example uses real BTN ciphers.

Admission receives the verified source, operation, primary contract, complete
policy set, and typed causal references together. `matches_contract` compares
the authority, content reference, optional signed revision, and all five required
rule fields. Applications also evaluate machine-readable extensions and all
attached contracts. Template construction validates its normalized policy
content before creating the contract.

## Policy attachment preserves existing contracts

`writer.attach(&mut data, policy, decision)` passes the writer identity, current
object, and proposed policy to an authority decision. Approval adds the policy;
it cannot replace the primary contract or remove earlier policies. Release
encrypts the whole set in `tn.agents` and signs it with the data. `governed_by`
is the writer-authenticated authority declaration. Application admission checks
whether that writer may act for the authority. Signed `PolicyRevision`
publications can supply accepted authority-issued rules.

`data.include(&other)` retains the other input's policies and typed causal
references. Computation remains application code. Distinct machine rules remain
distinct contracts even when the five standard text fields match. Source
references describe computation; `PolicyDag` parents describe policy history.
When associating a reply with an admitted input, use
`source.references_with_policy(&input, &accepted_policy)` to compare source
identity, authority, policy reference and exact selected revision. Supply the
policy already accepted from that input. Check selected groups, operation and
business correlation separately. `references(&input)` compares the identity and
public marker; the selected revision is encrypted and needs the accepted policy.

## Release preserves history and selective access

Unopened groups remain as their original ciphertext. The new release signs them
together with changed groups, the continuing primary governance marker, attached
policies, and causal references. Applications may remove business groups from a
new output; earlier signed versions remain intact. Data mutation reserves
`tn.agents` and cannot set or delete it.

`data.retain_groups(["report"])` keeps an explicit set of business groups for the
next release and removes all other plaintext and opaque groups. Every requested
name must already exist; unknown and reserved names fail before any mutation.
An explicitly retained opaque group keeps its ciphertext. Policies and historical
snapshots always remain. The application approves the resulting group selection
in its release callback.

Release asks the application to admit the current state for its purpose and
destination. Refusal or encryption failure preserves current data and the prior
snapshot. Success becomes the next immutable snapshot. Retain its exact `wire()`
alongside business effects when retries must return the same result. Another
release intentionally creates another signed version.

`has_unreleased_changes()` reports successful mutation since the last signed
snapshot, including policy attachment or additional inputs. It is false after
creation, receipt without an added dataset binding, or successful release.
`receive_for` with an accepted dataset selection installs that binding in the
working object and marks it changed; the received signed snapshot stays intact.
Refusal preserves the flag's current value.
It describes local working state. A successful signature and a committed business
transaction are separately recorded facts. For delivery, persist the explicit
successful release return with the application's business changes.

`check_groups()` reports publishing readiness for every requested group and
`tn.agents`; `require_groups()` makes this a startup requirement. Both inspect
loaded capabilities without trial encryption. Retained opaque groups need no
publishing material until the application replaces their contents.

## Each service can keep creation and release registers

`Objects` captures `TN_OBJECT_CREATION_REGISTER` and
`TN_OBJECT_RELEASE_REGISTER` at construction. Unset or empty values disable their
register. `with_registers(ObjectRegisters::new(...))` sets explicit paths. The
default native SDK enables `fs-locking` for concurrent append safety.

Successful creation and release append ordinary signed, hash-chained TN rows
with object identity, action, policy references, purpose, and destination.
Business values stay in the governed object. `register_error()` reports a
register write failure while preserving the completed signed snapshot. Each
service owns its registers; business inbox/outbox transactions retain their own
atomicity contract.

The [enterprise experience](ENTERPRISE_EXPERIENCE.md) maps the consumer complaints
to these APIs and gives transaction and replay recipes.

## Envelope primitives support adapters and policy publications

The following sections retain the lower-level draft/seal/admit/open interface
and signed policy publication model for adapter authors.

`governed` is the contract of these types: sealing always signs and binds every
encrypted group to the carried `tn.agents` policy. Event profiles such as
`Transaction` select event-stream behavior separately. A governed object can be
sent in an API call, stored as an artifact, forwarded between programs, or
retained as exhaust.

## Policy revisions carry authenticated update history

`PolicyRevisionDraft` creates a revision containing the complete normalized
policy document, selected event, content reference, governing authority, scope,
and parent revision identities. `into_draft(administration_contract)` puts this
record in the encrypted `policy_revision` group of a `tn.policy.revision`
object. Seal it with the existing object writer. Its `tn.agents` describes the
contract for administering that publication; its revision payload describes
the effective policy being published.

After signature verification, administration-policy admission, and opening
`policy_revision`, `PolicyRevision::from_opened` checks the typed record and
recomputes its policy reference using TN's existing normalized-document hash.
It checks every event in that document, including events other than the
selected section. The original signed envelope stays attached to the revision.

There are two identities:

- `revision.governance().policy_ref()` identifies the policy content and selected
  section using the established policy-reference format.
- `revision.id()` is the TN row hash of the complete signed publication,
  including its parents, scope, and publisher identity. Identical effective
  policy content can occur in distinct authenticated revision histories.

`PolicyRelation` defines the relationship recorded for each parent:

| Relationship | Parent count | Application meaning |
|---|---|---|
| Root | Zero | Establish policy through the application's accepted root authority. |
| `Revise` | One | Succeed an earlier revision within an authorized scope. |
| `Extend` | One | Carry applicable parent obligations and add requirements. |
| `Combine` | At least two; every edge is `Combine` | Record an explicit effective contract incorporating the named parents. |

`PolicyDag::admit` first resolves every parent against its accepted history. It
then requires an application authority callback to approve the root, or each
parent edge separately. The callback receives the candidate and either `None`
for a root or `Some((edge, accepted_parent))`. It checks the writer, governing
authority, scope, and the allowed policy change. The application evaluates the
effective policy text and how obligations continue through an extension or
merge. A refusal or callback error leaves the DAG unchanged.

Accepted revisions are immutable. Parents must already be admitted, so a
revision can refer only to earlier accepted nodes. This makes the history
acyclic by construction. Unknown parents and attempts to replace an admitted
identity are refused before authority callbacks run. Retain the signed objects
and rebuild the in-memory DAG by reopening and admitting them in parent-first
order under the application's trust configuration.

```rust,no_run
use tn_proto::{Governance, PolicyDag, PolicyRevision};

fn accept_and_select(
    dag: &mut PolicyDag,
    revision: PolicyRevision,
    accepted_writer: &str,
    accepted_authority: &str,
    approved_policy: &str,
) -> tn_core::Result<Governance> {
    let id = revision.id().to_owned();
    dag.admit(revision, |candidate, parent| {
        Ok(candidate.writer() == accepted_writer
            && candidate.governance().governed_by() == accepted_authority
            && candidate.governance().policy_ref() == approved_policy
            && candidate.scope() == "research"
            && parent.is_none_or(|(_, p)| p.scope() == "research"
                && p.governance().governed_by() == accepted_authority))
    })?;
    dag.select(&id, "research", |candidate| {
        Ok(candidate.governance().policy_ref() == approved_policy)
    })
}
```

Selection requires an exact admitted revision identity, exact scope, and an
application applicability decision. It does not choose a revision by timestamp,
version label, or branch tip. The returned `Governance` carries `policy_revision`
inside encrypted, signed `tn.agents`. Every group's AAD remains the existing
two-field `governed_by` / `policy` marker. The row signature binds the selected
revision identity together with all encrypted data and governance.

A receiver calls `dag.resolve(carried_contract, scope)` during application
admission. This checks the revision identity against accepted history and
compares the governing authority, policy reference, and all five policy fields
with the selected revision. The ordinary operation callback still decides
permitted use. Possessing a revision record or admitting an update does not
grant a reader key.

`opened.derive(...)` continues the selected revision. `derive_under(...)` can use
a separately selected revision for the result. Both record the input revision
in `source_lineage` when one is present. The source envelope and its earlier
policy remain intact. This keeps policy history and computation history
connected while preserving their distinct meanings.

Run `cargo run --offline -p tn-proto --example policy_revisions` for a complete
root, two branches, a merge, and a data result under the selected merged policy.
The example uses independent in-memory BTN group material and explicitly
approved policy content. The revision/DAG API is exported by the Rust SDK; the
native Python session binding continues to use the underlying governed-object
operations.

Policy publications are decoded from their admitted immutable `OpenedObject`.
An authority adapter uses `parse`, `governance`, `authorize_with`, `open` of
`POLICY_REVISION_GROUP`, then `PolicyRevision::from_opened`. It stores the original
wire with the revision identity and admits each DAG parent before its child.
This keeps the decoded policy publication tied to the exact signed source.
Ordinary business computation uses the mutable `receive` flow. The catalog and
durable-workflow patterns package the publication-reading sequence in their
policy adapters so business callers select an already accepted contract.

## An application supplies the policy and assigns data to groups

Open an existing TN configuration with:

```rust,no_run
use serde_json::json;
use tn_proto::Tn;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let objects = Tn::open_objects("tn.yaml")?;
    let draft = objects.draft("research.sample")?
        .group("observations", json!({"counts": [12, 18]}))?
        .group("identities", json!({"participants": ["Alice", "Bob"]}))?;
    let source = objects.seal(draft)?;
    println!("{}", source.wire());
    Ok(())
}
```

`open_objects` reads the configuration, signing identity, policy document, and
group material. It does not initialize event handlers, open logs, scan chains,
rotate files, or emit lifecycle events. An existing `Tn` handle supplies the
same interface through `tn.objects()`.

The configuration declares the encrypted business groups and the private
`tn.agents` group. `draft("research.sample")` selects that section from the
loaded `.tn/config/agents.md`, relative to the configuration directory, and uses
the writer DID as `governed_by`. A missing section produces an error at draft
construction. To select another governing authority or policy document, pass an
explicit `Governance` to `GovernedDraft::new`.

Groups are the access unit. Each `.group(name, fields)` assigns a JSON object to
one encrypted group. The same group key opens the fields within that group.
Distinct groups can have distinct access. Numeric, boolean, array, and nested
object values retain their JSON types inside encrypted groups.

## Sealing constructs the governance binding and signs the complete object

`Governance::from_markdown` uses the existing TN policy parser. It selects the
object section and fills the five policy fields: `instruction`, `use_for`,
`do_not_use_for`, `consequences`, and `on_violation_or_error`. The sixth field,
`policy`, identifies the section, version, and SHA-256 of the normalized parsed
policy document. This identifies policy content; it is not a hash of the raw
Markdown file bytes.

`seal` performs the following operations:

1. Insert the contract fields as the reserved `tn.agents` group.
2. Produce a common marker containing `governed_by` and `policy`.
3. Compute each field's existing HMAC index token using its group's index key.
4. Encrypt each group's canonical JSON with the marker as AEAD associated data.
5. Carry the canonical map of group markers in the public `tn_aad` string.
6. Compute the existing TN row hash over the signed headers, public metadata,
   every group's ciphertext, and every field token.
7. Sign the UTF-8 row-hash string with the writer's Ed25519 key, encode the
   signature, and return the verified wire object.

The signature binds the complete envelope. AEAD binds each encrypted group to
its declared governance marker. `governed_by` is a declaration authenticated by
the writer's signature; it does not introduce a second signature. Applications
accept governing authorities and writers according to their own trust rules.

The object uses the existing standalone TN wire conventions: `tn_sealed: 1`,
`sequence: 0`, and empty `prev_hash` and `level`. It receives a new event ID and
timestamp. Creation returns bytes without a receipt or a severity setting.
The existing row hash excludes `sequence`; stream ordering remains a separate
chaining concern.

## The application admits use before opening selected business groups

```rust,no_run
use tn_proto::GovernedObject;
fn receive(objects: &tn_proto::Objects<'_>, wire: &str, accepted_writer: &str,
           accepted_authority: &str, accepted_policy: &str)
           -> tn_core::Result<tn_proto::OpenedObject> {
    let received = GovernedObject::parse(wire)?;
    let reader = objects.reader()?;
    let view = reader.governance(&received)?;
    let writer_is_accepted = view.object().writer() == accepted_writer;
    let admitted = view.authorize("aggregate", |contract, operation| {
        Ok(writer_is_accepted
            && contract.governed_by() == accepted_authority
            && contract.policy_ref() == accepted_policy
            && contract.get("use_for") == Some(&serde_json::json!("Aggregate research."))
            && operation == "aggregate")
    })?;
    let opened = reader.open(&admitted, ["observations"])?;
    Ok(opened)
}
```

Parsing verifies the row hash and signature, requires encrypted governance and
matching AAD for every group, and rejects duplicate JSON names. It retains the
exact received string for forwarding. Public metadata uses string values;
`tn_sealed` has the fixed integer value `1`. This preserves one interpretation
of public values under the established wire hash. Business values use encrypted
group JSON. A signed event row with this governed shape can also be admitted;
checking its stream position uses the event-chain reader.

`reader.governance` decrypts only `tn.agents` and checks that its policy reference
matches the authenticated marker. The application evaluates writer, governing
authority, expected policy, carried policy fields, and intended operation. The
example callback is an explicit application decision; an application can use a
full contract evaluator in its place. The reference hash addresses the parsed
document; the receiving application establishes trust in the carried contract
through its accepted writer and policy content.

`authorize` records that decision in an `AdmittedObject`. A refusal or callback
error ends this opening path. `reader.open` requires that admitted value and
opens exactly the named business groups. All requested groups must be present
and decryptable; the result retains every unselected group as ciphertext in the
original envelope.

Key possession and application approval serve separate purposes. Matching
group material provides cryptographic access; application approval admits an
operation. An AEAD nonce provides encryption freshness. It is not an access
credential or an application permission.

## Forwarding preserves the object and derivation signs a new one

Forward `opened.object().wire()` or `source.wire()` unchanged. The complete
signed envelope travels with all its groups, including those this reader has
not opened. Retain it as the source evidence for later inspection.

After computing the approved result:

```rust,no_run
fn release(objects: &tn_proto::Objects<'_>, opened: &tn_proto::OpenedObject,
           total: u64) -> tn_core::Result<tn_proto::GovernedObject> {
    let result = objects.seal(
        opened.derive("research.aggregate")?
            .group("observations", serde_json::json!({"total": total}))?
    )?;
    Ok(result)
}
```

`derive` carries the source contract into a new draft. `derive_under` accepts an
explicit output contract when the application's release rules select one. Both
record `source_lineage` inside encrypted, signed `tn.agents`: source row hash,
source type, writer, governing authority, input policy, selected groups, and
approved operation. The immediate source reference leads back through earlier
objects. The application supplies output fields explicitly, then sealing
creates fresh ciphertext, identity, hash, and signature. The original remains
unchanged.

The program that sees plaintext owns the permitted-use and release decision.
The Rust types keep source, contract, and selected data together through that
program's workflow. This is the interface for implementing governed LLM calls
or governed compute wrappers: inspect policy, admit input, mediate computation,
check release, and seal the result.

## Retained key generations preserve inspectable exhaust

A historical object retains its original ciphertext and key relationship.
Retained eligible keys can reopen it for truthful reconstruction. A new key
generation assigns access to newly created objects. `GovernedReader` accepts
multiple cipher candidates per group, and configured readers load retained
material alongside current material for their declared groups. Additional
candidates can be supplied with `reader.with_group`. Reopening an object does not rewrite its
history.

An `Objects` handle opened from disk loads configured publisher state at open;
reopen it to pick up external key changes. An adapter from `tn.objects()` shares
the runtime's existing group states. Each reader is a snapshot of cipher
candidates when it is built; build a new reader after changing those states.

## The runnable example uses the same core without configuration

[examples/governed_objects.rs](examples/governed_objects.rs) creates real BTN
group material locally, seals observations and identities, opens only
observations, computes an aggregate, and signs a derivative. It creates no
project or logger.

```sh
cargo run -p tn-proto --example governed_objects
```

An embedded Rust caller can use `tn_core::governed` with default features
disabled. `GovernedWriter` takes an existing `DeviceKey` plus group cipher and
index material. `GovernedReader` takes only the cipher candidates it needs.
Configured contexts and distribution APIs are supporting adapters over these
same operations.

## Implementation and validation are directly inspectable

| Component | Source |
|---|---|
| Policy selection and typed contract | `crypto/tn-core/src/governed/policy.rs` |
| Draft and signed construction | `crypto/tn-core/src/governed/writer.rs` |
| Verified immutable envelope | `crypto/tn-core/src/governed/object.rs` |
| Governance, admission, selected opening, derivation | `crypto/tn-core/src/governed/reader.rs` |
| Configured object context | `crypto/tn-core/src/runtime/objects.rs` |
| Rust SDK entry points | `rust-sdk/src/objects.rs` |
| Protocol tests using real ciphers | `crypto/tn-core/tests/governed_objects.rs` |
| Configured interface tests | `rust-sdk/tests/governed_objects.rs` |

The tests check automatic policy carriage and signing, selected access,
application refusal, exact forwarding, source lineage, historical readability,
duplicate JSON admission, marker typing, row mutation, and AEAD rebinding.
Existing seal/unseal and golden-vector tests check the shared wire construction.
