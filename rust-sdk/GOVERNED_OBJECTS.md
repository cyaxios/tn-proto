# Rust carries data and its use contract as one governed object

TN-Proto moves data and a use contract together. Group keys control which data
opens. A signature authenticates the complete envelope. The application checks
the contract, performs the permitted operation, and signs its output with the
continuing policy and a reference to its source.

The Rust interface follows that order:

```text
Governance + explicitly assigned groups
    → GovernedDraft → seal → GovernedObject
    → verify → governance → application approval → selected plaintext
    → compute → derive → seal → new GovernedObject
```

`governed` is the contract of these types: sealing always signs and binds every
encrypted group to the carried `tn.agents` policy. Event profiles such as
`Transaction` select event-stream behavior separately. A governed object can be
sent in an API call, stored as an artifact, forwarded between programs, or
retained as exhaust.

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
