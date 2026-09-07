# Python sessions carry governed data through computation

TN-Proto moves data and a use-contract together. Group keys control access,
signatures authenticate the object, and the application decides whether to carry
out a requested operation. The Python SDK exposes this workflow through native
Rust objects in `tn.governed`, with `tn.Session` as its entry point.

## Each session owns its identity and groups

```python
import tn

policy = """---
version: 1
schema: tn-agents-policy@v1
---
## research.sample
### instruction
Create an aggregate report.
### use_for
Aggregate research.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""

source_session = tn.Session(policy, groups=["observations", "identities"])
output_session = tn.Session(policy, groups=["reports"])
assert source_session.did != output_session.did
```

Each constructor creates an independent Ed25519 signing identity, parsed policy
tree, and BTN group material in memory. `groups` names the business groups;
`tn.agents` is supplied automatically. Omitting `groups` supplies a business group
named `default`. The constructor creates no files and starts no event runtime.

Both sessions can remain active, work in parallel, and close independently.
Their methods always use their own context. The existing lowercase `tn.session()`
continues to manage the module's event runtime; the uppercase `tn.Session` is the
instance API for governed objects.

## Sealing binds the contract to every group

```python
source = source_session.seal(
    source_session.draft("research.sample")
    .group("observations", {"counts": [12, 18]})
    .group("identities", {"names": ["Alice", "Bob"]})
)
wire = source.wire
```

`draft()` selects the named policy section. It fills the typed contract from
`instruction`, `use_for`, `do_not_use_for`, `consequences`, and
`on_violation_or_error`, together with its parsed-content policy reference.
`seal()` inserts that contract into the reserved encrypted `tn.agents` group.
It supplies the same `governed_by` and `policy` markers in every group's AAD,
encrypts each assigned group, and signs the complete object with the session's
identity. This governed sealing path always supplies governance and a signature.

Groups are the access unit. `.group("observations", fields)` routes those fields
into one encryption group. A reader assigned that group's material can open its
fields. The wire contains group names and field-index names; field values and the
contract travel encrypted. `governed_by` is the writer-authenticated declaration
of the governing authority. The object's signature is made by `source.writer`.

`source.id` is its signed row hash. `source.wire` and `bytes(source)` preserve the
transport representation. Forward those bytes to carry the existing object.

## Applications inspect governance before opening business data

```python
# The application obtains these expectations from its accepted source/contract.
trusted_writer = source_session.did
approved_policy = source_session.policy("research.sample").policy_ref

received = tn.GovernedObject.parse(wire)
if received.writer != trusted_writer:
    raise ValueError("source writer is outside this application's accepted writers")

reader = source_session.reader(groups=["tn.agents", "observations"])
view = reader.governance(received)
admitted = view.authorize(
    "aggregate",
    lambda contract, operation: (
        operation == "aggregate"
        and contract.governed_by == trusted_writer
        and contract.policy_ref == approved_policy
    ),
)
opened = reader.open(admitted, ["observations"])
counts = opened.groups["observations"]["counts"]
assert opened.hidden_groups == ["identities"]
```

`parse()` verifies the envelope, row hash, and writer signature. The application
checks whether that writer belongs to its accepted set. `governance()` opens
`tn.agents` and checks its binding to the authenticated markers. The decision
callback then evaluates a named operation against the contract. It must return a
Python `bool`: `True` creates an `AdmittedObject`; `False` raises `UseDenied`.
An exception from the callback propagates to the caller.

`open()` requires that admitted object and an explicit group selection. It
returns selected plaintext together with the admitted governance and the complete
source envelope. The group reader determines cryptographic access. The callback
is the application's permitted-use decision; the application carries that
decision through its computation and release steps.

The example approves a known contract reference for one operation. A service can
make its callback consult its own contract registry or policy engine. The policy
reference hashes parsed policy content, so applications compare the authenticated
contract content rather than the Markdown file's byte layout.

For a session using all its own reader material, the equivalent convenience calls
are `session.governance(source)` and `session.open(admitted, ["observations"])`.
An explicit `session.reader(groups=[...])` lets the application pass a smaller
set of group capabilities to the code performing the operation.

## A derived result is a new signed object

```python
result = output_session.seal(
    opened.derive("report.generated")
    .group("reports", {"total": sum(counts)})
)
assert result.writer == output_session.did
contract = output_session.governance(result).governance
assert contract.governed_by == trusted_writer
assert contract.policy_ref == approved_policy
assert contract.fields["source_lineage"][0]["object_id"] == source.id
```

`derive()` retains the input contract and adds an immediate source record with the
input object ID, writer, type, governing authority, policy reference, opened
groups, and admitted operation. The output session supplies its own encryption
groups and signs the new result. The original object remains available unchanged
as `opened.object`.

When the application chooses an approved output contract, use
`opened.derive_under("report.generated", output_contract)`. The source record
still identifies the input contract. Obtain a contract from
`session.policy(object_type)` or
`tn.Governance.from_markdown(authority, markdown, policy_id, object_type)`.
An explicit contract can also be supplied to `session.draft(..., governance=...)`.

## Existing configuration supplies persistent identities and access

```python
from pathlib import Path

with tn.Session.from_config(Path("project/tn.yaml")) as session:
    source = session.seal(
        session.draft("research.sample").group("default", {"count": 30})
    )
```

`from_config()` uses the Rust object loader to read the existing configuration,
device identity, group material, and `agents.md` tree. It creates its own context
without opening or emitting an event log. The configuration must provide
`tn.agents` and the business groups used by the workflow. Configured cipher
selection stays with the existing Rust loader. Reopening the configuration loads
its current material; retained reader material supports historical exhaust.

Fresh `Session(policy)` contexts are in memory. Use `from_config()` when identity
and access material should survive the process. Supplying an explicit reader to
another component is an application choice, separate from constructing a session.

## Closing releases one session's ownership

`with tn.Session(...) as session:` closes that session on exit. `close()` is
idempotent, and `closed` reports its state. Subsequent operations on that session
raise `SessionClosed`; other sessions continue operating.

Native operations capture their context before releasing the Python GIL for
cryptographic work. An operation already started can complete while another
thread closes its session. Explicit readers own their selected material and
remain usable after the creating session closes. Sealed, admitted, and opened
objects likewise retain their own state.

Draft methods return new drafts. Envelope, policy, and plaintext dictionaries
returned to Python are copies. Editing them does not modify the native object.
JSON fields accept strings, booleans, `None`, finite floats, integers from
`-2**63` through `2**64 - 1`, lists, tuples, and dictionaries with string keys.
Integers and finite floats round-trip exactly; tuples return as JSON lists.
Unsupported values and excessive nesting are rejected before sealing.

## The native types identify each workflow step

| Type | State it carries |
|---|---|
| `Session` | Independent signing identity, policy tree, and group context |
| `Governance` | Governing authority, policy reference, and contract fields |
| `GovernedDraft` | Contract and assigned plaintext groups ready to seal |
| `GovernedObject` | Verified signed envelope and exact wire representation |
| `GovernedReader` | Selected group-reading material |
| `GovernanceView` | Authenticated contract and source awaiting a use decision |
| `AdmittedObject` | Source and contract admitted for a named operation |
| `OpenedObject` | Selected plaintext, governance, and complete source |

All types are native PyO3 classes exported through `tn.governed`. `Session`,
`Governance`, `GovernedDraft`, and `GovernedObject` also have top-level `tn` names.
Typing stubs are included with the package.

The workflow exceptions live in `tn.governed`: `UseDenied`, `NotEntitled`,
`NotAPublisher`, `VerificationError`, and `SessionClosed` derive from
`GovernedError`. Invalid inputs raise the corresponding Python `ValueError`,
`TypeError`, or `OverflowError`; configuration I/O errors raise `OSError`.

Run [the complete two-session example](examples/governed_sessions.py) to inspect
the transition from signed source through selected access to signed aggregate.
