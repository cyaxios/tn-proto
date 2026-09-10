# Python carries governed data through mutation and release

TN-Proto moves data and a use contract together. Keys control which groups open.
Signatures authenticate the object. Applications check permitted use at admission
and release. The Python SDK uses the Rust core for that whole object lifecycle.

Python applications call native types through PyO3. Rust owns contract parsing,
edition selection, admission, policy accumulation, lineage verification, and
signing. Both languages read and write the same TN wire. The executable
[Python workflow](examples/governed_workflow.py) and
[Rust workflow](../crypto/tn-core/examples/governed_workflow.rs) perform the same
calculation and exchange signed publications in the interoperability tests.

## A service originates data with its policy

```python
import tn

policy_text = """## finance.account
### instruction
Prepare aggregate analysis.
### use_for
Analysis.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""

session = tn.Session(policy_text)
policy = session.policy("finance.account")
account = session.create_obj(
    {"rows": [{"amount": 12}, {"amount": 18}]},
    policy,
    object_type="finance.account",
)
wire = bytes(account.snapshot)
```

`create_obj` requires an explicit `Governance` contract and retains the initial
signed snapshot. At a service origin, a Unity adapter supplies the applicable
contract for the service context and purpose. The runnable local example selects
it from the session's parsed policy tree. `Governance.from_markdown(authority,
text, policy_id, object_type)` is also available to policy adapters.

Rust fills the reserved encrypted `tn.agents` group with the contract. It binds
each group through the governance AAD marker, encrypts the assigned fields,
hashes all groups, and signs with the session's identity. `governed_by` is the
writer-authenticated authority declaration. Endpoint admission checks the
writer's accepted relationship to that authority.

For several business groups, originate the complete initial shape in one call:

```python
with tn.Session(policy_text, groups=["balances", "identities"]) as origin:
    account = origin.create_obj_with_groups(
        {"balances": {"balance": 1200}, "identities": {"owner": "Ada"}},
        origin.policy("finance.account"), object_type="finance.account",
        primary_group="balances",
    )
    assert len(account.history) == 1
    assert account.data["balance"] == 1200
```

`primary_group` selects the live `.data` view and must name a supplied group;
it defaults to `default`. `.groups` exposes every opened group. Rust validates
the complete collection before signing one initial snapshot and recording one
optional creation entry. The existing single-group `create_obj` stays available.

## A receiver admits the complete source and contract

```python
accepted_writer = session.did
expected_policy = policy
analysis_use = tn.UseContext("analytics", "portfolio_analysis", "calculate")

def admit(context):
    return (
        context.writer == accepted_writer
        and context.object_type == "finance.account"
        and context.use_context == analysis_use
        and context.groups == ["default"]
        and len(context.policies) == 1
        and context.governance.matches_contract(expected_policy)
    )

account = session.receive(
    wire, use=analysis_use, groups=["default"], decide=admit,
)
```

`receive` accepts a sealed object, UTF-8 wire text, or bytes. It verifies the
signature and row hash, opens governance, presents `AdmissionContext`, and opens
selected business groups after approval. `groups=["observations"]` selects a
named group; the default is `["default"]`. Production receiving sessions load
their own assigned material with `Session.from_config(...)`.

`UseContext` keeps application, purpose, and operation together. Strict acceptance
binds that use and the selected groups to this receiving session. The explicit
two-step interface is `session.governance(object).accept(use=..., groups=...,
decide=...)`, followed by `session.open(admitted, groups)`. An admitted value
cannot open an additional group or move to another session. Endpoint configuration
or authenticated request handling supplies the application identity.

The context includes the verified object, writer, type, requested operation,
primary governance, all attached contracts, and typed source references. A
contract match compares authority, content reference, optional revision, and all
five standard rule fields. Applications additionally evaluate machine-readable
extensions and every attached policy. Normalized policy content determines the
policy hash; Markdown formatting is not part of that identity.

## Dataset editions select an exact source publication

A signed `DatasetEdition` names the dataset, edition, exact source object,
source groups, policy revision bindings, eligible use tuples, grant reference,
and evaluator artifact digests. It travels as an ordinary TN object with its own
governance. A `PolicyDag` retains accepted signed revisions. A `DatasetCatalog`
admits edition records against those revisions and the catalog authority decision.

```python
# The registry adapter has opened these signed metadata records through TN.
policy_dag.admit(revision, accept_revision_authority)
catalog.admit(edition_record, policy_dag, accept_catalog_authority)
selection = catalog.select(
    "market.prices", "close-2026-09-08", edition_record.id, analysis_use,
)
prices = session.receive(
    source_wire, use=analysis_use, groups=["finance"],
    selection=selection, decide=accept_source,
)
assert prices.dataset_bindings[0].source_object_id == selection.source_object_id
```

Rust compares the selected source, complete contracts, use, and groups before
opening business data. Equal values in another publication still have a different
identity. Each eligible use is a complete tuple; applications cannot combine an
application from one tuple with an operation from another. Previously accepted
editions remain independently selectable under their assigned uses and keys.

`DatasetSelection` is returned by the accepted native catalog. Python cannot
construct one from a dictionary. The working object carries its dataset bindings
through mutation, inclusion, release, and subsequent receipt.

For downstream computation, use `catalog.accepts(context, policy_dag)` in the
admission decision to check every carried binding and contract against the current
use. `LineageVerifier().verify(view, catalog, policy_dag, resolve)` checks retained
parent publications back to the selected origins. The resolver returns
writer-accepted governance views for exact retained bytes. Ancestor inspection
opens governance only. The result lists verified publication and source identities.

## Ordinary data edits retain governance

```python
account.data["total"] = sum(row["amount"] for row in account.data["rows"])
del account.data["rows"]
```

`account.data` is a live dictionary view of its primary group. Nested dictionaries
and lists also write through to Rust. `account.groups` exposes all opened groups,
for example `account.groups["report"] = {"total": 30}`. The object preserves its
policy set, causal inputs, unopened ciphertext, and earlier signed snapshots.
`tn.agents` cannot be assigned or removed through these views.

A saved view follows its group/key/index path. Use `.copy()` to capture the
values at that moment; `pop()` and `popitem()` return detached removed values.

`account.state` is a detached inspection snapshot. Its dictionaries can be read
or edited locally without changing the working object. The same owned state is
supplied to decision callbacks so they evaluate a consistent version.
`state.hidden_groups` lists the retained opaque groups in that same snapshot.

`account.retain_groups(["report"])` keeps only the named business groups for the
next release. It applies to both opened and opaque groups, preserves every policy
and historical snapshot, and validates all requested names before changing data.
Unknown names and reserved `tn.agents` raise `ValueError`. An empty list removes
all business groups. The primary `.data` view keeps its configured path; use
`.groups` when selecting a differently named output group.

## Authority-approved attachment only adds policy

```python
# additional_policy comes from the application's accepted policy authority.
# authority_check examines context.authority, context.policy and context.data.
# account.attach(additional_policy, decide=authority_check)
```

`attach` asks the authority callback whether this session may add the proposed
contract. Approval retains every existing contract and adds the new one. Each
contract keeps its own authority and optional revision. Repeated identical
contracts are deduplicated; contracts with different machine rules remain
separate. The next release signs the whole set with the current data.

For computations with multiple admitted inputs, call `account.include(other)`.
It retains the other input's contracts and causal references. The application
assigns computed values normally. Source references identify data inputs;
policy-revision DAG parents identify policy history.
Dataset bindings merge with those contracts. `account.copy()` makes an independent
working object for a second calculation while retaining the same accepted inputs.
For a pending request, `source.references_with_policy(request, accepted_policy)`
also compares the selected revision with the policy already accepted from that
request. `references(request)` checks identity and the public governance marker.
The application separately checks source groups, admitted operation and business
correlation.

## Release signs the current result for a destination and purpose

```python
def admit_release(context):
    return (
        context.destination == "llm"
        and context.use_context == report_use
        and context.data.groups["default"]["total"] == 30
        and all(p.matches_contract(expected_policy) for p in context.policies)
    )

report_use = tn.UseContext("analytics", "portfolio_analysis", "release_calculation")
result = account.release(
    to="llm", use=report_use, decide=admit_release,
    object_type="finance.summary",
)
outbox_bytes = bytes(result)
assert account.snapshot.wire == result.wire
```

`ReleaseContext` contains current data, all policies, causal sources, writer,
output type, use, and destination. Approval seals the current state and
retains the signed version. Its governance records the immediate source
references and release context. Refusal or a sealing error preserves the prior
snapshot. The caller never copies policy or calls `derive()`.
The signed `release_context` records application, purpose, operation, and
destination. Earlier contexts remain in their retained signed publications.

Unopened groups retain their exact ciphertext under the continuing primary AAD
marker. Explicitly deleting a business group removes it from the next output;
its earlier signed versions remain in `history`. Each new release becomes the
next working version's immediate source.

`account.has_unreleased_changes` is true after successful mutation, attachment
or inclusion since the last signed snapshot. It is false after creation, receipt
without an added dataset binding, and successful release. Receipt with an accepted
dataset selection adds that binding to the working object and sets the flag while
preserving the received signed snapshot. Refusal preserves the current flag and prior snapshot.
The same property is available on `DataState` inside release decisions. It tracks
local edits; database commitment and delivery are application-owned facts.

Transport retries use the stored `outbox_bytes`. Another `release()` intentionally
creates another signed version. Application transactions store business effects,
source identity, and response/outbox bytes together. The
[enterprise recipes](../rust-sdk/ENTERPRISE_EXPERIENCE.md) describe this for
request/reply, saga, outbox, and projection consumers.

[governed_outbox.py](examples/governed_outbox.py) implements a small SQLite
service with this API. It commits the inbox, credit, signed receipt, and outbox
together, reuses the exact receipt after reopening the database, and applies a
separate uniqueness rule to the business sale ID.

## A separate publisher releases received data

`data.release(...)` uses the session that created or received the working object.
When input reading and output publishing use separate identities or group keys,
call `publisher.release(data, ...)` with the existing native object:

```python
with tn.Session.from_config("input/tn.yaml") as receiver:
    data = receiver.receive(
        source_wire, use=analysis_use, groups=["finance"],
        selection=selection, decide=accept_source,
    )
    data.groups["default"] = {"report_html": "<p>Approved result.</p>"}
    data.retain_groups(["default"])

with tn.Session.from_config("output/tn.yaml") as publisher:
    report = publisher.release(
        data, use=tn.UseContext("reporting", "portfolio_analysis", "publish_report"),
        to="recipient", decide=accept_report_release, object_type="report.generated",
    )
```

Rust retains every contract, dataset binding, and source reference. The publishing
session supplies its identity, keys, and optional release register; it does not
need the input decryption keys. Successful release updates `data.snapshot` and
`data.history`. Refusal or a callback error leaves that signed state unchanged.
Mutation during the decision invalidates the candidate before signing.

Explicit publication can use retained data after the receiving session closes.
It does not change which session `data.release(...)` uses for later calls. The
selected publishing session must remain open through its decision and release.

## Adapters own admission and release decisions

A governed Polars helper holds the `DataObject` while dataframe operations update
selected data. Its `release(to=..., purpose=...)` puts the dataframe result back
into that object and invokes the application's policy decision. A governed LLM
wrapper admits the input for its request, opens the selected prompt data, and
releases the model result with the retained contracts. These adapters encapsulate
the decision callbacks; application callers work with data and destinations.

The SDK supplies the object lifecycle and callback contexts. Unity resolution,
OPA decisions, Polars operations, and LLM transport belong to their adapters.
[governed_data.py](examples/governed_data.py) is an executable example of the
SDK lifecycle with local application decisions and real TN encryption/signing.

## Sessions own independent contexts

Each `Session(policy_text, groups=[...])` creates independent in-memory identity
and BTN material. Several sessions can work in one process and close separately.
`Session.from_config("service/tn.yaml")` loads existing identity, policy, and
assigned group material. `session.require_groups([...])` checks every intended
output group and `tn.agents` at startup. `check_groups` provides the full report.

`close()` is idempotent. Closing a session prevents subsequent bound attachment
or release; other sessions continue. Explicit readers own their selected
material and remain usable after that session closes. Sealed history and working
data remain inspectable. An operation already admitted and started may complete
while another thread closes its session.

Decision callbacks must return a literal Python `bool`. Their original errors
propagate. Callbacks run without Rust locks and may call other session methods.
If a callback changes the same working object, the outer decision is refused as
stale. The changed working data remains available for a new decision. This also
covers concurrent mutation while a release decision is running.

## Services optionally record creations and releases

Set `TN_OBJECT_CREATION_REGISTER` and `TN_OBJECT_RELEASE_REGISTER` before
constructing a session. Each captures its own paths; an unset or empty value
disables that register. Successful operations append signed, hash-chained TN
metadata rows containing object identity, action, policy references, purpose,
and destination. Business plaintext stays in the governed object.

`account.register_error` reports an optional register write failure while
`account.snapshot` retains the completed signed object. Exact signed bytes remain
available for storage and retry. These service registers accompany the workflow;
business transaction and outbox state remain under application ownership.

## The envelope primitives remain available

`GovernedDraft`, `seal`, `GovernanceView.authorize`, `GovernedReader.open`, and
`OpenedObject.derive` remain available for existing adapters. Their dictionaries
are detached copies. `DataObject.data` and `.groups` are the live mutation views.

JSON values support strings, booleans, `None`, finite floats, integers from
`-2**63` through `2**64 - 1`, lists, tuples, and string-keyed dictionaries.
Tuples become JSON lists. Invalid values are rejected before state mutation.

The native classes and typing stubs are exported through `tn.governed`.
`Session`, `DataObject`, `Governance`, `GovernedDraft`, and `GovernedObject` also
have top-level `tn` names. Workflow exceptions are `GovernedError` subclasses:
`UseDenied`, `NotEntitled`, `NotAPublisher`, `VerificationError`, and
`SessionClosed`. Invalid Python inputs use `ValueError`, `TypeError`, or
`OverflowError`; configuration I/O errors use `OSError`.
