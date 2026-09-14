# Governed Python API

This guide describes `tn-proto==2026.9.13b5` on Python 3.10 or newer. The distribution includes native Rust-backed governed objects, independent sessions, provider interfaces, and Python business-data views. Linux x86-64 and Windows x64 wheels are the supported release targets.

Start with the [step-by-step README walkthrough](../README.md#1-start-a-session), the [bank/vendor program](../python/examples/bank_vendor.py), or the [enterprise pattern examples](../python/examples/enterprise/README.md). The [governed type signatures](../python/tn/governed/__init__.pyi) and [provider type signatures](../python/tn/providers/__init__.pyi) describe every argument and return type.

## The three controls

Key possession can be the application's entire access rule. With `decide=lambda _: True`, governed receipt verifies the publication and requires the appropriate group keys without adding an application policy restriction. Evaluators can add further checks to that baseline.

Group encryption determines which business groups a reader has the capability to decrypt. A signature authenticates a publication under its writer's signing key. Admission is the application's decision that the verified writer, carried contracts, selected groups, and complete requested use are acceptable.

The matching group key opens the encrypted data. Within governed receipt, an application can add a decision before selected business-group plaintext is returned. The SDK supplies the verified writer, contract, and requested use to that decision.

Public envelope metadata and ciphertext lengths remain visible. Equality tokens reveal equality within their configured key domain. A signed chain can establish the observed predecessor relationships; an independently known expected head is needed to detect a missing suffix. Retain publications and expected identities when completeness matters.

## Public objects

| Type | Purpose |
| --- | --- |
| `Session` | Own an independent identity, key capabilities, policy selection, and receive/release configuration. |
| `Workflow` | Bind configured input and output purposes for repeated work. |
| `DataObject` | Work with opened business fields while retaining contracts, source references, and the last signed snapshot. |
| `GovernedObject` | Hold an exact verified signed publication, suitable for storage or transport. |
| `Governance` | Hold a selected or carried contract and its authority, reference, sources, and dataset bindings. |
| `UseContext` | Name an immutable `(application, purpose, operation)` use. |
| `GovernanceView` | Inspect authenticated governance before admitting business use. |
| `AdmittedObject` | Hold an accepted object/use/reader/group binding. |
| `OpenedObject` | Hold the opened groups from the explicit admission API. |
| `DataState` | Supply a detached view of working data to inspection and decisions. |

Import the common types from `tn`, or the full governed surface from `tn.governed`. Provider classes are in `tn.providers`.

## Session setup

```python
import tn

# Fresh in-memory identity and keys; intended for local examples and tests.
session = tn.Session(policy_text, groups=["amounts", "identity"])

# Existing application identity, policy, and keys through the config loader.
session = tn.Session.from_config("service.yaml")
```

`Session(policy, *, groups=None, policy_id="agents.md", registers=None)` defaults to business group `default` and includes the governance group `tn.agents`. `Session.from_config(path, *, registers=None)` loads existing material. Applications with external identity/key/policy sources can instead construct a session through [providers](#providers).

Use a context manager or call `session.close()`. `session.did` identifies its signer and `session.closed` exposes its lifecycle. Sessions do not select a module-global default. Their capabilities are snapshots; closing one session does not close another. A closed session cannot continue signing or opening through its bound workflow.

### Select a policy

`session.policy(object_type)` selects the named Markdown section. A contract includes an authority (`governed_by`), policy reference, and the statements `instruction`, `use_for`, `do_not_use_for`, `consequences`, and `on_violation_or_error`.

For an externally supplied contract:

```python
policy = tn.Governance.from_markdown(
    authority_did, policy_text, "agents.md", "invoice"
)
```

The application must decide whether that authority and exact contract are trusted. Use `candidate.matches_contract(expected)` to compare a carried contract with an accepted one. Read statements with `policy.get(name)` or the detached `policy.fields` dictionary. Do not assume that a matching object type, policy filename, or human-readable label establishes exact contract equality.

`create` normally infers the type from policy selection. An independently decoded contract without that local selection may require `object_type=` explicitly.

### Configure input, output, and attachment

```python
session.configure_receive(
    use=tn.UseContext("invoice-app", "accounting", "read"),
    object_type="invoice", groups=["amounts"], decide=accept_invoice,
)
session.configure_release(
    use=tn.UseContext("invoice-app", "reporting", "publish"),
    to="report-service", object_type="invoice.report", decide=accept_report,
)
session.configure_attach(decide=accept_additional_contract)
work = session.workflow(receive="accounting", release="reporting")
```

The names `accept_invoice`, `accept_report`, and `accept_additional_contract` are application functions receiving the [decision contexts](#decision-contexts) below. Complete runnable setup appears in [bank_vendor.py](../python/examples/bank_vendor.py).

`configure_receive(*, use, decide, groups=None, object_type=None)` defaults to group `default`. It can register different signed input types for one purpose. An exact type route takes precedence over a wildcard route. Duplicate purpose/type entries and missing routes are refused.

`configure_release(*, use, to, object_type, decide)` supplies the output type, destination, and decision for a purpose. `configure_attach(*, decide)` supplies the authority check for adding policy. Register attachment before binding a workflow that needs it.

`session.workflow(*, receive, release)` requires both purposes to exist and captures their settings. Later registration does not change an existing workflow. The captured evaluators execute for every operation and may consult current application authorization state. Binding selects configuration; it does not approve future data in advance.

The release destination is part of the decision context. Release returns a signed object that the application can save, enqueue, or send through its chosen transport.

## Object operations

The fifteen verbs cover origination, business work, transport, and explicit admission.

### Create and receive

```python
invoice = session.create(
    {"amounts": [12, 18]}, policy, object_type="invoice", group="amounts"
)
data = work.receive(invoice)
```

`session.create(fields, policy, *, object_type=None, group="default") -> DataObject` creates an initial signed publication and its working object. `create_obj` accepts the same arguments. To originate several encrypted groups together, use:

```python
invoice = session.create_obj_with_groups(
    {"amounts": {"amounts": [12, 18]}, "identity": {"account": "A-100"}},
    policy, object_type="invoice", primary_group="amounts",
)
```

`work.receive(source, *, selection=None) -> DataObject` verifies the publication, obtains its governance, runs the configured admission decision, and opens the selected business groups. `source` can be wire text, wire bytes, a `GovernedObject`, or an unchanged `DataObject`. Receiving a working object with pending edits is refused; publish the edits first or deliberately select its older `.snapshot`.

Use the configured session operation without a workflow when only input is needed:

```python
data = session.receive(publication, purpose="accounting", selection=selection)
```

`selection` is optional and must come from an accepted dataset catalog when supplied. It preserves exact edition/source/use checks alongside the configured route.

The integration form is `session.receive(source, *, decide=None, purpose=None, use=None, groups=None, selection=None)`. Explicit use or group overrides require an explicit evaluator. Use `use=UseContext(...)` for the complete application/purpose/operation tuple. The configured `purpose=` form reuses the registered full use and evaluator.

### Inspect, get, and set

| Call | Behavior |
| --- | --- |
| `data.inspect()` | Return detached `DataState`, including groups, policies, dataset bindings, sources, revision, hidden groups, and snapshot. |
| `publication.inspect()` | Return the authenticated envelope dictionary; encrypted groups remain ciphertext. |
| `data.get(name=None, *, group=None)` | Return a field, or the complete opened group if `name` is omitted. |
| `data.set(name, value, *, group=None)` | Set a field; `name=None` replaces the group's business fields. |

`group=None` means the working object's primary group. Business values use JSON-compatible scalars, arrays, and objects. `data.data` and `data.groups` are optional mutable Python views over the same native work. Detached inspection results do not mutate the object.

```python
amounts = data.get("amounts", group="amounts")
data.set("aggregate", sum(amounts), group="amounts")
state = data.inspect()
assert state.has_unreleased_changes
```

`data.snapshot` is the last signed publication; `.history`, `.revision`, and `.has_unreleased_changes` describe local progress. Editing data does not rewrite the previous publication. `data.copy()` creates a separate working copy. Governance is not editable through business mappings.

### Select, include, and attach

`data.select(groups, *, fields=None)` retains selected business groups and optionally projects fields in retained opened groups:

```python
data.select(["amounts"], fields={"amounts": ["aggregate"]})
```

The projection is atomic: invalid groups or fields leave the original object unchanged. Selected fields must exist in opened groups. Selection does not remove carried governance. `retain_groups(groups)` remains available when only group selection is needed. Hidden groups may be retained as encrypted material without opening their values; the bank/vendor example explicitly selects the groups intended for its output.

`data.include(other)` adds the contributing source references, contracts, and dataset bindings from another working object. It **does not** copy or merge that object's business fields. The application computes values itself and records every contributing input explicitly:

```python
first = work.receive(first_publication)
second = work.receive(second_publication)
first.include(second)
first.set("aggregate", sum(first.get("amounts")) + sum(second.get("amounts")))
```

`work.attach(data, policy)` runs the configured attachment decision and adds the contract while retaining the previous contracts. `data.attach(policy, *, decide=None)` uses the object's session or an explicit attachment decision. Applications cannot use attachment to replace the contracts of included sources.

### Release

`work.release(data, *, decide=None) -> GovernedObject` evaluates current data against the configured output decision and creates a signed publication. An optional request-specific `decide` is an additional requirement, useful for checking the expected calculation or exact set of sources for that request.

```python
result = work.release(
    data, decide=lambda context: context.data.groups["amounts"]["aggregate"] == 35
)
```

That request check cannot override a configured refusal. Callbacks receive a stable decision snapshot. If a callback mutates the working object, the changed state needs a fresh decision rather than publication under the old decision. Refusal preserves the previous snapshot and pending edits.

Other release forms:

- `data.release(*, to=None, decide=None, purpose=None, use=None, object_type=None)` uses the working object's session.
- `session.release(data, *, use=None, purpose=None, to=None, decide=None, object_type=None)` explicitly chooses the publisher session.
- Configured `purpose=` obtains destination and output type from setup; explicit `use=`, destination, type, and decision support integrations.

An explicit publisher needs the capabilities to publish the retained groups. `session.check_groups(groups)` returns a `PublicationReport` with `required_groups`, `supported_groups`, `missing_groups`, `unavailable_groups`, `unknown_groups`, and `is_ready`. `session.require_groups(groups)` refuses if the required publication capabilities are absent.

After release, `data.sources` refers to the just-published version for subsequent work. To inspect the inputs carried by a particular publication, read `session.governance(result).governance.sources`. This distinguishes the ancestry of that publication from the sources of a future release.

### Read, write, and forward

```python
result.write("result.tn")
publication = tn.GovernedObject.read("result.tn")
wire = publication.forward()
```

Python `read` and `write` accept a filesystem path or binary stream. `GovernedObject.read(source)` parses and verifies its publication. `GovernedObject.parse(wire)` accepts exact wire text or bytes. `.wire`, `str(publication)`, and `bytes(publication)` expose the retained serialization; `.id`, `.writer`, `.object_type`, `.group_names`, and `.envelope` expose its identity and envelope metadata.

`write` preserves the signed bytes and replaces the contents of a destination file. `forward` returns bytes for an application-supplied transport. Neither creates another version. `DataObject.write` and `.forward` refuse pending edits before writing or returning its snapshot. Reading or forwarding a signed object does not admit business use.

### Verify, accept, and open

```python
publication = session.verify(wire)
view = session.governance(publication)
admitted = view.accept(
    use=tn.UseContext("invoice-app", "accounting", "read"),
    groups=["amounts"], decide=accept_invoice,
)
opened = session.open(admitted, ["amounts"])
print(opened.groups["amounts"])
```

Verification authenticates the publication and validates its governed shape and bindings. Obtaining its governance view opens the governance available to that reader, not the business groups. `accept` binds the verified object, accepting reader, requested complete use, and selected groups. `open` requires that binding and the corresponding key capabilities; requesting a wider selection is refused.

`session.reader(*, groups=None)` makes a reader with selected capabilities. Its `.governance(publication)` and `.open(admitted, groups)` expose the same explicit stages. Opening uses the corresponding group keys.

`OpenedObject` exposes `.groups`, `.hidden_groups`, `.governance`, `.object`, and `.use_context`. `.derive(object_type)` creates a draft under inherited governance; `.derive_under(object_type, governance)` supplies an explicit derivation contract. Ordinary mutable application work generally uses `receive` instead.

## Seal and unseal

The governed operations use the same decisions and return types as the corresponding receive and release calls:

| Signature | Corresponding operation |
| --- | --- |
| `session.unseal(source, *, decide=None, purpose=None, use=None, groups=None, selection=None)` | `session.receive` → `DataObject` |
| `work.unseal(source, *, selection=None)` | `work.receive` → `DataObject` |
| `data.seal(*, to=None, decide=None, purpose=None, use=None, object_type=None)` | `data.release` → `GovernedObject` |
| `work.seal(data, *, decide=None)` | `work.release` → `GovernedObject` |

`session.seal(draft)` retains its origination meaning. Construct its draft with `session.draft(object_type, *, governance=None)` or `tn.GovernedDraft(object_type, governance)`, and add groups using `draft.group(name, fields)`. That draft API is useful for explicit integration and signed administrative records; use governed release to publish existing working data.

Module-level `tn.seal` / `tn.unseal` are the independent sealed-object API used with the event-stream runtime. Module-level `tn.unseal` verifies and decrypts available groups without running governed admission. Use `Session.unseal` or `Workflow.unseal` when an application must decide a use before opening business data.

## Decision contexts

Evaluators must return a boolean. False refuses; exceptions and invalid results stop the operation. Compare every carried contract required by the application, rather than only the first contract or a policy label.

| Context | Available decision data |
| --- | --- |
| `AdmissionContext` | Authenticated `object`, `writer`, `object_type`, `governance`, full `policies`, `sources`, `operation`, `purpose`, `use_context`, and selected `groups`. Business plaintext is not supplied here. |
| `AttachmentContext` | Requesting `authority`, detached working `data`, proposed `policy`, and current `policies`. |
| `ReleaseContext` | Publishing `writer`, detached working `data`, target `object_type`, `purpose`, full `use_context`, `destination`, accumulated `policies`, and `sources`. |

For example, [bank_vendor.py](../python/examples/bank_vendor.py) checks the expected bank writer and all approved contracts on receipt, then checks the vendor's output shape and exact contributing sources on release. The provider-backed `PolicyDirectory` checks explicit writer and exact-contract assignments for the complete use. Application-specific grant eligibility, arithmetic, audience, completeness, or business authorization remains part of the application's decision.

## Providers

Providers separate application startup from object operations. The interface types use Python `Protocol`; included adapters implement the typed native boundaries.

| Interface | Methods and responsibility |
| --- | --- |
| `IdentityProvider` | `resolve(application) -> ApplicationIdentity`, carrying `application` and `did`. |
| `KeyProvider` | `resolve(identity) -> KeySet`, carrying the owner's assigned `GroupCapability` values. |
| `GovernanceProvider` | `policy(PolicyRequest)`, `workflow(WorkflowRequest)`, and boolean `accept`, `attach`, and `release` decisions. |
| `CatalogProvider` | `resolve(CatalogRequest) -> CatalogEntry`, pairing an accepted native selection with its exact publication. |
| `RegisterProvider` | `record(RegisterEvent) -> None`, optionally retaining publication metadata. |

Compose them with:

```python
from tn.providers import Providers

providers = Providers(identity, keys, governance, catalog=catalog, registers=registers)
session = providers.session("invoice-app", workflows=[workflow_request])
policy = providers.policy(policy_request)
```

`catalog` and `registers` are optional. This setup sketch expects configured providers; [providers/hello.py](../python/examples/providers/hello.py) is a complete program.

`PolicyRequest(object_type, use_context)` identifies origination policy. `WorkflowRequest(input, output)` pairs two complete `UseContext` values. `InputRule(groups, *, object_type=None)` routes an input type to business groups. `WorkflowPolicy(inputs, output_type, destination)` defines the selected workflow. Empty identifiers/groups, duplicate routes, and a workflow whose uses belong to different applications are rejected. `Providers.session` requires its workflow uses to belong to the resolved application.

### Included local adapters

- `LocalIdentity(application)` generates a signer. `LocalIdentity.from_private_bytes(application, seed)` loads an existing seed.
- `LocalKeys(groups)` creates group material. `assign(identity, *, read, publish)` assigns capabilities. Governance reading is included; governance publication must be explicitly granted. A publisher assignment in this adapter also includes reading.
- `PolicyDirectory.trust(identity)` records an accepted writer. `add_policy(request, contract)` selects origination policy and approves it for that use. `approve_contract(request, contract)` approves another exact contract without replacing the origination default. `add_workflow(request, policy)` registers routing and output settings. Every carried contract must be approved for the requested use.
- `EditionCatalog.insert(entry)` retains an accepted native selection for later resolution.
- `FileRegisters(ObjectRegisters(...))` records signed metadata through the native implementation.

See the [provider examples and commands](../python/examples/providers/README.md) for separate identity, key, governance, catalog, and register exercises.

### Cipher capabilities

Custom key providers return `KeySet(identity, capabilities)` using the following constructors:

| Constructor | Material |
| --- | --- |
| `GroupCapability.btn_reader(group, kits, index)` | Retained serialized BTN reader kits and index key. |
| `GroupCapability.btn_publisher(group, state, kits, index)` | BTN publisher state, reader kits, and index key. |
| `GroupCapability.jwe(group, recipients, readers, index)` | X25519 public recipient keys, private reader keys, and index key. |
| `GroupCapability.hibe(group, public, path, readers, index)` | HIBE public parameters, target identity path, scoped reader keys, and index key. |

Constructors validate serialized material in Rust. Assign each application the group capabilities it needs. Providers load that material into the session for signing and opening objects.

The [BTN cover reference](BTN_COVER.md) describes the subset-difference labels, tree configuration, and ciphertext encoding.

## Persistent identities and keys

`FileKeyStore` implements both identity and key resolution. Provision once, then reopen:

```python
from tn.providers import FileKeyStore, Providers

store = FileKeyStore.create(
    "private/service.json", "invoice-app", ["amounts", "identity"], cipher="btn"
)
# Subsequent process:
store = FileKeyStore.open("private/service.json")
providers = Providers(store, store, governance)
```

`create` enrolls that application as reader and publisher for the named groups and `tn.agents`. It refuses an existing path. `open` validates the existing store and does not replace missing or malformed material with a new identity. Properties are `application`, `cipher`, `path`, and `groups`.

Store the signing seed and key capabilities in private application storage. Unix creation uses mode `0600`; Windows uses the containing directory's access controls. Assign each application its own capabilities through a key provider.

Supported file-store cipher choices are `btn`, `jwe`, and `hibe`. JWE uses native content encryption and recipient wrapping. HIBE file-store creation generates separate depth-one group authorities and retains the resulting public parameters and scoped reader keys, not authority master secrets. Hierarchical authority provisioning/delegation is a separate operation illustrated in [hibe_delegation.py](../python/examples/persistent_keys/hibe_delegation.py).

The [persistent-key examples](../python/examples/persistent_keys/README.md) run setup, publication, and reading in separate processes for each cipher, proving that later sessions use the saved material.

## Registers and transport

```python
registers = tn.ObjectRegisters(creation="created.jsonl", release="released.jsonl")
session = tn.Session.from_config("service.yaml", registers=registers)
```

Use `ObjectRegisters()` to explicitly disable both registers. When omitted, native session setup captures `TN_OBJECT_CREATION_REGISTER` and `TN_OBJECT_RELEASE_REGISTER`. Explicit configuration overrides those paths.

Registers record signed metadata about creation and release. A failed register write is exposed as `data.register_error`; the signed publication remains available. Configure the application's transaction and recovery behavior around those results.

Provider-backed applications pass `FileRegisters(registers)` or their own `RegisterProvider`. A Python `RegisterEvent` exposes `action`, the signed `publication`, `purpose`, `destination`, and `policy_refs`. The Python callback does not receive the private signing key.

## Policy revisions, dataset editions, and lineage

These APIs bind accepted policy revisions and dataset editions to exact signed publications and their selected uses.

1. Build a `PolicyRevisionDraft.from_markdown(...)`, add any parents with `.parent(revision_id, relation)`, convert it with `.into_draft(administration_contract)`, and seal it as an administrative publication.
2. Verify and admit that record before constructing `PolicyRevision.from_opened(opened)`. `PolicyDag.admit(revision, decide)` applies the authority/parent decision. `dag.select(revision_id, scope, decide)` returns the selected contract.
3. Build a `DatasetEditionDraft` identifying dataset, edition, exact source publication, source groups, contract bindings, eligible complete uses, grant reference, and optional evaluator artifacts. Seal and admit its record, then construct `DatasetEdition.from_opened(opened)`.
4. `DatasetCatalog.admit(edition, dag, decide)` accepts its provenance. `catalog.select(dataset, edition, record_id, use)` returns a `DatasetSelection` fixed to that record, source, and use.
5. Pass that `selection` to governed receipt. Wrong sources, editions, groups, or complete uses are refused before business opening. Included work retains its `DatasetBinding` values through release.

`ContractBinding(revision_id, scope)` identifies an exact contract revision. `EvaluatorArtifactSet` binds policy revision and the hashes of compiled policy, profile, WASM, and data artifacts; the application or integration must execute its evaluator. `DatasetBinding` exposes dataset/edition, exact source object, edition record, and contracts. `DatasetSelection` cannot be freely constructed; obtain it through catalog selection.

`CatalogEntry(publication, selection)` pairs the source and accepted selection. A configured provider resolves it with `providers.resolve(CatalogRequest(dataset, edition, use_context))`, after which `work.receive(entry.publication, selection=entry.selection)` preserves the same checks. See [providers/catalog.py](../python/examples/providers/catalog.py) for complete construction.

`LineageVerifier(max_objects=1024, max_depth=64).verify(...)` verifies retained lineage using a governance view, admitted catalog and policy DAG, and an application resolver for exact source publications. Its `VerifiedLineage` lists verified object and source IDs. The resolver must retain the publications needed for the proof; references alone do not recover missing data. `SourceReference.references(publication)` and `.references_with_policy(publication, accepted_policy)` support exact identity checks.

## Application patterns

The [fifteen enterprise examples](../python/examples/enterprise/README.md) combine the object verbs with application calculations and database transactions.

| Pattern | Application decision and retained state |
| --- | --- |
| Modular monolith | Keep calculation separate from approval of a particular client publication. |
| Request/reply | Bind correlation identity to the accepted exact reply; recover that result on retry. |
| Publish/subscribe | Admit each subscriber's use and transactionally retain its progress. |
| Saga | Bind review to the reserved publication and retain cancellation/completion receipts. |
| Outbox/inbox | Commit business state with exact publication bytes; reject conflicting duplicates. |
| CQRS | Reconstruct the requested source head and verify required input completeness. |
| Gateway | Select the audience's groups and fields and separately approve its output. |
| Aggregation | Admit all required contributors, include their identities, and check completeness. |
| Pipeline | Validate representations and units at each processing and release boundary. |
| Data product | Select an admitted exact edition and eligible complete use. |
| Tenant repository | Bind account assignment and reject conflicting revisions transactionally. |
| Legacy adapter | Preserve approved content and retain the downstream archive receipt. |
| Cache | Retain the original signed publication and reevaluate rights for each new use. |
| Durable workflow | Resume from accepted source identities/checkpoints and recover committed outputs. |
| Strangler migration | Share accepted request/reply state across old and replacement implementations. |

For dataframe or model integrations, admit data before passing it to the library, record contributors with `include`, and release through the configured application decision. TN carries the evaluator bindings and contracts with the result.

## Errors and integration checks

| Signal | Meaning and next step |
| --- | --- |
| `VerificationError` | The publication failed authentication or governed validation; do not accept it. |
| `UseDenied` | The requested use or release was refused. Review the decision and complete use. |
| `NotEntitled` | The reader lacks the required group capability. Provision an approved grant. |
| `NotAPublisher` | Required publication capability is missing. Check the publishing session. |
| `SessionClosed` | The session or bound workflow has been closed. Load a new session with the intended material. |
| `ValueError` / `TypeError` | Invalid arguments, incompatible bindings, or evaluator failure; inspect the error. |
| `data.register_error` | Publication exists but optional recording failed; apply the application's recovery rule. |

Configured callback failures may surface as `ValueError` with the original description. Test acceptance, refusal, missing-key behavior, exact source identity, and retry handling for each integration.
