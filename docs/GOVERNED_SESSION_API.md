# Governed application sessions

The [fifteen-verb API reference](TN_VERBS_API.md) is the application-facing vocabulary. The detailed setup and compatibility signatures follow here.

A service returns a governed object. The receiving application names its purpose and gets the admitted data. Rust implements creation, purpose selection, signature verification, contract acceptance and selected opening. Python calls that implementation through PyO3.

```python
def hello(session):
    return session.create_obj(
        {"message": "Hello, world!"}, policy=session.policy("hello.message")
    )

message = session.receive(hello(session), purpose="greeting")
print(message.data["message"])
```

Application startup configures `greeting` once with `configure_receive(use=tn.UseContext("hello", "greeting", "read"), decide=admit)`. The evaluator receives the verified writer, complete carried policy set, source references, selected groups and requested use. It decides admission before business data is decrypted. The executable hello example accepts its configured writer and exactly the selected contract.

## Bound workflows

Use a `Workflow` when an application repeatedly receives and releases under the same rules. Startup registers those rules on the session. Binding selects the input purpose and output purpose. Ordinary operations then carry only the object and request-specific arguments.

```python
work = session.workflow(receive="analysis", release="report")
data = work.receive(publication)
# Application code changes data.data or data.groups.
output = work.release(data)
```

The public programming types have separate jobs:

| Type | Responsibility |
| --- | --- |
| `Session` | Identity, key material, configuration, policy selection and origination. |
| `Workflow` | Bound input/output rules with live admission, attachment and release decisions. |
| `DataObject` | Mutable business data, contributing sources and accumulating contracts. |
| `GovernedObject` | Exact signed publication for transport or storage. |

`Workflow` captures the registered routes, release plan and optional attachment evaluator. Register attachment before binding when the workflow will add policy. Additional registrations do not change an existing binding. The captured evaluators execute for every call and can consult current authorization state. Binding is configuration selection, not advance approval.

| Rust signature | Python signature | Behavior |
| --- | --- | --- |
| `Session::workflow(&self, receive: &str, release: &str) -> Result<Workflow<'a>>` | `session.workflow(*, receive: str, release: str) -> Workflow` | Requires both purposes to exist and captures their settings. |
| `Workflow::receive(&self, source: &impl Publication) -> Result<DataObject>` | `work.receive(source, *, selection=None) -> DataObject` | Verifies the publication and accepts the complete use before opening the routed groups. Python also accepts exact wire text or bytes. |
| `Workflow::receive_selected(&self, source: &impl Publication, selection: Option<&DatasetSelection>) -> Result<DataObject>` | Same `receive`, with `selection` | Retains the exact dataset selection checks. |
| `Workflow::attach(&self, data: &mut DataObject, policy: Governance) -> Result<()>` | `work.attach(data, policy) -> None` | Uses the bound attachment authority and retains existing contracts. |
| `Workflow::release(&self, data: &mut DataObject) -> Result<GovernedObject>` | `work.release(data) -> GovernedObject` | Evaluates and signs the current state with configured type, use and destination. |
| `Workflow::release_checked<F>(&self, data: &mut DataObject, check: F) -> Result<GovernedObject>` where `F: FnOnce(&ReleaseContext) -> Result<bool>` | `work.release(data, *, decide=check)` | Requires both configured approval and the extra request decision. |
| `Workflow::primary_group(&self, object_type: &str) -> Result<&str>` | Used by the native binding | Identifies the first configured business group for an input type. |
| `Workflow::release_plan(&self) -> Arc<ReleasePlan>` | Used by the native binding | Exposes the immutable native output plan to integrations. |

Combine inputs with `data.include(other)`, mutate fields through `DataObject`, and create objects with `session.create_obj(fields, policy)`.

Python calls the native workflow for receipt and attachment. Release reuses the Rust release plan and native object operation through the existing revision-safe PyO3 bridge. Callbacks run without the object lock; a changed object cannot be published using a decision about its previous state. Closing the Python session closes access through its bound workflows.

## Rust interface

The `tn_core::runtime::Session` type is also exported as `tn_proto::Session` by the Rust SDK. Each instance has independent material and receiving configuration.

| Function | Capability |
| --- | --- |
| `Session::ephemeral(policy: &str) -> Result<Session<'static>>` | Creates in-memory identity and keys with a default business group. |
| `Session::open(path: &Path) -> Result<Session<'static>>` | Loads existing identity, keys and policy configuration. |
| `Session::new(objects: Objects<'a>) -> Session<'a>` | Uses an existing object context. |
| `policy(name: &str) -> Result<Governance>` | Selects the named contract. |
| `create_obj(fields: impl Serialize, policy: Governance) -> Result<DataObject>` | Uses the type selected by the policy loader, including an external authority or policy DAG selection. |
| `configure_receive(use_context: UseContext, groups, decide) -> Result<()>` | Registers a purpose with groups and a reusable `Fn(&AdmissionContext) -> Result<bool> + Send + Sync + 'static` evaluator. |
| `configure_receive_for(object_type: Option<&str>, use_context, groups, decide) -> Result<()>` | Registers different input types for the same purpose; exact types take precedence over a wildcard registration. |
| `receive(source: &impl Publication, purpose: &str) -> Result<DataObject>` | Verifies and admits an object using that configured purpose before opening business data. |
| `receive_selected(source, purpose, selection: Option<&DatasetSelection>) -> Result<DataObject>` | Checks the selected edition through the native strict admission path. |
| `configure_release(use_context, destination: &str, object_type: &str, decide) -> Result<()>` | Registers the output type, destination and release evaluator for a purpose. |
| `release(data: &mut DataObject, purpose: &str) -> Result<GovernedObject>` | Evaluates current data and creates its signed output. |
| `release_checked(data, purpose, check) -> Result<GovernedObject>` | Requires both configured approval and a request-specific decision. |
| `configure_attach(decide) -> Result<()>` | Registers the authority evaluator for additional policies. |
| `attach(data: &mut DataObject, policy: Governance) -> Result<()>` | Adds a policy under the configured authority check. |
| `release_plan(purpose: &str) -> Result<Arc<ReleasePlan>>` | Gives integration code the immutable output settings and conjunctive `authorize` decision. |
| `objects() -> &Objects` | Exposes explicit group, dataset and release operations. |
| `primary_group(purpose: &str, object_type: &str) -> Result<String>` | Returns the first business group configured for that input type and purpose. |
| `Publication::publication() -> Result<&GovernedObject>` | Gets the signed publication from a `GovernedObject` or unchanged `DataObject`. |

## Python interface

| Function | Capability |
| --- | --- |
| `tn.Session(policy, *, groups=None, policy_id="agents.md")` | Creates an independent native session. |
| `tn.Session.from_config(path)` | Loads existing material. |
| `session.create_obj(fields, policy, *, object_type=None, group="default")` | Calls native creation; the policy loader's selection supplies the type when omitted. |
| `session.create_obj_with_groups(groups, policy, *, object_type=None, primary_group="default")` | Creates all initial groups in one publication, with the same type inference. |
| `session.configure_receive(*, use, decide, groups=None, object_type=None)` | Registers the complete use and evaluator for an input type. Groups default to `default`. |
| `session.receive(source, *, purpose, selection=None)` | Calls native configured admission; accepts working objects, sealed objects, strings or bytes. |
| `session.configure_release(*, use, to, object_type, decide)` | Registers the output purpose's evaluator, type and destination. |
| `data.release(*, purpose, decide=None)` | Evaluates the configured decision and any additional request check, then signs. |
| `session.release(data, *, purpose, decide=None)` | Uses this publishing session's configuration and keys for the same operation. |
| `session.configure_attach(*, decide)` | Registers the session's attachment authority check once. |
| `data.attach(policy)` | Adds a policy using its session's authority check. |

The existing explicit `receive(..., use=..., groups=..., selection=..., decide=...)` form remains available for integrations. Explicit use or group overrides require an explicit evaluator. Configured receipt accepts an exact dataset selection without replacing the registered checks. Duplicate purpose/type pairs are rejected. A missing route is refused. Evaluators must return a boolean; errors stop opening. Python configured evaluator errors are surfaced as `ValueError` with their original error description.

A configured release takes its type and destination from session setup. An optional request-specific `decide` is an additional check; it cannot turn a configured refusal into approval. Explicit release with `to`, type and evaluator remains available for integrations. Callback evaluation holds no mutable-object lock. If either evaluator changes the working object, release requires a fresh decision on that changed state. A refused release preserves the earlier publication and pending edits.

The selected policy type is local construction metadata retained by `Governance::from_template`, Markdown selection and policy DAG selection. It is excluded from the contract's wire fields and equality. A decoded contract without this selection requires an explicit output type unless it matches a local template.

## Adapter and application responsibilities

A valuation adapter can receive two input types under the same purpose. Session setup maps `market.observation` to the prices group and its source checks, and `client.position` to holdings and its checks. The adapter calls `receive` with the same purpose for both. It performs the calculation, includes the second input, attaches the configured supervision requirement and releases for inference.

Calculation correctness, grant eligibility and exact source selection are application decisions. The configured release evaluator checks persistent rules; a request check compares the particular result with its calculation and selected sources. Both must accept. Configure these callbacks when constructing the adapter.

`data.sources` identifies inputs for its next release. After release it refers to the just-published version. To inspect the inputs carried by a particular publication, verify/open its governance and read `governance.sources`. This distinction preserves each version's exact ancestry.

A working object's unpublished changes must be released before receipt. This keeps the returned data tied to a signed publication. Passing its explicit older snapshot selects that publication deliberately. Creation and release continue to use the optional native administrative registers.

The in-memory hello example uses one session for service and caller. Separately deployed services load their respective configured identities and group grants and register their application admission evaluators during startup.

## Executable examples

Python: `python/examples/governed_hello.py`.

Rust: `cargo run -p tn-core --example governed_hello`.

Version history: this API was available in development version `2026.9.10b2.dev2`; `2026.9.10b1` predates it.
