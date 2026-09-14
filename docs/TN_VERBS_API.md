# TN object API

TN's object operations use Rust enforcement through PyO3. Python provides the application methods, including governed `seal` and `unseal`. Application rules belong in configured evaluators. Business calculations belong in application code.

## Ordinary operations

| Verb | Python signature | Native implementation |
| --- | --- | --- |
| create | `session.create(fields, policy, *, object_type=None, group="default") -> DataObject` | `Session::create`; explicit type/group uses `Objects::create_obj` or `create_selected`. |
| unseal | `work.unseal(source, *, selection=None) -> DataObject` | Calls native workflow receipt to verify the publication, accept its complete use and open selected groups. |
| receive | `work.receive(source, *, selection=None) -> DataObject` | `Workflow::receive_selected`; verifies, accepts the full use and opens selected groups. |
| inspect | `data.inspect() -> DataState`; `publication.inspect() -> dict` | `DataObject::inspect` returns detached working state; `GovernedObject::inspect` returns authenticated envelope metadata and encrypted blocks. |
| get | `data.get(name=None, *, group=None) -> JSON` | `DataObject::get(group, field)`; no name returns the complete opened group. |
| set | `data.set(name, value, *, group=None) -> None` | `DataObject::set(group, field, value)`; name `None` replaces the group's business fields. |
| select | `data.select(groups, *, fields=None) -> None` | `DataObject::select(groups, fields)`; retains named groups and optional field projections atomically. |
| include | `data.include(other) -> None` | `DataObject::include`; records contributing sources and contracts without copying their business fields. |
| attach | `work.attach(data, policy) -> None` | `Workflow::attach`; requires configured attachment authority and retains previous contracts. |
| seal | `work.seal(data, *, decide=None) -> GovernedObject` | Calls native workflow release; evaluates output rules, retains contracts and lineage, encrypts and signs the publication. |
| release | `work.release(data, *, decide=None) -> GovernedObject` | Native release plan and `Objects::release_for`; Rust callers use `Workflow::release` or `release_checked`. |

`group=None` uses the working object's primary group. In Rust, the group is explicit. Field projection uses a mapping such as `fields={"result": ["total", "currency"]}`. Fields must exist in retained opened groups. A failed projection leaves the original object unchanged. Governance cannot be edited through business fields or removed by selection.

```python
work = session.workflow(receive="analysis", release="report")
data = work.unseal(publication)
data.set("total", calculated_total)
data.select(["result"], fields={"result": ["total", "currency"]})
result = work.seal(data)
```

The input route in this example selects `result` as the primary group. The application supplies `calculated_total`. `seal` and `release` always run the configured evaluator; an additional `decide` must also accept. Including another input remains an explicit operation because TN cannot infer which plaintext contributed to a calculation.

## Governed seal and unseal

```text
session.unseal(
    sealed, *, decide=None, purpose=None, use=None, groups=None, selection=None
) -> DataObject
work.unseal(source, *, selection=None) -> DataObject
work.seal(data, *, decide=None) -> GovernedObject
data.seal(
    *, to=None, decide=None, purpose=None, use=None, object_type=None
) -> GovernedObject
session.seal(draft: GovernedDraft) -> GovernedObject
```

`session.unseal` accepts a `GovernedObject`, a released `DataObject`, signed wire text, or signed wire bytes. Use `purpose="analysis"` to select configured input rules. For explicit admission, supply `use=UseContext(...)`, `groups=[...]`, and `decide=...`; omitted groups select `default`. Native receipt authenticates the publication and contract, validates any dataset selection against the exact source and use, evaluates admission, and opens only the selected business groups. It returns a mutable native `DataObject`. Denial, invalid signatures, missing keys, and invalid selections prevent receipt. A decision must return a boolean; explicit callback errors propagate to the caller.

`work.unseal` uses the input purpose and group selection bound when the workflow was created. Both unseal methods retain unopened groups as ciphertext. Use `data.select(...)` explicitly when the output should retain only particular groups or fields.

`data.seal(purpose="report")` uses its owning session's configured output rules. For explicit release, supply `use=UseContext(...)`, `to="destination"`, and `decide=...`; `object_type` can select the output type. `work.seal(data)` uses its bound output rules. These operations run native release checks before publishing and retain the contracts, selected dataset bindings, and source lineage. Successful release updates the working object's signed snapshot and history. A failed decision does not replace its snapshot, and mutation during a decision prevents a stale publication from being signed.

`session.seal(draft)` publishes a `GovernedDraft` and keeps its existing signature. To publish a working `DataObject`, use `work.seal(data)`, `data.seal(...)`, or `publisher.release(data, ...)` when a separate session is the publisher. The module-level `tn.seal(...)` and `tn.unseal(...)` retain their existing portable-envelope API.

Sessions created by `Providers.session(...)` support the same operations. Closing a session disables its governed receipt and publication operations.

## Publication transport

| Verb | Python signature | Rust signature |
| --- | --- | --- |
| read | `GovernedObject.read(source) -> GovernedObject` | `GovernedObject::read(source: impl Read) -> Result<Self>` |
| write | `publication.write(destination) -> None`; also available on a released `DataObject` | `write(&self, destination: impl Write) -> Result<()>` |
| forward | `publication.forward() -> bytes`; also available on a released `DataObject` | Publication: `forward(&self) -> &[u8]`; working object: `forward(&self) -> Result<&[u8]>` |

Python sources and destinations can be filesystem paths or binary streams. Reading verifies integrity; it does not accept a requested use or open business data. Writing preserves the exact signed bytes and replaces the contents of a destination file. Forwarding returns those bytes for the application's transport. Neither operation creates a new publication. Working objects with pending edits must be released first; a refused write leaves the destination untouched.

```python
result.write("result.tn")
publication = tn.GovernedObject.read("result.tn")
data = work.unseal(publication)
```

## Explicit admission steps

| Verb | Python signature | Native implementation |
| --- | --- | --- |
| verify | `session.verify(wire) -> GovernedObject` | `Session::verify` calls native publication verification for signatures and group bindings. |
| accept | `view.accept(*, use, groups, decide) -> AdmittedObject` | `GovernanceView::accept` pins the complete use and group selection. |
| open | `session.open(admitted, groups) -> OpenedObject` | `GovernedReader::open` checks the admitted reader/use/group binding before decryption. |

Integrations obtain the authenticated contract view with `session.governance(publication)`. `unseal` and `receive` compose these steps for ordinary application code. Accepted writer identity and permitted use are application decisions; group keys provide decryption capability.

## Generic setup helpers

| Helper | Purpose |
| --- | --- |
| `tn.Session(policy, *, groups=None, policy_id="agents.md", registers=None)` | New independent in-memory identity and group keys. Default business group is `default`; governance is automatic. |
| `tn.Session.from_config(path, *, registers=None)` | Load an existing signing identity, policies and configured group material, including reader grants, through the native configuration loader. |
| `tn.ObjectRegisters(*, creation=None, release=None)` | Configure separate optional signed metadata registers. Empty configuration disables both. |
| `session.policy(name)` | Select the initial contract. |
| `session.configure_receive(use=..., groups=..., object_type=..., decide=...)` | Register input rules. |
| `session.configure_attach(decide=...)` | Register additional-policy authority. |
| `session.configure_release(use=..., to=..., object_type=..., decide=...)` | Register output rules. |
| `session.workflow(receive=..., release=...)` | Bind registered input/output purposes. Evaluators execute on every operation. |
| `session.close()` or a context manager | Close this Python session independently of other sessions. |

```python
registers = tn.ObjectRegisters(
    creation="created.jsonl", release="released.jsonl"
)
session = tn.Session.from_config("service.yaml", registers=registers)
```

When `registers` is omitted, native configuration captures `TN_OBJECT_CREATION_REGISTER` and `TN_OBJECT_RELEASE_REGISTER`. Explicit register settings override those paths. Registers contain signed object metadata. Registration errors are exposed through `data.register_error`; the signed publication remains available.

Rust setup uses `Session::ephemeral(policy)` or `Session::open(path)`. For explicit registers, construct `Session::new(Objects::open(path)?.with_registers(ObjectRegisters::new(creation, release)))`. `Objects::open` loads the existing keys.

## Other object entry points

`create_obj`, `retain_groups`, draft publication, and the explicit admission steps are also available. Mutable mapping views expose the native mutation operations in Python.
