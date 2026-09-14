# Providers configure governed TN workflows

For a walkthrough, start with [management systems](MANAGEMENT_SYSTEMS.md) or [Unity Catalog](UNITY_CATALOG.md).

Providers supply the signing identity, group capabilities, contracts, decisions, and catalog entries used by a TN session. Rust validates provider results and executes the object operations. Python providers return native typed values through PyO3.

An application creates a session from its configured providers, then uses the same fifteen verbs. Identity generation, key assignment and policy administration belong in setup. They are separate from the calculation that consumes and releases data.

From `python/examples/providers`, run this calculation with the supplied setup:

```python
from hello import configured

providers, session, request = configured()
with session:
    source = session.create({"value": 7}, providers.policy(request))
    work = session.workflow(receive="analysis", release="report")
    data = work.unseal(source)
    data.set("value", data.get("value") + 1)
    result = work.seal(data)
    print(session.unseal(result, purpose="analysis").get("value"))
```

It prints `8`. The complete executable is [hello.py](../python/examples/providers/hello.py). Its setup modules resolve the application's DID and native capabilities. Application names, purpose names and group names describe the requested work; cryptographic identities and policy references come from the providers.

## Five provider contracts

| Provider | Rust signature | Result and responsibility | Included adapter |
| --- | --- | --- | --- |
| Identity | `resolve(&self, application: &str) -> Result<ApplicationIdentity>` | Application name and native signing identity. The bundle rejects an identity for another application. | `LocalIdentity` generates a fresh identity. Rust also accepts an existing `DeviceKey`. |
| Keys | `resolve(&self, identity: &ApplicationIdentity) -> Result<KeySet>` | Assigned encrypted-group capabilities. The bundle checks their owner against the resolved identity. | `LocalKeys` generates BTN groups and explicitly assigns read and publish capabilities. |
| Governance | `policy(&self, request: &PolicyRequest) -> Result<Governance>` | Default contract for the requested object type and complete use. | `PolicyDirectory` resolves explicitly configured contracts. |
| Governance | `workflow(&self, request: &WorkflowRequest) -> Result<WorkflowPolicy>` | Input routes, output type and destination. | `PolicyDirectory` resolves registered workflow settings. |
| Governance | `accept(&self, context: &AdmissionContext) -> Result<bool>` | Accept the writer, carried contracts and requested use before opening selected business groups. | `PolicyDirectory` checks a trusted writer and every exact contract against the complete use. |
| Governance | `attach(&self, context: &AttachmentContext) -> Result<bool>` | Authorize an additional contract. | `PolicyDirectory` checks the requesting authority and approved contract. |
| Governance | `release(&self, context: &ReleaseContext) -> Result<bool>` | Approve the current result and carried contracts for publication. | `PolicyDirectory` checks the writer and complete output use against every carried contract. |
| Catalog | `resolve(&self, request: &CatalogRequest) -> Result<CatalogEntry>` | Accepted edition selection plus its exact source publication. Rust checks the dataset, edition, use and source identity. | `EditionCatalog` retains previously admitted native selections. |
| Register | `record(&self, signer: &DeviceKey, event: &RegisterEvent) -> Result<()>` | Record an already signed creation or release. | `FileRegisters` writes the existing signed TN metadata register format. |

Python uses the same method names with exceptions in place of Rust `Result`. Its register callback is `record(event) -> None`; the private signer is not passed to Python. `FileRegisters` executes its signing operation in Rust. A custom Python recorder can retain the supplied signed publication and event metadata.

The Rust files are in `crypto/tn-core/src/providers/`. Corresponding Python `Protocol` files are in `python/tn/providers/`. PyO3 implementations are in `crypto/tn-core-py/src/governed/providers/`. The Python signature reference is `python/tn/providers/__init__.pyi`.

See the [Rust provider implementations](../crypto/tn-core/src/providers/) and [PyO3 bindings](../crypto/tn-core-py/src/governed/providers/) for the native operations behind these interfaces.

## Typed requests carry the application decision

| Type | Fields |
| --- | --- |
| `PolicyRequest` | `object_type`, `use_context` |
| `WorkflowRequest` | `input`, `output`, both `UseContext` values |
| `InputRule` | `groups`, optional signed `object_type` |
| `WorkflowPolicy` | `inputs`, `output_type`, `destination` |
| `CatalogRequest` | `dataset`, `edition`, `use_context` |
| `CatalogEntry` | `publication`, `selection` |
| `RegisterEvent` | `action`, `publication`, `purpose`, `destination`, `policy_refs` |

`UseContext` contains application, purpose and operation. Provider request constructors call native validation. Empty identifiers, empty or duplicate business groups, the reserved governance group in an input route, duplicate routes and workflow uses assigned to different applications are rejected at construction. Provider composition requires both workflow uses to belong to the application's resolved identity. Session routes reject duplicate purpose/type entries; release settings reject duplicate purposes. A session's workflow settings are fixed at construction. Acceptance, attachment and release call the provider again at each boundary, so a service-backed provider can evaluate its current decisions.

## Configure local providers

`LocalIdentity(application)` owns a generated signer. `LocalIdentity.from_private_bytes(application, seed)` loads an existing 32-byte Ed25519 signing seed. `LocalKeys(groups)` creates fresh BTN material. `assign(identity, read=[...], publish=[...])` grants selected capabilities. Governance read is included; governance publication must be assigned explicitly. Publisher capabilities in this local adapter include reading. A session retains its assigned capability snapshot independently of later assignments or another session closing.

`PolicyDirectory.add_policy(request, contract)` sets the origination default and approves the contract for that use. `approve_contract(request, contract)` accepts another exact contract, such as a reviewed policy revision carried by an edition, while preserving that default. Every carried contract must be approved for the requested use. The directory evaluates these explicit assignments. Python governance providers implement the same `accept`, `attach`, and `release` methods for application decisions.

`EditionCatalog.insert(entry)` requires a native accepted `DatasetSelection`. The example in `python/examples/providers/catalog.py` creates and admits a signed policy revision and edition record before inserting the selection. A catalog result is received with its selection:

```python
entry = providers.resolve(catalog_request)
data = work.receive(entry.publication, selection=entry.selection)
```

`FileRegisters(ObjectRegisters(...))` chooses separate creation and release files. A custom register receives a detached event after signing. If recording fails, the signed publication remains available and the working object's `register_error` records the failure. The register is an optional administrative record, not the application's business transaction. During publication, callbacks should use `event.publication`; reentrant access to the same working object reports that it is busy rather than waiting on itself.

Leaving `registers` absent uses the existing environment-configured registers. An explicit file-register adapter takes precedence. An empty `ObjectRegisters()` explicitly selects no files.

## Load provisioned identities and keys

An identity provider returns an `ApplicationIdentity`; a key provider returns `KeySet(identity, capabilities)`. The following constructors load provisioned material into the native TN process, where signing, encryption, and decryption run:

| Constructor | Supplied material |
| --- | --- |
| `LocalIdentity.from_private_bytes(application, seed)` | A 32-byte Ed25519 seed. |
| `GroupCapability.btn_reader(group, kits, index)` | Serialized BTN reader kits and a 32-byte group index key. |
| `GroupCapability.btn_publisher(group, state, kits, index)` | Serialized BTN publisher state, reader kits, and index key. |
| `GroupCapability.jwe(group, recipients, readers, index)` | X25519 public recipient keys, private reader keys, and index key. |
| `GroupCapability.hibe(group, public, path, readers, index)` | HIBE public parameters, target path, scoped reader keys, and index key. |

The constructors parse and validate the supplied material in Rust. Retained BTN reader kits can cover historical generations. [`test_existing_identity_and_btn_material_can_be_loaded`](../python/tests/test_governed_providers.py) demonstrates an imported identity and capabilities used by a Python provider in a complete calculation.

Governance providers return native contracts and workflow settings, then explicit Boolean decisions. Catalog providers return accepted native selections with exact publications. Invalid return types and provider exceptions stop the requested operation. Register errors follow the separate recording behavior described above. The [Unity examples](UNITY_CATALOG.md) supply an HTTP volume lookup and verify stored publications before using these native catalog types.

## Executable examples

| File | Demonstrates |
| --- | --- |
| `python/examples/providers/identity.py` | Resolve the configured application's generated identity. |
| `python/examples/providers/keys.py` | Assign named read and publication capabilities to that identity. |
| `python/examples/providers/governance.py` | Register contracts, complete uses and workflow settings. |
| `python/examples/providers/catalog.py` | Admit and resolve a signed edition with exact source identity. |
| `python/examples/providers/register.py` | Signed file registers and a custom Python event collector. |
| `python/examples/providers/hello.py` | Compose providers and execute the governed calculation. |
| `crypto/tn-core/examples/governed_providers.rs` | Execute the same create, receive, change and release flow in Rust. |

Run the Python examples against the built wheel. Run the native example with `cargo run -p tn-core --example governed_providers --locked`. Provider tests also exercise wrong identity and key ownership, missing assignments, read-only capabilities, live refusal, invalid callback results, exact edition matching and register failure.


## Persistent local provider and explicit cipher capabilities

`FileKeyStore.create(path, application, groups, cipher="btn")` generates and atomically saves one application's publisher and reader enrollment. Choose `cipher="jwe"` to use native General JSON JWE instead. Creation never overwrites an existing file. `FileKeyStore.open(path)` reuses the saved identity and capabilities; missing or invalid stores fail without creating replacements.

Pass the store to both provider slots: `Providers(store, store, governance, registers=registers)`. `store.resolve(application)` returns its identity; `store.resolve(identity)` returns the saved key set. `application`, `cipher`, `path` and `groups` expose metadata without exposing credentials. Rust uses the separate `IdentityProvider` and `KeyProvider` trait methods on the same store.

Each store holds one application's signing seed, group index keys, and cipher capabilities. Place it in private application storage: Unix creation uses mode `0600`, and Windows uses the containing directory's ACL. Distribute encrypted publications separately. Use `KeySet` and the capability constructors above to assign provisioned material to other applications.

`GroupCapability::jwe` / `GroupCapability.jwe(group, recipients, readers, index)` also accepts externally supplied native X25519 capabilities. Rust performs JWE content encryption and recipient key wrapping. The persistent examples in `python/examples/persistent_keys/` run creation, publication and reading in separate processes. Generated secrets are kept outside source directories.

## HIBE group capabilities

`GroupCapability.hibe(group, public, path, readers, index)` loads serialized HIBE public parameters and reader keys into the Rust HibeCipher. Python exposes the same constructor through PyO3. Empty readers permit public-parameter encryption. Assigned reader keys supply decryption for the target path.

`FileKeyStore.create(..., cipher="hibe")` creates independent depth-one authorities per group and saves public parameters and scoped reader keys. The Rust-backed `tn._hibe.setup`, `keygen`, and `delegate` functions provide hierarchical authority provisioning. [hibe_delegation.py](../python/examples/persistent_keys/hibe_delegation.py) issues a parent grant, delegates a child, and opens a governed object with the child's capability.
