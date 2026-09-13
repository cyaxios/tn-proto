# Rust and PyO3 API implementation map

The governed API has two parts: the fifteen object verbs and the five provider contracts. Rust executes the protocol, capability loading, selection validation and local adapter decisions. Python provider modules contain type protocols and imports. A custom Python provider supplies service decisions through Rust trait bridges.

## Provider methods

Paths in this table are relative to the repository. Native files are under `crypto/tn-core/src/providers/`; binding files are under `crypto/tn-core-py/src/governed/providers/` with the same module names.

| Python class | Methods or properties | Rust implementation | Binding module |
| --- | --- | --- | --- |
| `Providers` | constructor, `session`, `policy`, `resolve` | `Providers` in `mod.rs`; composition calls `runtime::Session` | `mod.rs` |
| `ApplicationIdentity` | `application`, `did` | `ApplicationIdentity` | `identity.rs` |
| `LocalIdentity` | constructor, `from_private_bytes`, `resolve` | `LocalIdentity::generate`, `from_private_bytes`, `IdentityProvider::resolve` | `identity.rs` |
| `GroupCapability` | `btn_reader`, `btn_publisher`, `jwe`, `group` | `GroupCapability`; native BTN decoding and cipher construction | `keys.rs` |
| `KeySet` | constructor, `owner`, `groups` | `KeySet::new`, `owner`, `groups` | `keys.rs` |
| `LocalKeys` | constructor, `assign`, `resolve` | `LocalKeys::generate`, `assign`, `KeyProvider::resolve` | `keys.rs` |
| `PolicyRequest` | constructor, `object_type`, `use_context` | `PolicyRequest::new` and native fields | `governance.rs` |
| `WorkflowRequest` | constructor, `input`, `output` | `WorkflowRequest::new` and native fields | `governance.rs` |
| `InputRule` | constructor, `groups`, `object_type` | `InputRule::new` and native fields | `governance.rs` |
| `WorkflowPolicy` | constructor, `inputs`, `output_type`, `destination` | `WorkflowPolicy::new` and native fields | `governance.rs` |
| `PolicyDirectory` | constructor, `trust`, `add_policy`, `approve_contract`, `add_workflow`, `policy`, `workflow`, `accept`, `attach`, `release` | `PolicyDirectory` and its `GovernanceProvider` implementation | `governance.rs` |
| `CatalogRequest` | constructor, `dataset`, `edition`, `use_context` | `CatalogRequest::new` and native fields | `catalog.rs` |
| `CatalogEntry` | constructor, `publication`, `selection` | Native `CatalogEntry`; native `validate` checks pairing at insert/resolve | `catalog.rs` |
| `EditionCatalog` | constructor, `insert`, `resolve` | `EditionCatalog` and `CatalogProvider::resolve` | `catalog.rs` |
| `RegisterEvent` | `action`, `publication`, `purpose`, `destination`, `policy_refs` | Native event created after signing in `runtime/objects.rs` | `register.rs` |
| `FileKeyStore` | `create`, `open`, `resolve`, `application`, `cipher`, `path`, `groups` | `FileKeyStore` with native identity/key provider traits and atomic file creation | `file.rs` |
| `FileRegisters` | constructor | `FileRegisters::new`; Rust invokes `RegisterProvider::record` | `register.rs` |

`IdentityBridge`, `KeysBridge`, `GovernanceBridge`, `CatalogBridge` and `RegisterBridge` implement the five Rust traits for custom Python objects. Native adapters are passed directly as Rust trait objects. Governance return values must be Boolean; identity, key, contract and catalog returns must be the corresponding native classes.

A Python register callback receives `RegisterEvent`; the signer remains in Rust. Native `FileRegisters` receives that signer internally and writes signed TN register entries. Constructor validation is shared in Rust. Rust callers may also construct public request fields directly, so provider composition and directory registration repeat validation at the boundary.

## The fifteen object verbs

| Verb | Canonical Rust implementation | PyO3 file under `crypto/tn-core-py/src/governed/` |
| --- | --- | --- |
| `create` | `runtime::Session::create`, `Objects::create_selected` / `create_obj` | `session.rs`, `data.rs` |
| `receive` | `runtime::Workflow::receive_selected`, `Session::receive_selected` | `data.rs` |
| `inspect` | `DataObject::inspect`, `GovernedObject::inspect` | `data.rs`, `objects.rs` |
| `get` | `DataObject::get` | `data.rs` |
| `set` | `DataObject::set` | `data.rs` |
| `select` | `DataObject::select` | `data.rs` |
| `include` | `DataObject::include` | `data.rs` |
| `attach` | `runtime::Workflow::attach`, `Session::attach`, `Objects::attach` | `data.rs` |
| `release` | `runtime::Workflow::release_checked`, `Objects::release_for` | `data.rs` |
| `read` | `GovernedObject::read` | `objects.rs` |
| `write` | `GovernedObject::write`; working objects first call native `DataObject::publication` | `objects.rs`, `data.rs` |
| `forward` | `GovernedObject::forward`, `DataObject::forward` | `objects.rs`, `data.rs` |
| `verify` | `runtime::Session::verify` | `session.rs` |
| `accept` | `GovernanceView::accept` | `reader.rs` |
| `open` | `GovernedReader::open` | `session.rs`, `reader.rs` |

Binding code handles Python conversion, binary streams, callback ownership and Python session lifetime. Python-facing convenience defaults choose a primary group before calling the native operation. These do not duplicate cryptography or governance validation.

The Rust SDK exports providers through `tn_proto::providers`, and governed types through `tn_proto::objects`. Owned admission, attachment and release snapshots are exported there as well.

## Executable coverage

`python/tests/test_governed_providers.py` compares every concrete class and method in the shipped provider stub to the compiled PyO3 extension, including parameter names. Behavioral tests exercise native and Python service adapters, imported capabilities, independent sessions, strict decisions, exact catalog identity and register behavior. Constructor tests cover nine invalid configuration cases in the native path.

`crypto/tn-core/tests/governed_providers.rs` exercises the native workflow, additive policy approval and direct Rust request validation. The existing object, edition, complete-use, session and verb suites cover the underlying protocol operations. `docs/GOVERNED_PROVIDERS.md` is the usage reference; `docs/TN_VERBS_API.md` is the object-operation reference.


## Verification snapshot

Validation recorded on 2026-09-10: 41 focused Rust integration tests and 118 installed-wheel Python tests passed. `cargo check -p tn-core-py -p tn-proto --locked` passed without compiler warnings. Native and Python provider examples and the Python edition-catalog example ran successfully. The signature comparison reads the stub shipped inside the installed wheel and checks its compiled extension classes and methods.


Persistent-provider validation on 2026-09-10: 53 Rust integration tests passed, including the explicit Rust-to-joserfc test. The installed-wheel suite passed 123 tests. A separate companion-example suite recorded 45 passes, including executable source excerpts and separate-process BTN/JWE examples. That suite is outside this repository's test count.
