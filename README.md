# TN-Proto

TN-Proto is a Python SDK for sharing encrypted data between applications. You put data fields into a TN object, encrypt and sign it, then save it to a file or send it to another application.

Fields are organized into named groups. Each group can have different readers: a reader needs the matching key to open that group's fields. This makes key possession the basis of access to the encrypted data.

The SDK keeps an application's identity and keys in a `Session`. If `session` already holds the required keys and `sealed` is an encrypted TN object, this call opens it:

<!-- tn-example: key-access -->
```python
data = session.unseal(
    sealed, purpose="read", decide=lambda _: True
)
```

`unseal` verifies the object's signature and decrypts its data. `decide` lets the application add an access check; returning `True` adds no further restriction. `purpose="read"` names the operation. The walkthrough below creates the session and object needed for this call.

[Why TN exists](#why-tn-exists) · [Install](#install) · [First object](#your-first-object) · [Bank and vendor](#from-a-greeting-to-a-bank-report) · [Application rules](#optional-application-rules) · [Python API](#python-api) · [Keys and providers](#keys-and-providers) · [Application examples](python/examples/enterprise/README.md)

## Why TN exists

A bank asks a vendor to total transaction amounts. The records also contain customer names, which the vendor does not need. The bank puts amounts and names in separate groups and gives the vendor the key for the amounts. The vendor can then calculate the total while the names remain encrypted.

When the vendor returns the total, the bank needs to know which records contributed to it. A TN result can retain references to those input objects. Signing the result lets the bank verify which identity published it and whether its signed content has changed.

The bank may also supply terms describing how the data can be used. TN carries this text as a use contract alongside the data. The result can keep the input contracts so the application receiving it can decide whether its intended use is allowed.

The examples start with a greeting, then build this bank/vendor exchange using the same object operations.

For applications with existing identity, key, or policy services, see the [management systems guide](docs/MANAGEMENT_SYSTEMS.md). The [Unity Catalog guide](docs/UNITY_CATALOG.md) shows how to locate and open a stored TN object.

## Install

```bash
python -m pip install "tn-proto==2026.9.13b5"
```

Python 3.10 or newer. Linux x86-64 and Windows x64 wheels include the native implementation. Install the wheel with pip; use the [Rust SDK](rust-sdk/README.md) for Rust applications.

## Your first object

### 1. Start a session

Save the sample [agents.md](python/examples/getting_started/agents.md) in your working folder. Its `## hello.message` section contains the greeting's use contract. The session loads this file, and `session.policy("hello.message")` selects that contract for the object you will create.

Run the following Python snippets in order, in the same process:

<!-- tn-example: greeting -->
```python
from pathlib import Path
import tn

session = tn.Session(Path("agents.md").read_text(encoding="utf-8"))
policy = session.policy("hello.message")
```

This session creates a fresh signing identity and keys for the data and its contract metadata. The example uses this session for the whole walkthrough.

### 2. Create an object and read a field

<!-- tn-example: greeting -->
```python
message = session.create({"message": "Hello, world!"}, policy)
print(message.get("message"))
```

```text
Hello, world!
```

`create` returns an editable data object and also makes an encrypted, signed copy called a publication. `get` reads the message from the editable object.

### 3. Change the field

<!-- tn-example: greeting -->
```python
message.set("message", "Hello again!")
print(message.get("message"))
```

```text
Hello again!
```

`set` changes the editable object. Its existing publication still contains `Hello, world!`.

### 4. Seal the changed object

Call `seal` to encrypt and sign a new publication containing the changed message:

<!-- tn-example: greeting -->
```python
publication = message.seal(
    purpose="send", to="local-reader", decide=lambda _: True
)
```

The new publication keeps the contract and a reference to the preceding version. `to` names its intended destination. In this example, the same session acts as the local reader, and the next step saves the publication to a file.

### 5. Save and read the publication

<!-- tn-example: greeting -->
```python
publication.write("greeting.tn")
saved = tn.GovernedObject.read("greeting.tn")
```

`write` saves the exact signed bytes. `read` verifies the saved publication; the message remains encrypted.

### 6. Unseal with the keys

This session can decrypt the saved message because it holds the matching keys:

<!-- tn-example: greeting -->
```python
received = session.unseal(
    saved, purpose="read", decide=lambda _: True
)
print(received.get("message"))
```

```text
Hello again!
```

`received` is a new editable data object containing the decrypted message.

Close the session when finished:

<!-- tn-example: greeting -->
```python
session.close()
```

The complete walkthrough is available as [hello.py](python/examples/getting_started/hello.py), alongside its `agents.md` file.

## From a greeting to a bank report

The [bank/vendor program](python/examples/bank_vendor.py) implements the exchange described above. Its setup gives the bank and vendor separate signing identities, then assigns the groups each can read and publish. The use contract is stored in an encrypted governance group that both applications can read:

| Application | Can open | Can publish |
| --- | --- | --- |
| Bank | `amounts`, `identity`, and governance | Both business groups and governance |
| Vendor | `amounts` and governance | `amounts` and governance |

The bank publishes two batches. One contains amounts 12 and 18; the other contains 5. Customer names are in the separate `identity` group. The vendor receives the same signed publications but has no key for that group.

The following code runs from the repository root after installing the SDK. `configured` supplies the identities, group assignments, and application decisions described in the example's setup. `publish_inputs` creates the two bank publications. The vendor totals both inputs and publishes only the aggregate:

<!-- tn-example: bank-vendor -->
```python
from python.examples.bank_vendor import configured, publish_inputs

with configured() as parties:
    first_input, second_input = publish_inputs(parties)
    first = parties.vendor.unseal(first_input, purpose="aggregate")
    second = parties.vendor.unseal(second_input, purpose="aggregate")

    total = sum(first.get("values")) + sum(second.get("values"))
    first.include(second)
    first.set("aggregate", total)
    first.select(["amounts"], fields={"amounts": ["aggregate"]})
    first.attach(parties.report_contract)
    result = first.seal(purpose="report")

    report = parties.bank.unseal(result, purpose="inspect-report")
    print(report.get("aggregate"))
    print(len(report.policies))
    print(len(report.governance.sources))
```

```text
35
2
2
```

Python computes the total. `include` records the second input and its contract. `select` keeps only the aggregate and removes the original values and unopened identity ciphertext from the output. `attach` adds the vendor's reporting contract while retaining the bank's contract. The bank receives a result with two contracts and references to both source publications.

Run `python python/examples/bank_vendor.py` for the complete demonstration, including refused identity access and a refused marketing use. Its [tests](python/tests/test_bank_vendor_example.py) check the result, group boundary, contracts, and sources.

## Optional application rules

The bank/vendor setup checks who signed the object and its requested use as well as the keys. For these checks, the SDK supplies the signer's verified identity (`context.writer`), the object's contracts, the requested use, and the selected groups before decrypting their data. The receiving application decides whether to allow the operation.

Key possession can be the application's entire access rule, as in the greeting. An application can also require a specific writer or an accepted contract. This separate example uses the same `agents.md` file:

<!-- tn-example: optional-rule -->
```python
from pathlib import Path
import tn

with tn.Session(Path("agents.md").read_text(encoding="utf-8")) as session:
    policy = session.policy("hello.message")
    publication = session.create({"message": "Hello, world!"}, policy).snapshot

    def accepted(context):
        return (
            context.writer == session.did
            and len(context.policies) == 1
            and context.policies[0].matches_contract(policy)
        )

    data = session.unseal(publication, purpose="read", decide=accepted)
    print(data.get("message"))
```

The decision returns a boolean. False refuses the operation; errors also stop it. The contract check compares the exact contract, including its authority.

For repeated work, configure decisions with `session.configure_receive`, `configure_attach`, and `configure_release`, then bind them with `session.workflow(receive=..., release=...)`. A workflow runs its configured decisions on every operation. The [configuration guide](docs/GOVERNED_PYTHON_API.md#configure-input-output-and-attachment) shows the arguments and routing behavior.

| Decision | Context available to the application |
| --- | --- |
| Receive | Verified writer, contracts, source references, requested use, and selected groups; no business plaintext |
| Attach | Requesting authority, proposed contract, existing contracts, and working data |
| Release | Publishing writer, current result, contracts, sources, purpose, optional complete `UseContext`, and destination |

The contract text is input to the application's decision. The SDK calls the decision function at the receive, attach, or release step; the application supplies the interpretation of the contract and the decision itself.

## Python API

### Objects and sessions

| Type | Role |
| --- | --- |
| `Session` | Owns an identity, group capabilities, policy selection, and operation configuration |
| `DataObject` | Holds working data, inherited contracts, source references, and its last signed snapshot |
| `GovernedObject` | Holds a signed publication for verification, storage, or transport |
| `Governance` | Describes a contract, its authority, references, and dataset bindings |
| `UseContext(application, purpose, operation)` | Identifies the requested use |
| `Workflow` | Binds configured input and output purposes for repeated operations |
| `GovernanceView`, `AdmittedObject`, `OpenedObject` | Expose the separate governance, acceptance, and opening stages |

The full set of types is in `tn.governed`; common types such as `Session` and `DataObject` are also exported from `tn`. Provider interfaces are in `tn.providers`. `Session(policy_text, groups=...)` creates fresh local material. `Session.from_config(path)` loads an existing configuration. A context manager or `close()` ends the session independently of other sessions.

| Setup call | Configures |
| --- | --- |
| `session.policy(name)` | Selects the contract for a new object |
| `session.configure_receive(use=..., groups=..., object_type=..., decide=...)` | Input type, groups, complete use, and decision |
| `session.configure_attach(decide=...)` | Authority to add a contract |
| `session.configure_release(use=..., to=..., object_type=..., decide=...)` | Output type, destination, complete use, and decision |
| `session.workflow(receive=..., release=...)` | A workflow bound to the named input and output purposes |

`UseContext` carries the application, purpose, and operation. The `to` destination is decision context; callers choose the transport. A workflow captures its configuration when bound, and its evaluators run on subsequent operations.

### Object operations

In this table, `session` owns the work, `data` is a `DataObject`, `publication` is a `GovernedObject`, and `work` is a configured `Workflow`. Calls show the usual arguments; linked references give full signatures and defaults.

| Operation | Python call | Result or effect |
| --- | --- | --- |
| Create | `session.create(fields, policy, group="default")` | Working data with an initial signed publication |
| Unseal / receive | `session.unseal(source, purpose=..., decide=..., groups=...)` or `work.unseal(source)` | Verify, decide the use, and open selected business groups; `receive` is the corresponding name |
| Inspect | `data.inspect()` / `publication.inspect()` | Detached working state / authenticated envelope metadata and encrypted blocks |
| Get | `data.get(name, group=...)` | Read a field; omit `name` to read its opened group |
| Set | `data.set(name, value, group=...)` | Change a field; `name=None` replaces a group's business fields |
| Select | `data.select(groups, fields=...)` | Retain named groups and optional fields in the result |
| Include | `data.include(other)` | Retain a contributor's source references and contracts without merging values |
| Attach | `data.attach(policy, decide=...)` / `work.attach(data, policy)` | Add a contract through an explicit or configured attachment decision while retaining existing contracts |
| Seal / release | `data.seal(purpose=..., to=..., decide=...)` or `work.seal(data)` | Check publication, encrypt, and sign a new version; `release` is the corresponding name |
| Read | `tn.GovernedObject.read(path_or_stream)` | Load and verify a signed publication |
| Write | `publication.write(path_or_stream)` | Save its exact signed bytes |
| Forward | `publication.forward()` | Return signed bytes for the application's transport |
| Verify | `session.verify(wire)` | Authenticate and validate a governed publication |
| Accept | `session.governance(publication).accept(use=..., groups=..., decide=...)` | Bind the accepted object, reader, use, and selected groups |
| Open | `session.open(admitted, groups)` | Open the admitted groups with the reader's capabilities |

When `group` is omitted, `get` and `set` use the working object's primary group. `data.snapshot` is its last signed publication. `history`, `revision`, and `has_unreleased_changes` describe its local progress; `data.copy()` creates a separate working copy. Pending edits must be released before a working object can write or forward its snapshot. Use `select` explicitly to remove unopened ciphertext from a result when it should not travel onward.

`Session.seal(draft)` originates a `GovernedDraft`, built with `session.draft(...)` and `draft.group(...)`. Use `DataObject.seal` or `Workflow.seal` to publish working data. Module-level `tn.seal` and `tn.unseal` belong to the separate portable-envelope API; the governed lifecycle described here uses session and workflow methods.

The [complete Python API guide](docs/GOVERNED_PYTHON_API.md) documents signatures, defaults, callbacks, group selection, publication history, and transport. The [object-operation reference](docs/TN_VERBS_API.md) maps the verbs to their native operations. [Type signatures](python/tn/governed/__init__.pyi) describe the exposed Python types.

### Policy revisions, datasets, and lineage

If an application tracks dataset editions or changes to use contracts, these APIs identify the exact versions used by a result:

| API | Use |
| --- | --- |
| `PolicyRevisionDraft`, `PolicyRevision`, `PolicyDag` | Publish, admit, and select exact contract revisions with explicit parent and authority decisions |
| `DatasetEditionDraft`, `DatasetEdition`, `DatasetCatalog` | Bind an accepted dataset edition to its exact source publication, contracts, and eligible use |
| `DatasetSelection` | Carry a catalog-approved selection into `unseal(..., selection=...)` |
| `LineageVerifier` | Verify retained source publications through an application-supplied resolver |
| `ObjectRegisters` | Configure optional signed creation and release metadata records |

The [catalog example](python/examples/providers/catalog.py) creates a contract revision and dataset edition, then selects the corresponding source object. The [dataset and lineage guide](docs/GOVERNED_PYTHON_API.md#policy-revisions-dataset-editions-and-lineage) covers selection and following a result's references back to its inputs.

Common failures are `VerificationError` for invalid publications, `NotEntitled` for missing group capabilities, `UseDenied` for a refused decision, and `NotAPublisher` for missing publication capabilities. The [error reference](docs/GOVERNED_PYTHON_API.md#errors-and-integration-checks) covers callback failures, closed sessions, and register errors as well.

## Keys and providers

A fresh session is convenient for a first run. Deployed applications can load identities and keys from persistent storage and assign them to their readers. `FileKeyStore.create(...)` provisions a local store once; `FileKeyStore.open(path)` reopens it. It implements both identity and key resolution. Store its files in private application storage.

The [persistent-key examples](python/examples/persistent_keys/README.md) run setup, publication, and reading in separate processes. They cover three encryption options: BTN for shared reader groups, JWE for specified recipients, and HIBE for keys assigned within a hierarchy. The [capability constructors](docs/GOVERNED_PYTHON_API.md#cipher-capabilities) accept existing key material for these options.

Applications can connect their own infrastructure through five provider contracts:

| Interface | Method and responsibility |
| --- | --- |
| `IdentityProvider` | `resolve(application)` supplies the application's native signing identity |
| `KeyProvider` | `resolve(identity)` supplies assigned group capabilities as a `KeySet` |
| `GovernanceProvider` | `policy` and `workflow` supply configuration; `accept`, `attach`, and `release` decide operations |
| `CatalogProvider` | `resolve(request)` supplies an accepted edition selection and its exact publication |
| `RegisterProvider` | `record(event)` retains an already signed publication and event metadata |

`Providers(identity, keys, governance, catalog=..., registers=...)` composes these interfaces. Its `session(application, workflows=...)` method creates a session with the assigned capabilities. The [provider guide](docs/GOVERNED_PROVIDERS.md), [type signatures](python/tn/providers/__init__.pyi), and [executable setup examples](python/examples/providers/README.md) cover each contract.

Key resolution happens at session setup; the session retains those capabilities for its operations. Applications choose how to obtain that material. An adapter can also consult a live authorization service whenever a configured receive, attach, or release decision runs. The [management systems guide](docs/MANAGEMENT_SYSTEMS.md) shows the supported integration points.

## Application examples

The repository contains [15 application examples](python/examples/enterprise/README.md) covering common service and storage patterns. Each uses the object API to handle a specific task:

| Application need | Patterns and worked behavior |
| --- | --- |
| Return the same accepted result after a retry | Request/reply, outbox/inbox, and durable workflow retain exact results and recovery state |
| Give each reader an appropriate view | Gateway and tenant repository select data and check account boundaries |
| Combine the right inputs | Aggregation and pipeline check contributors, representations, and completeness |
| Reuse historical data for a current request | Cache, CQRS, and data product retain source identities and evaluate the selected use |
| Coordinate publication and change | Monolith, publish/subscribe, saga, archive, and migration separate decisions from transaction and delivery state |

The examples use SQLite for their application records. They show where to commit business state, how to handle duplicates, and what to retain for recovery. TN operations supply signed objects within those transactions; application code owns the transaction and transport behavior.

## Testing

The release checks execute every Python block in this README, the standalone greeting, and the governed API, provider, persistent-key, bank/vendor, and enterprise tests against installed wheels. The [release workflow](.github/workflows/release-python.yml) builds and verifies Linux and Windows wheels before publication.

From a checkout of this release, install the test dependencies and run the example checks. The Rust command also requires a Rust toolchain:

```bash
python -m pip install "tn-proto[test]==2026.9.13b5"
python python/examples/bank_vendor.py
python -m pytest python/tests/test_bank_vendor_example.py python/examples/enterprise -q
cargo test --locked -p tn-btn
```

## Source, support, and license

The Python SDK calls the Rust implementation in [crypto/tn-core](crypto/tn-core) through the [PyO3 bindings](crypto/tn-core-py). The Python package is in [python](python). Use [GitHub issues](https://github.com/cyaxios/tn-proto/issues) for reproducible bugs and documentation corrections, including the package version and a minimal example with private data removed.

Dual-licensed under the MIT License or the Apache License, Version 2.0.
