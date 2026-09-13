# TN-Proto

TN-Proto lets applications exchange encrypted data together with authenticated provenance and use contracts. Applications can open selected fields, calculate a result, and publish a new object that retains its contributing sources and contracts. The Python SDK uses the canonical Rust implementation through PyO3.

**Key access is access to encrypted data.** Group keys determine which fields a reader can open. Application rules can add restrictions when needed. With the required keys already loaded in `session` and a publication in `sealed`:

<!-- tn-example: key-access -->
```python
data = session.unseal(
    sealed, purpose="read", decide=lambda _: True
)
```

The callback adds no application permission check. TN still verifies the publication and requires the matching keys. `purpose="read"` labels the operation; it does not grant access. Keys cover groups of fields, so fields that need independent access belong in separate groups.

[Why TN exists](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#why-tn-exists) · [Install](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#install) · [First object](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#your-first-object) · [Bank and vendor](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#from-a-greeting-to-a-bank-report) · [Application rules](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#optional-application-rules) · [Python API](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#python-api) · [Keys and providers](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#keys-providers-and-revocation) · [Book examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#enterprise-patterns-from-the-book) · [Evidence](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/README.md#evidence-and-paper-reproducibility)

## Why TN exists

A bank asks a vendor to total transaction amounts. The vendor needs the amounts, while customer identities must stay private. The bank also needs to recognize the returned report, identify its inputs, and keep the conditions under which those inputs were supplied.

That problem continues after the first handoff. Another service may combine the report with licensed data, a cache may serve it later, and an archive may need the exact version used in an earlier decision. Encryption, source identity, and use context need to survive those steps together.

TN puts encrypted field groups and authenticated governance in a signed object that an application can store or send through its existing transport. Different readers can open different groups of the same object. When an application produces a result, it can retain references to the contributing publications and their contracts as part of that new signed publication.

This is useful for selective data sharing, licensed-data processing, derived reports, and work that must remain explainable across services. The application supplies the calculation, chooses its recipients, and owns its database transactions and delivery. TN supplies the object operations used inside that work.

## Install

```bash
python -m pip install "tn-proto==2026.9.13b5"
```

Python 3.10 or newer. Linux x86-64 and Windows x64 wheels include Rust and require no Rust toolchain to install. This is a beta of the Python SDK; see the [release notes](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/CHANGELOG.md) for changes. Other language packages have separate interfaces and release schedules.

## Your first object

### 1. Start a session

For a complete example, save the sample [agents.md](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/getting_started/agents.md) in your working folder. It supplies the contract metadata used when creating the greeting object. This walkthrough carries that metadata without evaluating additional contract rules.

Run the following Python snippets in order, in the same process:

<!-- tn-example: greeting -->
```python
from pathlib import Path
import tn

session = tn.Session(Path("agents.md").read_text(encoding="utf-8"))
policy = session.policy("hello.message")
```

The session has its own identity and encryption keys. This example creates fresh keys and uses them for the whole walkthrough.

### 2. Create an object and read a field

<!-- tn-example: greeting -->
```python
message = session.create({"message": "Hello, world!"}, policy)
print(message.get("message"))
```

```text
Hello, world!
```

`create` returns a data object with an initial signed copy. `get` reads a field.

### 3. Change the field

<!-- tn-example: greeting -->
```python
message.set("message", "Hello again!")
print(message.get("message"))
```

```text
Hello again!
```

The working data has changed. The previous signed copy still contains the original greeting.

### 4. Seal the changed object

The creating session has the publishing capabilities needed to seal its changes:

<!-- tn-example: greeting -->
```python
publication = message.seal(
    purpose="send", to="local-reader", decide=lambda _: True
)
```

`seal` creates a new encrypted, signed publication, keeping the contract and the reference to the preceding version. Here, the callback adds no application restriction. `to` records an intended destination; it does not distribute keys or deliver the bytes.

### 5. Save and read the publication

<!-- tn-example: greeting -->
```python
publication.write("greeting.tn")
saved = tn.GovernedObject.read("greeting.tn")
```

`write` saves the signed bytes. `read` verifies the saved publication; its business fields remain encrypted.

### 6. Unseal with the keys

The same session already holds the keys for its saved publication:

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

`unseal` verifies the publication and decrypts the message. A session without the required keys cannot open it, even with `decide=lambda _: True`.

Close the session when finished:

<!-- tn-example: greeting -->
```python
session.close()
```

The complete walkthrough is available as [hello.py](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/getting_started/hello.py), alongside its policy file.

## From a greeting to a bank report

The [bank/vendor program](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/bank_vendor.py) extends these operations to two applications. Its setup creates separate signing identities and assigns their group capabilities explicitly:

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

Python computes the total. `include` records the second input and its contract; it does not merge business values. `select` keeps only the aggregate and removes the original values and unopened identity ciphertext from the output. `attach` adds the vendor's reporting contract while retaining the bank's contract. The bank receives a result with two contracts and references to both source publications.

Run `python python/examples/bank_vendor.py` for the complete demonstration, including refused identity access and a refused marketing use. Its [tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tests/test_bank_vendor_example.py) check the result, group boundary, contracts, and sources.

## Optional application rules

TN's governed SDK enforces when a governance decision happens and what contract context is supplied. On receipt, it presents the authenticated writer, carried contracts, requested use, and selected groups before opening business data. The receiving application decides whether that use is allowed.

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

The decision returns a boolean. False refuses the operation; errors also stop it. The contract check compares the exact contract, including its authority. Comparing only a policy name would not establish that match.

For repeated work, configure decisions with `session.configure_receive`, `configure_attach`, and `configure_release`, then bind them with `session.workflow(receive=..., release=...)`. A workflow runs its configured decisions on every operation. The [configuration guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md#configure-input-output-and-attachment) shows the arguments and routing behavior.

| Decision | Context available to the application |
| --- | --- |
| Receive | Verified writer, contracts, source references, requested use, and selected groups; no business plaintext |
| Attach | Requesting authority, proposed contract, existing contracts, and working data |
| Release | Publishing writer, current result, contracts, sources, purpose, optional complete `UseContext`, and destination |

The wire format carries contracts and provenance. Applications interpret those contracts and decide permitted use; TN does not execute policy prose. Applications also control what they do with plaintext after opening it. A signature authenticates a publication and its declared sources. Checking the calculation requires application evidence beyond that signature.

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

The [complete Python API guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md) documents signatures, defaults, callbacks, group selection, publication history, and transport. The [object-operation reference](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/TN_VERBS_API.md) maps the verbs to their native operations. [Type signatures](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tn/governed/__init__.pyi) describe the exposed Python types.

### Policy revisions, datasets, and lineage

| API | Use |
| --- | --- |
| `PolicyRevisionDraft`, `PolicyRevision`, `PolicyDag` | Publish, admit, and select exact contract revisions with explicit parent and authority decisions |
| `DatasetEditionDraft`, `DatasetEdition`, `DatasetCatalog` | Bind an accepted dataset edition to its exact source publication, contracts, and eligible use |
| `DatasetSelection` | Carry a catalog-approved selection into `unseal(..., selection=...)` |
| `LineageVerifier` | Verify retained source publications through an application-supplied resolver |
| `ObjectRegisters` | Configure optional signed creation and release metadata records |

Edition names and source references need accepted records behind them. The [catalog example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/providers/catalog.py) constructs those records; the [dataset and lineage guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md#policy-revisions-dataset-editions-and-lineage) explains how receipt binds them to the requested source and use.

Common failures are `VerificationError` for invalid publications, `NotEntitled` for missing group capabilities, `UseDenied` for a refused decision, and `NotAPublisher` for missing publication capabilities. The [error reference](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md#errors-and-integration-checks) covers callback failures, closed sessions, and register errors as well.

## Keys, providers, and revocation

A fresh session is convenient for a first run. Deployed applications need identities and keys that survive restarts, plus explicit assignments for other readers. `FileKeyStore.create(...)` provisions a local store once; `FileKeyStore.open(path)` reopens it. It implements both identity and key resolution. The store contains unencrypted credentials protected by filesystem access controls. Keep it in private application storage.

The [persistent-key examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/persistent_keys/README.md) run setup, publication, and reading in separate processes. They cover BTN, JWE, and HIBE. BTN uses reader kits and publisher state; JWE uses recipient keys; HIBE uses scoped hierarchical keys. The [capability constructors](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md#cipher-capabilities) accept existing material through the same session interfaces.

Applications can connect their own infrastructure through five provider contracts:

| Interface | Method and responsibility |
| --- | --- |
| `IdentityProvider` | `resolve(application)` supplies the application's native signing identity |
| `KeyProvider` | `resolve(identity)` supplies assigned group capabilities as a `KeySet` |
| `GovernanceProvider` | `policy` and `workflow` supply configuration; `accept`, `attach`, and `release` decide operations |
| `CatalogProvider` | `resolve(request)` supplies an accepted edition selection and its exact publication |
| `RegisterProvider` | `record(event)` retains an already signed publication and event metadata |

`Providers(identity, keys, governance, catalog=..., registers=...)` composes these interfaces. Its `session(application, workflows=...)` method creates a session with the assigned capabilities. The [provider guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PROVIDERS.md), [type signatures](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tn/providers/__init__.pyi), and [executable setup examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/providers/README.md) cover each contract.

Giving a reader the relevant group capabilities gives it decryption authority without requiring an online key-release service for each read. Key stores and live authorization services are also supported through providers. Key resolution happens at session setup; the session retains that capability snapshot. An adapter can consult a live authorization service whenever a configured receive, attach, or release decision runs.

### Preserve evidence when excluding future access

**Revocation must not destroy required evidence.** That requirement motivates BTN's forward-only exclusion. A revoked reader is excluded from future ciphertexts produced with the updated publisher state. Retained keys still open historical publications they covered. An application can therefore retain the publications and capabilities needed to inspect earlier work while changing who receives new data.

The application must retain that evidence and set its retention policy. Revocation cannot recall plaintext or keys already copied by a reader. Current BTN cover compression preserves existing wire formats and reader kits; the [BTN guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/BTN_COVER.md) explains its bounds, byte costs, and compatibility tests.

## Enterprise patterns from the book

The TN Enterprise Patterns book follows portfolio reporting across data suppliers, analytics, model operations, review, and records management. The SDK includes all [15 executable patterns](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/examples/enterprise/README.md). Each combines the object API with a concrete application responsibility:

| Application need | Patterns and worked behavior |
| --- | --- |
| Return the same accepted result after a retry | Request/reply, outbox/inbox, and durable workflow retain exact results and recovery state |
| Give each reader an appropriate view | Gateway and tenant repository select data and check account boundaries |
| Combine the right inputs | Aggregation and pipeline check contributors, representations, and completeness |
| Reuse historical data for a current request | Cache, CQRS, and data product retain source identities and evaluate the selected use |
| Coordinate publication and change | Monolith, publish/subscribe, saga, archive, and migration separate decisions from transaction and delivery state |

The examples use SQLite for their application records. They show where to commit business state, how to handle duplicates, and what to retain for recovery. TN operations supply signed objects within those transactions; application code owns the transaction and transport behavior.

## Evidence and paper reproducibility

The release checks execute every Python block in this README, the standalone greeting, and the governed API, provider, persistent-key, bank/vendor, and enterprise tests against installed wheels. The [release workflow](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/.github/workflows/release-python.yml) builds and verifies Linux and Windows wheels before publication.

| Claim to inspect | Executable evidence |
| --- | --- |
| Invalid signatures and altered signed content are refused before admission | [Python signature tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tests/test_governed_seal_unseal.py) and [native content-integrity tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/crypto/tn-core/tests/governed_objects.rs) |
| A vendor opens amounts while identity data stays unavailable | [Bank/vendor example and assertions](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tests/test_bank_vendor_example.py) |
| A result retains the bank and vendor contracts and both source references | [Bank/vendor result checks](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python/tests/test_bank_vendor_example.py) |
| Refusal and evaluator failure precede business decryption | [Instrumented native receipt tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/crypto/tn-core/tests/governed_use_context.rs) |
| Compressed BTN covers exclude revoked readers and preserve covered historical access | [Real-key compression tests](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/crypto/tn-btn/tests/compressed_cover.rs) |
| Cover geometry and serialized costs match the implementation | [BTN derivation, scoped tests, and encoding arithmetic](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/BTN_COVER.md) |
| Paper test counts and measurements have a defined artifact scope | [Paper reproducibility review](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/PAPER_REPRODUCIBILITY.md) |

From a checkout of this release, install the test dependencies and run the example checks. The Rust command also requires a Rust toolchain:

```bash
python -m pip install "tn-proto[test]==2026.9.13b5"
python python/examples/bank_vendor.py
python -m pytest python/tests/test_bank_vendor_example.py python/examples/enterprise -q
cargo test --locked -p tn-btn
```

The paper's historical experiment pins SDK revision `c83a46a57310fcaccc832e50d6dbd75bd477b5b5`. Its 34 Python cases and ten native tests describe the separate experiment suite. Current SDK release checks have their own scope. The September 13 [paper review](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/PAPER_REPRODUCIBILITY.md) records the inspected artifacts and the changes present in beta 2; this documentation release does not rerun or replace those historical measurements.

For example, the current BTN implementation uses one difference entry for a single revoked leaf in a height-eight tree, reducing overhead from 545 to 132 bytes. The paper's retained tables measured the earlier walker. This comparison measures serialized overhead; it includes no new latency measurements. The separate experiment still needs an identified public, immutable archive; this SDK checkout alone does not reproduce every paper result.

The [Python guide's security boundaries](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/docs/GOVERNED_PYTHON_API.md#the-three-controls) describe visible envelope metadata, equality leakage, and the external information needed to check history completeness. Signatures authenticate declared provenance; applications remain responsible for checking calculations, required inputs, and permitted disclosure.

## Source, support, and license

The implementation is in [crypto/tn-core](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/crypto/tn-core), the PyO3 bindings in [crypto/tn-core-py](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/crypto/tn-core-py), and the Python package in [python](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b5/python). Use [GitHub issues](https://github.com/cyaxios/tn-proto/issues) for reproducible bugs and documentation corrections, including the package version and a minimal example with private data removed.

Dual-licensed under the MIT License or the Apache License, Version 2.0.
