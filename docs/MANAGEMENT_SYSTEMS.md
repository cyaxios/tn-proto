# Connect TN to management systems

TN's provider interfaces load an application's identity, group capabilities, contracts, and workflow settings into a `Session`. Providers also supply the application's decisions when data is accepted, a contract is attached, or a result is published.

The group keys still determine which encrypted fields the session can open. A governance provider adds application decisions about accepting an object, attaching a contract, and publishing a result. These decisions can use the application's current rules.

This guide uses the SDK's local providers, persistent key store, Python callbacks, and Unity Catalog examples. See [keys and providers](../README.md#keys-and-providers) for an overview and the [provider reference](GOVERNED_PROVIDERS.md) for complete interfaces.

## Run the composed example

Install the SDK and run these commands from a checkout of this repository:

```bash
python -m pip install "tn-proto==2026.9.14b1"
python python/examples/providers/hello.py
```

It prints `8`. The example creates an encrypted object containing `7`, opens it, adds one, and seals the result. Its setup is split across these files:

| File | What it supplies |
| --- | --- |
| [identity.py](../python/examples/providers/identity.py) | A signing identity for `analysis-service`. |
| [keys.py](../python/examples/providers/keys.py) | Read and publish capabilities for named groups. |
| [governance.py](../python/examples/providers/governance.py) | The use contract, accepted writer, and receive/release settings. |
| [register.py](../python/examples/providers/register.py) | Optional records of signed creations and releases. |
| [hello.py](../python/examples/providers/hello.py) | Provider composition and the calculation. |

To use that configuration in your own calculation, start Python from `python/examples/providers` and run:

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

This also prints `8`. `configured()` resolves the identity and group capabilities and installs the workflow settings. The calculation uses the same object operations as the [getting started example](../README.md#your-first-object).

## Assign access by group

For a bank/vendor exchange, a local key provider can give the vendor access to amounts while keeping customer identities encrypted:

```python
from tn.providers import LocalIdentity, LocalKeys

bank = LocalIdentity("bank").resolve("bank")
vendor = LocalIdentity("vendor").resolve("vendor")
keys = LocalKeys(["amounts", "identity"])
keys.assign(
    bank,
    read=["amounts", "identity"],
    publish=["amounts", "identity", "tn.agents"],
)
keys.assign(vendor, read=["amounts"], publish=[])
print(sorted(keys.resolve(vendor).groups))
```

```text
['amounts', 'tn.agents']
```

`tn.agents` holds contract metadata. `LocalKeys` includes access to that metadata when assigning business groups. The vendor has no capability for the `identity` group and no publication capability in this assignment. The [complete bank/vendor example](../python/examples/bank_vendor.py) also gives the vendor a group in which to publish its report.

`LocalKeys` assigns shared BTN group material. For individually revocable readers, load each reader's BTN enrollment through `GroupCapability.btn_reader(group, kits, index)`. The [provider reference](GOVERNED_PROVIDERS.md#load-provisioned-identities-and-keys) lists the constructors for existing reader and publisher material.

## Reuse keys across processes

`FileKeyStore` saves one application's identity and group capabilities. The persistent greeting example creates the store once, then opens it in separate publish and read processes. From the repository root:

```bash
python python/examples/persistent_keys/setup.py ../tn-key-demo --cipher btn
python python/examples/persistent_keys/hello_btn.py ../tn-key-demo publish
python python/examples/persistent_keys/hello_btn.py ../tn-key-demo read
```

The final command prints `Hello, world!`. Setup requires a new directory and refuses to overwrite an existing one. Choose another path if `../tn-key-demo` already exists.

The directory contains private credentials. Keep it under the application's account permissions and outside shared publication storage. [`configuration.py`](../python/examples/persistent_keys/configuration.py) opens the store and passes it to both the identity and key provider slots. The same examples include [JWE and HIBE configurations](../python/examples/persistent_keys/README.md).

## Provider values and callbacks

Pass a Python object implementing the corresponding interface to `Providers`. Its methods return the native TN values listed here:

| Integration | Python method | Required result |
| --- | --- | --- |
| Application identity | `resolve(application)` | `ApplicationIdentity` for that application. `LocalIdentity.from_private_bytes` can load an existing signing seed. |
| Key management | `resolve(identity)` | `KeySet(identity, capabilities)` containing the assigned `GroupCapability` values. |
| Contract lookup | `policy(request)` | `Governance` for the requested object type and use. |
| Workflow configuration | `workflow(request)` | `WorkflowPolicy` describing input groups, output type, and destination. |
| Access decisions | `accept(context)`, `attach(context)`, `release(context)` | An explicit Python `bool` for the requested operation. |
| Dataset lookup | `resolve(request)` | `CatalogEntry` containing an accepted edition selection and its exact publication. |
| Event recording | `record(event)` | Record the supplied event; no return value. |

The [provider tests](../python/tests/test_governed_providers.py) exercise Python identity, key, governance, catalog, and recording callbacks alongside the local adapters. The [Python signatures](../python/tn/providers/__init__.pyi) give their argument and return types.

For a provisioned identity, `LocalIdentity.from_private_bytes(application, seed)` loads a 32-byte Ed25519 seed into the native signer. `GroupCapability` loads BTN state and reader kits, JWE X25519 keys, or HIBE public parameters and scoped reader keys, together with a group index key. Rust validates this material and performs signing, encryption, and decryption in the TN process. The [imported-material test](../python/tests/test_governed_providers.py) runs a complete workflow with an existing seed and BTN capabilities; the [HIBE delegation example](../python/examples/persistent_keys/hibe_delegation.py) loads a delegated reader grant.

`FileKeyStore` provides the same identity and key values from a saved application installation, as shown above. Applications supply identity and key callbacks during session construction, and governance callbacks at each decision point.

## Key loading, credential caching, and S3 encryption

The SDK supplies these paths for application key material and storage credentials:

| Path | Implemented operation | Where it is used |
| --- | --- | --- |
| Provisioned signing seed | `LocalIdentity.from_private_bytes(application, seed)` loads the Ed25519 seed; Rust signs with the resulting `DeviceKey`. | Governed session identity. |
| Assigned group material | `KeyProvider.resolve(identity)` returns a `KeySet` of validated `GroupCapability` values. | Native group encryption and decryption in the session. |
| Saved application installation | `FileKeyStore.create` and `open` persist and reload the signing identity and group capabilities. | The [persistent examples](../python/examples/persistent_keys/README.md). |
| Current application decisions | `GovernanceProvider.accept`, `attach`, and `release` return a Boolean for each operation. | Governed receipt, attachment, and publication. |
| Account wrapping-key cache | [`default_credential_store`](../python/tn/credential_store.py) selects a usable OS `keyring` backend or `FileCredentialStore`; both expose `get`, `set`, and `delete`. | Account initialization and wallet key pickup. |
| S3 server-side encryption | [`S3Handler`](../python/tn/handlers/s3.py) passes `sse="aws:kms"` and `sse_kms_key_id` as `ServerSideEncryption` and `SSEKMSKeyId` in `put_object`. | Storage encryption for uploaded log batches; install the `tn-proto[s3]` extra. |

The account credential cache stores the account wrapping key used by initialization and wallet operations. The governed examples load their signing and group material through `FileKeyStore` or the provider constructors. S3 encryption is applied by the storage service to the uploaded batch.

## Check current rules when opening or publishing

A session resolves its keys and workflow configuration during setup and retains that capability snapshot. Create a new session to use changed key assignments.

The session calls governance methods again for each acceptance, attachment, and release. Each callback receives the operation's context and returns the application's current decision. Return `False` to refuse; a callback exception stops the operation.

The `test_live_python_decision_and_strict_bool` case in the [provider tests](../python/tests/test_governed_providers.py) changes a decision after session creation and verifies that subsequent operations are refused.

## Catalogs and records

Run the local dataset catalog example from the repository root:

```bash
python python/examples/providers/catalog.py
```

It creates and admits a signed policy revision and dataset edition, resolves the edition, and prints the selected publication's identity. A `CatalogProvider` must return that exact publication together with its accepted `DatasetSelection`. This lets a receive operation check the requested dataset, edition, and use. The [Unity Catalog guide](UNITY_CATALOG.md) starts with locating a stored publication and explains where edition selection fits.

`FileRegisters` records signed creations and releases. A custom recorder can forward `event.publication` and the accompanying action, purpose, destination, and contract references to an administrative system. Recording happens after signing. If it fails, the publication remains available and the working object's `register_error` reports the error; the application decides how to retry or handle delivery.

To run the provider and persistent-store checks, install `pytest` in your development environment and run:

```bash
python -m pytest python/tests/test_governed_providers.py python/tests/test_governed_file_keystore.py -q
```
