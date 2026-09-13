# Connect TN to management systems

An application may already use an identity directory, a key store, or a service that approves data use. TN's provider interfaces let that application obtain its configuration from those systems and use it in a `Session`.

The group keys still determine which encrypted fields the session can open. A governance provider adds application decisions about accepting an object, attaching a contract, and publishing a result. These decisions can use the application's current rules.

This guide starts with the SDK's local provider examples, then explains what an adapter for an existing service needs to return. See the [provider reference](GOVERNED_PROVIDERS.md) for the complete interfaces.

## Run the composed example

Install the SDK and run these commands from a checkout of this repository:

```bash
python -m pip install "tn-proto==2026.9.13b5"
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

`LocalKeys` creates fresh group material using BTN, the SDK's broadcast-encryption option. Its assignments share that material, so this helper does not give each identity a separately revocable enrollment. BTN also supports individual reader enrollments, each with a reader kit containing its decryption material. An administrator that manages those enrollments can load their kits through `GroupCapability.btn_reader`.

## Reuse keys across processes

`FileKeyStore` saves one application's identity and group capabilities. The persistent greeting example creates the store once, then opens it in separate publish and read processes. From the repository root:

```bash
python python/examples/persistent_keys/setup.py ../tn-key-demo --cipher btn
python python/examples/persistent_keys/hello_btn.py ../tn-key-demo publish
python python/examples/persistent_keys/hello_btn.py ../tn-key-demo read
```

The final command prints `Hello, world!`. Setup requires a new directory and refuses to overwrite an existing one. Choose another path if `../tn-key-demo` already exists.

The directory contains private credentials. Keep it under the application's account permissions and outside shared publication storage. [`configuration.py`](../python/examples/persistent_keys/configuration.py) opens the store and passes it to both the identity and key provider slots. The same examples include [JWE and HIBE configurations](../python/examples/persistent_keys/README.md).

## Use an existing service

Replace a local provider with a Python object implementing the corresponding interface. Its methods can call your service's client and convert the response to the native TN types listed here:

| Integration | Python method | Required result |
| --- | --- | --- |
| Application identity | `resolve(application)` | `ApplicationIdentity` for that application. `LocalIdentity.from_private_bytes` can load an existing signing seed. |
| Key management | `resolve(identity)` | `KeySet(identity, capabilities)` containing the assigned `GroupCapability` values. |
| Contract lookup | `policy(request)` | `Governance` for the requested object type and use. |
| Workflow configuration | `workflow(request)` | `WorkflowPolicy` describing input groups, output type, and destination. |
| Access decisions | `accept(context)`, `attach(context)`, `release(context)` | An explicit Python `bool` for the requested operation. |
| Dataset lookup | `resolve(request)` | `CatalogEntry` containing an accepted edition selection and its exact publication. |
| Event recording | `record(event)` | Record the supplied event; no return value. |

The SDK includes the local adapters used above. A client for your identity directory, cloud key service, or policy engine belongs in the adapter you supply. The [Python signatures](../python/tn/providers/__init__.pyi) and [provider tests](../python/tests/test_governed_providers.py) show the accepted values and how Python adapters compose with native operations.

For existing encryption material, `GroupCapability` has BTN reader and publisher constructors, plus `jwe` and `hibe` constructors. These accept the cipher-specific key material and group index key; a service's arbitrary key identifier is not a TN capability. Rust validates the supplied material and performs encryption and decryption. The [HIBE delegation example](../python/examples/persistent_keys/hibe_delegation.py) shows provisioning from an external authority.

The identity interface currently supplies a native signer with a local private seed. Using a nonexportable signing key in an HSM would require an additional signing interface.

## Check current rules when opening or publishing

A session resolves its keys and workflow configuration during setup. Changing a key provider's assignments later does not update an existing session's capabilities.

The session calls governance methods again for each acceptance, attachment, and release. An adapter can therefore consult a policy service or key-management service at those points to check whether the requested use is still approved. It should return `False` when approval is refused and propagate service failures so the operation stops. TN supplies the operation's context; the application supplies the judgment.

The `test_live_python_decision_and_strict_bool` case in the [provider tests](../python/tests/test_governed_providers.py) changes a decision after session creation and verifies that subsequent operations are refused. An online refusal cannot erase plaintext or keys already held by an application. To exclude a reader from future publications cryptographically, use the cipher's revocation/provisioning operations described in [keys and revocation](../README.md#keys-providers-and-revocation).

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
