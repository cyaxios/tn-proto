# Provider examples

Install `tn-proto==2026.9.13b5` and run these commands from the repository root:

```shell
python python/examples/providers/hello.py
python python/examples/providers/catalog.py
```

The greeting calculation prints `8` after creation, acceptance, mutation, and release. The catalog example creates and admits a signed policy revision and dataset edition, then prints the exact source publication's identifier.

| Setup module | Working path |
| --- | --- |
| [identity.py](identity.py) | Generate and resolve an application's signing identity. |
| [keys.py](keys.py) | Assign BTN reader and publisher capabilities by group. |
| [governance.py](governance.py) | Configure trusted writers, exact contracts, complete uses, and workflow routes. |
| [catalog.py](catalog.py) | Admit policy revisions and editions, then resolve the exact publication and selection. |
| [register.py](register.py) | Record signed metadata in files or collect publication events in Python. |

[hello.calculate](hello.py) uses the configured session and object methods. For identities and keys reused by later processes, run the [persistent-key examples](../persistent_keys/README.md).

See [provider interfaces](../../../docs/GOVERNED_PROVIDERS.md) for signatures, configuration behavior and service-adapter responsibilities.

The [management systems guide](../../../docs/MANAGEMENT_SYSTEMS.md) walks through these modules, imported key material, and Python callbacks. The [Unity Catalog guide](../../../docs/UNITY_CATALOG.md) starts with [an encrypted greeting](unity_catalog.py), then uses [a signed dataset edition](unity_edition.py) to calculate an invoice total. Preparation is separate from the calculation. Both examples use the [HTTP volume lookup and publication checks](unity_client.py).
