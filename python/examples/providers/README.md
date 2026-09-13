# Provider examples

Run `python python/examples/providers/hello.py` against the installed SDK wheel. It prints `8` after native creation, acceptance, mutation and release. Identity, key assignment, governance and optional registers each have a separate setup module beside it.

Run `python python/examples/providers/catalog.py` to create an admitted policy revision and dataset edition, then resolve the exact publication. Its printed identity is computed from the signed object.

`identity.py`, `keys.py`, `governance.py`, `catalog.py` and `register.py` implement the providers used by these examples. `hello.calculate` is application code. The setup modules may call the policy-revision and edition APIs; application code uses session and object methods.

See [provider interfaces](../../../docs/GOVERNED_PROVIDERS.md) for signatures, configuration behavior and service-adapter responsibilities.

The [management systems guide](../../../docs/MANAGEMENT_SYSTEMS.md) walks through the setup modules and explains how to connect existing services. The [Unity Catalog guide](../../../docs/UNITY_CATALOG.md) starts with [an encrypted greeting](unity_catalog.py), then uses [a signed dataset edition](unity_edition.py) to calculate an invoice total. Preparation is separate from the calculation, and both examples share the [Unity transport helpers](unity_client.py).
