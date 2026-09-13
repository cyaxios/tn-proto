# Provider examples

Run `python python/examples/providers/hello.py` against the installed SDK wheel. It prints `8` after native creation, acceptance, mutation and release. Identity, key assignment, governance and optional registers each have a separate setup module beside it.

Run `python python/examples/providers/catalog.py` to create an admitted policy revision and dataset edition, then resolve the exact publication. Its printed identity is computed from the signed object.

`identity.py`, `keys.py`, `governance.py`, `catalog.py` and `register.py` contain the first implementations. `hello.calculate` is application code. The setup modules are administrative examples and may call the specialist policy-revision and edition APIs; application code uses the agreed object verbs.

See [provider interfaces](../../../docs/GOVERNED_PROVIDERS.md) for signatures, configuration behavior and service-adapter responsibilities.
