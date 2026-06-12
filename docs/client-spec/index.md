# TN client / runtime specs

This set covers how a **client** integrates with the hosted TN
services and how a TN **runtime** is configured. It is separate from,
and sits above, the [wire protocol spec](../spec/index.md): the wire
spec defines the bytes a producer emits and a verifier validates; this
set defines the surfaces a client talks to and the knobs that configure
a runtime.

These documents are not part of the wire format and do not carry a
`wire/N` version.

## Documents

- [**Vault HTTP**](./vault-http.md) — the REST endpoints a client uses
  to push, pull, and redeem from a hosted vault.
- [**Env vars**](./env-vars.md) — the `TN_*` runtime configuration
  variables and their conventions.
