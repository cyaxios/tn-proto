# tn-core

The shared Rust implementation of the TN governed data protocol. TN carries
encrypted data and its use contract in one signed envelope. Applications use
that binding to admit input, select data, mediate computation, and sign derived
output with its contract and source references.

## Governed objects are the primary data interface

- `Governance` selects the use contract from parsed policy content.
- `GovernedDraft` assigns typed JSON fields to encrypted groups.
- `GovernedWriter` constructs `tn.agents`, common governance AAD, and a signature.
- `GovernedObject` verifies and retains the complete wire envelope.
- `GovernedReader` opens governance, then selected groups after application admission.
- `OpenedObject` keeps plaintext with its source and contract and starts derivatives.

These types live in `tn_core::governed` and work with default features disabled.
The caller supplies an existing signing identity and group cipher material;
transport, storage, and application use remain explicit choices.

See the [Rust governed-object guide](../../rust-sdk/GOVERNED_OBJECTS.md) and
[runnable example](../../rust-sdk/examples/governed_objects.rs).

## Configured objects and event streams share the wire construction

`runtime::Objects::open` loads configuration, policy, identity, and group
material directly. `Runtime::objects` adapts an already loaded event runtime.
The `Runtime` event, read, administration, and package methods continue to use
the shared canonicalization, HMAC indexing, Ed25519 signing, envelope, and
cipher implementations. BTN, JWE, and HIBE implement the group cipher trait.

## Feature flags select runtime facilities

- `fs` (default): configured objects, filesystem storage, event runtime, CLI.
- Without `fs`: governed objects and protocol primitives with supplied material.
- `fs-locking` (default): native cross-process advisory locks.
- `hibe` (default): the native hierarchical cipher implementation.

The Rust SDK exposes these operations ergonomically. Python wraps the shared
core through PyO3; Node and browser integrations use WASM.