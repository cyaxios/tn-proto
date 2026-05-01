# `tn-btn` — Broadcast-Transaction Encryption

Encrypt for N future decryptors. Hand each one an opaque reader kit. Revoke individual readers later without redistributing anything to the survivors.

No server. No PKI. No pre-shared secret. No identity. No network.

## Design

See [the full design spec](../docs/superpowers/specs/2026-04-21-bcast-rust-library-design.md) in the parent repository for the architecture, algorithm choices, wire formats, and implementation milestones.

Core algorithm: NNL subset-difference (Naor-Naor-Lotspiech 2001) + Asano's layered storage optimization (2002).

## Status

Pre-1.0. API may change across minor versions until 1.0. Tree height is currently hard-coded at 8 (256 leaves); bumping it is a constant change, not a wire-format change.

## The Six Verbs

```rust
use tn_btn::{Config, PublisherState};

// Publisher side
let mut state = PublisherState::setup(Config::default())?;
let alice_kit = state.mint()?;
let bob_kit   = state.mint()?;
state.revoke(&alice_kit)?;
let ct = state.encrypt(b"hello bob")?;

// Reader side
let pt = bob_kit.decrypt(&ct)?;   // Ok(b"hello bob")
// alice_kit.decrypt(&ct)         // Err(NotEntitled)
```

## License

MIT OR Apache-2.0
