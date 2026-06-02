# tn-core rustdoc coverage tracker

Tracks the file-by-file rustdoc completeness pass over `crypto/tn-core/src/**`.
Plan: `docs/superpowers/plans/2026-06-02-tn-core-rustdoc-pass.md`.
Spec (rubric + front-door rule): `docs/superpowers/specs/2026-06-02-tn-core-doc-quality-pass-design.md`.

Status legend: ☐ todo · ◑ in progress · ✓ done.

Verification per file (run in the `codex` WSL distro from the repo root):
- `cargo test -p tn-core --doc`
- `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc -p tn-core --no-deps`

Note: the crate already sets `#![warn(missing_docs)]`, so *presence* gaps show
as build warnings; this pass adds the richer bar (doctests, `# Errors`/`# Panics`,
front-door redirects, cross-refs) which the compiler does not check.

## File status (bottom-up order)

| # | File | ~pub items | status |
|---|------|-----------:|--------|
| 1 | `error.rs` | 2 | ✓ |
| 2 | `canonical.rs` | 2 | ☐ |
| 3 | `signing.rs` | 10 | ☐ |
| 4 | `chain.rs` | 12 | ☐ |
| 5 | `envelope.rs` | 3 | ☐ |
| 6 | `indexing.rs` | 7 | ☐ |
| 7 | `body_encryption.rs` | 6 | ☐ |
| 8 | `tnpkg.rs` | 18 | ☐ |
| 9 | `config.rs` | 17 | ☐ |
| 10 | `path_template.rs` | 6 | ☐ |
| 11 | `log_file.rs` | 15 | ☐ |
| 12 | `storage.rs` | 3 | ☐ |
| 13 | `keystore_backend.rs` | 6 | ☐ |
| 14 | `cipher/mod.rs` | 1 | ☐ |
| 15 | `cipher/btn.rs` | 13 | ☐ |
| 16 | `cipher/jwe.rs` | 1 | ☐ |
| 17 | `cipher/bgw.rs` | 2 | ☐ |
| 18 | `read_as_recipient.rs` | 4 | ☐ |
| 19 | `identity.rs` | 3 | ☐ |
| 20 | `classifier.rs` | 1 | ☐ |
| 21 | `agents_policy.rs` | 8 | ☐ |
| 22 | `perf.rs` | 7 | ☐ |
| 23 | `runtime.rs` | 64 | ☐ |
| 24 | `runtime_export.rs` | 7 | ☐ |
| 25 | `admin_cache.rs` | 20 | ☐ |
| 26 | `admin_catalog.rs` | 6 | ☐ |
| 27 | `admin_reduce.rs` | 3 | ☐ |
| 28 | `handlers/mod.rs` | 3 | ☐ |
| 29 | `handlers/spec.rs` | 8 | ☐ |
| 30 | `handlers/stdout.rs` | 7 | ☐ |
| 31 | `handlers/fs_drop.rs` | 6 | ☐ |
| 32 | `handlers/fs_scan.rs` | 7 | ☐ |
| 33 | `handlers/vault_pull.rs` | 11 | ☐ |
| 34 | `handlers/vault_push.rs` | 10 | ☐ |
| 35 | `lib.rs` (crate `//!`) | 0 | ☐ |

## Per-item detail

### 1. `error.rs` ✓
- [x] module `//!` — front-door framing (errors returned across the public API; surfaced via `tn.*`/`tn` CLI) + recoverable-handling doctest (passes)
- [x] `Result<T>` (type alias) — prose; trivial alias, no doctest
- [x] `Error` (enum) — summary + cross-refs to the public surfaces that return it; variants/fields already documented
- verified: doctest 1/1; `cargo doc` broken-link gate clean

## Outcome — 2026-06-02 (time-boxed re-scope)

Re-scoped to "primary interfaces good; internal primitives marked + redirected":

- **Primary interfaces documented** to the rubric: `lib.rs` crate map (where-to-start),
  `error.rs`, `runtime.rs` (the `Runtime` front door), `tnpkg.rs` (`Manifest`), `signing.rs`
  (`DeviceKey`), `runtime_export.rs`, `admin_cache.rs`, and the `cipher`/`handlers`/`storage`
  extension-point traits.
- **23 internal primitives** got a module-`//!` redirect to the primary interface
  (`[crate::Runtime]` / `[crate::Manifest]` / `[crate::AdminState]` + the user-facing verb),
  steering readers/agents to the front door instead of the low-level internals.
- **Verification:** `cargo test -p tn-core --doc` = 22 passed / 0 failed (11 runnable +
  11 `no_run` compile-checked); `cargo doc` broken-intra-doc-links gate = green. Also fixed
  3 pre-existing broken links (`config.rs`, `keystore_backend.rs`, `log_file.rs`).
- **Deferred (not full rubric):** per-item docs on `config.rs`, `log_file.rs`,
  `path_template.rs`, the individual cipher/handler impls, and the `admin_catalog`/`admin_reduce`
  bodies — these carry redirects but not the full per-item pass. Future work.
