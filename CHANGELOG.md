# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0a3] - 2026-05-05

Dispatch refactor + stdout cosmetic cleanup. Requires `tn-core` 0.2.0a2.

### Python SDK (tn-protocol)

- `DispatchRuntime` no longer disables the Rust path when custom Python
  handlers are registered. Btn ceremonies stay on Rust; user-registered
  handlers (kafka, S3, vault.sync, fs.drop, etc.) are fanned out
  post-Rust-emit. Closes the long-standing limitation where mixing
  custom handlers with btn admin verbs (`add_recipient_btn` etc.)
  raised `NotImplementedError`.
- The post-emit fan-out skips handlers whose write target Rust has
  already covered: `StdoutHandler`-class instances (Rust auto-registers
  its native one) and file handlers whose `path` resolves to Rust's
  `cfg.logs.path` (Rust's internal log_writer wrote it). The skip rule
  is path-equality + class-match, replacing the imprecise
  `_tn_default` flag that incorrectly swallowed multi-file-handler
  fan-outs.
- `StdoutHandler` default format is now a terse single line:
  `HH:MM:SS.mmm LEVEL  seq=N  event_type`. No DID, no hashes, no
  signatures, no ciphertext on a developer's terminal. Opt back into
  the canonical NDJSON envelope via `TN_STDOUT_FORMAT=json` env var or
  `format: json` on the yaml stdout entry. Same setting honored by the
  Rust-side `StdoutHandler`.

### Bug fixes

- `examples/ex06_multi_handler.py`: parse-replace-dump yaml instead of
  appending a duplicate top-level `handlers:` key (latent bug — the
  prior append-string pattern produced malformed yaml that strict
  parsers reject; only worked before because the user-handler gate
  forced the whole dispatch to Python's lenient yaml loader).

[0.3.0a3]: https://github.com/cyaxios/tn-proto/releases/tag/v0.3.0a3

## [0.2.0a2] - 2026-05-01

Loosened sub-package version constraints for rapid alpha iteration.
Functionally identical to 0.2.0a1.

### Changed

- `tn-btn` / `tn-core` deps now `>=0.2.0a1,<0.3` (was `==0.2.0a1`).
  Patches to either wheel flow into tn-protocol installs without
  forcing a coordinated bump. Tighten back to `==` for stable.

[0.2.0a2]: https://github.com/cyaxios/tn-proto/releases/tag/v0.2.0a2

## [0.2.0a1] - 2026-05-01

First public alpha. Initial release of tn-proto under the `cyaxios`
namespace.

### Python SDK

- Cipher-agnostic admin verbs: `tn.admin.add_recipient`,
  `tn.admin.revoke_recipient`, `tn.admin.rotate`. Each branches
  internally on the group's cipher and returns a structured dataclass
  (`AddRecipientResult`, `RevokeRecipientResult`, `RotateGroupResult`).
- New subpackages: `tn.admin`, `tn.pkg`, `tn.vault`, `tn.admin.cache`.
- Protocol primitives in `canonical`, `chain`, `indexing`, `signing`,
  `sealing`, `tnpkg`, `contacts`, `filters`, `identity`, `classifier`,
  `reconcile`, `wallet_restore*` are now underscore-prefixed and not
  part of the SemVer-public set.
- The 18 flat aliases (`tn.admin_*`, `tn.cached_*`, `tn.vault_*`,
  `tn.export`, `tn.absorb`, `tn.bundle_for_recipient`, top-level
  `add_recipient` / `revoke_recipient` / `rotate` / `recipients`) are
  removed without deprecation aliases.
- `tn/__init__.py` reduced from 1844 to 845 LOC; private impls live in
  `tn/_session_impl.py`, `tn/_pkg_impl.py`, `tn/_vault_impl.py`,
  `tn/_read_impl.py`.

[0.2.0a1]: https://github.com/cyaxios/tn-proto/releases/tag/v0.2.0a1
