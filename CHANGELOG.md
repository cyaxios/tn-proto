# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
