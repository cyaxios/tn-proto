# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2a1] - 2026-05-17

Four follow-up fixes surfaced by the white-glove suite run against
0.4.1a3. Picks up where the read / absorb default flips left off.

Released in Python as `tn-protocol 0.4.2a1` and in TS as
`@tnproto/sdk 0.4.2-alpha.1`.

### Changed

- **CLI `tn read` defaults to `--all-runs`.** Matches the Python API
  change from 0.4.1a3. A fresh `tn read` invocation now returns every
  entry on disk. Restrict to the current process run with
  `tn read --no-all-runs`.

- **`tn.init(stream='<name>')` rebinds the module singleton.** Before
  0.4.2a1, passing `stream=` returned a per-stream handle but left
  module-level `tn.info(...)` calls bound to the default ceremony, so
  emits silently landed in `default` instead of the named stream. The
  rebind now matches the docstring ("focus on `<name>` for subsequent
  module-level calls"). The handle return value is unchanged.

### Added

- **`tn.KeystoreConflictError`** at the package top level. Re-export
  of the Rust-bound runtime exception so callers can write a stable
  `except tn.KeystoreConflictError:` instead of importing from the
  private `tn_core._core` module.

- **`tn.is_keystore_diverged(exc)`** predicate. The runtime
  exception class is shared across many failure modes; this helper
  returns `True` only when the exception message carries the
  divergence marker, so deploy scripts can safely retry the admin
  verb after a concurrent writer race::

      try:
          tn.admin.add_recipient(group="default", recipient_did=did)
      except tn.KeystoreConflictError as exc:
          if tn.is_keystore_diverged(exc):
              # safe to re-read state + retry
              ...
          else:
              raise

- **`--seal-for-recipient` flag on `tn bundle` and `tn add_recipient`.**
  Wraps the bundle body under a per-export key only the named recipient
  DID can unwrap. Previously the seal-for-recipient feature lived only
  in the Python `tn.export(...)` call; operators following `tn --help`
  could not discover it.

### Notes

- TS parity: TS gets the read default flip in tandem (already shipped
  in 0.4.1-alpha.3). The stream-singleton fix, exception export, and
  CLI seal flag are Python-only this round; TS callers already use
  `Tn.init({stream: ...})` returning a focused handle by convention,
  so the per-stream emit issue does not surface in TS.

- `TN_NO_STDOUT=1` env-var suppression was re-verified across fresh
  ceremonies, existing ceremonies, and admin-event emit paths. Works
  as documented in 0.4.2a1; the D1 white-glove finding was not
  reproducible in this build.

- JWE CLI surface (offer / enrolment handshake) is intentionally
  deferred to a later release. Today's JWE recipient onboarding still
  flows through the Python `tn.offer(...)` + `tn.admin.add_recipient(
  ..., public_key=...)` path.

## [0.4.1a3] - 2026-05-17

Two papercuts removed from the day-one user journey.

Released in Python as `tn-protocol 0.4.1a3` and in TS as
`@tnproto/sdk 0.4.1-alpha.3`.

### Changed (Python and TS)

- **`tn.read()` now defaults to "all runs on disk".** A fresh process
  calling `tn.read()` returns every entry on disk, which is what most
  callers want on first contact. The old behavior is still reachable
  by passing `all_runs=False` (Python) / `{allRuns: false}` (TS).
  Same flip applied to the MCP `ReadInput` schema.

### Changed (Python)

- **`tn.absorb()` auto-creates a ceremony when none exists.** Calling
  `tn.absorb(<bundle>)` as the very first verb no longer raises
  `RuntimeError` for kit_bundle and similar non-bootstrap kinds. The
  standard autoinit banner fires (the same one `tn.info(...)` triggers
  today) so the caller sees that a fresh identity was minted in the
  cwd. Set `TN_AUTOINIT_QUIET=1` to silence.

### Notes on TS parity

- The TS SDK keeps its existing absorb split: `Tn.absorb(source)` (the
  static method) auto-bootstraps for `project_seed` / `identity_seed`
  kinds, while non-bootstrap kinds (kit_bundle, admin_log_snapshot)
  flow through `await Tn.init(yamlPath)` then `tn.pkg.absorb(source)`.
  Aligning TS absorb with the Python "any kind autoinits" model is a
  follow-up.

- Both Python and TS changes are alpha-cycle adjustments to defaults.
  Behavior is flipped at the public surface; private internal helpers
  keep their existing defaults.

## [0.4.0a4] - 2026-05-09

Python-only packaging patch.

- **`tn` console script now installs.** The 0.4.0a3 wheel declared
  `tn-mcp-server` under `[project.scripts]` but not `tn` itself, so
  `pip install tn-protocol` left users running `python -m tn.cli ...`
  even though the cli.py docstring promised `tn [verb] ...`. Fixed:
  `tn = "tn.cli:main"` is now in pyproject.toml. `tn rotate`,
  `tn init`, `tn bundle`, `tn absorb`, `tn read`, `tn wallet ...`
  all work as advertised after install. No source-code changes —
  pure packaging fix.

No TS changes; `@tnproto/sdk` stays at `0.4.0-alpha.3`.

## [0.4.0a3] - 2026-05-09

CI-shaped CLI surface: rotation as a deploy primitive + non-TTY safe init.
Same release in Python (`tn-protocol` 0.4.0a3) and TS (`@tnproto/sdk`
0.4.0-alpha.3).

### Rotation as the deploy primitive

- **`tn rotate [<group>] [--groups a,b,c] [--out path]`** (Python CLI)
  and **`tn-js admin rotate ...`** (TS CLI). No-arg form rotates every
  non-internal group in the ceremony — the deploy-shaped default. Per-
  group it bumps `index_epoch`, regenerates the publisher state, renames
  the prior key material to `.revoked.<UTC_TS>`, and emits
  `tn.rotation.completed` to the admin log.
- **Per-recipient `.tnpkg` artifacts**: after rotation the verb mints a
  fresh `kit_bundle` for every surviving recipient and writes one
  `.tnpkg` per recipient under `./rotated_<UTC_TS>/` by default
  (override via `--out <dir>` or `--out <single>.tnpkg`). CI uploads
  the directory as a build artifact and the publisher hands the
  individual files to recipients out-of-band.
- **Vault path is free**: `tn.admin.rotate` already calls
  `_maybe_autosync(cfg)` post-rotation; vault-linked ceremonies push
  the new state automatically and the vault drives recipient
  notification from there. Vault-less ceremonies use the artifact
  channel.
- **TS BTN rotation now actually works**: pre-0.4.0a3 the TS
  `tn.admin.rotate(group)` threw `"btn cipher does not support in-band
  rotation"`. It now mirrors Python end-to-end (mint a fresh
  `BtnPublisher`, swap on disk, bump epoch, attest). JWE rotation
  remains Python-only.

### Non-TTY safe `tn init`

- `tn init <project>` no longer requires a TTY for first-time
  provisioning. In CI / containers / scripts it auto-skips the
  "Press Enter" prompt, suppresses the mnemonic banner (would have
  leaked into CI logs), and persists the mnemonic into
  `identity.json`. The operator treats `identity.json` as the
  secret-handling boundary and can recover the mnemonic later via
  `tn wallet export-mnemonic`.

### Documentation

- README and CLI top-of-file docstrings updated to cover the new
  verbs and CI-shaped behavior.
- `docs/sdk-parity.md` gains a CLI parity table.

## [0.4.0a2] - 2026-05-08

Cross-language dirt-easy lifecycle. Same release in Python (`tn-protocol`
0.4.0a2) and TS (`@tnproto/sdk` 0.4.0-alpha.2).

### Lifecycle UX

- **`tn.absorb('bundle.tnpkg')` now bootstraps a runtime when nothing is
  bound yet.** For self-contained bundle kinds (`project_seed`,
  `identity_seed`) the absorb writes the layout to disk *and* binds the
  runtime to the freshly-absorbed `./tn.yaml`. The user can immediately
  call `tn.info(...)` / `tn.read()` without a separate `tn.init()` step.
- **`tn.init()` no-args discovery chain expanded** to walk
  `$TN_YAML` → `./tn.yaml` → `./.tn/default/tn.yaml` → `~/.tn/tn.yaml`,
  then mint a fresh `.tn/default/` ceremony if nothing is found.
- **Top-level `tn.absorb` / `tn.export` aliases** (Python) and
  **`Tn.absorb(source)` static factory** (TS) returning a usable Tn
  bound to the absorbed dir.

### Cross-language interop

- **`project_seed` and `identity_seed` absorb** is wired up in both
  languages with shared manifest-kind handlers. Closes the gap where the
  deployed dashboard at `https://vault.tn-proto.org` could mint these
  bundles but neither SDK could install them.

### Type surface

- `tn.absorb(source)` narrows to `AbsorbReceipt`; legacy
  `tn.absorb(cfg, source)` narrows to `AbsorbResult` (Python @overload).
- `tn.read()` narrows to `Iterator[Entry]`; `tn.read(raw=True)` narrows
  to `Iterator[dict[str, Any]]` (Python @overload).
- TS: `Tn.absorb()` returns `Promise<Tn>` instead of a receipt-or-Tn
  union.

### Cleanup

- Drop dead `_absorb_offer` / `_absorb_enrolment` / `_extract_peer_did`
  legacy compat helpers (no in-tree importers).
- Correct `_emit_via` / `_emit_with_splice` annotation from
  `-> dict[str, Any]` to `-> None` (stale since the dispatch refactor).
- Widen `_open_zip` / `_read_manifest` `source:` to also accept `str`.

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
