# tn-proto PyPI Beta Release Triage

Date: 2026-06-09
Scope: Consolidates Codex review plus pasted external-agent review for the `tn-proto` PyPI beta decision.

## Decision

Do not upload the beta to PyPI until the P0 items below are resolved and verified in a clean install.

Version numbers are currently inconsistent and must be cleaned before publish, but they are not the only release gate. The higher-risk issues are default behavior and secret-handling choices that users will experience immediately after install.

## P0 Blockers

### P0-1: Hosted vault auto-link runs by default in notebooks

`tn.init()` auto-runs vault linking when `link is None and _in_ipython()`:

- `python/tn/__init__.py:388`
- `python/tn/__init__.py:465`
- `python/tn/vault_client.py:37`

Impact: In notebook/IPython/Databricks contexts, a user can trigger outbound network traffic to `https://vault.tn-proto.org` and an encrypted ceremony upload without explicit opt-in. Even if encrypted, this is surprising behavior for a cryptography/audit package.

Decision: Make hosted vault linking opt-in. `tn.init()` should not contact the network unless the caller passes `link=True`, a CLI command explicitly asks for link/backup, or a clearly named env var enables it.

### P0-2: Claim URL / BEK is persisted into admin/outbox records

`init_upload()` builds a claim URL with the BEK in the fragment, then `_emit_claim_url_admin_event()` writes the full URL:

- `python/tn/handlers/vault_push.py:372`
- `python/tn/handlers/vault_push.py:245`
- `python/tn/handlers/vault_push.py:251`

Impact: The URL fragment contains the decryption key for the uploaded full-keystore backup. Persisting it in admin/outbox creates a durable local secret leak.

Decision: Never write the fragment-bearing claim URL to admin logs/outboxes. Store `vault_id`, expiry, and a redacted URL only. If a cat-friendly claim URL file remains, treat it as a secret and protect it.

### P0-3: Secret files are written with default filesystem permissions

Several paths write key material or backup decryptors using default process umask:

- `python/tn/config.py:447`
- `python/tn/config.py:604`
- `python/tn/config.py:611`
- `python/tn/sync_state.py:121`
- `python/tn/handlers/vault_push.py:267`

Impact: `local.private`, `index_master.key`, sync state, and claim URL files can be broader-readable than intended on POSIX systems, and temp/replace semantics vary across the codebase.

Decision: Add one hardened secret-write primitive and use it everywhere secrets are persisted. Requirements: atomic write, POSIX `0600`, same-dir temp files, cleanup on failure, and documented Windows behavior.

### P0-4: `tn.read()` and `watch()` do not verify integrity by default

The public read APIs default to `verify=False`:

- `python/tn/read.py:327`
- `python/tn/read.py:642`
- `python/tn/read.py:694`
- `python/tn/read.py:769`

Impact: The package describes attested logging, but the default read path can yield unverified/tampered rows unless users know to opt in.

Decision: For beta, default to verification or make unverified reads impossible to miss. Preferred: `verify="raise"` by default for `read()` and `watch()`. Acceptable short-term compromise: keep compatibility but emit a loud one-time warning and document `verify=` prominently.

### P0-5: `.tnpkg` reads are unbounded before validation

The package reader loads every zip entry into memory before manifest signature verification and before kind-specific validation:

- `python/tn/tnpkg.py:348`
- `python/tn/tnpkg.py:356`
- `python/tn/tnpkg.py:362`
- `python/tn/absorb.py:340`

Impact: A malicious or malformed `.tnpkg` can consume excessive memory through CLI absorb or watched `fs.scan` inboxes.

Decision: Add zip limits before reading body members: max file count, max manifest size, max per-entry size, max total uncompressed size, compression policy, and body path allowlists.

### P0-6: Public `tn-mcp-server` entry point is a stub

The package publishes `tn-mcp-server`, but it exits successfully after saying the dispatch loop is not implemented:

- `python/pyproject.toml:98`
- `python/tn/mcp/server.py:36`

Impact: A public console command in a beta wheel appears available but does not function. It also forces `mcp` into base dependencies.

Decision: Remove the console entry point and move `mcp` to an extra until the server is implemented, or finish the server before beta.

### P0-7: Publish/install path must be proven clean

The Python package depends on Rust wheels:

- `python/pyproject.toml:63`
- `python/pyproject.toml:64`

The release workflow builds all three package families, but a clean install must prove the dependency chain exists on the target index before publishing `tn-proto`.

Decision: Publish/verify `tn-core` and `tn-btn` first for targeted platforms, then verify:

```bash
python -m venv .venv-release-check
.venv-release-check/Scripts/python -m pip install --upgrade pip
.venv-release-check/Scripts/python -m pip install tn-proto --pre
.venv-release-check/Scripts/python -c "import tn; print('ok')"
```

### P0-8: Agent-facing `llms.txt` contradicts runtime network behavior

`llms.txt` claims network-quiet behavior, while the notebook auto-link path can contact the hosted vault:

- `llms.txt:60`
- `llms.txt:63`
- `python/tn/__init__.py:388`
- `python/tn/__init__.py:528`

Impact: This is the doc agents are most likely to trust. An agent can honestly but wrongly tell users that `tn.init()` is offline by default while notebook/IPython behavior may upload to `https://vault.tn-proto.org`.

Decision: Fix the runtime default in P0-1, then update `llms.txt` to match. If any auto-link behavior remains, document exact trigger conditions and opt-out/opt-in semantics in `llms.txt`.

## P1 Must Fix Before Release Candidate

### P1-1: Import-time surface FileHandler

Importing `tn` opens a process-scoped log file under temp even when `TN_SURFACE_LOG` is unset:

- `python/tn/__init__.py:136`
- `python/tn/__init__.py:144`

Decision: Default to no file sink. Only attach this handler when `TN_SURFACE_LOG` is explicitly set.

### P1-2: Stale build artifacts and package metadata

The repo contains stale `dist/` artifacts and prior package names/versions. A clean build no longer reproduced the old `../python` sdist duplication, but stale artifacts can still be uploaded by broad `dist/*` commands.

Decision: Clean stale `dist/`, `dist-wheelhouse`, and egg-info artifacts before release. Build into an empty directory. Inspect wheel `METADATA` and `entry_points.txt` before upload.

### P1-3: Broad exception swallowing is too dense

Current count: 164 `except Exception` / `except BaseException` matches under `python/tn`.

Decision: Do not try to fix all before beta, but narrow catches around crypto verification, bootstrap, and persistence paths. Keep broad catches only where fail-open behavior is explicit and tested.

### P1-4: Tests and fixtures ship inside artifacts

Clean build evidence:

- wheel included 11 in-package test files
- sdist included 175 top-level test entries plus in-package tests

Decision: Exclude `tn/lint/tests` and `tn/mcp/tests` from wheels unless intentionally public fixtures. Decide whether top-level tests belong in sdist; if retained, ensure no live credentials or local state can ship.

### P1-5: Missing `py.typed` makes the SDK untyped to downstream tools

The codebase has many annotations, but no PEP 561 marker:

- `python/tn/py.typed` is absent

Impact: Type checkers, IDEs, and agent coding tools can treat `import tn` as untyped/`Any`, losing the structured surface the SDK otherwise exposes.

Decision: Add `python/tn/py.typed` and include it in package data. Verify the built wheel contains `tn/py.typed`.

### P1-6: Agent-facing API signature docs are stale

`llms.txt` documents a simplified `tn.init(name=None, *, profile="transaction", ...)`, but the real multi-ceremony API has `profile: str | None = None` plus additional first-class kwargs:

- `llms.txt:29`
- `python/tn/_multi.py:1086`
- `python/tn/_multi.py:1091`
- `python/tn/_multi.py:1092`
- `python/tn/_multi.py:1094`

Impact: Agents tend to copy signatures verbatim. Stale signatures produce bad calls and bad explanations.

Decision: After the P0 default-behavior decisions, refresh `llms.txt` from the actual public signatures and keep it in the release gate.

### P1-7: Malformed `agents.md` errors need recovery guidance

Malformed policy files fail fast with a missing-subsection error:

- `python/tn/_agents_policy.py:186`
- `python/tn/_agents_policy.py:210`

Impact: Fail-fast is defensible for policy correctness, but agents need a repair path. The current error does not include a minimal template or "remove the file to disable policy" hint.

Decision: Keep fail-fast unless product decides policy should be best-effort, but add a concise recovery hint and point to the required subsection template.

## Version Cleanup

Known required release chore:

- Align `python/pyproject.toml`, `crypto/tn-core-py/pyproject.toml`, `crypto/tn-btn-py/pyproject.toml`, README install table, changelog, release tag, and any generated metadata.
- Decide whether the public package is `tn-proto` only; stale `tn_protocol-*` artifacts should not be uploaded.
- Confirm PyPI/TestPyPI names before final release.

This is mandatory, but it should not be treated as the primary risk. It is a release checklist item after the P0 behavior/security fixes.

## Verification Gate

Before PyPI upload:

1. Build from a clean tree into an empty output directory.
2. Run `twine check` on exactly the files intended for upload.
3. Install from the target index in a fresh venv.
4. Verify `import tn`, `tn init --no-link`, `tn read` with verification, and basic `.tnpkg` absorb limits.
5. Confirm no hosted network call occurs without explicit opt-in.
6. Confirm no claim URL fragment appears in logs, admin outbox, stdout test captures, or built artifacts.
7. Confirm `llms.txt` matches runtime defaults and the wheel contains `tn/py.typed`.
