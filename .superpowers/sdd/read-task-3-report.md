# Secure-read Task 3 report

## Outcome

Implemented Python `read()` secure-by-default behavior from the approved
Task 3 brief. The public default is now receiver-local `verify="auto"`, with
strict pre-decrypt policy enforcement, stable failure reasons, handle-bound
configuration/trust snapshots, skip observability, explicit compatibility
aliases, a non-weakenable `secure_read()` wrapper, and the required CLI
mappings. The `_ReadIterator`, `Entry`, and raw envelope-dict shapes remain in
place; raw results now include `_valid` audit metadata.

The task began at base commit `8fb829a6`. The shared worktree HEAD advanced
concurrently and the initial Task 3 implementation was checkpointed externally
at `2324cc9`; final verification ran at shared HEAD
`3f54dd9669585859ae759ee12e1ed391f0678297`. This task agent performed no reset,
commit, staging operation, or cleanup.

## Scope and dirty-baseline handling

Task-owned production paths:

- `python/tn/read.py`
- `python/tn/_read_impl.py`
- `python/tn/_entry.py`
- `python/tn/reader.py`
- `python/tn/config.py`
- `python/tn/_handle.py`
- `python/tn/__init__.py`
- `python/tn/cli.py`
- `python/tn/cli_read.py`

Task-owned new tests:

- `python/tests/test_read_secure_default.py`
- `python/tests/test_handle_read_policy.py`
- `python/tests/test_cli_read_security.py`

The five plan-listed resilience tests were updated:

- `python/tests/test_secure_read_tamper.py`
- `python/tests/test_read_skip_observability.py`
- `python/tests/test_verify_respects_sign_setting.py`
- `python/tests/test_verify_roundtrip.py`
- `python/tests/test_read_parse_resilience.py`

One narrow test-only expansion was explicitly approved during implementation:
`python/tests/test_signing_flag.py` now uses `verify=False` in its raw-storage
inspection helper, because that helper intentionally examines unsigned rows
below the newly secure public default.

The initial shared index was empty. `python/tn/_handle.py` already had approved,
unstaged BTN-only package-bundling edits. Those exact hunks were preserved:
the BTN-only docstrings and `_require_btn_bundle_groups(cfg, requested)` call
remain separate from the Task 3 read hunk. No unrelated dirty file was edited,
staged, reverted, or removed.

## Test-first evidence

Initial focused RED, before implementation:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_secure_default.py -q
7 failed in 0.28s
```

Complete Step-2 RED:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_secure_default.py python/tests/test_handle_read_policy.py python/tests/test_cli_read_security.py python/tests/test_secure_read_tamper.py python/tests/test_read_skip_observability.py python/tests/test_verify_respects_sign_setting.py python/tests/test_verify_roundtrip.py python/tests/test_read_parse_resilience.py -q
14 failed, 29 passed in 15.11s
```

The pre-decrypt ordering spy was also observed failing before the gate was
implemented:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_secure_default.py::test_security_rejection_happens_before_group_decrypt -q
3 failed in 0.27s
```

Final prescribed GREEN, run fresh after the last test and implementation edits:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_secure_default.py python/tests/test_handle_read_policy.py python/tests/test_cli_read_security.py python/tests/test_secure_read_tamper.py python/tests/test_read_skip_observability.py python/tests/test_verify_respects_sign_setting.py python/tests/test_verify_roundtrip.py python/tests/test_read_parse_resilience.py -q
73 passed in 19.39s
```

Additional read/signing compatibility gate:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_0_4_2a9_regression.py python/tests/test_emit_propagation.py python/tests/test_entry.py python/tests/test_signing_flag.py python/tests/test_read_trust_provider.py python/tests/test_read_trust_policy.py python/tests/test_read_skip_observability.py python/tests/test_read_secure_default.py python/tests/test_read_parse_resilience.py python/tests/test_read_all_runs_default.py python/tests/test_read_admin_address.py python/tests/test_log_level_kwarg_and_verify_typing.py -q
214 passed in 39.39s
```

### Independent-review parse-resilience fix

Review found that invalid JSON was decoded outside the per-row sentinel catch
in `_lines_with_keybag` and `read_as_recipient`. `_wrap_parse_errors` could
observe the raised exception, but the source generator was then closed, so the
later clean row was never scanned. Configured network reads inherited the same
failure because they feed their transport iterator through `_lines_with_keybag`.

Transport-level tests were added for an explicit-log keybag read,
`read_as_recipient`, and configured-network input. Each is parameterized over
invalid JSON and a valid-JSON/non-envelope shape, and asserts the later row,
callback, parse/verify counters, stable reason, and chain fact.

RED before the production fix:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "explicit_log_keybag or read_as_recipient or configured_network" -q
3 failed, 3 passed, 6 deselected in 2.12s
```

The three invalid-JSON cases reproduced the reviewer's `['a']` result; the
shape cases confirmed that the existing envelope scanner already converted
shape failures and continued. After moving JSON decoding inside the same
narrow per-row parse/shape catch:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "explicit_log_keybag or read_as_recipient or configured_network" -q
6 passed, 6 deselected in 2.23s

.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -q
29 passed in 4.51s
```

### Independent-review authenticated-plaintext fix

A second review found that each decrypting scanner placed cipher open and
plaintext UTF-8/JSON decoding in one broad catch. A successful authenticated
open followed by malformed plaintext was therefore mislabeled as
`aad_invalid`/`$decrypt_error`; non-object JSON could also derail later rows.

The regression matrix uses a spy cipher across local, explicit keybag, and
recipient paths (configured network input reuses the keybag scanner). It covers
non-JSON bytes, invalid UTF-8, and valid non-object JSON. Each case includes a
pre-decrypt-rejected row, the authenticated malformed-plaintext row, and a
later clean row.

RED before the production fix:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "authenticated_bad_plaintext" -q
9 failed, 12 deselected in 1.68s
```

Invalid JSON/UTF-8 produced `aad_invalid` with `skipped_parse=0`; non-object
JSON interrupted or misclassified later-row handling. After separating cipher
open from a shared post-open plaintext-object decoder:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "authenticated_bad_plaintext" -q
9 passed, 12 deselected in 0.33s
```

The matrix asserts `record_invalid` (never `aad_invalid`), parse-versus-verify
counters, callback order, no group/partial plaintext on the sentinel, later-row
continuation, and exact spy calls proving the pre-decrypt-rejected ciphertext
was never opened.

### Independent-review mixed-candidate precedence fix

A third review found that keybag and recipient candidate loops recorded only
whether any cipher raised `NotARecipientError`. If another candidate raised a
generic/authenticated-open failure and none succeeded, the not-recipient flag
incorrectly won, producing `$no_read_key` with `aad=true` instead of
`$decrypt_error`/`aad_invalid`.

RED across the local single-open baseline plus explicit keybag, configured
network, and recipient public surfaces:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "candidate" -q
3 failed, 1 passed, 25 deselected in 0.81s
```

The local baseline already returned `aad_invalid`; both keybag-backed surfaces
incorrectly returned the row as no-read-key, and recipient returned
`not_a_recipient`. After recording hard open failures independently in both
candidate loops:

```text
.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "candidate" -q
4 passed, 25 deselected in 0.74s

.\.venv\Scripts\python.exe -m pytest python/tests/test_read_parse_resilience.py -k "all_not_recipient or success_after" -q
4 passed, 25 deselected in 0.14s
```

The preservation matrix proves all-candidate not-recipient remains
`$no_read_key`/`aad=true`, while a later successful candidate still wins after
an earlier not-recipient or generic failure. Post-open plaintext parse failures
remain `record_invalid` through their earlier branch.

## Static and worktree gates

Scoped Ruff passed on every owned implementation/test path. The repository
virtual environment does not include Ruff, so the available `ruff` executable
was used:

```text
ruff check <all owned paths except python/tn/__init__.py>
All checks passed!

ruff check --ignore I001 python/tn/__init__.py
All checks passed!
```

`I001` is a pre-existing baseline finding in `python/tn/__init__.py`; piping
the current committed file from `git show HEAD:python/tn/__init__.py` through
Ruff reproduces that single import-order finding. The task did not mass-sort
the module.

Whitespace validation passed:

```text
git -c core.whitespace=cr-at-eol diff --check -- <all owned paths>
(no errors)
```

The final shared index check produced no paths:

```text
git diff --cached --name-only
(empty)
```

## Security review

- `ReadContext`, local trust material, exact trusted writer DIDs, configuration,
  runtime, source resolution, and template targets are snapshotted once per
  iterator from the bound `TN` handle.
- A handle read no longer activates/rebinds the process-global ceremony; lazy
  iterators from simultaneous handles retain their own signed/unsigned policy.
- Foreign or detached reads never inherit local `sign:false` or `chain:false`.
  Unsigned relaxation requires both `require_signature=False` and
  `allow_unauthenticated=True`.
- An absent signature may be accepted only where the resolved policy allows it
  and never becomes authenticated. An invalid-present signature remains a hard
  rejection even when unauthenticated rows are allowed.
- Parse, record hash, chain, signature, authentication, and writer authorization
  facts are computed and gated before group decryption/plaintext exposure. The
  parameterized cipher spy covers row-hash, signature, and writer rejection.
- Every decrypting scanner now contains JSON decoding and envelope-shape
  scanning within its per-row `_parse_error_triple` boundary. Policy gates and
  decrypt handling remain outside that catch, so a malformed row cannot close
  the transport generator and policy/decrypt failures are not misclassified.
- Cipher-open exceptions remain `$decrypt_error`/AAD or not-recipient outcomes.
  Once authenticated open succeeds, invalid UTF-8, JSON, or JSON-object shape
  becomes an empty-plaintext `record_invalid` sentinel; partial plaintext from
  earlier groups is discarded and later source rows continue.
- Mixed-cipher resolution is order independent: any success wins; otherwise a
  generic/open failure takes precedence as `$decrypt_error`/`aad_invalid`; only
  an exclusively not-recipient candidate set yields `$no_read_key`.
- Raise mode exposes stable primary and full reasons through `VerifyError`.
  Skip mode preserves cursor traversal while updating stats, invoking callbacks,
  and attaching full `_valid.reasons` metadata to observed raw envelopes.
- Disabled mode does not fabricate authentication or authorization facts.
- `secure_read()` fixes strict verification/authentication/authorization options
  internally and exposes no weakening parameters.
- CLI omission leaves `verify` out of the `read()` call. Explicit CLI choices
  map only to `"raise"`, `"skip"`, and `False`; `auto` is not accepted as a
  weakening flag value.

The third-review `reader.py`/parse-resilience changes and this report remain
unstaged. The shared parent checkpointed the earlier Task 3 implementation;
this task agent performed no staging or commit.
