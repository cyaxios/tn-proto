# tn-protocol DX Review Fixes — testers' reference

Patch notes for the fixes landed in response to the
`tn-protocol 0.4.2a1` developer-experience review. Each section reflects
one numbered finding from that review and contains:

- **Status** — fixed / partially fixed / declined (with reasoning) and
  the commit / files touched
- **Root cause** — code-level explanation
- **What changed** — the fix in one paragraph
- **How to verify** — the original report's repro, with the new
  expected output
- **Tests added** — paths and what they assert
- **Risks / regressions to watch** — anything that might bite under
  load, on a different OS, or in concurrent flows

Use this doc as the checklist for the 0.4.2a2 acceptance round. Each
`How to verify` block is copy-paste-runnable; treat a green run on every
one as the gate.

---

## #1 — Concurrent `tn.init()` across processes corrupts ceremony silently

**Severity:** critical
**Status:** Fixed in `python/tn/_multi.py`
**Tests:** `python/tests/test_concurrent_init.py` (4 cases)

### Root cause

`_ensure_ceremony_on_disk(name=...)` did a `yaml_path.is_file()` check
then dropped straight into `_create_default_ceremony`, which mints a
fresh device DID + signing key + yaml. With N processes racing against
an empty `.tn/`, all N saw `is_file() == False` simultaneously and all
N tried to create. Worker A wrote `keys/local.private` first; worker B
hit `RuntimeError: refusing to create a fresh ceremony` from
`config.create_fresh`, but in the meantime its concurrent write
trajectory had already deposited a partial yaml with a different
`me.did`. The next `tn.init` in any process then raised
`ValueError: keystore DID ... does not match yaml me.did`.

### What changed

Added `_ceremony_create_lock(project_dir, name)` — a per-ceremony
sentinel file under `.tn/.init.<name>.lock` acquired with
`os.O_CREAT | os.O_EXCL` (atomic on Linux, macOS, and Windows). The
create branch of `_ensure_ceremony_on_disk` now acquires the lock,
re-checks `yaml_path.is_file()` (the race we lost case), and only
mints if still missing. Subsequent arrivals spin (50 ms steps, 30 s
timeout) until the holder releases or the yaml appears; a lock older
than 60 s is treated as crashed-holder debris and reaped.

Lock scoping is per-name, so concurrent inits of different ceremonies
(`default` vs `billing`) do not serialise on each other.

### Caveats

- On local filesystems (NTFS, ext4, APFS) `O_EXCL` is atomic. On NFS
  pre-v3 and some SMB configurations the guarantee weakens; if you
  deploy on a network filesystem and see corruption return, raise a
  ticket so we can switch to `fcntl.flock` on that path.
- The 60 s stale-lock threshold assumes a sub-second normal init. If
  your environment legitimately takes longer (slow disk, hardware
  HSM key generation, an SSH-tunneled keystore mount), bump the
  constant in `_ceremony_create_lock` and re-run the soak.

### How to verify

```bash
# From an empty cwd:
rm -rf .tn
python - <<'PY'
import subprocess, sys, textwrap, pathlib
pathlib.Path("worker.py").write_text(textwrap.dedent("""
    import os; os.environ['TN_NO_STDOUT'] = '1'
    import tn
    tn.init()
    tn.flush_and_close()
""").strip())
procs = [subprocess.Popen([sys.executable, "worker.py"]) for _ in range(8)]
for p in procs: p.wait()
import tn
tn.init()  # must NOT raise "keystore DID ... does not match"
tn.info("post.race.evt", marker="reader"); tn.flush_and_close()
print("OK")
PY
```

Expected: prints `OK`. yaml's `me.did` matches `keys/local.public`.

### Tests

| Test | Asserts |
|--|--|
| `test_concurrent_init_does_not_corrupt[4]` | 4 worker processes race init. yaml.me.did matches keys/local.public; a fresh reader can re-init and read its own event. |
| `test_concurrent_init_does_not_corrupt[8]` | Same at 8 workers (stress). |
| `test_create_lock_releases_after_success` | After a clean init, `.tn/.init.default.lock` is gone (no leak). |
| `test_create_lock_reaps_stale` | A pre-existing 120s-old lock file is reaped on next init. |

### Risks / regressions to watch

- **Chain coherence under concurrent user writes is a separate
  problem.** Fix #1 makes init safe; it does not serialise
  per-emit chain writes. ~~The previously-published reproduction
  script (workers each call `tn.info` in a loop) will still raise
  `VerifyError: chain` on a `tn.read(verify=True)` because the
  workers concurrently advance the same chain.~~ **Fixed in
  0.4.2a3** — the emit pipeline now bookends chain advance through
  commit with an advisory file lock, refreshing chain state from
  disk truth under the lock. 2000/2000 rows across 10 stress
  iterations pass `verify=True`. See the 0.4.2a3 CHANGELOG entry.
- **Lock release on `SIGKILL`**: the OS doesn't auto-unlink the
  sentinel. The 60 s stale reaper handles this. Soak-test sites
  should monitor for `.init.*.lock` files older than 5 minutes as
  a leak indicator.
- **A misbehaving wrapper that calls `_create_default_ceremony`
  directly bypasses the lock.** The lock lives in
  `_ensure_ceremony_on_disk`. External callers should always
  enter via `tn.init` / `_ensure_ceremony_on_disk` — direct calls
  to the private creator are unsupported.

---

## #2 — `tn validate` reports OK on ceremony where yaml.me.did != keystore DID

**Severity:** critical
**Status:** Fixed in `python/tn/cli.py`
**Tests:** `python/tests/test_validate_did_consistency.py` (4 cases)

### Root cause

`cmd_validate` ran three checks (yaml parse, profile catalog,
default-exists warning). It never compared `yaml['me']['did']` to the
did:key stored in `keys/local.public`. So the *exact* on-disk
inconsistency the runtime refuses to load (raises
`ValueError: keystore DID ... does not match yaml me.did`) was
invisible to the validator that should be guarding against it.

### What changed

- New helper `_validate_resolve_keystore_pub(yaml_path, yaml_doc,
  project_dir)` — resolves the `local.public` path for a ceremony,
  honouring stream yamls that point at default via
  `keystore.path: ../default/keys` and falling back to
  `<yaml_dir>/keys/local.public` for the default layout.
- `cmd_validate` now reads that file and compares it to
  `yaml['me']['did']`. Mismatch becomes a non-zero exit with a
  diagnostic that names both DIDs and instructs the operator to
  reseat one to match the other.

### How to verify

```bash
mkdir -p /tmp/v2 && cd /tmp/v2 && rm -rf .tn
python -c "import tn; tn.init(); tn.flush_and_close()"
python - <<'PY'
import yaml, pathlib
p = pathlib.Path(".tn/default/tn.yaml")
doc = yaml.safe_load(p.read_text())
doc["me"]["did"] = "did:key:z6MkfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE"
p.write_text(yaml.safe_dump(doc, sort_keys=False))
PY
python -m tn.cli validate; echo "exit=$?"
```

Expected:

```
ERROR: .../tn.yaml: yaml me.did does not match keystore. yaml me.did =
did:key:z6MkfakeFAKE...; keys/local.public = did:key:z6Mk... <real>.
Reseat one to match the other before any further writes — the runtime
will refuse to load this ceremony otherwise.
exit=1
```

### Tests

| Test | Asserts |
|--|--|
| `test_validate_passes_on_clean_ceremony` | Sanity baseline: clean init validates with exit 0 + `OK:` message. |
| `test_validate_catches_yaml_did_keystore_mismatch` | Mutated `yaml.me.did` → non-zero exit + diagnostic naming both DIDs. |
| `test_validate_catches_keystore_drift_after_swap` | Symmetric test: mutate `keys/local.public` instead. Same error. |
| `test_validate_clean_when_no_tn_directory` | No `.tn/` → "(nothing to validate)" + exit 0 (unchanged behavior, pinned). |

### Risks / regressions to watch

- **Streams that legitimately have no `me.did` field** are skipped
  (defensive). If your stream yamls store the DID somewhere else,
  this check won't catch a mismatch there. Open a ticket if you
  need the resolver extended.
- **`keystore.path` resolution** uses `(yaml_dir / raw_path).resolve()`.
  Symlinked keystores are followed; bind-mounts work.
- **Empty `local.public`** (no content) is skipped rather than
  flagged as a mismatch — a separate hygiene problem from divergence.

---

## #3 — `tn.info(...)` silently drops extra positional args

**Severity:** critical
**Status:** Fixed in `python/tn/emit.py` and `python/tn/_handle.py`
**Tests:** `python/tests/test_emit_rejects_positionals.py` (8 cases)

### Root cause

The five verbs (`tn.log`, `.debug`, `.info`, `.warning`, `.error`)
plus the per-instance `TN.<verb>` methods passed `*args` through a
helper that joined extras into a single concatenated `message` field
(stdlib-`logger`-style brevity). The user's structured intent — what
they thought was `user=...`, `amount=...`, `currency=...` — became a
single space-separated string under `Entry.message`, and `Entry.fields`
came back empty. No warning, no error, no telemetry.

### What changed

- Removed `_absorb_positional_message` (and the equivalent inline
  block in `TN._emit`).
- New helper `_reject_extra_positionals(verb, args)` raises
  `TypeError` with a migration hint:
  ```
  tn.info(event_type, **fields) — got 3 extra positional argument(s)
  after event_type: ('user-123', 4999, 'USD'). For structured data
  use kwargs: tn.info('evt', user='alice', amount=4999). For a
  free-text message use the 'message' kwarg: tn.info('evt',
  message='hello world').
  ```
- All five module-level verbs and all five `TN.*` instance verbs
  call this helper as the first thing they do, so the rejection
  fires before any threshold short-circuit or runtime work.

### Migration path

| Old (silently mangled) | New (canonical) |
|--|--|
| `tn.info("evt", "user-123", 4999, "USD")` | `tn.info("evt", user="user-123", amount=4999, currency="USD")` |
| `tn.info("evt", "user said hi")` | `tn.info("evt", message="user said hi")` |
| `tn.info("evt", "user", "said", "hi")` | `tn.info("evt", message="user said hi")` |

### How to verify

```python
import tn
tn.init()
tn.info("payment.completed", "user-123", 4999, "USD")
# -> TypeError: tn.info(event_type, **fields) — got 3 extra positional ...
```

And the canonical kwargs form works:

```python
tn.info("payment.completed", user="user-123", amount=4999, currency="USD")
for e in tn.read():
    if e.event_type == "payment.completed":
        assert e.fields == {"amount": 4999, "currency": "USD", "user": "user-123"}
```

### Tests

| Test | Asserts |
|--|--|
| `test_module_verbs_reject_extra_positionals[info/warning/error/debug/log]` | Each of the five module-level verbs raises TypeError on `("evt", "user-123", 4999, "USD")`. |
| `test_kwargs_path_still_works` | Structured-kwargs form produces correct `Entry.fields`. |
| `test_message_kwarg_is_the_migration_path` | `message="..."` kwarg lands on `Entry.message`. |
| `test_handle_verbs_reject_extra_positionals` | Per-instance `TN.<verb>` mirrors the module-level reject. |

139 pre-existing emit/log/verb tests continue to pass.

### Risks / regressions to watch

- **This is a breaking change** for any caller relying on the
  stdlib-style positional message. We found zero such callers in
  the python tree, and the docs don't document this form. External
  alpha users WILL break if they were doing this. The fail-loud
  TypeError is intentional — the silent data loss was worse.
- The `_sign` keyword-only param is unchanged. Existing scripts
  using `_sign=False` keep working.
- TS SDK is not affected by this change (different surface).

---

## #4 — `profile=` kwarg is partially wired (telemetry/stdout still sign)

**Severity:** critical
**Status:** **Partially fixed** in `python/tn/_multi.py`
**Tests:** `python/tests/test_profile_wiring.py` (11 cases)

### Scope of this fix

Wires the `signs` bit of the profile catalog onto `ceremony.sign` in
the freshly-minted yaml. The Rust runtime already consults
`ceremony.sign` (it produces empty signatures when `False`), so this
closes the perf complaint that the `telemetry` / `stdout` profiles
were silently as expensive as `transaction`.

The other three profile axes (`chains`, `flush`, `default_sink`) are
not driven by profile in this fix. See "Out of scope" below.

### Root cause

The default-ceremony writer in `_create_default_ceremony`
(post-`config.create_fresh`) was stamping the profile *name* into
`ceremony.profile` for documentation purposes but not propagating
any of the catalog's actual fields. `ceremony.sign` stayed at the
hard-coded `True` from `config.create_fresh`'s base yaml. (The
stream-yaml writer already wired `sign: p.signs` — only the default
path was broken.)

### What changed

In `_create_default_ceremony`, after `_config.create_fresh` returns,
the stamping block now reads the profile from the catalog and writes
`ceremony.sign = profile.signs` alongside `ceremony.profile`.

### How to verify

```bash
rm -rf .tn
python -c "import tn; tn.init(profile='telemetry'); tn.info('evt', x=1); tn.flush_and_close()"
python - <<'PY'
import json, pathlib
last = json.loads(pathlib.Path(".tn/default/logs/tn.ndjson").read_text().splitlines()[-1])
print("signature_present:", bool(last.get("signature")))   # → False
import yaml
print("yaml sign:", yaml.safe_load(open(".tn/default/tn.yaml"))["ceremony"]["sign"])  # → False
PY
```

Expected: `signature_present: False`, `yaml sign: False`. Repeat with
`profile='transaction'` to confirm baseline still signs.

### Tests

| Test | Asserts |
|--|--|
| `test_profile_drives_yaml_sign[*]` (5 profiles) | Each profile name → `ceremony.sign` matches catalog `signs`. |
| `test_profile_drives_emit_signature[*]` (5 profiles) | Each profile produces (empty if signs=False, present if signs=True) `signature` on-disk. |
| `test_default_profile_signs` | Sanity: bare `tn.init()` picks `transaction` and signs. |

### Out of scope (Rust runtime follow-up)

The `chains`, `flush`, and `default_sink` profile axes are not yet
honoured by the runtime:

- **`chains=False`** would require the Rust runtime to skip the
  per-event-type `prev_hash`/`sequence` bookkeeping and emit
  envelopes without those fields. `crypto/tn-core/src/chain.rs`
  has no off-switch today. Filed as Rust crate work.
- **`flush`** maps to handler-level fsync/buffered/async behaviour
  that's already controlled by the `handlers:` block. Wiring the
  profile to defaults for this block is doable but touches handler
  config in two writers; deferred.
- **`default_sink`** for `telemetry` and `stdout` should suppress
  the file.rotating handler entirely. The stream-yaml writer
  already does this (`if p.default_sink == "file_rotating": ...`);
  the default-ceremony writer always declares both. Wiring requires
  reshaping `config.create_fresh`'s baseline yaml; deferred.

### Risks / regressions to watch

- **Existing pre-`a2` yamls** with `profile: telemetry` + `sign: true`
  on disk will continue to sign until rewritten. Re-init or manually
  edit `ceremony.sign` to align.
- **Per-emit signature path** in the Rust runtime is the same code
  whether `sign: false` or `sign: true` — we're not skipping
  Ed25519 setup, just the signing step. The "near-zero overhead"
  perf target in the catalog docstring is contingent on this
  being benchmarked + tightened as a separate workstream.

---

## #5 — `link=False` kwarg to `tn.init()` is a silent no-op

**Severity:** high
**Status:** Fixed in `python/tn/_multi.py` and `python/tn/config.py`
**Tests:** `python/tests/test_link_kwarg.py` (4 cases)

### Root cause

`tn.init`'s `link=` kwarg was wired only to the *post-init* auto-link
prompt (the IPython claim-URL display). The yaml writer
`config.create_fresh` hard-coded `mode: linked` and the production
vault URL; there was no init-time path to produce an offline,
air-gapped ceremony. The kwarg name suggested otherwise and the
report flagged it accordingly.

### What changed

- `config.create_fresh` learned a `link: bool | None = None` kwarg.
  When `link is False`, the freshly-minted yaml carries
  `ceremony.mode: local` and `ceremony.linked_vault: ""`. For
  `link=True` or `link=None` (the legacy default) the yaml stays
  `mode: linked` with the production URL — fully backwards
  compatible.
- `_create_default_ceremony` learned a `link` param and passes it
  through to `create_fresh`.
- `_ensure_ceremony_on_disk` learned a `link` param and forwards
  it to `_create_default_ceremony`.
- `_init_named_default_layout` pulls `link` from `legacy_kwargs`
  (already populated by `_build_legacy_kwargs`) and threads it
  into the chain.

The post-init auto-link block in `tn.__init__._init_impl` already
respected `link=False` (it's the `link is True or (link is None and
_in_ipython())` predicate). No change there.

### How to verify

```bash
mkdir -p /tmp/v5 && cd /tmp/v5 && rm -rf .tn
python -c "import tn; tn.init(link=False); tn.flush_and_close()"
python - <<'PY'
import yaml
doc = yaml.safe_load(open(".tn/default/tn.yaml"))
print("mode:        ", doc["ceremony"]["mode"])           # → local
print("linked_vault:", repr(doc["ceremony"]["linked_vault"]))  # → ''
PY
```

Expected: `mode: local`, `linked_vault: ''`. Repeat with `link=True`
(or no kwarg) to confirm the linked default still produces
`mode: linked` and the production URL.

### Tests

| Test | Asserts |
|--|--|
| `test_link_false_produces_local_mode` | `mode == "local"`, empty `linked_vault`. |
| `test_link_true_keeps_linked_mode` | `mode == "linked"`, non-empty URL. |
| `test_link_omitted_defaults_to_linked` | Bare `tn.init()` (no `link=`) preserves linked baseline. |
| `test_link_false_then_load_works` | An unlinked ceremony emits + reads cleanly without vault contact. |

### Risks / regressions to watch

- **The kwarg only takes effect on fresh init.** Calling
  `tn.init(link=False)` against an existing linked yaml will load
  the existing one unchanged — the same behaviour as every other
  init-time kwarg today. Operators who want to flip an existing
  ceremony to offline must edit yaml by hand or use
  `tn.wallet.unlink()` (separate verb, separate semantics).
- **`link=True` and `link=None` are still distinct** at the post-init
  auto-link step: `True` forces the prompt even outside IPython,
  `None` only fires in IPython. Yaml output is identical for
  both — both produce `mode: linked`.
- **Existing tests that pass `link=False` and assumed it was a
  pure auto-link suppressor will now also see a different yaml.**
  Search hits in your test suite for `link=False` and confirm
  expected yaml shape if you depend on it.

---

## #6 — `sign: false` in yaml + `verify=True` always fails

**Severity:** high
**Status:** Fixed in `python/tn/config.py` and `python/tn/read.py`
**Tests:** `python/tests/test_verify_respects_sign_setting.py` (4 cases)

### Root cause

`ceremony.sign: false` is a documented option that the Rust runtime
honours: emit-time, entries are written with an empty `signature`
string. But the read side ran the same signature validity check
regardless of what the writer chose. So every entry came back with
`valid = {"signature": False, "chain": True}`, and
`tn.read(verify=True)` raised `VerifyError: failed: signature` on
the very first entry — the configuration produced logs that were
"unverifiable by design."

### What changed

- `_CeremonySettings` (the yaml-to-config bridge) now extracts
  `ceremony.sign` (default `True` for back-compat with older yamls
  that didn't write the key).
- `LoadedConfig` carries the new `sign: bool` field.
- `tn.read` now consults `current_config().sign`. When that's
  `False`, the `"signature"` entry is dropped from the
  `failed_checks` list before deciding whether to raise / skip.
  Other checks (`chain`, `row_hash`, `decrypt`) continue to fire
  normally.
- If only the signature check failed on a `sign:false` ceremony,
  the entry passes verify cleanly.

### How to verify

```bash
mkdir -p /tmp/v6 && cd /tmp/v6 && rm -rf .tn
python -c "import tn; tn.init(); tn.flush_and_close()"
python - <<'PY'
import yaml, pathlib
p = pathlib.Path(".tn/default/tn.yaml")
doc = yaml.safe_load(p.read_text())
doc["ceremony"]["sign"] = False
p.write_text(yaml.safe_dump(doc, sort_keys=False))
PY
python -c "import tn; tn.init(); tn.info('nosign.evt', x=1); tn.flush_and_close()"
python -c "import tn; tn.init(); print(list(tn.read(verify=True)))"
```

Expected: list of entries (the `nosign.evt` included). Previously
this raised `VerifyError: entry seq=1 ... failed: signature`.

### Tests

| Test | Asserts |
|--|--|
| `test_sign_false_verify_true_does_not_raise` | `sign:false` + `verify=True` doesn't raise. |
| `test_sign_false_verify_true_yields_entries` | The entry actually surfaces in the iterator (not silently skipped). |
| `test_sign_true_verify_true_still_works` | Backwards-compat sanity: signed ceremonies still verify. |
| `test_sign_false_verify_skip_yields_entries` | `verify='skip'` on a `sign:false` ceremony yields rather than treating the design-empty signature as a tampered row. |

### Risks / regressions to watch

- **Other integrity checks still fire.** If a `sign:false` ceremony
  hits a *real* chain break (concurrent writes broke `prev_hash`)
  or a decrypt failure, verify will still raise / skip. Only the
  signature axis is short-circuited.
- **Mid-stream sign flip** is messy: if a ceremony was written
  with `sign:true` and then switched to `sign:false`, the early
  signed entries should still verify-with-signature. The current
  fix uses the *current* `cfg.sign` value, so post-flip reads will
  no longer demand signatures on the earlier signed entries.
  That's lenient but consistent. Don't flip mid-stream without
  also rotating the ceremony.
- **Streams inheriting from default**: `cfg.sign` is per-yaml. If
  the stream's yaml carries its own `sign:` it wins; otherwise the
  parent default's value applies via the `extends` loader.

---

## #7 — README contradicts actual `tn.read()` default

**Severity:** high
**Status:** Fixed in `python/README.md` (docs-only)
**Tests:** `python/tests/test_read_all_runs_default.py` (3 cases pinning
the contract)

### Decision

The implementation default for `tn.read()` is `all_runs=True` and was
intentionally flipped in 0.4.1a3 to match the CLI `tn read` behaviour
("show me what's in this log"). The README never got updated. The
report flagged the divergence and offered two fix paths:

1. Flip the default back to `False`.
2. Update the README.

We went with **(2) update the README** because:

- 0.4.1a3's flip was deliberate and shipped under its CHANGELOG entry;
  reverting now is a second breaking change in two minor releases.
- Operators expect `tn read` to surface every entry on disk; the CLI
  behaviour is the right anchor.
- Code that explicitly wants per-run scoping can pass
  `all_runs=False` (now documented in the README).

### What changed

- Renamed the README section "Reading: this run, all runs, admin"
  to "Reading: all runs, this run, admin" — order reflects the
  defaults.
- Flipped the example narrative: bare `tn.read()` now demonstrates
  the cross-run view, with `all_runs=False` as the opt-in for the
  this-run-only view.
- Troubleshooting table entry updated to reflect the new default.
- Added a note explaining the 0.4.1a3 alignment.

### How to verify

- Open `python/README.md`, find "Reading: all runs, this run, admin".
  Confirm the example block uses `tn.read()` for the cross-run case
  and `tn.read(all_runs=False)` for the per-run case.
- `inspect.signature(tn.read).parameters["all_runs"].default is True`.

### Tests

| Test | Asserts |
|--|--|
| `test_read_signature_default_is_all_runs_true` | Pins the signature default. If you flip it, this test fires, forcing a coordinated README update. |
| `test_default_read_sees_previous_runs` | Cross-process read: A writes, B's bare `tn.read()` sees A's marker. |
| `test_all_runs_false_restricts_to_current_run` | `all_runs=False` correctly filters to the current process run. |

### Risks / regressions to watch

- **Any docs / examples / scenarios still showing the old "this
  run only" framing.** Grep for "this process's run" /
  "fresh `python hello.py` clean" across the docs tree before
  shipping.
- **The TS SDK** mirrors the Python contract. Confirm
  `ts-sdk/src/tn.ts` `ReadOptions` documents `allRuns` consistently
  (out of scope for this PR; flag if mismatched).

---

## #8 — `tn.ensure_group()` doesn't hot-reload in the calling process

**Severity:** medium
**Status:** Fixed in `python/tn/admin/__init__.py`,
`python/tn/logger.py`, `python/tn/_dispatch.py`
**Tests:** `python/tests/test_ensure_group_hot_reload.py` (3 cases)

### Root cause

`ensure_group` correctly:
1. Wrote the new group to `tn.yaml`
2. Updated the in-memory `cfg.groups` and `cfg.field_to_groups`
3. Emitted the `tn.group.added` admin event

But the *Rust dispatch runtime* (`_dispatch_rt._rt = _RustRuntime.init(yaml)`)
caches its own view of group keys + field routing at init time and has
no observer pattern. Subsequent emits in the same process consulted
the cached view and routed all fields through `default`. The docstring
acknowledged the limitation and told callers to `flush_and_close() +
tn.init()` — but most users don't read docstrings before reaching for
the verb.

### What changed

- **`DispatchRuntime.reload()`** — new method on the Rust-backed
  dispatch runtime. Re-runs `_RustRuntime.init` against the current
  yaml (resolving `extends:` if present). The Rust runtime's init
  loads existing keystore material; pre-existing chain state is
  preserved, no fresh keys are minted.
- **`tn.logger.reload_from_yaml()`** — new top-level helper. Re-reads
  yaml into the active `TNRuntime.cfg`, then calls
  `_dispatch_rt.reload()`. Quiet: does not re-emit `tn.ceremony.init`
  or other init-time admin events.
- **`tn.admin.ensure_group`** — at the end, after the yaml write and
  the admin event emit, calls `tn.logger.reload_from_yaml()`.
  Best-effort: a reload failure is logged and ensure_group still
  returns (the on-disk write is durable; the next process will see
  the new group regardless).

### How to verify

```python
import tn
tn.init()
cfg = tn.current_config()
tn.ensure_group(cfg, "finance", fields=["amount"])
tn.info("order.created", amount=4999, notes="hi")
tn.flush_and_close()

import json, pathlib
last = json.loads(
    pathlib.Path(".tn/default/logs/tn.ndjson")
        .read_text().splitlines()[-1]
)
groups = [k for k in last if isinstance(last[k], dict) and "ciphertext" in last[k]]
print("groups:", sorted(groups))   # → ['default', 'finance']
```

Expected: both `default` and `finance` ciphertexts on the entry.
Prior to 0.4.2a2, only `default` appeared.

### Tests

| Test | Asserts |
|--|--|
| `test_ensure_group_makes_new_routing_visible_same_process` | Headline fix: same-process emit after `ensure_group` writes to both `default` and the new group. |
| `test_ensure_group_persists_across_process_boundary` | Cross-process case (previously working) still works. |
| `test_ensure_group_idempotent_second_call` | Calling `ensure_group(..., fields=[f])` twice doesn't double-route `f`. |

### Risks / regressions to watch

- **Per-handle (`TN`) state** vs module-level. `reload_from_yaml`
  rebinds the module-level singleton's view. Callers using
  `handle = tn.init('billing'); handle.info(...)` against a
  per-handle runtime get the singleton-only refresh. The
  per-handle TN's underlying runtime is reused when it
  matches the singleton, so single-ceremony deploys are fine;
  multi-ceremony deploys with a stale non-singleton handle need
  to either re-acquire the handle or call `tn.init` again.
- **Rust runtime re-init cost** — measured under 5 ms on a local
  filesystem on the test machine; effectively a no-op for chain
  state because the keystore material loads from disk unchanged.
  Don't call `ensure_group` in a hot loop.
- **Duplicate `tn.ceremony.init` emission** — the reload path goes
  out of its way NOT to re-emit init-time admin events. If your
  audit log contains spurious init events after this fix, file a
  ticket; we'll trace the missing suppression point.

---

## Profile audit — `transaction` / `audit` / `secure_log` / `telemetry` / `stdout`

**Status:** Two of four axes wired; two require Rust runtime work
**Tests:** `python/tests/test_profile_full_matrix.py` (15 pass + 8 xfailed = full matrix captured)
**Docs:** `python/README.md` "Profiles" section now lists the catalog,
one example per profile, and the wired-vs-gap matrix.

### What the catalog promises

Source of truth: `tn._profiles._CATALOG`. Each profile bundles four
axes (encryption is always on as the floor):

| Profile | signs | chains | flush | default_sink |
|--|--|--|--|--|
| transaction | yes | yes | fsync | file_rotating |
| audit | yes | yes | buffered | file_rotating |
| secure_log | yes | no | buffered | file_rotating |
| telemetry | no | no | async | stdout |
| stdout | no | no | async | stdout |

### What 0.4.2a2 actually wires

| Axis | Status | Notes |
|--|--|--|
| `signs` | **wired** | `_create_default_ceremony` and `_create_stream_yaml` both stamp `ceremony.sign = profile.signs` into yaml. The Rust runtime honours this — entries from `telemetry` / `stdout` carry empty `signature` values. |
| `default_sink` | **wired** | Default-ceremony writer (this PR) and stream-yaml writer (pre-existing) both drop the `file.rotating` handler when `profile.default_sink == "stdout"`. Telemetry / stdout ceremonies are now genuinely file-free. |
| `chains` | **GAP (Rust runtime)** | `crypto/tn-core/src/chain.rs` has no off-switch; the chain advances on every emit regardless of `ceremony.chain`. Profiles claiming `chains=False` (secure_log, telemetry, stdout) still emit `prev_hash` + `sequence` on disk. |
| `flush` | **GAP (Rust runtime + Python handler config)** | The catalog's `flush: fsync / buffered / async` axis has no corresponding field on the handler dicts; today the Rust file handler's fsync behaviour is fixed at build time. Wiring this requires a new handler-level `flush:` field plus runtime support to honour it per-emit. |

### How to verify

```bash
cd C:/codex/tn/tn_proto/python
rtk proxy python -m pytest tests/test_profile_full_matrix.py -v
# expect: 15 passed, 8 xfailed
```

The 8 xfailed cases pin the documented gaps. Once Rust grows the
chain off-switch and a handler-level flush field, those xfails flip
to xpass and you'll know to remove the `pytest.xfail` markers.

### Per-axis acceptance

| Test | What it asserts |
|--|--|
| `test_signs_axis_wired_in_yaml[*]` (5) | `ceremony.sign` in yaml matches `catalog[profile].signs`. |
| `test_signs_axis_wired_in_emit[*]` (5) | On-disk `signature` is empty iff `signs=False` (with skip for stdout-only ceremonies that have no file log). |
| `test_chains_axis_GAP[secure_log/telemetry/stdout]` | XFAIL while runtime ignores `chains=False`. |
| `test_default_sink_axis_GAP[telemetry/stdout]` | Default-ceremony yaml does NOT carry a file.rotating handler. |
| `test_stream_yaml_honors_default_sink_stdout[telemetry/stdout]` | Stream yamls obey `default_sink` (this path was already correct; pinned to prevent regression). |
| `test_flush_axis_GAP[*]` (5) | XFAIL while handler dicts have no flush field. |
| `test_catalog_has_five_documented_profiles` | Catalog change detector. |

### Risks / regressions to watch

- **Existing pre-0.4.2a2 yamls** with `profile: telemetry` + a
  `file.rotating` handler on disk will continue to write to that
  file. The new behaviour only fires on a *fresh* `tn.init`. To
  retrofit, delete and re-mint the ceremony or edit the yaml by
  hand.
- **`tn.read()` on a stdout-only ceremony** returns empty (no log
  to read). The catalog method `Profile.has_replay_surface()`
  already returned `False` for these profiles; the runtime behaviour
  now matches.
- **The two unwired axes (`chains`, `flush`) ship as documented
  gaps.** Code paths that assumed full implementation should
  inspect `Profile.chains` / `.flush` themselves until the runtime
  catches up.

---

## #10 + #11 — Read-side observability: parse-error halt and silent `verify='skip'`

**Severity:** medium (both)
**Status:** Fixed in `python/tn/read.py`
**Tests:** `python/tests/test_read_skip_observability.py` (7 cases)

These two findings share one underlying surface (read-side observability),
so they got one coordinated fix:

- **#11** was silent: `verify='skip'` dropped failing rows with no
  count, no callback, no way to know whether 0 or 50,000 entries
  were skipped.
- **#10** had no observable signal at all: parse failures under
  `verify=True` raised straight out, callers couldn't react before
  the exception.

The user-confirmed design (see DX_FIXES discussion):

- `verify=False` (default): **UNCHANGED** — parse errors raise as
  today. Callers who rely on this fail-loud contract are safe.
- `verify=True`: gains an optional `on_skip` callback that fires
  *before* the raise. One terminal observer call, then the
  `VerifyError` propagates. Production callers can log / alert /
  metric before the exception lands.
- `verify='skip'`: gains the same `on_skip` callback (per-row),
  populates the new `.stats` attribute (`ReadStats`), and continues
  to emit `tn.read.tampered_row_skipped` admin events as before.

### What changed

- New public types `tn.read.ReadStats` (dataclass:
  `yielded`, `skipped_parse`, `skipped_verify`,
  `skipped_reasons: list[str]`) and `tn.read._ReadIterator` (the
  iterator wrapper that carries `.stats`).
- `tn.read(...)` returns `_ReadIterator` instead of a bare
  generator. Iteration protocol is unchanged (`for e in
  tn.read(): ...` works exactly as before); `.stats` is an
  attribute on the returned object that ticks incrementally
  during iteration.
- New optional kwarg `on_skip: Callable[[envelope_dict, reason_str],
  None]`. Fires:
  - Before any raise under `verify=True`.
  - For every dropped row under `verify='skip'`.
  - Never under `verify=False` (preserves the unchanged contract).
- Buggy callbacks that raise are caught and logged via
  `logging.getLogger("tn.read")` so they can't tank the read loop.

### How to verify

```python
import tn
tn.init()
tn.info("a", x=1); tn.info("b", x=2); tn.info("c", x=3)
tn.flush_and_close()

# Tamper with entry 2's plaintext event_type.
import json, pathlib
log = pathlib.Path(".tn/default/logs/tn.ndjson")
lines = log.read_text().splitlines()
doc = json.loads(lines[1])
doc["event_type"] = "<TAMPERED>"
lines[1] = json.dumps(doc)
log.write_text("\n".join(lines) + "\n")

# Resilient read with observability:
tn.init()
seen = []
result = tn.read(verify="skip", on_skip=lambda env, why: seen.append((env, why)))
out = [e.event_type for e in result]
print("yielded:", out)                # ['a', 'c']
print("skipped:", result.stats.skipped_verify)   # 1
print("reasons:", result.stats.skipped_reasons)  # ['<integrity axis>']
print("observer fired:", len(seen))   # 1

# verify=True with on_skip — one final observer call before the raise:
seen.clear()
try:
    list(tn.read(verify=True, on_skip=lambda env, why: seen.append((env, why))))
except Exception:
    print("raised after", len(seen), "observer call")   # raised after 1 observer call
```

### Tests

| Test | Asserts |
|--|--|
| `test_skip_mode_returns_stats` | `verify='skip'` populates `result.stats.yielded` + `skipped_verify` + `skipped_reasons`. |
| `test_skip_mode_fires_on_skip_callback` | `on_skip(env, reason)` fires per skipped row under `verify='skip'`. |
| `test_verify_true_fires_callback_before_raise` | `verify=True` + `on_skip` fires the callback once before the `VerifyError` propagates. Stats reflect the partial run. |
| `test_default_verify_false_unchanged` | Sanity baseline: clean log under `verify=False` yields every entry, `skipped_*` stays at 0. |
| `test_verify_false_still_raises_on_parse_error` | The `verify=False` raise-on-parse contract is preserved (no behaviour change). |
| `test_on_skip_callback_exceptions_dont_break_iteration` | A buggy observer raising RuntimeError doesn't tank the read loop. |
| `test_stats_partial_consumption` | Stats tick incrementally during iteration; early `break` shows partial counts. |

### Risks / regressions to watch

- ~~**#10 parse-error resilience is partial.**~~ **Closed in
  0.4.2a3.** The Rust read pipeline (`read_from`,
  `read_from_with_validity`) now wraps each row's body so per-row
  failures (JSON parse, base64 decode, post-decrypt plaintext
  json) yield a sentinel envelope (`event_type == "<parse-error>"`)
  and iteration continues. The Python verify loop routes the
  sentinel into `stats.skipped_parse` (distinct from
  `skipped_verify`) and fires `on_skip` with a `parse:`-prefixed
  reason. Clean rows on either side of a bad one now both yield.
  See `python/tests/test_read_parse_resilience.py`.
- **Return type change** — `tn.read` previously returned `Iterator[Entry]`;
  it now returns `_ReadIterator`. The iteration protocol is preserved
  so consumers using `for e in tn.read(): ...` are unaffected. Callers
  who type-annotated the return value as `Generator[Entry, ...]`
  may need to update to `Iterable[Entry]` or `_ReadIterator`.
- **`verify=True` callback fires once, then raises.** If your
  callback was a long-running operation, the exception still
  propagates after it returns. Don't block forever in the
  callback.
- **`on_skip` is called inside the read loop.** It runs on the
  caller's thread; do quick work and move on. For heavy logging,
  enqueue the entry into your own queue.

---

## #13 — `tn.log` naming + missing level affordance

**Severity:** low
**Status:** Fixed in `python/tn/emit.py`, `python/tn/_handle.py`,
`python/README.md`
**Tests:** `python/tests/test_log_level_kwarg_and_verify_typing.py` (5 cases)

### Root cause

`tn.log` looked like it should take a level (matching stdlib
`logging.log(level, msg, ...)`) but actually had the same signature
as `tn.info` and emitted with the severity-less slot
(`Entry.level == ""`). The README grouped `.log` with the level-named
verbs (`.info` / `.warning` / `.error` / `.debug`) which reinforced
the misconception.

A user reaching for it by analogy (`tn.log("info", "payment.completed",
amount=100)`) got `event_type="info"`, the actual event name
swallowed as a positional, and `level=""`. After the #3 fix that
silent drop became a `TypeError`, but the underlying naming
confusion remained.

### What changed

- `tn.log` (module-level) and `TN.log` (per-handle) both gained an
  optional `level: str = ""` keyword. Default behaviour is
  unchanged (severity-less).
- Sharpened both docstrings: "not an alias of the named-level
  verbs; always emits regardless of threshold; pass `level=` to
  stamp a custom level."
- README's verb table separates `tn.log` from `.info / .warning /
  .error / .debug` and includes a short "tn.log vs the level
  verbs" section with examples.

### Usage

```python
tn.info("user.signed_in", user="alice")           # level="info"  (threshold-aware)
tn.log("user.signed_in", user="alice")            # level=""     (always emits)
tn.log("scan.tick", level="trace", phase="hi")    # level="trace" (custom)
tn.log("bridged", level=loguru_record["level"])   # foreign-logger bridge
```

### Tests

| Test | Asserts |
|--|--|
| `test_tn_log_default_level_is_empty_string` | Bare `tn.log("e")` keeps level="". |
| `test_tn_log_with_level_kwarg` | `level="trace"` lands on `Entry.level`. |
| `test_tn_log_with_level_emits_regardless_of_threshold` | `tn.set_level("error")` doesn't suppress `tn.log(..., level="info")`. |
| `test_tn_handle_log_level_kwarg` | Per-instance `TN.log` mirrors the module-level signature. |
| `test_tn_log_still_rejects_extra_positionals` | The #3 protection holds. |

### Risks / regressions to watch

- **The `level` kwarg is keyword-only.** Calling
  `tn.log("e", "info")` still raises TypeError from the #3 fix.
  The TypeError message points users at `message=` for free text;
  if you intended a level, write `level="info"`.
- **`tn.log` always emits.** Threshold filtering (`tn.set_level`)
  doesn't apply. If you want threshold-aware semantics with a
  custom level, build your own filter via the `where=` predicate
  on `tn.read` / `tn.watch`.

---

## #14 — `tn.init('billing')` materializes `.tn/default/` as a side effect

**Severity:** low
**Status:** Docs-only fix in `python/tn/_multi.py` (`tn.init`
docstring + inline comment) and `python/README.md`
**Tests:** none (no behaviour change)

### Decision

The auto-create of `.tn/default/` when minting a named ceremony is
**architecturally load-bearing, not a bug**. Named ceremonies are
*streams* that share the project's identity (DID + signing key)
which lives at `.tn/default/keys/`. The stream's yaml carries
`extends: ../default/tn.yaml`; the loader pulls identity, keystore,
groups, and recipients from default at config-load time. Removing
the auto-create would leave the stream unable to encrypt anything.

The fix is purely communication:

- `tn.init`'s docstring now explicitly calls out the side effect
  on the named-ceremony shape, with a pointer at the
  `yaml_path=` form for callers who want a truly self-contained
  ceremony.
- A new inline comment in `tn.init`'s named-ceremony dispatch
  block explains the architecture for future readers.
- New README section "Project identity and named streams" walks
  through the on-disk layout, why default exists, and when to
  reach for `yaml_path=` instead.

### How to verify

- Read [tn.init's docstring](python/tn/_multi.py) — the "Common
  shapes" section under `tn.init("payments")` now mentions the
  side effect.
- Read [README "Project identity and named streams"](python/README.md)
  — explains the model with the directory tree.

### Risks / regressions to watch

- **Documentation drift.** If the underlying architecture changes
  (e.g. streams gain self-contained mode), update both the
  docstring and the README section together.
- **`tn.init(yaml_path=...)` as the standalone path** is the
  documented escape hatch. If that path stops working as the
  README claims, the workaround vanishes.

---

## #17 — `verify=True` and `verify='raise'` are synonyms; type was `bool | str`

**Severity:** nit
**Status:** Fixed in `python/tn/read.py`
**Tests:** `python/tests/test_log_level_kwarg_and_verify_typing.py` (6 cases)

### Decision

Kept both `True` and `'raise'` as legal values (user's call —
preserves any code spelling either form), but tightened the type
annotation from `bool | str` to `bool | Literal["skip", "raise"]`.
IDEs now autocomplete the legal string values; passing a string
that isn't `"skip"` or `"raise"` is a type error at the call site
and a `ValueError` at runtime.

### What changed

- `_check_verify_kwarg`'s parameter type annotation:
  `bool | str` → `bool | Literal["skip", "raise"]`.
- `tn.read`'s overloads and main signature: same change.
- `tn.watch`'s signature: same change.
- Docstring on `_check_verify_kwarg` now lists the four legal
  values + their behaviour + the synonym note.

### How to verify

```python
import inspect, tn
print(inspect.signature(tn.read).parameters["verify"].annotation)
# bool | Literal['skip', 'raise']
```

IDEs like Pylance / Pyright autocomplete `'skip'` / `'raise'`
inside `tn.read(verify=...)`.

### Tests

| Test | Asserts |
|--|--|
| `test_verify_type_annotation_uses_literal` | Annotation includes `Literal['skip', 'raise']`. Pins it against accidental widening. |
| `test_verify_validator_accepts_legal_values[False/True/skip/raise]` (4) | All four values pass `_check_verify_kwarg`. |
| `test_verify_validator_rejects_unknown_strings` | `"strict"` raises `ValueError` with a clear list of legal values. |

### Risks / regressions to watch

- **`'raise'` still works** — code spelling `verify='raise'` is
  unchanged.
- **Strict type checkers may flag old callers** passing dynamic
  strings (`verify=some_str_var`). They'll either narrow the
  variable's type or get a Pyright warning. Runtime behaviour is
  unchanged.

---
