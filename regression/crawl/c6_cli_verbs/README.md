# C6 — `tn` CLI verbs

## What this silo proves

The `tn` CLI surface (the operator-facing path, not the library-tier
verbs):

```bash
$ python -m tn.cli init <projectdir>
$ python -m tn.cli add_recipient default did:key:zAlice --yaml ...
$ python -m tn.cli rotate default --yaml ...
$ python -m tn.cli read --yaml ...
```

Each verb produces the right side effects on disk (yaml + keystore +
log + .tnpkg artifacts) AND the CLI exit code accurately reflects
success/failure.

## Why it's load-bearing

Operators use the CLI from cron jobs, shell scripts, CI pipelines.
Library-tier tests don't catch:

* argparse regressions (a renamed flag silently no-ops via the default)
* exit-code regressions (cron expects `tn rotate` to exit non-zero on
  failure; if it always exits 0 the operator never knows)
* subprocess-context bugs (env var propagation, TN_NO_STDOUT default,
  the cwd-vs-discovery interaction)
* stdout/stderr separation (stderr scraping is how CI tooling parses
  TN output)

## Code paths exercised

- `python/tn/cli.py` — every verb's entry point + flag parsing
- Subprocess wire: `_shared/fixtures.py` re-exports + a `cli_run`
  helper in this silo's conftest that invokes `python -m tn.cli ...`
  against the hermetic machine

## Tests in this silo

- `test_tn_init_creates_ceremony.py` — `tn init <dir>` produces yaml +
  keystore + .tn/ subdir; exit 0; stdout mentions DID.
- `test_tn_add_recipient_writes_pkg.py` — after init,
  `tn add_recipient default <did>` writes a .tnpkg artifact + the
  ceremony's admin log records `tn.recipient.added`.
- `test_tn_rotate_bumps_epoch.py` — after a `tn add_recipient`, a
  `tn rotate default` bumps the group's `index_epoch` and writes
  rotated kit packages.
- `test_tn_exit_codes.py` — invalid verb → non-zero exit + readable
  error message; missing required positional → non-zero with help-
  pointer.

## How to run only this silo

```
make c6
# or
pytest regression/crawl/c6_cli_verbs -v
```

No vault contact — TN_NO_LINK is set by hermetic_machine.

## Failure investigation guide

| symptom | first place to look |
|---|---|
| `tn init` exits 0 but writes nothing | `python/tn/cli.py:cmd_init` — likely an exception swallowed before writing |
| `tn add_recipient` writes wrong DID | `cli.py:cmd_add_recipient` recipient-label normalization (`did:key:zLabel-...` prefix) |
| `tn rotate` exits 0 but doesn't bump epoch | `cli.py:cmd_rotate` group resolution + `python/tn/admin/__init__.py:rotate` actual mutation |
| Exit code 0 on bad args | argparse must have `required=True` on positionals; missing positional should fall through `_die` with code=2 |
| stderr empty on failure | `_die` should write to stderr not stdout |
