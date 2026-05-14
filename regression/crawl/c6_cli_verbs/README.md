# C6 — `tn` CLI verbs

**Status: scaffolded, no tests yet. Implemented in the C6 PR.**

## What this silo proves

The CLI surface that operators (not library callers) reach for:

```bash
$ tn init payments
$ tn add_recipient default --recipient-did did:key:z6Mk...
$ tn rotate default
$ tn read
```

Each verb produces the right side effects on disk (yaml + keystore +
log) AND the CLI exit code accurately reflects success/failure.

## Why it's load-bearing

Operators use the CLI from cron jobs, shell scripts, CI pipelines.
Library-tier tests don't catch CLI argument-parsing regressions,
exit-code regressions, or subprocess-context bugs (env var
propagation, signal handling, etc.).

## Code paths exercised

- `python/tn/cli.py` — every verb's entry point + flag parsing
- Subprocess-level: invoked via `subprocess.run([sys.executable, "-m", "tn.cli", ...])`
- `python/tn/__main__.py` — module entry shim

## Tests to add (in the C6 PR)

- `test_tn_init_creates_ceremony.py` — `tn init <name>` produces valid yaml + keystore
- `test_tn_add_recipient_updates_yaml.py` — after `tn add_recipient`, ceremony yaml lists the recipient
- `test_tn_rotate_advances_keystore.py` — `tn rotate` produces a new epoch + new state
- `test_tn_read_lists_entries.py` — `tn read` exit 0 + writes envelopes to stdout in NDJSON
- `test_tn_exit_codes.py` — invalid args exit non-zero with a useful error message

## How to run only this silo

```bash
make -C regression c6
# or
pytest regression/crawl/c6_cli_verbs -v
```

## Failure investigation guide (skeleton)

| symptom | first place to look |
|---|---|
| CLI exits 0 but no files appear | `cli.py:cmd_init` — verify side effects are actually performed |
| CLI exits non-zero on valid args | `cli.py:_argparse` setup; check that subcommand names match |
| Output goes to stderr not stdout | `cli.py` — print routing; spec is "envelopes to stdout, status to stderr" |
| Yaml gets mangled after `add_recipient` | `admin/__init__.py:add_recipient` write step + `config.py:_dump_yaml` |
