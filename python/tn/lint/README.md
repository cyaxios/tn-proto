# tn.lint

Static analyzer for the TN logging protocol. Walks Python source, cross-references a project's `tn.yaml` plus any extended industry packs, and reports violations.

## Usage

```bash
# Default: lint the current directory using the nearest tn.yaml
python -m tn.lint

# Lint a specific path
python -m tn.lint src/

# JSON output for CI
python -m tn.lint --json src/ > lint-report.json

# Subset of rules
python -m tn.lint --rules R1,R3 src/

# Skip the extends: list (project-only mode)
python -m tn.lint --no-extends src/
```

Exit codes follow the flake8/mypy convention:

| Code | Meaning |
|------|---------|
| 0    | No findings |
| 1    | One or more findings |
| 2    | Config error (no tn.yaml, invalid YAML, conflicting `forbidden_post_auth` override) |

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| R1 | error    | PII pattern in `event_type` literal (email, card-shape digits, JWT, SSN). |
| R2 | warning  | Undeclared field used as a `tn.*(...)` kwarg. |
| R3 | error    | `forbidden_post_auth` field referenced in a logged call (CVV, PIN, full track data, etc.). |
| R4 | (stub)   | Plain `print()`/`logger.*` in sensitive code paths (db/http/payment/auth). Future work. |
| R5 | (stub)   | Project group's policy disagrees with the inherited pack policy. Future work. |

R1 looks at the first positional argument of every `tn.info`, `tn.warning`, `tn.error`, `tn.attest`, or `tn.log` call. If it is a string literal, it is scanned against the PII regex set. R2 looks at every kwarg name and complains when the name is not in `tn.yaml` `fields`, `public_fields`, or any extended pack's `fields`. R3 fires for any kwarg whose name appears in the union of `forbidden_post_auth: true` fields across extended packs.

## The `extends:` list in tn.yaml

`tn.lint` adds support for a top-level `extends:` list on `tn.yaml`. Each entry is either a pack id or a path:

```yaml
extends:
  - pci-cardholder              # pack id, resolved against the search path
  - oauth-oidc
  - ./packs/internal-domain.yaml  # explicit path, relative to tn.yaml
```

### Resolution order for a pack id

1. `<tn.yaml dir>/industry-agents/<id>.yaml`
2. `<tn.yaml dir>/packs/<id>.yaml`
3. `<repo root>/tnproto-org/static/industry-agents/<id>.yaml` (dev fallback for in-tree work)

### Merge semantics

Pack `groups` and `fields` are applied first, the project's own `groups` and `fields` override them. A project may not move a `forbidden_post_auth: true` field into a public-policy group. Doing so is a config error and surfaces as exit code 2.

## Reserved kwargs

These kwarg names are protocol-reserved and never flagged by R2:

```
correlation_id, request_id, event_id, level, timestamp, event_type
```

## Tests

```bash
.venv/Scripts/python.exe -m pytest tn-protocol/python/tn/lint/tests/
```

The fixtures under `tests/fixtures/` cover one violation per active rule plus a clean baseline. The fixture `tn.yaml` extends the real `pci-cardholder` pack from the repo, so R3 exercises the actual `forbidden_post_auth` set.

## Architecture

| File | What |
|------|------|
| `cli.py` | Arg parsing, output formatting, exit codes. |
| `config.py` | Loads `tn.yaml`, resolves `extends:`, returns a frozen `LintConfig`. |
| `engine.py` | AST walker that finds `tn.<method>(...)` calls and dispatches to rules. |
| `rules.py` | `Rule` protocol and `R1`-`R5` implementations. |
| `findings.py` | `Finding` dataclass, with sort key and human/JSON formatters. |
| `__main__.py` | Module entry point so `python -m tn.lint` works. |

## Future work

- R4: AST-walk function bodies for `print()`, `logger.*`, `logging.*`, `sys.stdout` / `sys.stderr` in functions that contain DB writes, HTTP calls, payment ops, or auth ops.
- R5: cross-check project group's `policy` against the same group's policy in any extended pack.
- A `tn lint --add-pack <id>` helper that updates `extends:` and a sibling `tn lint --check-coverage` that reports which pack fields are referenced anywhere in source.
- A pre-commit hook configuration in `.pre-commit-hooks.yaml`.
- TypeScript / JavaScript source support via `@typescript-eslint/parser`.
