"""Attested-log query DSL for TN-native assertions.

Whenever a regression test is checking TN's own protocol output
(envelopes in an attested log), the assertion should go through
`LogQuery.assert_contains(...)` — NOT a bare equality check, NOT
plumbed through generic `assert_named`.

Why a dedicated DSL: log queries have a specific failure-output shape
that's much more useful than "expected list with item, got list."
On miss we want:

- The named predicate spelled out.
- A summary of what IS in the log (event_type counts, latest sequence).
- A "closest match" envelope if one exists (same event_type, different fields).
- A pointer to where the test thinks the envelope should have come from.

The query operates against the raw attested log file (NDJSON). It does
NOT depend on `tn` being initialized — every regression test should be
able to read any log by path, regardless of whether the runtime that
produced it is alive.

See `_shared/README.md` for the contract + Style-1 example.
"""
from __future__ import annotations

import dataclasses
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from regression._shared.assertions import (
    AssertionRecord,
    NamedAssertionError,
    _record,
    _resolve_silo,
    _resolve_test,
)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Envelope:
    """One row from an attested NDJSON log. Holds the raw dict + a
    convenience accessor for top-level fields."""

    raw: dict[str, Any]

    def __getitem__(self, key: str) -> Any:
        return self.raw.get(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    @property
    def event_type(self) -> str:
        return str(self.raw.get("event_type", ""))

    @property
    def sequence(self) -> int:
        s = self.raw.get("sequence")
        return int(s) if isinstance(s, int) else 0

    @property
    def row_hash(self) -> str:
        return str(self.raw.get("row_hash", ""))


class LogQuery:
    """Query against one or more attested NDJSON log files.

    Construct with:
        - `ceremony_path=<path>` — yaml file; reads its resolved
          `logs.path` plus the admin log if separate. Use this when
          you have a `LoadedConfig`-style ceremony in scope.
        - `log_paths=[<path>, <path>, …]` — explicit file list. Use
          this when the test knows exactly which logs to inspect.

    Methods:
        - `envelopes()` — iterator over all envelopes in chrono order.
        - `find_all(where=...)` — list of matching envelopes.
        - `find_one(where=...)` — first match or None.
        - `assert_contains(name=..., where=..., on_miss=...)` — named
          assertion; fails with a structured report on miss.
    """

    def __init__(
        self,
        *,
        ceremony_path: Path | str | None = None,
        log_paths: list[Path | str] | None = None,
    ) -> None:
        if ceremony_path and log_paths:
            raise ValueError(
                "LogQuery: pass either ceremony_path OR log_paths, not both"
            )
        if not ceremony_path and not log_paths:
            raise ValueError(
                "LogQuery: must pass ceremony_path or log_paths"
            )

        if ceremony_path:
            self._log_paths = _resolve_ceremony_logs(Path(ceremony_path))
        else:
            assert log_paths is not None  # narrow for type-checkers
            self._log_paths = [Path(p) for p in log_paths]

    # -- read paths ---------------------------------------------------------

    def envelopes(self) -> Iterator[Envelope]:
        """Yield every envelope from every log path in chronological
        order. Skips malformed lines silently — a regression test on
        malformed data should assert on the malformed-line case
        explicitly, not rely on the iterator to crash."""
        rows: list[tuple[str, dict[str, Any]]] = []
        for path in self._log_paths:
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    env = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(env, dict):
                    continue
                ts = str(env.get("timestamp", ""))
                rows.append((ts, env))
        rows.sort(key=lambda r: r[0])
        for _, env in rows:
            yield Envelope(env)

    # -- find -------------------------------------------------------------

    def find_all(self, *, where: dict[str, Any]) -> list[Envelope]:
        """All envelopes matching every key/value in `where`. Top-level
        envelope fields only (no plaintext-group field matching yet —
        decryption is the runtime's job, not the assertion's)."""
        out: list[Envelope] = []
        for env in self.envelopes():
            if _matches(env.raw, where):
                out.append(env)
        return out

    def find_one(self, *, where: dict[str, Any]) -> Envelope | None:
        for env in self.envelopes():
            if _matches(env.raw, where):
                return env
        return None

    def event_type_counts(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for env in self.envelopes():
            c[env.event_type] += 1
        return dict(c)

    # -- named assertion --------------------------------------------------

    def assert_contains(
        self,
        *,
        name: str,
        where: dict[str, Any],
        on_miss: str | None = None,
    ) -> Envelope:
        """Assert at least one envelope matches `where`. Returns the
        first match for further inspection (caller can chain
        additional checks).

        On miss:
            - Prints the named predicate.
            - Prints the event_type histogram for the log.
            - Prints the "closest match" (same event_type, different
              fields) if one exists — usually the right next thing
              to look at.
            - Prints the operator-supplied `on_miss` pointer.
        """
        matches = self.find_all(where=where)
        silo = _resolve_silo()
        test = _resolve_test()

        if matches:
            _record(
                AssertionRecord(
                    name=name,
                    style="log-query",
                    passed=True,
                    expected=f"at least 1 envelope where {_pp(where)}",
                    observed=f"{len(matches)} match(es)",
                    on_miss=on_miss or "",
                    silo=silo,
                    test=test,
                )
            )
            return matches[0]

        # MISS — build the structured failure report.
        et = where.get("event_type")
        counts = self.event_type_counts()
        closest = _find_closest(self.envelopes(), where) if et else None
        miss_pointer = on_miss or "(no pointer supplied — add `on_miss=` to the assertion)"

        observed_repr = (
            f"no envelope matched; event_type counts in log = "
            f"{_pp(counts)}; closest match = {_pp(closest.raw) if closest else 'none'}"
        )

        _record(
            AssertionRecord(
                name=name,
                style="log-query",
                passed=False,
                expected=f"at least 1 envelope where {_pp(where)}",
                observed=observed_repr,
                on_miss=miss_pointer,
                silo=silo,
                test=test,
            )
        )

        msg_lines = [
            f"ASSERTION FAILED: {name}",
            f"  silo: {silo}",
            f"  test: {test}",
            f"  style: log-query",
            f"  predicate: {_pp(where)}",
            f"  observed in log:",
            f"    paths: {[str(p) for p in self._log_paths]}",
            f"    total event_types: {_pp(counts)}",
        ]
        if closest is not None:
            msg_lines.append(f"  closest match (same event_type): {_pp(closest.raw)}")
        else:
            msg_lines.append(f"  closest match: <none — no envelope had event_type={et!r}>")
        msg_lines.append(f"  look at: {miss_pointer}")
        raise NamedAssertionError("\n".join(msg_lines))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matches(env: dict[str, Any], where: dict[str, Any]) -> bool:
    """Predicate: every (k, v) in `where` must equal env[k]. Missing
    keys count as a miss; nested matching is NOT supported (assertion
    on group-plaintext requires decryption, out of scope for
    log-level queries)."""
    for k, v in where.items():
        if env.get(k) != v:
            return False
    return True


def _find_closest(
    envs: Iterator[Envelope], where: dict[str, Any]
) -> Envelope | None:
    """Best-effort: an envelope with matching event_type but
    differing on at least one other key. Helpful in failure output
    so the maintainer can see "you got a tn.recipient.added but for
    a different DID."""
    et = where.get("event_type")
    if not et:
        return None
    for env in envs:
        if env.event_type == et:
            return env
    return None


def _pp(value: Any) -> str:
    """Compact repr suitable for failure messages — never None,
    never raises."""
    if value is None:
        return "None"
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return repr(value)


def _resolve_ceremony_logs(yaml_path: Path) -> list[Path]:
    """Resolve a ceremony yaml to its log file list (main + admin if
    separate). Hand-rolled; does NOT depend on `tn.config.load()`
    because we want the regression suite to be inspectable even when
    the runtime is broken.

    Convention: read just enough yaml to find `logs.path` and
    optionally `ceremony.admin_log_location`. PyYAML is a hard dep
    of tn-protocol so it's always available.
    """
    import yaml

    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(doc, dict):
        return []

    base = yaml_path.parent
    paths: list[Path] = []

    logs = doc.get("logs") or {}
    main = logs.get("path") if isinstance(logs, dict) else None
    if isinstance(main, str):
        paths.append((base / main).resolve())

    cer = doc.get("ceremony") or {}
    admin = cer.get("admin_log_location") if isinstance(cer, dict) else None
    if isinstance(admin, str) and admin not in ("main_log", "") and "{" not in admin:
        paths.append((base / admin).resolve())

    return paths
