"""Design prototype: the tn.read() reader_options surface.

STANDALONE MOCK — does not touch core tn.read(). Fake in-memory data.

    read(selector, *, filter=, where=, reader_options=)

  selector        event_type / topic — PRIMARY, positional.
  reader_options  PURE opaque passthrough bag -> the underlying reader.
                  read() never reads OR writes a key in it.
  filter          declarative spec. Passed to the reader as a pushdown HINT
                  AND re-applied client-side as the authoritative gate.
  where           opaque predicate -> last-mile, post-decrypt.

  statefulness    a key in reader_options: group_id present = durable resume.

Reader contract:
  reader(options, *, selection=None, filter=None) -> Iterator[bytes]
    options    the user's pure bag (kafka consumer config)
    selection  read()'s event_type hint (handler may use for topic pushdown)
    filter     read()'s declarative hint (handler may pre-filter; optional)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterator, Protocol, runtime_checkable


@runtime_checkable
class ReadableHandler(Protocol):
    name: str
    def resolved_address(self) -> str | None: ...
    def reader(
        self,
        options: dict[str, Any],
        *,
        selection: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> Iterator[bytes]: ...


# ───────────────────────────────────────────────────────────────────────
# Mock handlers
# ───────────────────────────────────────────────────────────────────────

class MockFileHandler:
    def __init__(self, name: str, lines: list[bytes]) -> None:
        self.name = name
        self._lines = lines

    def resolved_address(self) -> str:
        return f"file://./.tn/logs/{self.name}.ndjson"

    def reader(self, options, *, selection=None, filter=None):
        if options:
            print(f"    [file.reader] ignoring non-file reader_options: {sorted(options)}")
        # A file can't push anything down — it reads the whole log. read()
        # re-applies selection+filter, so the file handler does nothing here.
        yield from self._lines


_KAFKA_PASSTHROUGH = {
    "group_id", "offset", "max_poll_records", "session_timeout_ms",
    "fetch_min_bytes", "isolation_level",
}


class MockKafkaHandler:
    def __init__(self, name, topic_tmpl, messages, yaml_read_cfg=None):
        self.name = name
        self._topic_tmpl = topic_tmpl
        self._messages = messages
        self._yaml_read_cfg = yaml_read_cfg or {}

    def resolved_address(self) -> str:
        return f"kafka://seed-xxx.redpanda.cloud:9092/{self._topic_tmpl}"

    def reader(self, options, *, selection=None, filter=None):
        # reader_options is the USER's pure bag — merged over yaml standing cfg.
        cfg = {**self._yaml_read_cfg, **options}
        mode = "durable-resume" if cfg.get("group_id") else "stateless-replay"
        passthrough = {k: v for k, v in cfg.items() if k in _KAFKA_PASSTHROUGH}
        print(f"    [kafka.reader] mode={mode}  consumer={passthrough}")

        topics = self._topics_for(selection, filter or {})
        print(f"    [kafka.reader] subscribed topics: {topics}")
        for topic in topics:
            yield from self._messages.get(topic, [])

    def _topics_for(self, selection: str | None, filter: dict) -> list[str]:
        """Topic subscription, no wildcards. Precedence:
          exact selector  ->  one topic
          event_type_in   ->  those topics
          event_type_prefix -> topics under the prefix
          none of the above -> all topics
        """
        if "{event_type}" not in self._topic_tmpl:
            return [self._topic_tmpl]                       # fixed firehose topic
        render = lambda et: self._topic_tmpl.replace("{event_type}", et)
        if selection is not None:
            return [render(selection)]                      # exact event_type
        if "event_type_in" in filter:
            want = {render(et) for et in filter["event_type_in"]}
            return sorted(t for t in self._messages if t in want)
        if "event_type_prefix" in filter:
            base = render(filter["event_type_prefix"])
            return sorted(t for t in self._messages if t.startswith(base))
        return sorted(self._messages)                       # all


# ───────────────────────────────────────────────────────────────────────
# Generic read() — reader_options stays PURE; selection+filter are separate
# named hints passed to the reader, and re-applied here as the gate.
# ───────────────────────────────────────────────────────────────────────

def read(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    where: Callable[[dict[str, Any]], bool] | None = None,
    reader_options: dict[str, Any] | None = None,
    handlers: list[ReadableHandler],
) -> Iterator[dict[str, Any]]:
    reader_options = dict(reader_options or {})   # forwarded verbatim, untouched

    file_h = next(
        (h for h in handlers if (h.resolved_address() or "").startswith("file://")),
        None,
    )
    src = file_h or next((h for h in handlers if hasattr(h, "reader")), None)
    if src is None:
        print("source: none — no readable handler")
        return
    print(f"source: {src.resolved_address()}")

    pulled = kept = 0
    for raw in src.reader(reader_options, selection=selector, filter=filter):
        pulled += 1
        env = json.loads(raw)                      # MOCK: decrypt + verify here

        # AUTHORITATIVE gate — re-apply selection + filter + where client-side,
        # regardless of what the handler did/didn't push down.
        if selector is not None and not _match_event_type(env["event_type"], selector):
            continue
        if filter is not None and not _filter_match(env, filter):
            continue
        if where is not None and not where(env):
            continue
        kept += 1
        yield env
    print(f"    [read] pulled={pulled} yielded={kept}")


def _match_event_type(et: str, selector: str) -> bool:
    return et == selector            # exact only — no wildcards


def _filter_match(env: dict[str, Any], spec: dict[str, Any]) -> bool:
    et, lvl = env.get("event_type", ""), env.get("level", "")
    if "event_type_in" in spec and et not in spec["event_type_in"]:
        return False
    if "event_type_prefix" in spec and not et.startswith(spec["event_type_prefix"]):
        return False
    if "level_in" in spec and lvl not in spec["level_in"]:
        return False
    return True


# ───────────────────────────────────────────────────────────────────────
# Demo
# ───────────────────────────────────────────────────────────────────────

def _line(event_type: str, level: str, **fields: Any) -> bytes:
    env = {"event_type": event_type, "level": level,
           "device_identity": "did:key:zMOCK", **fields}
    return (json.dumps(env) + "\n").encode()


def _demo() -> None:
    kafka_msgs = {
        "tn.transaction.review":  [_line("transaction.review", "info", amount=500),
                                   _line("transaction.review", "info", amount=5000)],
        "tn.transaction.flagged": [_line("transaction.flagged", "warning", amount=99000)],
        "tn.session.started":     [_line("session.started", "info", user="u1")],
    }
    file_lines = [_line("transaction.review", "info", amount=500),
                  _line("session.started", "info", user="u1")]

    kafka = MockKafkaHandler("redpanda", "tn.{event_type}", kafka_msgs,
                             yaml_read_cfg={"offset": "earliest"})
    file = MockFileHandler("tn", file_lines)

    def show(title: str, gen: Iterator[dict[str, Any]]) -> None:
        print(f"\n=== {title} ===")
        for r in list(gen):
            print(f"    -> {r['event_type']:<22} {r.get('amount', r.get('user', ''))}")

    show("all events: tn.read()  (no selector = everything)",
         read(handlers=[kafka]))

    show("exact: tn.read('transaction.review')",
         read("transaction.review", handlers=[kafka]))

    show("prefix is EXPLICIT, not a glob: filter={event_type_prefix}",
         read(filter={"event_type_prefix": "transaction."}, handlers=[kafka]))

    show("membership: filter={event_type_in: [...]}",
         read(filter={"event_type_in": ["transaction.review", "session.started"]},
              handlers=[kafka]))

    show("durable resume: reader_options={group_id, max_poll_records}",
         read("transaction.review",
              reader_options={"group_id": "nightly-audit", "max_poll_records": 500},
              handlers=[kafka]))

    show("filter + where: level_in=[warning] AND amount>50000",
         read(filter={"level_in": ["warning"]},
              where=lambda e: e.get("amount", 0) > 50000,
              handlers=[kafka]))

    show("file present: bag stays pure, group_id ignored",
         read("transaction.review",
              reader_options={"group_id": "ignored-when-file"},
              handlers=[file, kafka]))


if __name__ == "__main__":
    _demo()
