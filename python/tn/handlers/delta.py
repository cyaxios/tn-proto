"""Delta Lake handler via Databricks SQL Connector.

Writes attested envelopes to a bronze Delta table through a Databricks
SQL warehouse. Events are batched by size + time and sent as a single
`INSERT INTO ... VALUES (...), (...), ...` statement per flush to keep
round-trips low.

YAML:
    kind: delta
    host:        env:DATABRICKS_HOST
    token:       env:DATABRICKS_TOKEN
    warehouse_id: 79d7e46984c59aa2        # or `auto` to pick first running
    catalog:     workspace
    schema:      bronze
    table:       tn_events_bronze          # bronze layer; one row per envelope
    partition_by: [event_type, event_date]
    batch_max_rows:    500                 # flush sooner if we hit this
    batch_max_bytes:   10485760            # or 10 MB
    batch_window_sec:  60                  # or 60s elapsed since first enqueue
    # opt-in: one table per event_type instead of shared bronze
    one_table_per_event_type: false

Auth:
    host/token can be literal values or `env:<NAME>` references. When
    `warehouse_id: auto`, the handler uses Databricks SDK to pick the
    first RUNNING warehouse on the workspace.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .base import AsyncHandler

_BRONZE_DDL = """
CREATE TABLE IF NOT EXISTS {full_name} (
    did          STRING,
    timestamp    TIMESTAMP,
    event_date   DATE,
    event_id     STRING,
    event_type   STRING,
    level        STRING,
    sequence     BIGINT,
    prev_hash    STRING,
    row_hash     STRING,
    signature    STRING,
    envelope     STRING                   -- full envelope JSON as received
)
USING DELTA
PARTITIONED BY ({partition_cols})
""".strip()


def _resolve(value: str | None) -> str:
    if not value:
        return ""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


def _escape_sql_literal(s: str) -> str:
    # Simple SQL string escape. We only build INSERTs with bound literals;
    # no user SQL is concatenated. Still: belt + suspenders.
    return s.replace("\\", "\\\\").replace("'", "''")


def _discover_warehouse(host: str, token: str) -> str:
    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient(host=host, token=token)
    for wh in w.warehouses.list():
        state = str(wh.state)
        if "RUNNING" in state or "STARTING" in state:
            return wh.id
    # Fall back to the first one — Databricks auto-starts serverless
    # warehouses on first query anyway.
    for wh in w.warehouses.list():
        return wh.id
    raise RuntimeError("no SQL warehouses available on this workspace")


class DeltaTableHandler(AsyncHandler):
    def __init__(
        self,
        name: str,
        *,
        outbox_path: str | Path,
        host: str,
        token: str,
        warehouse_id: str,
        catalog: str = "workspace",
        schema: str = "bronze",
        table: str = "tn_events_bronze",
        partition_by: list[str] | None = None,
        batch_max_rows: int = 500,
        batch_max_bytes: int = 10 * 1024 * 1024,
        batch_window_sec: float = 60.0,
        one_table_per_event_type: bool = False,
        filter_spec: dict[str, Any] | None = None,
    ):
        try:
            from databricks import sql
        except ImportError as e:
            raise ImportError(
                "DeltaTableHandler requires databricks-sql-connector. "
                "Install via `pip install 'tn-protocol[delta]'`."
            ) from e

        self._sql_module = sql
        self._host = _resolve(host).rstrip("/").removeprefix("https://")
        self._token = _resolve(token)

        wh = _resolve(warehouse_id)
        if wh == "auto" or not wh:
            wh = _discover_warehouse(self._host, self._token)
        self._http_path = f"/sql/1.0/warehouses/{wh}"

        self._catalog = catalog
        self._schema = schema
        self._table = table
        self._partition_by = partition_by or ["event_type", "event_date"]
        self._batch_max_rows = batch_max_rows
        self._batch_max_bytes = batch_max_bytes
        self._batch_window_sec = batch_window_sec
        self._one_per_event_type = one_table_per_event_type

        # Base class starts the background worker that calls _publish.
        super().__init__(name, outbox_path, filter_spec=filter_spec)

        self._buf_lock: threading.Lock = threading.Lock()
        self._buffer: list[dict[str, Any]] = []
        self._buf_bytes: int = 0
        self._buf_first_ts: float = 0.0
        self._ddl_cache: set[str] = set()

    # ------------------------------------------------------------------

    def _connect(self):
        return self._sql_module.connect(
            server_hostname=self._host,
            http_path=self._http_path,
            access_token=self._token,
        )

    def _full_table_name(self, event_type: str) -> str:
        if self._one_per_event_type:
            # event_type is already whitelisted [A-Za-z0-9._-]; replace
            # dots with _ so it's a valid identifier.
            safe = event_type.replace(".", "_").replace("-", "_")
            return f"`{self._catalog}`.`{self._schema}`.`{self._table}_{safe}`"
        return f"`{self._catalog}`.`{self._schema}`.`{self._table}`"

    def _ensure_table(self, conn, event_type: str) -> None:
        full = self._full_table_name(event_type)
        if full in self._ddl_cache:
            return
        ddl = _BRONZE_DDL.format(
            full_name=full,
            partition_cols=", ".join(self._partition_by),
        )
        with conn.cursor() as cur:
            cur.execute(ddl)
        self._ddl_cache.add(full)

    # AsyncHandler interface ------------------------------------------------

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Buffer the envelope. Actual INSERT happens when any of:
             - buffer has batch_max_rows items
             - buffer total raw size >= batch_max_bytes
             - batch_window_sec elapsed since first enqueue
        A force-flush also happens on close().
        """
        row_size = len(raw_line)
        row = {
            "envelope": envelope,
            "raw": raw_line.decode("utf-8", errors="replace"),
            "size": row_size,
        }
        should_flush = False
        with self._buf_lock:
            if not self._buffer:
                self._buf_first_ts = time.time()
            self._buffer.append(row)
            self._buf_bytes += row_size

            if (
                len(self._buffer) >= self._batch_max_rows
                or self._buf_bytes >= self._batch_max_bytes
                or (time.time() - self._buf_first_ts) >= self._batch_window_sec
            ):
                should_flush = True

        if should_flush:
            self._flush()

    def _flush(self) -> None:
        with self._buf_lock:
            batch = self._buffer
            if not batch:
                return
            self._buffer = []
            self._buf_bytes = 0
            self._buf_first_ts = 0.0

        # Group by table (matters only when one_table_per_event_type).
        groups: dict[str, list[dict[str, Any]]] = {}
        for r in batch:
            full = self._full_table_name(r["envelope"]["event_type"])
            groups.setdefault(full, []).append(r)

        with self._connect() as conn:
            for full, rows in groups.items():
                self._ensure_table(conn, rows[0]["envelope"]["event_type"])
                self._insert_batch(conn, full, rows)

    def _insert_batch(self, conn, full_table: str, rows: list[dict[str, Any]]) -> None:
        # Databricks SQL statement length ceiling is generous (~16 MB
        # statement) but we already cap by batch_max_bytes so fine.
        values_chunks: list[str] = []
        for r in rows:
            env = r["envelope"]
            ts = env["timestamp"]
            # event_date partition column — ISO prefix from timestamp
            date_part = ts[:10]
            envelope_json = _escape_sql_literal(json.dumps(env, separators=(",", ":")))
            values_chunks.append(
                "("
                f"'{_escape_sql_literal(env['did'])}', "
                f"TIMESTAMP'{_escape_sql_literal(ts)}', "
                f"DATE'{_escape_sql_literal(date_part)}', "
                f"'{_escape_sql_literal(env['event_id'])}', "
                f"'{_escape_sql_literal(env['event_type'])}', "
                f"'{_escape_sql_literal(env.get('level', ''))}', "
                f"{int(env['sequence'])}, "
                f"'{_escape_sql_literal(env['prev_hash'])}', "
                f"'{_escape_sql_literal(env['row_hash'])}', "
                f"'{_escape_sql_literal(env['signature'])}', "
                f"'{envelope_json}'"
                ")"
            )
        stmt = (
            f"INSERT INTO {full_table} "
            f"(did, timestamp, event_date, event_id, event_type, level, "
            f"sequence, prev_hash, row_hash, signature, envelope) VALUES "
            + ", ".join(values_chunks)
        )
        with conn.cursor() as cur:
            cur.execute(stmt)

    def _final_flush(self) -> None:
        # Called by AsyncHandler.close() after the worker has drained the
        # outbox into our buffer. Emit any residual INSERT.
        self._flush()
