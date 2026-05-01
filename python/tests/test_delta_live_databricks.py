"""Live Delta/Databricks test.

Uses the workspace host + token at C:/codex/content_platform/databricks/_secrets.json
(falls back to DATABRICKS_HOST / DATABRICKS_TOKEN env). Creates a test
bronze Delta table, produces a few tn.log entries through the full
handler stack, verifies them via SELECT, drops the table.

Skips cleanly if secrets or databricks-sql-connector are missing.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


_SECRETS_CANDIDATES = [
    Path("C:/codex/content_platform/databricks/_secrets.json"),
    Path("/mnt/c/codex/content_platform/databricks/_secrets.json"),
]


def _load_secrets() -> dict | None:
    for p in _SECRETS_CANDIDATES:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    host = os.environ.get("DATABRICKS_HOST")
    tok = os.environ.get("DATABRICKS_TOKEN")
    if host and tok:
        return {"databricks_host": host, "databricks_token": tok}
    return None


def main() -> int:
    secrets = _load_secrets()
    if not secrets:
        print(
            "SKIP: no databricks credentials found "
            f"(looked at {_SECRETS_CANDIDATES} and env DATABRICKS_*)"
        )
        return 0

    try:
        import databricks.sql
        from databricks.sdk import WorkspaceClient
    except ImportError:
        print(
            "SKIP: databricks-sql-connector / databricks-sdk not installed "
            "(pip install 'tn-protocol[delta]')"
        )
        return 0

    import tn

    host = secrets["databricks_host"].rstrip("/").removeprefix("https://")
    token = secrets["databricks_token"]
    os.environ["DATABRICKS_HOST"] = host
    os.environ["DATABRICKS_TOKEN"] = token

    run_id = uuid.uuid4().hex[:8]
    catalog = "workspace"
    schema = "bronze"
    table = f"tn_events_test_{run_id}"

    # Pick a warehouse
    w = WorkspaceClient(host=host, token=token)
    warehouses = list(w.warehouses.list())
    if not warehouses:
        print("FAIL: no SQL warehouses on workspace")
        return 1
    wh = warehouses[0]
    print(f"workspace: https://{host}")
    print(f"warehouse: {wh.id}  ({wh.name!r}, {wh.cluster_size}, {wh.state})")

    # Ensure the bronze schema exists on this workspace's default catalog
    # (best-effort — skip failure if it's already there).
    def _sql(statement: str):
        conn = databricks.sql.connect(
            server_hostname=host,
            http_path=f"/sql/1.0/warehouses/{wh.id}",
            access_token=token,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(statement)
                try:
                    return cur.fetchall()
                except Exception:
                    return None
        finally:
            conn.close()

    try:
        _sql(f"CREATE SCHEMA IF NOT EXISTS `{catalog}`.`{schema}`")
    except Exception as e:
        print(f"WARN: could not create schema {catalog}.{schema}: {e}")

    # -----------------------------------------------------------------
    # Write via the handler: bootstrap ceremony + YAML + 3 tn.log events
    # -----------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="tndelta_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"
        tn.init(yaml_path)

        base = yaml_path.read_text(encoding="utf-8")
        block = f"""
handlers:
  - name: local
    kind: file.rotating
    path: ./.tn/logs/tn.ndjson
    max_bytes: 524288
    backup_count: 1
  - name: bronze
    kind: delta
    host: env:DATABRICKS_HOST
    token: env:DATABRICKS_TOKEN
    warehouse_id: {wh.id}
    catalog: {catalog}
    schema:  {schema}
    table:   {table}
    # Flush right away so the test isn't waiting 60 s for the window.
    batch_max_rows: 1
    batch_window_sec: 1
    filter:
      event_type:
        starts_with: "delta_"
"""
        yaml_path.write_text(base + block, encoding="utf-8")

        tn.flush_and_close()
        tn.init(yaml_path)

        sent = []
        for i in range(3):
            env = tn.log("delta_ping", seq=i, run_id=run_id, note="delta live test")
            sent.append(env["event_id"])

        print("produced 3 events; closing handlers (flushes Delta buffer + drains outbox)")
        tn.flush_and_close(timeout=120.0)

    # -----------------------------------------------------------------
    # Read back and verify
    # -----------------------------------------------------------------
    full = f"`{catalog}`.`{schema}`.`{table}`"
    print(f"SELECT FROM {full} ...")
    rows = _sql(
        f"SELECT did, event_id, event_type, level, sequence, row_hash, signature, "
        f"       envelope FROM {full} ORDER BY sequence"
    )

    rows = rows or []
    print(f"retrieved {len(rows)} rows")
    ok = len(rows) == 3

    got_ids = [r[1] for r in rows]
    if set(got_ids) != set(sent):
        print(f"FAIL: event_id mismatch\n  sent={sent}\n  got={got_ids}")
        ok = False
    else:
        print(f"event_ids match: {got_ids}")

    # Verify signature on the stored envelope JSON
    from tn.signing import DeviceKey, _signature_from_b64

    sig_ok = 0
    for r in rows:
        env = json.loads(r[7])
        if DeviceKey.verify(
            env["did"],
            env["row_hash"].encode("ascii"),
            _signature_from_b64(env["signature"]),
        ):
            sig_ok += 1
    print(f"signatures verify after Delta round-trip: {sig_ok}/{len(rows)}")
    if sig_ok != len(rows):
        ok = False

    # Cleanup
    try:
        _sql(f"DROP TABLE IF EXISTS {full}")
        print(f"dropped table: {catalog}.{schema}.{table}")
    except Exception as e:
        print(f"WARN: drop failed (harmless): {e}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
