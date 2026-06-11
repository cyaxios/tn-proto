"""Baseline 'how fast can Python write a log line' benchmarks.

For comparison against tn.info() throughput. Each scenario runs in
a fresh subprocess so import + setup + os state are isolated. Each
emit is durably persisted (flush+fsync OR commit per row) so we're
comparing like-for-like with tn.info()'s default durability story —
which DOES flush after every write.

Run:
    python bench_baselines.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

PY = sys.executable
N_VALUES = (500, 2000, 5000)


def measure(label: str, body: str) -> dict[int, float]:
    """Run `body` inside a fresh subprocess for each N in N_VALUES.

    `body` must define a function `run(path, N)` that performs N
    durable writes and returns wall-clock seconds (float).
    """
    out: dict[int, float] = {}
    for N in N_VALUES:
        script = (
            "import os, sys, time, tempfile\n"
            + body
            + "\ntd = tempfile.mkdtemp()\n"
            + 'path = os.path.join(td, "out")\n'
            + f"dt = run(path, {N})\n"
            + 'print(f"{dt:.6f}")\n'
        )
        proc = subprocess.run(
            [PY, "-c", script], capture_output=True, text=True, timeout=300
        )
        if proc.returncode != 0:
            print(f"  {label} N={N}: FAILED")
            print(proc.stderr)
            continue
        dt = float(proc.stdout.strip().splitlines()[-1])
        out[N] = dt
        print(
            f"  {label:30s} N={N:5d}  total={dt:7.3f}s  "
            f"per-emit={dt / N * 1000:7.3f} ms"
        )
    return out


# --- 1. Plain text file append, flush per row (closest to "raw fastest") ---
raw_file_body = """
def run(path, N):
    t0 = time.perf_counter()
    with open(path, "w", encoding="utf-8") as f:
        for i in range(N):
            f.write(f"info  some text message i={i}\\n")
            f.flush()
            os.fsync(f.fileno())
    return time.perf_counter() - t0
"""

# --- 2. Plain text file append, flush but NO fsync ---
raw_file_no_fsync_body = """
def run(path, N):
    t0 = time.perf_counter()
    with open(path, "w", encoding="utf-8") as f:
        for i in range(N):
            f.write(f"info  some text message i={i}\\n")
            f.flush()
    return time.perf_counter() - t0
"""

# --- 2b. Match TN exactly: re-open the file in append mode every emit,
#         no fsync, no flush. This is what `storage.append_bytes` does
#         on every call (open + write + close-on-drop).
raw_file_reopen_per_emit_body = """
def run(path, N):
    open(path, 'w').close()  # ensure empty file
    t0 = time.perf_counter()
    for i in range(N):
        with open(path, 'ab') as f:
            f.write(f'info  some text message i={i}\\n'.encode())
    return time.perf_counter() - t0
"""

# --- 2c. TN-matching but emit a JSON object instead of plain text. ---
raw_json_reopen_per_emit_body = """
def run(path, N):
    import json
    open(path, 'w').close()
    t0 = time.perf_counter()
    for i in range(N):
        line = json.dumps({'level': 'info', 'msg': 'some text message', 'i': i}) + '\\n'
        with open(path, 'ab') as f:
            f.write(line.encode())
    return time.perf_counter() - t0
"""

# --- 3. stdlib logging.FileHandler — what most Python devs reach for ---
stdlib_logging_body = """
def run(path, N):
    import logging
    log = logging.getLogger("bench")
    log.setLevel(logging.INFO)
    h = logging.FileHandler(path, mode="w", encoding="utf-8")
    h.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))
    log.addHandler(h)
    log.propagate = False
    t0 = time.perf_counter()
    for i in range(N):
        log.info("some text message i=%d", i)
    h.flush()
    h.close()
    return time.perf_counter() - t0
"""

# --- 4. stdlib logging.FileHandler with custom JSON formatter (like ndjson) ---
stdlib_json_logging_body = """
def run(path, N):
    import json, logging
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            return json.dumps({
                "level": record.levelname.lower(),
                "ts": record.created,
                "msg": record.getMessage(),
                "i": getattr(record, "i", None),
            })
    log = logging.getLogger("bench_json")
    log.setLevel(logging.INFO)
    h = logging.FileHandler(path, mode="w", encoding="utf-8")
    h.setFormatter(JsonFormatter())
    log.addHandler(h)
    log.propagate = False
    t0 = time.perf_counter()
    for i in range(N):
        log.info("some text message", extra={"i": i})
    h.flush()
    h.close()
    return time.perf_counter() - t0
"""

# --- 5. Raw JSON line, flush per row, no logging machinery ---
raw_json_body = """
def run(path, N):
    import json
    t0 = time.perf_counter()
    with open(path, "w", encoding="utf-8") as f:
        for i in range(N):
            f.write(json.dumps({"level": "info", "msg": "some text message", "i": i}) + "\\n")
            f.flush()
            os.fsync(f.fileno())
    return time.perf_counter() - t0
"""

# --- 6. Raw JSON line, flush but NO fsync ---
raw_json_no_fsync_body = """
def run(path, N):
    import json
    t0 = time.perf_counter()
    with open(path, "w", encoding="utf-8") as f:
        for i in range(N):
            f.write(json.dumps({"level": "info", "msg": "some text message", "i": i}) + "\\n")
            f.flush()
    return time.perf_counter() - t0
"""

# --- 7. SQLite, 10-column row, commit per row (durable) ---
sqlite_commit_per_row_body = """
def run(path, N):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute('''CREATE TABLE log (
        id INTEGER PRIMARY KEY, ts REAL, level TEXT, event_type TEXT,
        msg TEXT, did TEXT, event_id TEXT, sequence INTEGER,
        prev_hash TEXT, row_hash TEXT
    )''')
    conn.commit()
    cur = conn.cursor()
    t0 = time.perf_counter()
    for i in range(N):
        cur.execute(
            "INSERT INTO log (ts, level, event_type, msg, did, event_id, "
            "sequence, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), "info", "stress.evt", f"msg i={i}",
             "did:key:zABC", f"evt-{i}", i + 1, "sha256:00", "sha256:11"),
        )
        conn.commit()
    conn.close()
    return time.perf_counter() - t0
"""

# --- 8. SQLite WAL mode, commit per row (same durability, faster fsync) ---
sqlite_wal_body = """
def run(path, N):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute('''CREATE TABLE log (
        id INTEGER PRIMARY KEY, ts REAL, level TEXT, event_type TEXT,
        msg TEXT, did TEXT, event_id TEXT, sequence INTEGER,
        prev_hash TEXT, row_hash TEXT
    )''')
    conn.commit()
    cur = conn.cursor()
    t0 = time.perf_counter()
    for i in range(N):
        cur.execute(
            "INSERT INTO log (ts, level, event_type, msg, did, event_id, "
            "sequence, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), "info", "stress.evt", f"msg i={i}",
             "did:key:zABC", f"evt-{i}", i + 1, "sha256:00", "sha256:11"),
        )
        conn.commit()
    conn.close()
    return time.perf_counter() - t0
"""

# --- 9. SQLite WAL mode, batched commit every 100 rows (typical durable trade) ---
sqlite_wal_batched_body = """
def run(path, N):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute('''CREATE TABLE log (
        id INTEGER PRIMARY KEY, ts REAL, level TEXT, event_type TEXT,
        msg TEXT, did TEXT, event_id TEXT, sequence INTEGER,
        prev_hash TEXT, row_hash TEXT
    )''')
    conn.commit()
    cur = conn.cursor()
    t0 = time.perf_counter()
    for i in range(N):
        cur.execute(
            "INSERT INTO log (ts, level, event_type, msg, did, event_id, "
            "sequence, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), "info", "stress.evt", f"msg i={i}",
             "did:key:zABC", f"evt-{i}", i + 1, "sha256:00", "sha256:11"),
        )
        if (i + 1) % 100 == 0:
            conn.commit()
    conn.commit()
    conn.close()
    return time.perf_counter() - t0
"""


SCENARIOS = [
    ("raw file + flush + fsync", raw_file_body),
    ("raw file + flush, no fsync", raw_file_no_fsync_body),
    ("raw file (open per emit)", raw_file_reopen_per_emit_body),
    ("raw json (open per emit)", raw_json_reopen_per_emit_body),
    ("stdlib logging (text)", stdlib_logging_body),
    ("stdlib logging (json)", stdlib_json_logging_body),
    ("raw json line + fsync", raw_json_body),
    ("raw json line, no fsync", raw_json_no_fsync_body),
    ("sqlite (commit/row, default)", sqlite_commit_per_row_body),
    ("sqlite WAL (commit/row)", sqlite_wal_body),
    ("sqlite WAL (commit/100)", sqlite_wal_batched_body),
]


def main() -> None:
    print(f"Python: {sys.version.split()[0]}  platform: {sys.platform}\n")
    results: dict[str, dict[int, float]] = {}
    for label, body in SCENARIOS:
        print(f"-- {label} --")
        results[label] = measure(label, body)
        print()

    # Summary matrix.
    print("=== summary (per-emit ms) ===")
    header = f"{'scenario':32s}" + "".join(f"{n:>12d}" for n in N_VALUES)
    print(header)
    print("-" * len(header))
    for label, body in SCENARIOS:
        r = results.get(label, {})
        row = f"{label:32s}"
        for N in N_VALUES:
            if N in r:
                row += f"{r[N] / N * 1000:>12.3f}"
            else:
                row += f"{'--':>12s}"
        print(row)


if __name__ == "__main__":
    main()
