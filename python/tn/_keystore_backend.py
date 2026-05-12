"""Keystore persistence backend.

Owns the atomic-write primitive plus the CAS protocol for multi-writer
safety. The cipher layer used to do ``path.write_bytes(...)`` directly;
that pattern has no tear-resistance and no concurrency story. This
module is the single place that writes durable keystore files.

See ``docs/superpowers/specs/2026-05-12-runtime-correctness-design.md``.
"""
from __future__ import annotations

import os
from pathlib import Path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically: tmp file + fsync + replace.

    Guarantees:
      * On success, ``path`` contains exactly ``data``.
      * On failure mid-write (including OSError from fsync/replace),
        the *existing* contents of ``path`` (if any) are untouched.
      * No ``.<name>.tmp.<pid>`` siblings remain after either outcome.

    Uses ``os.replace``, which is atomic on POSIX and Windows when the
    source and destination share a filesystem (the keystore tmp file is
    always created in the same dir as its target, so this holds).
    """
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".{path.name}.tmp.{os.getpid()}"
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
