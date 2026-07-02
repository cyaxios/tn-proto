"""Aged cleanup of the autosync failure queue.

Every _append_sync_queue sweeps sync_queue/*.jsonl older than 30 days —
without it, throwaway ceremonies leave failure records forever (859 files
had accumulated by 2026-07-02).
"""
from __future__ import annotations

import os
import time

import pytest

from tn.admin import _append_sync_queue, _sync_queue_path


@pytest.fixture(autouse=True)
def _isolated_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("TN_STATE_DIR", str(tmp_path / "state"))


def _backdate(path, days: float) -> None:
    old = time.time() - days * 86400
    os.utime(path, (old, old))


def test_append_prunes_aged_files_machine_wide():
    _append_sync_queue("old-ceremony", "boom")
    old_path = _sync_queue_path("old-ceremony")
    assert old_path.exists()
    _backdate(old_path, 31)

    _append_sync_queue("fresh-ceremony", "boom")

    assert not old_path.exists(), "31-day-old queue file must be pruned"
    assert _sync_queue_path("fresh-ceremony").exists()


def test_append_keeps_files_within_age():
    _append_sync_queue("recent-ceremony", "boom")
    recent = _sync_queue_path("recent-ceremony")
    _backdate(recent, 29)

    _append_sync_queue("another-ceremony", "boom")

    assert recent.exists(), "29-day-old queue file must be kept"
