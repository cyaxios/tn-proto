"""Prove the new tn.read() source-resolution + reader contract, no network.

A MockReplay handler captures sealed bytes on emit and replays them via the
reader() contract — standing in for Kafka. Tests:

  1. NO REGRESSION — file present: tn.read() reads the file as before.
  2. KAFKA PATH    — file emptied: tn.read() resolves to the handler,
                      pulls sealed bytes, decrypts through the keybag.
  3. selector + filter gating on the handler path.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

os.environ["TN_NO_STDOUT"] = "1"

import tn
from tn.handlers.base import TNHandler


class MockReplay(TNHandler):
    """Captures sealed raw_lines on emit; replays them via reader()."""

    def __init__(self) -> None:
        super().__init__("mock-kafka")
        self.store: list[bytes] = []

    def emit(self, envelope, raw_line) -> None:
        self.store.append(raw_line)

    def resolved_address(self) -> str:
        return "kafka://mock/tn.events"

    def reader(self, options=None, *, selection=None, filter=None):
        print(f"  [mock.reader] options={options} selection={selection} filter={filter}")
        for i, rb in enumerate(self.store):
            line = rb.decode() if isinstance(rb, (bytes, bytearray)) else rb
            yield (f"kafka://mock@{i}", line)


def main() -> int:
    D = Path("/tmp/tn_read_source")
    if D.exists():
        shutil.rmtree(D)
    D.mkdir(parents=True)

    mock = MockReplay()

    # WRITE — file handler (default) + mock capturing sealed bytes.
    tn.init(project_dir=str(D), profile="transaction", stdout=False, extra_handlers=[mock])
    tn.info("transaction.review", amount=500, secret="alpha")
    tn.info("transaction.flagged", amount=99000, secret="bravo")
    tn.info("session.started", user="u1")
    log_path = tn.current_config().resolve_log_path()
    tn.flush_and_close()
    print(f"captured {len(mock.store)} sealed frames in mock")

    # ── TEST 1: no regression — file present, read() reads the file. ──
    tn.init(project_dir=str(D), profile="transaction", stdout=False, extra_handlers=[mock])
    file_rows = [(e.event_type, e.fields.get("amount")) for e in tn.read()]
    print(f"\nTEST1 file read: {file_rows}")
    assert len(file_rows) == 3, f"expected 3 from file, got {len(file_rows)}"
    assert ("transaction.review", 500) in file_rows
    tn.flush_and_close()
    print("TEST1 PASS — file path unchanged")

    # ── TEST 2: empty the file -> read() resolves to the mock handler. ──
    Path(log_path).write_text("")  # simulate "no local copy, only kafka"
    tn.init(project_dir=str(D), profile="transaction", stdout=False, extra_handlers=[mock])

    print("\nTEST2 handler read (all):")
    rows = [(e.event_type, e.fields.get("amount"), e.fields.get("secret"))
            for e in tn.read()]
    for r in rows:
        print(f"    -> {r}")
    # The handler stream carries EVERYTHING emitted — including tn.* protocol
    # events that the file main-log splits off to the admin log. So the count
    # is >= our 3 app events; the decrypt is the real assertion.
    assert ("transaction.review", 500, "alpha") in rows, "decrypt via handler failed"
    assert ("transaction.flagged", 99000, "bravo") in rows
    app_rows = [r for r in rows if not r[0].startswith("tn.")]
    assert len(app_rows) == 3, f"expected 3 app events, got {app_rows}"
    print(f"TEST2 PASS — kafka-source read + decrypt works "
          f"({len(rows)} total incl. protocol, {len(app_rows)} app)")

    # ── TEST 3: selector + filter gating on the handler path. ──
    print("\nTEST3 selector='transaction.flagged':")
    sel = [(e.event_type, e.fields.get("amount")) for e in tn.read("transaction.flagged")]
    print(f"    {sel}")
    assert sel == [("transaction.flagged", 99000)], sel

    print("TEST3b filter={event_type_in:[transaction.review, session.started]}:")
    filt = [e.event_type for e in tn.read(filter={"event_type_in": ["transaction.review", "session.started"]})]
    print(f"    {sorted(filt)}")
    assert sorted(filt) == ["session.started", "transaction.review"], filt
    tn.flush_and_close()
    print("TEST3 PASS — selector + filter gate on handler path")

    print("\nALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
