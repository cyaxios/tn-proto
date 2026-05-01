"""ceremony.logs.path — where tn.info writes and tn.read reads.

Default path is `./.tn/logs/tn.ndjson` relative to the yaml. A custom path in
the yaml (either relative or absolute) must be honored by the Rust runtime
AND by the Python legacy path so both code paths agree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _user_entries():
    """Filter bootstrap tn.* attestations so tests assert on user events only."""
    return [e for e in tn.read() if not e["event_type"].startswith("tn.")]


def test_default_log_path_is_yaml_dir_logs_tn_ndjson(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("x.test", k=1)
    tn.flush_and_close()

    # Per-stem layout: <yaml_dir>/.tn/<yaml_stem>/logs/tn.ndjson
    expected = tmp_path / ".tn" / yaml.stem / "logs" / "tn.ndjson"
    assert expected.exists(), f"expected log at {expected}"
    # Reopen and confirm read finds the entry.
    tn.init(yaml)
    entries = _user_entries()
    assert len(entries) == 1
    assert entries[0]["event_type"] == "x.test"


def test_yaml_advertises_log_path(tmp_path):
    """Freshly generated yaml must show where the log is written."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    text = yaml.read_text(encoding="utf-8")
    # The logs block should be present.
    assert "logs:" in text, f"generated yaml missing logs block:\n{text}"
    assert f"./.tn/{yaml.stem}/logs/tn.ndjson" in text


def test_custom_relative_log_path(tmp_path):
    """A relative path in yaml redirects writes to that path (relative to yaml dir)."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    # Edit the yaml to redirect logs to ./custom/events.ndjson
    text = yaml.read_text(encoding="utf-8")
    text = text.replace(f"./.tn/{yaml.stem}/logs/tn.ndjson", "./custom/events.ndjson")
    yaml.write_text(text, encoding="utf-8")

    tn.init(yaml)
    tn.info("custom.path", k=2)
    tn.flush_and_close()

    expected = tmp_path / "custom" / "events.ndjson"
    assert expected.exists(), f"expected log at {expected}"
    # Default location should NOT be used.
    default = tmp_path / ".tn" / yaml.stem / "logs" / "tn.ndjson"
    # (default may or may not exist depending on prior runs; ensure this new
    # event isn't in the default file at least)
    if default.exists():
        default_lines = default.read_text(encoding="utf-8").splitlines()
        for line in default_lines:
            assert "custom.path" not in line, "event landed at default path"

    # Read finds the entry at the custom path.
    tn.init(yaml)
    entries = _user_entries()
    assert len(entries) == 1
    assert entries[0]["event_type"] == "custom.path"


def test_custom_absolute_log_path(tmp_path):
    """An absolute path in yaml is used verbatim, not resolved against yaml dir."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    abs_log = (tmp_path / "absolute_logs" / "tn.ndjson").resolve()
    # Use forward slashes in yaml to keep parsing simple across platforms.
    text = yaml.read_text(encoding="utf-8")
    text = text.replace(f"./.tn/{yaml.stem}/logs/tn.ndjson", str(abs_log).replace("\\", "/"))
    yaml.write_text(text, encoding="utf-8")

    tn.init(yaml)
    tn.info("absolute.path", k=3)
    tn.flush_and_close()

    assert abs_log.exists(), f"expected log at {abs_log}"

    tn.init(yaml)
    entries = _user_entries()
    assert entries and entries[0]["event_type"] == "absolute.path"
