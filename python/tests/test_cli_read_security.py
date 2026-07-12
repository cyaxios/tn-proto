from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tn.cli import build_parser
from tn.cli_read import cmd_read


@pytest.mark.parametrize(
    ("argv", "expected_verify", "verify_present"),
    [
        (["read"], None, False),
        (["read", "--verify"], "raise", True),
        (["read", "--verify", "raise"], "raise", True),
        (["read", "--verify", "skip"], "skip", True),
        (["read", "--no-verify"], False, True),
    ],
)
def test_cli_read_maps_only_explicit_security_flags(
    argv: list[str],
    expected_verify: str | bool | None,
    verify_present: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    calls: list[dict[str, Any]] = []

    import tn.cli_read as cli_read

    monkeypatch.setattr(cli_read, "_resolve_yaml_or_discover", lambda value: tmp_path / "tn.yaml")
    monkeypatch.setattr(cli_read.tn, "init", lambda value: None)
    monkeypatch.setattr(cli_read.tn, "flush_and_close", lambda: None)
    monkeypatch.setattr(
        cli_read.tn,
        "read",
        lambda **kwargs: calls.append(kwargs) or iter(()),
    )

    assert cmd_read(args) == 0
    assert len(calls) == 1
    if verify_present:
        assert calls[0]["verify"] == expected_verify
    else:
        assert "verify" not in calls[0]


def test_cli_rejects_unknown_verify_mode() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["read", "--verify", "auto"])
