from __future__ import annotations

import json
from pathlib import Path

import pytest

import tn
from tn._entry import VerifyError


@pytest.fixture(autouse=True)
def isolated_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tn-home"))
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    tn.flush_and_close()
    try:
        yield
    finally:
        tn.flush_and_close()


def test_two_lazy_handle_reads_keep_receiver_context_and_do_not_rebind_global(
    tmp_path: Path,
) -> None:
    default = tn.init("default", project_dir=tmp_path, stdout=False)
    unsigned = tn.init(
        "unsigned",
        project_dir=tmp_path,
        profile="telemetry",
        stdout=False,
    )
    signed = tn.init(
        "signed",
        project_dir=tmp_path,
        profile="transaction",
        stdout=False,
    )
    unsigned.info("unsigned.local", owner="unsigned")
    signed.info("signed.local", owner="signed")

    # Handle creation currently activates the most recently created ceremony;
    # explicitly restore the module-level default so this assertion isolates
    # read-time leakage rather than creation-time compatibility behavior.
    tn.init("default", project_dir=tmp_path, stdout=False)

    active_yaml = Path(tn.current_config().yaml_path)
    assert active_yaml == default.yaml_path

    unsigned_result = unsigned.read()
    signed_result = signed.read()
    assert Path(tn.current_config().yaml_path) == active_yaml

    unsigned_rows = list(unsigned_result)
    signed_rows = list(signed_result)
    assert [row.event_type for row in unsigned_rows] == ["unsigned.local"]
    assert [row.event_type for row in signed_rows] == ["signed.local"]
    assert unsigned_rows[0].fields["owner"] == "unsigned"
    assert signed_rows[0].fields["owner"] == "signed"
    assert Path(tn.current_config().yaml_path) == active_yaml


def test_foreign_log_does_not_inherit_local_sign_or_chain_false(tmp_path: Path) -> None:
    local = tn.init(
        "local",
        project_dir=tmp_path,
        profile="telemetry",
        stdout=False,
    )
    foreign = tn.init(
        "foreign",
        project_dir=tmp_path,
        profile="telemetry",
        stdout=False,
    )
    foreign.info("foreign.unsigned", secret="not-returned")
    foreign_log = foreign.cfg.resolve_log_path()

    with pytest.raises(VerifyError) as raised:
        list(
            local.read(
                log=foreign_log,
                trusted_writers={foreign.cfg.device.did},
            ),
        )
    assert "row_hash_invalid" in raised.value.reasons
    assert "signature_required" in raised.value.reasons


def test_foreign_unsigned_requires_both_explicit_unsigned_overrides(tmp_path: Path) -> None:
    local = tn.init("local", project_dir=tmp_path, stdout=False)
    foreign = tn.init(
        "foreign",
        project_dir=tmp_path,
        profile="audit",
        stdout=False,
    )
    foreign.info("foreign.row", value=7)
    foreign_log = foreign.cfg.resolve_log_path()
    lines = foreign_log.read_text(encoding="utf-8").splitlines()
    envelope = json.loads(lines[0])
    envelope["signature"] = ""
    foreign_log.write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="both"):
        local.read(
            log=foreign_log,
            require_signature=False,
            trusted_writers={foreign.cfg.device.did},
        )
    with pytest.raises(ValueError, match="both"):
        local.read(
            log=foreign_log,
            allow_unauthenticated=True,
            trusted_writers={foreign.cfg.device.did},
        )

    rows = list(
        local.read(
            log=foreign_log,
            require_signature=False,
            allow_unauthenticated=True,
            trusted_writers={foreign.cfg.device.did},
            raw=True,
        ),
    )
    assert len(rows) == 1
    assert rows[0]["_valid"]["writer_authenticated"] is False
    assert rows[0]["_valid"]["writer_authorized"] is False
