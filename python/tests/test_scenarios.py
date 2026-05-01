"""Pytest collector: runs every discovered scenario.

Failure policy (per spec §11): scenarios NEVER fail pytest. Each scenario
is a parametrized test that always passes as long as run_scenario
returns (even when the scenario errored internally — that is recorded,
not raised). Infrastructure-level failures (import errors, missing
runid dir) still fail the pytest run, which is what CI cares about.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from scenarios._harness.env import load_repo_env
from scenarios._harness.registry import discover_all
from scenarios._harness.scenario import run_scenario

load_repo_env()
_ALL = discover_all()


def _param_id(s) -> str:
    return f"{s.persona}/{s.name}"


@pytest.fixture(scope="session")
def scenario_runid(tmp_path_factory) -> tuple[str, Path]:
    runid = os.environ.get("TN_SCENARIO_RUNID") or ("pytest-" + secrets.token_hex(4))
    results_root = Path(
        os.environ.get("TN_SCENARIO_RESULTS_ROOT")
        or (Path(__file__).resolve().parents[1] / "bench" / "results")
    )
    (results_root / runid).mkdir(parents=True, exist_ok=True)
    return runid, results_root


@pytest.mark.parametrize("scenario", _ALL, ids=_param_id)
def test_scenario(scenario, scenario_runid):
    runid, results_root = scenario_runid
    vault_factory = None
    if scenario.needs_vault:
        from scenarios._harness.vault import vault_fixture

        vault_factory = vault_fixture
    result = run_scenario(
        scenario,
        results_root=results_root,
        runid=runid,
        vault_factory=vault_factory,
    )
    # Never assert on result.status — that's recorded, not enforced.
    assert result.outdir.exists()
    assert (result.outdir / "metrics.json").exists()
