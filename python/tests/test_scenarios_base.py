"""Unit test for Scenario base + ScenarioContext.

Uses a toy scenario that does not call into tn.* — only exercises the
harness surface (timers, records, invariants, status).
"""

import json

from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.scenario import run_scenario


class ToyOK(Scenario):
    persona = "toy"
    name = "ok"
    tags = {"toy"}
    needs_vault = False
    needs_handlers = {"file"}

    def run(self, ctx: ScenarioContext) -> None:
        with ctx.timer("ceremony_ms"):
            pass
        for _ in range(10):
            with ctx.timer_us("log_us"):
                pass
        ctx.record("log_count", 10)
        ctx.assert_invariant("chain_verified", True)


class ToyBoom(Scenario):
    persona = "toy"
    name = "boom"
    tags = {"toy"}

    def run(self, ctx: ScenarioContext) -> None:
        raise RuntimeError("kaboom")


def test_ok_scenario_writes_metrics_and_snapshot(tmp_path):
    result = run_scenario(ToyOK(), results_root=tmp_path, runid="T1")
    assert result.status == "ok"
    outdir = tmp_path / "T1" / "toy_ok"
    doc = json.loads((outdir / "metrics.json").read_text())
    assert doc["status"] == "ok"
    assert doc["scalars"]["ceremony_ms"] >= 0
    assert len(doc["samples"]["log_us"]) == 10
    assert doc["invariants"]["chain_verified"] is True


def test_erroring_scenario_never_raises_out(tmp_path):
    result = run_scenario(ToyBoom(), results_root=tmp_path, runid="T2")
    assert result.status == "errored"
    assert "kaboom" in (result.error or "")
    doc = json.loads((tmp_path / "T2" / "toy_boom" / "metrics.json").read_text())
    assert doc["status"] == "errored"


class ToyMatrix(Scenario):
    persona = "toy"
    name = "matrix"
    tags = {"toy"}

    def run(self, ctx):
        for i in range(3):
            with ctx.cell(f"{i:02d}"):
                with ctx.timer("tn_init_ms"):
                    pass
                ctx.record("log_count", i * 10)


def test_cells_write_per_cell_json_and_csv_rows(tmp_path):
    from scenarios._harness.scenario import run_scenario

    run_scenario(ToyMatrix(), results_root=tmp_path, runid="T3")
    outdir = tmp_path / "T3" / "toy_matrix"
    for i in range(3):
        assert (outdir / f"metrics.cell_{i:02d}.json").exists()
    csv_text = (tmp_path / "T3" / "_summary.csv").read_text(encoding="utf-8")
    # One header + 3 cell rows + 1 top-level (cell=None) row = 5 lines (4 newlines min)
    assert csv_text.count("\n") >= 4
    assert "cell_00" in csv_text or ",00," in csv_text
