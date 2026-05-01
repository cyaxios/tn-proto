"""Scenario base class + ScenarioContext + run_scenario entry point.

Key contract: run_scenario() NEVER re-raises a scenario's exception.
Failures land in metrics.json as status='errored' and surface via the
_summary.csv notes column.
"""

from __future__ import annotations

import tempfile
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fixtures import Workspace, make_workspace
from .metrics import (
    MetricsStore,
    Timer,
    write_metrics_json,
    write_summary_row,
)
from .yaml_capture import snapshot_yaml


@dataclass
class ScenarioResult:
    persona: str
    scenario: str
    status: str  # "ok" | "errored"
    error: str | None
    outdir: Path


class ScenarioContext:
    """Per-scenario state passed to Scenario.run()."""

    def __init__(
        self,
        *,
        persona: str,
        name: str,
        outdir: Path,
        workspace: Workspace,
        vault=None,  # VaultHandle | None — set by harness
        runid: str = "",
        results_root: Path | None = None,
    ):
        self.persona = persona
        self.name = name
        self.outdir = outdir
        self.workspace = workspace
        self.yaml_path = workspace.yaml_path
        self.log_path = workspace.logs / "tn.ndjson"
        self.vault = vault
        self.store = MetricsStore()
        self._runid = runid
        self._results_root = results_root if results_root is not None else outdir.parent.parent

    # -- timer helpers -------------------------------------------------

    def timer(self, key: str):
        return Timer(self.store, key, unit="ms", sample=False)

    def timer_us(self, key: str):
        return Timer(self.store, key, unit="us", sample=True)

    # -- raw metrics ---------------------------------------------------

    def record(self, key: str, value: Any) -> None:
        self.store.set_scalar(key, value)

    def record_sample(self, key: str, value: float) -> None:
        self.store.add_sample(key, value)

    def assert_invariant(self, name: str, passed: bool) -> None:
        self.store.set_invariant(name, bool(passed))

    def note(self, text: str) -> None:
        self.store.add_note(text)

    # -- tn.yaml snapshot ---------------------------------------------

    def snapshot_yaml(self, suffix: str | None = None) -> Path:
        return snapshot_yaml(self.yaml_path, self.outdir, suffix=suffix)

    # -- matrix cell context manager ----------------------------------

    @contextmanager
    def cell(self, cell_id: str) -> Iterator[ScenarioContext]:
        """Enter a matrix cell: fresh MetricsStore, per-cell yaml snapshot,
        and a _summary.csv row with cell=<cell_id>."""
        import json

        prior_store = self.store
        cell_store = MetricsStore()
        self.store = cell_store
        try:
            yield self
            # Snapshot per-cell yaml (whatever self.yaml_path currently points at).
            self.snapshot_yaml(suffix=f"cell_{cell_id}")
            (self.outdir / f"metrics.cell_{cell_id}.json").write_text(
                json.dumps(cell_store.to_json(), indent=2, default=str),
                encoding="utf-8",
            )
            row = cell_store.summary_row(
                persona=self.persona,
                scenario=self.name,
                runid=self._runid,
                cell=cell_id,
                status="ok",
                error=None,
            )
            if self._results_root is not None:
                write_summary_row(
                    self._results_root / self._runid / "_summary.csv",
                    row,
                )
        finally:
            self.store = prior_store

    # -- envelope vs plaintext helpers --------------------------------

    def record_envelope_ratio(
        self,
        envelope_bytes: list[int],
        plaintext_bytes: list[int],
    ) -> None:
        if envelope_bytes:
            m = sum(envelope_bytes) / len(envelope_bytes)
            self.record("envelope_bytes_mean", m)
            # p99 via the metrics store's percentile path
            for b in envelope_bytes:
                self.record_sample("envelope_bytes_us", float(b))  # re-use percentile infra
        if plaintext_bytes:
            pm = sum(plaintext_bytes) / len(plaintext_bytes)
            self.record("plaintext_bytes_mean", pm)
            if envelope_bytes:
                self.record(
                    "envelope_plaintext_ratio",
                    (sum(envelope_bytes) / len(envelope_bytes))
                    / (sum(plaintext_bytes) / len(plaintext_bytes)),
                )


class Scenario:
    """Base class. Subclasses set class-level metadata and implement run()."""

    persona: str = ""
    name: str = ""
    tags: set[str] = set()
    needs_vault: bool = False
    needs_handlers: set[str] = {"file"}

    def run(self, ctx: ScenarioContext) -> None:
        raise NotImplementedError


def run_scenario(
    scenario: Scenario,
    *,
    results_root: Path,
    runid: str,
    vault_factory=None,  # callable → contextmanager yielding VaultHandle
) -> ScenarioResult:
    """Execute one scenario. Never raises."""
    if not scenario.persona or not scenario.name:
        raise ValueError(f"scenario missing persona/name: {scenario!r}")

    outdir = results_root / runid / f"{scenario.persona}_{scenario.name}"
    outdir.mkdir(parents=True, exist_ok=True)

    status = "ok"
    error: str | None = None

    with tempfile.TemporaryDirectory(prefix=f"tn_{scenario.persona}_{scenario.name}_") as td:
        workspace = make_workspace(root=Path(td), name="ws")
        vault_cm = None
        vault_handle = None
        if scenario.needs_vault and vault_factory is not None:
            vault_cm = vault_factory(Path(td) / "vault_harness")
            vault_handle = vault_cm.__enter__()

        ctx = ScenarioContext(
            persona=scenario.persona,
            name=scenario.name,
            outdir=outdir,
            workspace=workspace,
            vault=vault_handle,
            runid=runid,
            results_root=results_root,
        )
        try:
            scenario.run(ctx)
            ctx.snapshot_yaml()
        except Exception:
            status = "errored"
            error = traceback.format_exc()
            ctx.store.add_note(f"exception:{error.splitlines()[-1]}")
        finally:
            if vault_cm is not None:
                try:
                    vault_cm.__exit__(None, None, None)
                except Exception as e:
                    ctx.store.add_note(f"vault_teardown_error:{e}")

        write_metrics_json(
            outdir,
            ctx.store,
            persona=scenario.persona,
            scenario=scenario.name,
            runid=runid,
            status=status,
            error=error,
        )
        row = ctx.store.summary_row(
            persona=scenario.persona,
            scenario=scenario.name,
            runid=runid,
            cell=None,
            status=status,
            error=error,
        )
        write_summary_row(results_root / runid / "_summary.csv", row)

    return ScenarioResult(
        persona=scenario.persona,
        scenario=scenario.name,
        status=status,
        error=error,
        outdir=outdir,
    )
