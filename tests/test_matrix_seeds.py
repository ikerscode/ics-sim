"""Multi-seed matrix: aggregation of per-seed outcomes, the disagreement flag and the report."""

import os

import pytest

os.environ.setdefault("ICSSIM_MODBUS_PORT", "0")

from fastapi.testclient import TestClient  # noqa: E402

from icssim import runner  # noqa: E402
from icssim.report import matrix_cell_text, matrix_markdown  # noqa: E402
from icssim.server import app  # noqa: E402


def cell(seed, outcome, ttd=None, tth=None, av=100.0, by=None, hazards=()):
    return {"seed": seed, "outcome": outcome, "ttd_s": ttd, "tth_s": tth, "availability_pct": av,
            "quality_compliance_pct": 100.0, "safety_score": 100.0, "detected_by": by, "hazards": list(hazards)}


def test_agreeing_cell_reports_proportion_median_and_range():
    agg = runner.aggregate_cell([cell(s, "prevented", ttd=t, av=a, by="eng_limits")
                                 for s, t, a in [(1, 60, 100), (2, 40, 98), (3, 90, 100), (4, 60, 99), (5, 70, 100)]])
    assert agg["outcome"] == "prevented" and agg["agree"] is True
    assert agg["outcome_label"] == "prevented 5/5" and agg["n_seeds"] == 5
    assert (agg["ttd_s"], agg["ttd_min_s"], agg["ttd_max_s"], agg["ttd_n"]) == (60, 40, 90, 5)
    assert (agg["availability_pct"], agg["availability_min_pct"], agg["availability_max_pct"]) == (100, 98, 100)
    assert agg["detected_by"] == "eng_limits"
    assert [p["seed"] for p in agg["per_seed"]] == [1, 2, 3, 4, 5]


def test_disagreeing_cell_is_flagged_and_majority_wins():
    agg = runner.aggregate_cell([cell(1, "prevented", ttd=2940), cell(2, "prevented", ttd=3000),
                                 cell(3, "not detected", hazards=["chlorine_overdose"]),
                                 cell(4, "prevented", ttd=2800), cell(5, "not detected", hazards=["chlorine_overdose"])])
    assert agg["agree"] is False
    assert agg["outcome"] == "prevented"
    assert agg["outcome_label"] == "prevented 3/5, not detected 2/5"
    assert agg["ttd_n"] == 3 and agg["ttd_s"] == 2940
    assert agg["hazard_counts"] == {"chlorine_overdose": 2}
    text = matrix_cell_text(agg)
    assert text.startswith("MIXED **PREVENTED** 3/5") and "prevented 3/5, not detected 2/5" in text
    assert "(alert in 3/5)" in text


def test_tie_goes_to_the_worse_outcome():
    assert runner.majority(["prevented", "detected"]) == "detected"
    assert runner.majority(["prevented", "not detected", "prevented", "not detected"]) == "not detected"
    assert runner.majority(["hazard", "no hazard"]) == "hazard"


def test_spread_ignores_missing_values():
    assert runner.spread([None, None]) == {"median": None, "min": None, "max": None, "n": 0}
    assert runner.spread([10, None, 30]) == {"median": 20.0, "min": 10, "max": 30, "n": 2}


def test_seed_list_bounds():
    assert runner.seed_list(5) == [1, 2, 3, 4, 5]
    assert runner.seed_list(2, first=7) == [7, 8]
    for bad in (0, runner.MAX_SEEDS + 1):
        with pytest.raises(ValueError):
            runner.seed_list(bad)


def _mx(cells_by_col):
    cols = list(cells_by_col)
    cells = {"setpoint_change": {c: runner.aggregate_cell(v) for c, v in cells_by_col.items()}}
    base = {c: runner.aggregate_baseline([{"false_alerts": 0, "hazards": [], "availability_pct": 100.0, "alerts": []}] * 3)
            for c in cols}
    return {"seed": 1, "seeds": [1, 2, 3], "n_seeds": 3, "columns": cols, "cells": cells, "baseline": base,
            "disagreements": runner.disagreements(cells), "horizon_s": 10800, "attack_at_s": 1800, "runs": 18,
            "workers": 2, "sim_run_s": 1.0, "wall_s": 1.0, "generated": "test",
            "scenarios": [{"key": "setpoint_change", "requires": [], "title": "t", "techniques": []}]}


def test_matrix_markdown_lists_disagreements_and_seed1_changes():
    mx = _mx({"none": [cell(s, "hazard", tth=1900 + s, hazards=["chlorine_overdose"]) for s in (1, 2, 3)],
              "operator": [cell(1, "not detected"), cell(2, "prevented", ttd=60), cell(3, "prevented", ttd=70)]})
    assert mx["disagreements"] == [{"scenario": "setpoint_change", "column": "operator",
                                    "label": "prevented 2/3, not detected 1/3"}]
    md = matrix_markdown(mx)
    assert "seeds 1-3 (3 per cell)" in md
    assert "**HAZARD** 3/3 in 31.7 min av 100 |" in md      # range collapses when it rounds to one value
    assert "## Cells where seeds disagree" in md and "1: not detected; 2: prevented (60 s)" in md
    assert "| setpoint_change | operator | not detected | prevented 2/3, not detected 1/3 |" in md


def test_matrix_api_validates_seed_count_and_serves_cells():
    with TestClient(app) as c:
        assert c.post("/api/matrix/run", json={"seeds": 0}).status_code == 400
        assert c.post("/api/matrix/run", json={"seeds": runner.MAX_SEEDS + 1}).status_code == 400
        r = c.get("/api/matrix/cells")
        assert r.status_code == 200 and isinstance(r.json()["rows"], list)
