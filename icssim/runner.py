"""Fast-forward runs, baseline comparison, outcome classification and the mitigation matrix."""

from __future__ import annotations

import statistics
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

from .constants import MITIGATIONS
from .scenarios import ATTACK_AT, HORIZON, SCENARIOS, get
from .sim import Simulation

COLUMNS = ["none"] + MITIGATIONS + ["all"]
DETECTION_SOURCES = set(MITIGATIONS)
TIMELINE_KINDS = {"attack", "alert", "hazard", "sis", "operator", "plc", "hmi", "alarm"}
DEFAULT_SEEDS = 5           # seeds per matrix cell
MAX_SEEDS = 10              # keeps a matrix run under about 10 minutes on two workers
# Worst first. When two outcomes are equally common across seeds the worse one is reported.
OUTCOME_ORDER = ["hazard", "not detected", "detected", "prevented", "no hazard"]


def column_mitigations(col: str) -> set[str]:
    if col == "none":
        return set()
    if col == "all":
        return set(MITIGATIONS)
    return {col}


def run(scenario: str | None, mitigations=(), seed: int = 1, horizon: float = HORIZON,
        attack_at: float = ATTACK_AT, start_hour: float | None = None, trend: bool = True) -> dict:
    """Run one simulation fast-forward and return a JSON-friendly result."""
    sc = get(scenario) if scenario else None
    mits = set(mitigations) | (set(sc.requires) if sc else set())
    sh = start_hour if start_hour is not None else (sc.start_hour if sc else 6.0)
    sim = Simulation(seed=seed, mitigations=mits, start_hour=sh)
    if sc:
        sc.schedule(sim, attack_at)
    t_start = time.perf_counter()
    sim.run_for(horizon)
    return collect(sim, sc, attack_at, mits, seed, horizon, sh, time.perf_counter() - t_start, trend)


def collect(sim, sc, attack_at, mits, seed, horizon, start_hour, wall_s=0.0, trend=True) -> dict:
    ev = sim.events
    timeline = []
    for e in ev.events:
        if e["kind"] in TIMELINE_KINDS:
            timeline.append({**e, "clock": sim.clock(e["t"])})
    notable = [m for m in ev.modbus if m["write"] or m["result"] != "ok" or m["src"] not in ("10.10.2.10", "10.10.3.5")]
    first: dict[str, dict] = {}
    for a in ev.alerts:
        if a["t"] >= attack_at and a["source"] in DETECTION_SOURCES and a["source"] not in first:
            first[a["source"]] = {"t": a["t"], "ttd_s": round(a["t"] - attack_at, 1), "message": a["message"]}
    false_alerts = [a for a in ev.alerts if a["t"] < attack_at]
    return {
        "scenario": sc.key if sc else None,
        "title": sc.title if sc else "Baseline (no attack)",
        "mitigations": sorted(mits), "seed": seed, "horizon_s": horizon, "attack_at_s": attack_at if sc else None,
        "start_hour": start_hour, "start_clock": sim.clock(0.0), "end_clock": sim.clock(),
        "metrics": sim.metrics.summary(attack_at if sc else None),
        "detections": first,
        "alerts": [{**a, "clock": sim.clock(a["t"])} for a in ev.alerts][:400],
        "alerts_before_attack": len(false_alerts),
        "timeline": timeline[:600],
        "modbus_notable": notable[:400],
        "counters": dict(ev.counters),
        "sis_trips": sim.sis.trip_count,
        "trend": list(sim.trend) if trend else [],
        "wall_s": round(wall_s, 2),
    }


def classify(sc_key: str, result: dict, col: str) -> dict:
    """Outcome of one matrix cell: hazard / prevented / detected / not detected."""
    sc = SCENARIOS[sc_key]
    hit = [h for h in sc.target_hazards if h in result["metrics"]["hazards"]]
    tth = [result["metrics"]["time_to_hazard_s"][h] for h in hit]
    credit = column_mitigations(col)
    dets = {m: d for m, d in result["detections"].items() if m in credit}
    ttd = min((d["ttd_s"] for d in dets.values()), default=None)
    by = min(dets, key=lambda m: dets[m]["ttd_s"]) if dets else None
    if col == "none":
        outcome = "hazard" if hit else "no hazard"
    elif not hit:
        outcome = "prevented"
    elif dets:
        outcome = "detected"
    else:
        outcome = "not detected"
    m = result["metrics"]
    return {"outcome": outcome, "ttd_s": ttd, "detected_by": by, "tth_s": min(tth) if tth else None,
            "hazards": m["hazards"], "availability_pct": m["availability_pct"],
            "quality_compliance_pct": m["quality_compliance_pct"], "safety_score": m["safety_score"]}


def run_with_baseline(scenario: str, mitigations=(), seed: int = 1) -> dict:
    """Attack run plus a baseline run with the same seed and mitigations, and per-mitigation outcomes."""
    attack = run(scenario, mitigations, seed)
    sc = SCENARIOS[scenario]
    baseline = run(None, set(mitigations) | set(sc.requires), seed, start_hour=sc.start_hour)
    hit = [h for h in sc.target_hazards if h in attack["metrics"]["hazards"]]
    per_mit = {}
    for mit in attack["mitigations"]:
        det = attack["detections"].get(mit)
        per_mit[mit] = {"detected": bool(det), "ttd_s": det["ttd_s"] if det else None,
                        "message": det["message"] if det else ""}
    outcome = "hazard occurred" if hit else ("prevented" if attack["mitigations"] else "no hazard")
    return {"attack": attack, "baseline": baseline, "outcome": outcome, "target_hit": hit, "per_mitigation": per_mit,
            "scenario": SCENARIOS[scenario].describe()}


def _cell(args):
    sc_key, col, seed = args
    res = run(sc_key, column_mitigations(col), seed, trend=False)
    return sc_key, col, classify(sc_key, res, col) if sc_key else None, res["wall_s"]


def _baseline_cell(args):
    col, seed = args
    res = run(None, column_mitigations(col), seed, trend=False)
    return col, {"false_alerts": len(res["alerts"]), "hazards": res["metrics"]["hazards"],
                 "availability_pct": res["metrics"]["availability_pct"],
                 "alerts": [a["message"] for a in res["alerts"]][:5]}


# ------------------------------------------------------------ seed aggregation
def seed_list(n_seeds: int, first: int = 1) -> list[int]:
    """Seeds used for a matrix run: first, first+1, ... (seed 1 is the old single-seed table)."""
    if not 1 <= n_seeds <= MAX_SEEDS:
        raise ValueError(f"seeds must be between 1 and {MAX_SEEDS}")
    return list(range(first, first + n_seeds))


def spread(values) -> dict:
    """Median, min, max and count of the non-None values (None everywhere -> all None, n 0)."""
    vals = [v for v in values if v is not None]
    if not vals:
        return {"median": None, "min": None, "max": None, "n": 0}
    return {"median": round(statistics.median(vals), 1), "min": min(vals), "max": max(vals), "n": len(vals)}


def majority(outcomes) -> str:
    """Most common outcome; ties go to the worse outcome so a flip is never reported optimistically."""
    counts = Counter(outcomes)
    top = max(counts.values())
    return min((o for o, k in counts.items() if k == top), key=OUTCOME_ORDER.index)


def outcome_label(counts: dict, n: int) -> str:
    """'prevented 5/5' or 'prevented 3/5, detected 2/5' (most common first)."""
    order = sorted(counts.items(), key=lambda kv: (-kv[1], OUTCOME_ORDER.index(kv[0])))
    return ", ".join(f"{o} {k}/{n}" for o, k in order)


def aggregate_cell(per_seed: list[dict]) -> dict:
    """Combine one cell's per-seed classify() results (each with a "seed" key).

    Keeps the single-seed field names (outcome, ttd_s, tth_s, availability_pct ...) with the
    median as their value, so older readers of the matrix JSON still work, and adds the
    proportion, min/max and an agreement flag.
    """
    n = len(per_seed)
    counts = dict(Counter(c["outcome"] for c in per_seed))
    ttd = spread(c["ttd_s"] for c in per_seed)
    tth = spread(c["tth_s"] for c in per_seed)
    av = spread(c["availability_pct"] for c in per_seed)
    by = Counter(c["detected_by"] for c in per_seed if c["detected_by"])
    hazard_counts = Counter(h for c in per_seed for h in c["hazards"])
    return {
        "outcome": majority(c["outcome"] for c in per_seed),
        "outcome_counts": counts,
        "outcome_label": outcome_label(counts, n),
        "agree": len(counts) == 1,
        "n_seeds": n,
        "ttd_s": ttd["median"], "ttd_min_s": ttd["min"], "ttd_max_s": ttd["max"], "ttd_n": ttd["n"],
        "tth_s": tth["median"], "tth_min_s": tth["min"], "tth_max_s": tth["max"], "tth_n": tth["n"],
        "availability_pct": av["median"], "availability_min_pct": av["min"], "availability_max_pct": av["max"],
        "quality_compliance_pct": spread(c["quality_compliance_pct"] for c in per_seed)["median"],
        "safety_score": spread(c["safety_score"] for c in per_seed)["median"],
        "detected_by": by.most_common(1)[0][0] if by else None,
        "hazards": sorted(hazard_counts),
        "hazard_counts": dict(hazard_counts),
        "per_seed": [{k: c.get(k) for k in ("seed", "outcome", "ttd_s", "tth_s", "availability_pct", "detected_by")}
                     for c in sorted(per_seed, key=lambda c: c["seed"])],
    }


def aggregate_baseline(per_seed: list[dict]) -> dict:
    """Baseline (no attack) column over seeds: total false alerts, union of hazards, worst availability."""
    return {"false_alerts": sum(b["false_alerts"] for b in per_seed),
            "false_alerts_per_seed": [b["false_alerts"] for b in per_seed],
            "hazards": sorted({h for b in per_seed for h in b["hazards"]}),
            "availability_pct": min(b["availability_pct"] for b in per_seed),
            "alerts": [a for b in per_seed for a in b["alerts"]][:5]}


def disagreements(cells: dict) -> list[dict]:
    """Cells whose outcome differs across seeds."""
    return [{"scenario": k, "column": c, "label": cell["outcome_label"]}
            for k, row in cells.items() for c, cell in row.items() if not cell["agree"]]


def matrix(seed: int = 1, workers: int = 2, progress=None, scenarios=None, n_seeds: int = DEFAULT_SEEDS) -> dict:
    """Run every scenario x mitigation column for `n_seeds` seeds (in up to `workers` processes).

    Each cell is aggregated over the seeds (see aggregate_cell). The baseline row is the same
    columns with no attack, also over every seed, to count false alerts.
    """
    seeds = seed_list(n_seeds, seed)
    keys = list(scenarios or SCENARIOS)
    jobs = [(k, c, s) for k in keys for c in COLUMNS for s in seeds]
    base_jobs = [(c, s) for c in COLUMNS for s in seeds]
    t0 = time.perf_counter()
    raw: dict = {(k, c): [] for k in keys for c in COLUMNS}
    raw_base: dict = {c: [] for c in COLUMNS}
    run_s = 0.0
    done = 0
    total = len(jobs) + len(base_jobs)
    with ProcessPoolExecutor(max_workers=max(1, min(workers, 2))) as ex:
        for (k, c, cell, wall), (_, _, s) in zip(ex.map(_cell, jobs), jobs):
            raw[(k, c)].append({**cell, "seed": s})
            run_s += wall
            done += 1
            if progress:
                progress(done, total)
        for (c, info), (_, s) in zip(ex.map(_baseline_cell, base_jobs), base_jobs):
            raw_base[c].append({**info, "seed": s})
            done += 1
            if progress:
                progress(done, total)
    cells = {k: {c: aggregate_cell(raw[(k, c)]) for c in COLUMNS} for k in keys}
    baseline = {c: aggregate_baseline(raw_base[c]) for c in COLUMNS}
    return {"seed": seeds[0], "seeds": seeds, "n_seeds": len(seeds), "columns": COLUMNS,
            "scenarios": [SCENARIOS[k].describe() for k in keys],
            "cells": cells, "baseline": baseline, "disagreements": disagreements(cells),
            "horizon_s": HORIZON, "attack_at_s": ATTACK_AT, "runs": total, "workers": max(1, min(workers, 2)),
            "sim_run_s": round(run_s, 1),
            "wall_s": round(time.perf_counter() - t0, 1), "generated": time.strftime("%Y-%m-%d %H:%M:%S")}
