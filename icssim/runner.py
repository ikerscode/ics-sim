"""Fast-forward runs, baseline comparison, outcome classification and the mitigation matrix."""

from __future__ import annotations

import time
from concurrent.futures import ProcessPoolExecutor

from .constants import MITIGATIONS
from .scenarios import ATTACK_AT, HORIZON, SCENARIOS, get
from .sim import Simulation

COLUMNS = ["none"] + MITIGATIONS + ["all"]
DETECTION_SOURCES = set(MITIGATIONS)
TIMELINE_KINDS = {"attack", "alert", "hazard", "sis", "operator", "plc", "hmi", "alarm"}


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


def matrix(seed: int = 1, workers: int = 2, progress=None, scenarios=None) -> dict:
    """Run every scenario x mitigation column fast-forward (in up to `workers` processes)."""
    keys = list(scenarios or SCENARIOS)
    jobs = [(k, c, seed) for k in keys for c in COLUMNS]
    t0 = time.perf_counter()
    cells: dict = {k: {} for k in keys}
    done = 0
    total = len(jobs) + len(COLUMNS)
    with ProcessPoolExecutor(max_workers=max(1, workers)) as ex:
        for k, c, cell, _ in ex.map(_cell, jobs):
            cells[k][c] = cell
            done += 1
            if progress:
                progress(done, total)
        baseline = {}
        for c, info in ex.map(_baseline_cell, [(c, seed) for c in COLUMNS]):
            baseline[c] = info
            done += 1
            if progress:
                progress(done, total)
    return {"seed": seed, "columns": COLUMNS, "scenarios": [SCENARIOS[k].describe() for k in keys],
            "cells": cells, "baseline": baseline, "horizon_s": HORIZON, "attack_at_s": ATTACK_AT,
            "wall_s": round(time.perf_counter() - t0, 1), "generated": time.strftime("%Y-%m-%d %H:%M:%S")}
