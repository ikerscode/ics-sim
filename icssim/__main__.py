"""Command line interface.

    python -m icssim serve [--port 8104]
    python -m icssim list
    python -m icssim baseline [--hours 24] [--mitigations sis,detector]
    python -m icssim run-scenario <name> [--mitigations a,b|all|none] [--fast] [--speed 60]
    python -m icssim matrix [--seeds 5] [--seed 1] [--workers 2] [--write-docs]
    python -m icssim export-policy [--out policy.json]
    python -m icssim netmode plan <scenario> | verify | down
    python -m icssim report [<run-id>]
    python -m icssim docs
    python -m icssim tui [--url http://127.0.0.1:8104] [--once]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .constants import MITIGATIONS


def _mits(text: str | None) -> list[str]:
    if not text or text == "none":
        return []
    if text == "all":
        return list(MITIGATIONS)
    names = [m.strip() for m in text.split(",") if m.strip()]
    bad = set(names) - set(MITIGATIONS)
    if bad:
        sys.exit(f"unknown mitigation(s): {', '.join(sorted(bad))}; choose from {', '.join(MITIGATIONS)}")
    return names


def cmd_serve(args):
    import uvicorn
    uvicorn.run("icssim.server:app", host=args.host, port=args.port, log_level="warning")


def cmd_list(args):
    from .scenarios import SCENARIOS
    for key, cls in SCENARIOS.items():
        d = cls.describe()
        print(f"{key:16s} {d['title']}")
        print(f"{'':16s} ATT&CK: {', '.join(t['id'] for t in d['techniques'])}; target: {', '.join(d['target_hazards'])}")
    print("\nmitigations:", ", ".join(MITIGATIONS))


def _print_metrics(m: dict, label: str = ""):
    print(f"{label}availability {m['availability_pct']}% | quality compliance {m['quality_compliance_pct']}% | "
          f"safety score {m['safety_score']} | hazards: {', '.join(m['hazards']) or 'none'}")
    if m["time_to_hazard_s"]:
        print(f"{label}time to hazard: " + ", ".join(f"{k} {v / 60:.1f} min" for k, v in m["time_to_hazard_s"].items()))


def cmd_baseline(args):
    from .runner import run
    t = time.perf_counter()
    res = run(None, _mits(args.mitigations), args.seed, horizon=args.hours * 3600, trend=False)
    m = res["metrics"]
    print(f"Baseline {args.hours:g} h simulated in {time.perf_counter() - t:.1f} s ({res['start_clock']} -> {res['end_clock']})")
    _print_metrics(m)
    print(f"final Cl {m['min_final_cl']}-{m['max_final_cl']} mg/L, pH {m['min_final_ph']}-{m['max_final_ph']}, "
          f"min pressure {m['min_pressure']} bar, max raw level {m['max_raw_level']} m, alerts {len(res['alerts'])}")
    return 0 if not m["hazards"] and not res["alerts"] else 1


def cmd_run(args):
    from . import storage
    from .runner import run_with_baseline
    from .scenarios import SCENARIOS
    if args.name not in SCENARIOS:
        sys.exit(f"unknown scenario; try: {', '.join(SCENARIOS)}")
    mits = _mits(args.mitigations)
    if not args.fast:
        return _run_realtime(args, mits)
    t = time.perf_counter()
    data = run_with_baseline(args.name, mits, args.seed)
    run_id = storage.save_run(data, mode="fast")
    print(f"{data['scenario']['title']}  [{time.perf_counter() - t:.1f} s]")
    print(f"mitigations: {', '.join(data['attack']['mitigations']) or 'none'} -> outcome: {data['outcome']}")
    _print_metrics(data["baseline"]["metrics"], "  baseline: ")
    _print_metrics(data["attack"]["metrics"], "  attack:   ")
    for m, d in data["per_mitigation"].items():
        print(f"  {m:13s} " + (f"detected after {d['ttd_s'] / 60:.1f} min: {d['message']}" if d["detected"] else "no alert"))
    print(f"report: data/reports/{run_id}.md (and .html)")
    return 0


def _run_realtime(args, mits):
    """Start the scenario on the running server so it can be watched on the HUD; else run locally in real time."""
    import httpx
    url = f"http://127.0.0.1:{args.port}/api/scenarios/run"
    try:
        r = httpx.post(url, json={"key": args.name, "mitigations": mits, "mode": "realtime"}, timeout=5)
        r.raise_for_status()
        print(f"Started on the live server; watch it at http://127.0.0.1:{args.port}/ ({r.json()})")
        return 0
    except httpx.HTTPError:
        print("No server running; running locally in real time (Ctrl-C to stop).")
    from .scenarios import ATTACK_AT, HORIZON, get
    from .sim import Simulation
    sc = get(args.name)
    sim = Simulation(seed=args.seed, mitigations=set(mits) | set(sc.requires), start_hour=sc.start_hour)
    sc.schedule(sim, ATTACK_AT)
    seen = 0
    try:
        while sim.t < HORIZON:
            t0 = time.perf_counter()
            sim.run_for(sim.dt * max(1, int(args.speed)))
            evs = list(sim.events.events)
            for e in evs[seen:]:
                if e["kind"] in ("attack", "alert", "hazard", "sis", "operator", "plc"):
                    print(f"{sim.clock(e['t'])} {e['kind']:8s} {e['message']}")
            seen = len(evs)
            time.sleep(max(0.0, 0.5 - (time.perf_counter() - t0)))
    except KeyboardInterrupt:
        pass
    _print_metrics(sim.metrics.summary(ATTACK_AT))
    return 0


def cmd_matrix(args):
    from . import storage
    from .report import matrix_markdown
    from .runner import matrix

    def progress(d, t):
        print(f"\r{d}/{t} runs", end="", flush=True)
    try:
        mx = matrix(seed=args.seed, workers=args.workers, progress=progress, n_seeds=args.seeds)
    except ValueError as exc:
        sys.exit(str(exc))
    print()
    storage.save_matrix(mx)
    md = matrix_markdown(mx)
    print(md.split("## Scenarios")[0])
    if args.write_docs:
        Path("docs/MATRIX.md").write_text(md)
        print("wrote docs/MATRIX.md")
    if mx["disagreements"]:
        print("seeds disagree in: " + ", ".join(f"{d['scenario']}/{d['column']} ({d['label']})" for d in mx["disagreements"]))
    print(f"saved data/reports/matrix.md and .html ({mx['runs']} runs, {mx['wall_s']} s wall on {mx['workers']} workers)")
    return 0


def cmd_export_policy(args):
    from .network import export_policy
    text = json.dumps(export_policy(), indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_netmode(args):
    from . import netmode
    if args.action == "plan":
        if not args.scenario:
            sys.exit("netmode plan needs a scenario name")
        print(json.dumps(netmode.build_plan(args.scenario), indent=1))
        return 0
    if args.action == "down":
        return netmode.compose(["down", "--remove-orphans"]).returncode
    return netmode.verify(keep_up=args.keep_up, build=not args.no_build)


def cmd_report(args):
    from . import storage
    if args.run_id:
        p = storage.report_path(args.run_id, "md")
        if not p:
            sys.exit("no such run")
        print(p.read_text())
        return 0
    for r in storage.list_reports():
        print(f"{r['name']:32s} {r['title']}")
    return 0


def cmd_docs(args):
    from .registers import register_map_markdown
    Path("docs/REGISTER_MAP.md").write_text(register_map_markdown())
    print("wrote docs/REGISTER_MAP.md")
    return 0


def cmd_tui(args):
    from . import termhud
    from .tui_spec import SPEC
    return termhud.run(SPEC, args.url, args.once)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m icssim", description="Water treatment ICS security simulator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve", help="start the HUD (8104) and Modbus/TCP server (5020)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8104)
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("list", help="list scenarios and mitigations").set_defaults(fn=cmd_list)
    p = sub.add_parser("baseline", help="run without an attack and check it stays safe")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--mitigations", default="all")
    p.add_argument("--seed", type=int, default=1)
    p.set_defaults(fn=cmd_baseline)
    p = sub.add_parser("run-scenario", help="run one scenario")
    p.add_argument("name")
    p.add_argument("--mitigations", default="none", help="comma list, 'all' or 'none'")
    p.add_argument("--fast", action="store_true", help="fast-forward with baseline comparison and report")
    p.add_argument("--speed", type=float, default=60, help="real-time acceleration when no server is running")
    p.add_argument("--port", type=int, default=8104)
    p.add_argument("--seed", type=int, default=1)
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("matrix", help="run every scenario x mitigation fast-forward over several seeds")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--seed", type=int, default=1, help="first seed")
    p.add_argument("--seeds", type=int, default=5, help="seeds per cell (1-10)")
    p.add_argument("--write-docs", action="store_true", help="also write docs/MATRIX.md")
    p.set_defaults(fn=cmd_matrix)
    p = sub.add_parser("report", help="list reports or print one")
    p.add_argument("run_id", nargs="?")
    p.set_defaults(fn=cmd_report)
    sub.add_parser("docs", help="regenerate docs/REGISTER_MAP.md").set_defaults(fn=cmd_docs)
    p = sub.add_parser("export-policy", help="print the zone, segmentation and DPI policy as JSON")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_export_policy)
    p = sub.add_parser("netmode", help="containerised network mode (docker compose): plan, verify, down")
    p.add_argument("action", choices=["plan", "verify", "down"])
    p.add_argument("scenario", nargs="?")
    p.add_argument("--keep-up", action="store_true", help="leave the containers running after verify")
    p.add_argument("--no-build", action="store_true", help="reuse the existing image")
    p.set_defaults(fn=cmd_netmode)
    p = sub.add_parser("tui", help="terminal HUD against the running server")
    p.add_argument("--url", default="http://127.0.0.1:8104")
    p.add_argument("--once", action="store_true", help="print every view as plain text and exit")
    p.set_defaults(fn=cmd_tui)
    args = ap.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
