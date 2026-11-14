"""Containerised network mode: plan, run and check scenario traffic over real Docker networks.

The in-process simulator stays the default. This module drives the optional docker
compose stack in deploy/ (see docs/NETWORK_MODE.md):

  build_plan(scenario)  run the scenario in-process with segmentation + DPI on and record
                        every Modbus request it sends together with the simulator's own
                        policy decision (Simulation.recorder);
  verify()              start the stack, replay each scenario's requests from the container
                        that owns the source address, collect the gateway's decision log
                        and the PLC's Modbus log, compare them, write data/netmode/ and stop.

The comparison functions are pure and unit tested (tests/test_fwgate.py).
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path

from . import modbus as mb
from .network import EWS_IP, HMI_IP, Firewall
from .registers import HR
from .scenarios import ATTACK_AT, HORIZON, SCENARIOS, get
from .sim import Simulation

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "deploy" / "compose.yml"
PROJECT = "ics-sim-net"
HUD_URL = "http://127.0.0.1:8124"
OUT_DIR = ROOT / "data" / "netmode"

# Simulated source address -> compose service that has that address on the wire.
SOURCES = {"192.168.10.37": "labclient", HMI_IP: "hmi", EWS_IP: "ews", "10.10.2.66": "rogue"}
GATEWAY_FOR = {"labclient": "192.168.10.254", "hmi": "10.10.2.254", "ews": "10.10.2.254", "rogue": "10.10.2.254"}
FLOOD_SAMPLE = 200       # flood requests actually sent per scenario (the simulator sends 2.4 million)
HMI_POLL_SAMPLE = 8      # two HMI polls after the attack starts
NET_MITIGATIONS = {"firewall", "segmentation"}


# ------------------------------------------------------------------ plan
def _decision(allowed: int, count: int, layer, reason) -> dict:
    return {"allowed": allowed == count, "allowed_n": allowed, "layer": layer, "reason": reason}


def build_plan(scenario: str, seed: int = 1) -> dict:
    """Requests the scenario sends (attack steps, a flood sample, a few HMI polls) and the
    simulator's own decision for each one, with segmentation and the DPI firewall enabled."""
    sc = get(scenario)
    sim = Simulation(seed=seed, mitigations=NET_MITIGATIONS | set(sc.requires), start_hour=sc.start_hour)
    sc.schedule(sim, ATTACK_AT)
    sim.recorder = []
    sim.run_for(HORIZON)
    items, polls, flood_done, skipped = [], 0, False, Counter()
    for r in sim.recorder:
        if r["count"] > 1:
            if flood_done:
                continue
            flood_done, kind, count = True, "flood", FLOOD_SAMPLE
        elif not r["routine"]:
            kind, count = "attack", 1
        elif r["src"] == HMI_IP and r["t"] >= ATTACK_AT and polls < HMI_POLL_SAMPLE:
            polls += 1
            kind, count = "hmi_poll", 1
        else:
            continue
        if r["src"] not in SOURCES:
            skipped[r["src"]] += 1
            continue
        items.append({"i": len(items), "src": r["src"], "service": SOURCES[r["src"]], "t_sim": r["t"],
                      "kind": kind, "adu": r["adu"], "count": count,
                      "sim": _decision(r["allowed"], r["count"], r["layer"], r["reason"])})
    notes = []
    if not any(it["kind"] in ("attack", "flood") for it in items):
        notes.append("no Modbus attack traffic: this scenario acts at field level, only HMI polls are replayed")
    return {"scenario": scenario, "seed": seed, "mitigations": sorted(NET_MITIGATIONS | set(sc.requires)),
            "items": items, "skipped_sources": dict(skipped), "notes": notes}


def policy_probes() -> dict:
    """A few requests that exercise the DPI rules the scenarios do not hit (no attack steps)."""
    fw = Firewall()
    fw.segmentation = fw.dpi = True
    reqs = [
        (HMI_IP, 1, mb.req_write_register(HR.CL_HI_ALM, 300), "HMI writes an alarm limit (write target rule)"),
        (HMI_IP, 1, bytes([90, 0x01]), "HMI uses FC 90 (function code rule)"),
        (HMI_IP, 2, mb.req_read(2, 0, 8), "HMI reads the SIS unit (segmentation)"),
        (HMI_IP, 1, mb.req_write_register(HR.PRESS_SP, 300), "HMI writes PRESS_SP 3.00 bar (allowed)"),
        (EWS_IP, 1, bytes([17]), "EWS Report Server ID (allowed)"),
    ]
    items = []
    for src, unit, pdu, what in reqs:
        allowed, layer, reason = fw.decide(src, unit, mb.describe(pdu), 0.0)
        items.append({"i": len(items), "src": src, "service": SOURCES[src], "kind": "probe", "what": what,
                      "adu": mb.build_adu(0, unit, pdu).hex(), "count": 1, "sim": _decision(allowed, 1, layer, reason)})
    return {"scenario": "policy_probes", "items": items, "notes": []}


# ------------------------------------------------------------------ comparison
def parse_fw_log(text: str) -> list[dict]:
    """Decision entries from the gateway's stdout (one JSON object per line)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if "decision" in e:
            out.append(e)
    return out


def reevaluate(entries: list[dict]) -> dict:
    """Run every logged gateway decision back through the simulator's own policy code
    (network.Firewall.decide), in log order and at the gateway's logged times."""
    fw = Firewall()
    fw.segmentation = fw.dpi = True
    mismatches = []
    for e in entries:
        pdu = bytes.fromhex(e["pdu"])
        unit = 1 if e["unit"] in (0, 255) else e["unit"]
        allowed, layer, reason = fw.decide(e["src"], unit, mb.describe(pdu), e["t"], 1)
        ok = (allowed == 1) == (e["decision"] == "allow") and layer == e["layer"] and reason == e["reason"]
        if not ok:
            mismatches.append({"entry": e, "simulator": {"allowed": allowed, "layer": layer, "reason": reason}})
    return {"checked": len(entries), "agree": len(entries) - len(mismatches), "mismatches": mismatches[:20],
            "by_decision": dict(Counter(e["decision"] for e in entries)),
            "by_reason": dict(Counter(e["reason"] or "allowed" for e in entries))}


def match_items(plan: dict, results: list[dict], entries: list[dict]) -> dict:
    """For each replayed request: did the gateway log it from the container's own address,
    and is its decision the one the in-process simulator made for the same request?"""
    by_key = {(e["src"], e["sport"], e["tid"]): e for e in entries}
    res = {r["i"]: r for r in results}
    rows, agree, seen = [], 0, 0
    for it in plan["items"]:
        r = res.get(it["i"])
        if r is None:
            rows.append({**_row_base(it), "status": "not sent"})
            continue
        t1, t2 = r["tids"]
        logged = [by_key.get((r["src"], r["sport"], t)) for t in range(t1, t2 + 1)]
        logged = [e for e in logged if e]
        seen += bool(logged)
        allow_n = sum(e["decision"] == "allow" for e in logged)
        layers = {(e["layer"], e["reason"]) for e in logged if e["decision"] == "block"}
        sim = it["sim"]
        if it["count"] == 1:
            ok = bool(logged) and (allow_n == 1) == sim["allowed"] and (
                sim["allowed"] or layers == {(sim["layer"], sim["reason"])})
        else:   # flood sample: the simulator's verdict for the whole burst
            ok = len(logged) == it["count"] and (
                (sim["allowed_n"] == 0 and allow_n == 0 and layers == {(sim["layer"], sim["reason"])})
                or (sim["allowed_n"] > 0 and allow_n > 0))
        agree += ok
        rows.append({**_row_base(it), "logged": len(logged), "src_on_wire": r["src"], "gateway_allowed": allow_n,
                     "gateway_reason": sorted(x[1] for x in layers)[0] if layers else None,
                     "client_replies": r["replies"], "agree": ok,
                     "client_consistent": r["replies"] == allow_n})
    return {"scenario": plan["scenario"], "items": len(plan["items"]), "logged": seen, "agree": agree,
            "client_consistent": sum(1 for x in rows if x.get("client_consistent")), "rows": rows,
            "notes": plan.get("notes", [])}


def _row_base(it: dict) -> dict:
    pdu = bytes.fromhex(it["adu"])[7:]
    info = mb.describe(pdu)
    return {"i": it["i"], "kind": it["kind"], "src": it["src"], "service": it["service"], "fc": info["fc"],
            "addr": info["addr"], "count": it["count"], "sim_allowed": it["sim"]["allowed"],
            "sim_reason": it["sim"]["reason"]}


def plc_side(rows: list[dict], matched: list[dict]) -> dict:
    """What reached the PLC over TCP, by original source (from the gateway's PROXY header)."""
    tcp = [r for r in rows if r.get("transport") == "tcp"]
    by_src = Counter(r["src"] for r in tcp)
    seen = {(r["src"], r["fc"], r["addr"]) for r in tcp}
    allowed_attacks = [x for m in matched for x in m["rows"]
                       if x["kind"] in ("attack", "probe") and x.get("gateway_allowed")]
    arrived = [x for x in allowed_attacks if (x["src"], x["fc"], x["addr"]) in seen]
    blocked_only = {x["src"] for m in matched for x in m["rows"]} - {
        x["src"] for m in matched for x in m["rows"] if x.get("gateway_allowed")} - {HMI_IP}
    return {"tcp_rows": len(tcp), "by_source": dict(by_src),
            "allowed_attack_writes": len(allowed_attacks), "found_at_plc": len(arrived),
            "blocked_sources_seen_at_plc": sorted(s for s in blocked_only if by_src.get(s))}


# ------------------------------------------------------------------ docker side
def compose(args: list[str], stdin: str | None = None, timeout: float = 900) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT, *args]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)


def agent(service: str, *args: str, stdin: str | None = None) -> list[dict]:
    p = compose(["exec", "-T", service, "python", "-m", "icssim.netagent", *args], stdin=stdin, timeout=300)
    out = []
    for line in p.stdout.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    if p.returncode and not out:
        out.append({"error": (p.stderr or p.stdout).strip()[-400:]})
    return out


def _http(path: str, body: dict | None = None, timeout: float = 5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUD_URL + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _wait_health(limit_s: float = 90) -> dict:
    end = time.monotonic() + limit_s
    while time.monotonic() < end:
        try:
            return _http("/api/health")
        except OSError:
            time.sleep(1.5)
    raise RuntimeError("PLC HUD did not answer on " + HUD_URL)


def _replay(plan: dict) -> list[dict]:
    results = []
    for service in sorted({it["service"] for it in plan["items"]}):
        mine = [{"i": it["i"], "adu": it["adu"], "count": it["count"]} for it in plan["items"] if it["service"] == service]
        results += [r for r in agent(service, "replay", stdin=json.dumps(mine)) if "i" in r]
    return results


def _tool(service: str, gateway: str) -> str:
    p = compose(["exec", "-T", service, "python", "tools/read_plant.py", "--host", gateway, "--port", "5020"], timeout=60)
    return (p.stdout + p.stderr).strip()


def verify(keep_up: bool = False, build: bool = True) -> int:
    """Start the stack, run every check, write data/netmode/evidence.{json,md}, stop the stack."""
    t_start = time.time()
    ev: dict = {"started": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        if build:
            p = compose(["build"], timeout=1800)
            if p.returncode:
                print(p.stdout[-2000:], p.stderr[-2000:])
                return 1
        p = compose(["up", "-d"], timeout=300)
        if p.returncode:
            print(p.stderr[-2000:])
            return 1
        ev["health_via_fw_relay"] = _wait_health()
        _http("/api/sim", {"action": "speed", "speed": 1})
        ev["containers"] = compose(["ps", "--format", "{{.Service}} {{.State}}"]).stdout.split("\n")
        ev["probes"] = {
            "labclient -> PLC 10.10.1.10:5020 (direct)": agent("labclient", "probe", "10.10.1.10", "5020"),
            "hmi -> PLC 10.10.1.10:5020 (direct)": agent("hmi", "probe", "10.10.1.10", "5020"),
            "labclient -> HMI 10.10.2.10:5020 (across zones)": agent("labclient", "probe", "10.10.2.10", "5020"),
            "hmi -> 1.1.1.1:443 (internet)": agent("hmi", "probe", "1.1.1.1", "443"),
            "labclient -> gateway 192.168.10.254:5020": agent("labclient", "probe", "192.168.10.254", "5020"),
        }
        ev["read_plant"] = {"labclient (IT, CORP-WS-37)": _tool("labclient", "192.168.10.254"),
                            "hmi (DMZ, HMI-01)": _tool("hmi", "10.10.2.254")}
        plans = [build_plan(k) for k in SCENARIOS] + [policy_probes()]
        results = {}
        for plan in plans:
            t = time.monotonic()
            results[plan["scenario"]] = _replay(plan)
            print(f"{plan['scenario']}: {len(plan['items'])} requests replayed in {time.monotonic() - t:.1f} s", flush=True)
        ev["burst"] = agent("hmi", "burst", "80")
        time.sleep(1.0)
        entries = parse_fw_log(compose(["logs", "--no-log-prefix", "fw"]).stdout)
        ev["reevaluation"] = reevaluate(entries)
        ev["scenarios"] = [match_items(plan, results[plan["scenario"]], entries) for plan in plans]
        ev["plc"] = plc_side(_http("/api/modbus?limit=2000")["rows"], ev["scenarios"])
        ev["wall_s"] = round(time.time() - t_start, 1)
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "evidence.json").write_text(json.dumps(ev, indent=1, default=str))
        (OUT_DIR / "fw.log").write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        md = evidence_markdown(ev)
        (OUT_DIR / "evidence.md").write_text(md)
        print(md)
        ok = (ev["reevaluation"]["agree"] == ev["reevaluation"]["checked"]
              and all(s["agree"] == s["items"] for s in ev["scenarios"])
              and not ev["plc"]["blocked_sources_seen_at_plc"])
        return 0 if ok else 1
    finally:
        if not keep_up:
            compose(["down", "--remove-orphans", "--timeout", "5"], timeout=300)


def evidence_markdown(ev: dict) -> str:
    re_ = ev["reevaluation"]
    out = ["# Network mode verification", "", f"Run {ev['started']}, {ev.get('wall_s', '?')} s including start and stop.", "",
           "## Isolation probes", "", "| Probe | Result |", "|---|---|"]
    for k, v in ev["probes"].items():
        out.append(f"| {k} | {v[0].get('result', v[0]) if v else '-'} |")
    out += ["", "## Lab client (tools/read_plant.py) through the gateway", ""]
    for k, v in ev["read_plant"].items():
        out += [f"{k}:", "", "```", v[-900:], "```", ""]
    out += ["## Scenario traffic: gateway decision vs in-process simulator decision", "",
            "| Scenario | Requests | Logged by gateway | Same decision as simulator | Client replies consistent | Gateway outcomes |",
            "|---|---|---|---|---|---|"]
    for s in ev["scenarios"]:
        outc = Counter("allowed" if x.get("gateway_allowed") else (x.get("gateway_reason") or "-") for x in s["rows"])
        txt = "; ".join(f"{k} x{v}" for k, v in outc.most_common())
        out.append(f"| {s['scenario']} | {s['items']} | {s['logged']} | {s['agree']} | {s['client_consistent']} | {txt} |")
    out += ["", "## Every gateway log entry re-checked with network.Firewall.decide", "",
            f"{re_['agree']} of {re_['checked']} decisions identical (decision, layer and reason). "
            f"By decision: {re_['by_decision']}.", ""]
    out += ["| Reason | Entries |", "|---|---|"] + [f"| {k} | {v} |" for k, v in
                                                       sorted(re_["by_reason"].items(), key=lambda kv: -kv[1])]
    b = ev["burst"][0] if ev.get("burst") else {}
    out += ["", f"Rate limit burst from the HMI container: {b.get('sent')} back-to-back reads, {b.get('replies')} answered.", ""]
    plc = ev["plc"]
    out += ["## What reached the PLC", "",
            f"{plc['tcp_rows']} TCP transactions in the PLC's Modbus log, by original source (PROXY header): {plc['by_source']}. "
            f"{plc['found_at_plc']} of {plc['allowed_attack_writes']} allowed attack and probe requests found at the PLC. "
            f"Sources that were only ever blocked and still reached the PLC: {plc['blocked_sources_seen_at_plc'] or 'none'}.", ""]
    return "\n".join(out)
