"""FastAPI app: live simulation, Modbus/TCP listener on 127.0.0.1:5020 and the HUD API."""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import NAME, __version__, storage
from .constants import HAZARDS, MITIGATION_LABELS, MITIGATIONS
from .modbus import serve_tcp
from .network import HOSTS, LAB_CLIENT_IP, ZONES, policy_table, zone_of
from .registers import C, HR_BY_NAME, PLC_COILS, register_map
from .runner import collect, matrix, run, run_with_baseline
from .scenarios import ATTACK_AT, HORIZON, SCENARIOS, get
from .sim import Simulation

STATIC = Path(__file__).resolve().parent.parent / "static"
MODBUS_HOST = "127.0.0.1"
MODBUS_PORT = int(os.environ.get("ICSSIM_MODBUS_PORT", "5020"))
DEFAULT_LIVE_MITIGATIONS = {"sis", "detector", "integrity"}


class Live:
    """The one live simulation the HUD watches, plus real-time scenario bookkeeping."""

    def __init__(self, seed: int = 1):
        self.speed = 10.0
        self.paused = False
        self.ext_ip = LAB_CLIENT_IP
        self.reset(seed)
        self.matrix_job = {"running": False, "done": 0, "total": 0, "error": None}

    def reset(self, seed: int = 1, mitigations=None) -> None:
        mits = mitigations if mitigations is not None else getattr(self, "sim", None) and self.sim.mitigations
        self.sim = Simulation(seed=seed, mitigations=mits or DEFAULT_LIVE_MITIGATIONS, start_hour=6.0, live=True)
        self.scenario = None
        self.metrics_since = 0.0

    def advance(self, wall_dt: float) -> None:
        if self.paused:
            return
        self.debt = getattr(self, "debt", 0.0) + wall_dt * self.speed
        n = 0
        while self.debt >= self.sim.dt and n < 4000:
            self.sim.step()
            self.debt -= self.sim.dt
            n += 1
        self.debt = min(self.debt, 5.0)
        if self.scenario and self.sim.t >= self.scenario["end"]:
            self.finish_scenario()

    # ----------------------------------------------------- real-time scenario
    def start_scenario(self, key: str, mitigations: list[str]) -> dict:
        if self.scenario:
            self.finish_scenario()
        sc = get(key)
        mits = set(mitigations) | set(sc.requires)
        self.sim.set_mitigations(mits)
        from .consequences import ConsequenceTracker
        t0 = self.sim.t + 5.0
        self.sim.metrics = ConsequenceTracker(self.sim.events, t0=self.sim.t)
        self.metrics_since = self.sim.t
        sc.schedule(self.sim, t0)
        self.scenario = {"key": key, "obj": sc, "t0": t0, "start": self.sim.t, "end": t0 + HORIZON - ATTACK_AT,
                         "mitigations": sorted(mits), "start_hour": self.sim.plant.clock_hours()}
        return {"key": key, "t0": t0, "duration_s": HORIZON - ATTACK_AT, "mitigations": sorted(mits)}

    def finish_scenario(self) -> str | None:
        """Close the real-time run, build its report (with a fast baseline) and detach the attack."""
        s = self.scenario
        if not s:
            return None
        self.scenario = None
        sim, sc = self.sim, s["obj"]
        res = collect(sim, sc, s["t0"], set(s["mitigations"]), sim.seed, sim.t - s["start"], 6.0)
        res["timeline"] = [e for e in res["timeline"] if e["t"] >= s["start"]]
        res["modbus_notable"] = [m for m in res["modbus_notable"] if m["t"] >= s["start"]]
        res["attack_at_s"] = s["t0"]
        res["horizon_s"] = sim.t - s["start"]
        res["start_clock"] = sim.clock(s["start"])
        sc.detach(sim)
        warm = s["t0"] - s["start"]
        baseline = run(None, s["mitigations"], sim.seed, horizon=sim.t - s["start"], attack_at=warm,
                       start_hour=s["start_hour"], trend=False)
        hit = [h for h in sc.target_hazards if h in res["metrics"]["hazards"]]
        per = {m: {"detected": m in res["detections"], "ttd_s": res["detections"].get(m, {}).get("ttd_s"),
                   "message": res["detections"].get(m, {}).get("message", "")} for m in s["mitigations"]}
        data = {"attack": res, "baseline": baseline, "outcome": "hazard occurred" if hit else ("prevented" if s["mitigations"] else "no hazard"),
                "target_hit": hit, "per_mitigation": per, "scenario": sc.describe()}
        run_id = storage.save_run(data, mode="realtime")
        sim.events.add(sim.t, "system", f"Real-time scenario {s['key']} finished, report {run_id}", "info", "system")
        self.last_run_id = run_id
        return run_id


live = Live()


async def _sim_loop():
    loop = asyncio.get_running_loop()
    last = loop.time()
    while True:
        await asyncio.sleep(0.1)
        now = loop.time()
        try:
            live.advance(now - last)
        except Exception as exc:  # keep the loop alive; surface the error in the event log
            live.sim.events.add(live.sim.t, "system", f"simulation error: {exc!r}", "crit", "system")
        last = now


def _modbus_handler(peer_ip: str, adu: bytes):
    # Real TCP clients are mapped to a simulated source address chosen in the HUD.
    return live.sim.request(live.ext_ip, adu, transport="tcp")


async def _startup(app):
    app.state.tasks = [asyncio.create_task(_sim_loop())]
    try:
        app.state.modbus = await serve_tcp(_modbus_handler, MODBUS_HOST, MODBUS_PORT)
        live.sim.events.add(0, "system", f"Modbus/TCP listening on {MODBUS_HOST}:{MODBUS_PORT}", "info", "system")
    except OSError as exc:
        app.state.modbus = None
        live.sim.events.add(0, "system", f"Modbus/TCP listener failed: {exc}", "crit", "system")


async def _shutdown(app):
    for t in app.state.tasks:
        t.cancel()
    if getattr(app.state, "modbus", None):
        app.state.modbus.close()
        with contextlib.suppress(Exception):
            await app.state.modbus.wait_closed()


@contextlib.asynccontextmanager
async def lifespan(app):
    await _startup(app)
    yield
    await _shutdown(app)


app = FastAPI(title="ics-sim", version=__version__, lifespan=lifespan)


# ------------------------------------------------------------------ basics
@app.get("/api/health")
def health():
    return {"status": "ok", "name": NAME, "version": __version__}


@app.get("/api/state")
async def state():
    st = live.sim.state()
    st.update({"speed": live.speed, "paused": live.paused, "ext_ip": live.ext_ip,
               "modbus": f"{MODBUS_HOST}:{MODBUS_PORT}", "metrics_since": live.sim.clock(live.metrics_since),
               "live_scenario": None if not live.scenario else {k: v for k, v in live.scenario.items() if k != "obj"},
               "last_run_id": getattr(live, "last_run_id", None)})
    return st


@app.get("/api/trend")
async def trend(n: int = 360):
    return list(live.sim.trend)[-max(1, min(n, 8640)):]


@app.get("/api/events")
async def events(kind: str = "", limit: int = 200):
    evs = [e for e in live.sim.events.events if not kind or e["kind"] == kind]
    out = evs[-max(1, min(limit, 2000)):][::-1]
    return [{**e, "clock": live.sim.clock(e["t"])} for e in out]


@app.get("/api/modbus")
async def modbus_log(limit: int = 200):
    out = list(live.sim.events.modbus)[-max(1, min(limit, 2000)):][::-1]
    return {"counters": live.sim.events.counters, "rows": out}


@app.get("/api/meta")
def meta():
    return {"registers": register_map(), "mitigations": [{"key": k, "label": MITIGATION_LABELS[k]} for k in MITIGATIONS],
            "hazards": {k: v[0] for k, v in HAZARDS.items()}, "scenarios": [cls.describe() for cls in SCENARIOS.values()],
            "zones": ZONES, "hosts": [{"ip": ip, "host": h, "zone": zone_of(ip)} for ip, h in HOSTS.items()],
            "policy": policy_table(), "modbus": f"{MODBUS_HOST}:{MODBUS_PORT}"}


# ------------------------------------------------------------------ control
class Control(BaseModel):
    name: str
    value: float


@app.post("/api/control")
async def control(c: Control):
    """Operator action from the HUD, sent as a Modbus write from HMI-01 through the network path."""
    if c.name in HR_BY_NAME:
        reg = HR_BY_NAME[c.name]
        raw = int(round(c.value * reg.scale))
        if not 0 <= raw <= 65535:
            raise HTTPException(400, "value out of 16-bit range")
        result = live.sim.hmi.write("hr", reg.addr, raw)
    elif c.name in {r.name for r in PLC_COILS}:
        result = live.sim.hmi.write("coil", getattr(C, c.name), int(bool(c.value)))
    else:
        raise HTTPException(404, f"unknown point {c.name}")
    live.sim.events.add(live.sim.t, "hmi", f"HUD operator write {c.name}={c.value:g}: {result}", "info", "hmi")
    return {"result": result}


class SimCmd(BaseModel):
    action: str
    speed: float | None = None
    seed: int | None = None


@app.post("/api/sim")
async def sim_cmd(cmd: SimCmd):
    if cmd.action == "pause":
        live.paused = True
    elif cmd.action == "resume":
        live.paused = False
    elif cmd.action == "speed" and cmd.speed:
        live.speed = max(0.25, min(600.0, cmd.speed))
    elif cmd.action == "reset":
        live.reset(cmd.seed or live.sim.seed)
    elif cmd.action == "sis_reset":
        live.sim.sis.reset()
    elif cmd.action == "plc_reset":
        live.sim.plc.reset()
    elif cmd.action == "ack":
        live.sim.hmi.write("coil", C.ALARM_ACK, 1)
    else:
        raise HTTPException(400, "unknown action")
    return {"ok": True, "speed": live.speed, "paused": live.paused}


class Mits(BaseModel):
    mitigations: list[str]


@app.post("/api/mitigations")
async def set_mitigations(m: Mits):
    try:
        live.sim.set_mitigations(m.mitigations)
    except ValueError as e:
        raise HTTPException(400, str(e))
    live.sim.events.add(live.sim.t, "system", "Mitigations now: " + (", ".join(sorted(m.mitigations)) or "none"), "info", "system")
    return {"mitigations": sorted(live.sim.mitigations)}


class Client(BaseModel):
    ip: str


@app.post("/api/network/client")
async def set_client(c: Client):
    if c.ip not in HOSTS:
        raise HTTPException(400, "pick one of the simulated hosts")
    live.ext_ip = c.ip
    return {"ext_ip": live.ext_ip, "zone": zone_of(c.ip)}


# ------------------------------------------------------------------ scenarios
class RunReq(BaseModel):
    key: str
    mitigations: list[str] = []
    mode: str = "fast"
    seed: int = 1


@app.post("/api/scenarios/run")
async def run_scenario(r: RunReq):
    if r.key not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    bad = set(r.mitigations) - set(MITIGATIONS)
    if bad:
        raise HTTPException(400, f"unknown mitigations {sorted(bad)}")
    if r.mode == "realtime":
        return {"mode": "realtime", **live.start_scenario(r.key, r.mitigations)}
    data = await asyncio.to_thread(run_with_baseline, r.key, r.mitigations, r.seed)
    run_id = storage.save_run(data, mode="fast")
    return {"mode": "fast", "id": run_id, "outcome": data["outcome"], "attack": _slim(data["attack"]),
            "baseline": data["baseline"]["metrics"], "per_mitigation": data["per_mitigation"]}


def _slim(res: dict) -> dict:
    return {k: res[k] for k in ("metrics", "detections", "mitigations", "title", "start_clock", "end_clock")} | {
        "timeline": [e for e in res["timeline"] if e["kind"] != "alarm"][:80]}


@app.post("/api/scenarios/stop")
async def stop_scenario():
    run_id = await asyncio.to_thread(live.finish_scenario)
    return {"id": run_id}


@app.get("/api/runs")
def runs():
    return storage.list_runs()


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    d = storage.load_run(run_id)
    if d is None:
        raise HTTPException(404)
    return {"id": run_id, "outcome": d["outcome"], "attack": _slim(d["attack"]), "baseline": d["baseline"]["metrics"],
            "per_mitigation": d["per_mitigation"], "scenario": d["scenario"]}


# ------------------------------------------------------------------ matrix
def _matrix_worker():
    job = live.matrix_job
    try:
        mx = matrix(progress=lambda d, t: job.update(done=d, total=t))
        storage.save_matrix(mx)
    except Exception as exc:
        job["error"] = repr(exc)
    finally:
        job["running"] = False


@app.post("/api/matrix/run")
def matrix_run():
    job = live.matrix_job
    if job["running"]:
        return job
    job.update(running=True, done=0, total=0, error=None)
    threading.Thread(target=_matrix_worker, daemon=True).start()
    return job


@app.get("/api/matrix")
def matrix_get():
    return {"job": live.matrix_job, "matrix": storage.latest_matrix()}


# ------------------------------------------------------------------ reports
@app.get("/api/reports")
def reports():
    return storage.list_reports()


@app.get("/api/reports/{name}.{ext}")
def report_file(name: str, ext: str):
    p = storage.report_path(name, ext)
    if p is None:
        raise HTTPException(404)
    if ext == "html":
        return FileResponse(p, media_type="text/html")
    if ext == "md":
        return PlainTextResponse(p.read_text(), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
    return FileResponse(p, media_type="application/json")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
