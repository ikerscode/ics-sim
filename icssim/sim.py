"""Simulation orchestrator: wires the plant, PLC, SIS, network, HMI, detector and metrics.

One `Simulation` is used both by the live server (stepped in real time with an
acceleration factor) and by fast-forward scenario runs (stepped in a tight loop).
"""

from __future__ import annotations

import hashlib
from collections import deque

from . import modbus as mb
from .consequences import ConsequenceTracker
from .constants import MITIGATIONS
from .detector import Detector
from .events import EventLog
from .hmi import HMI, Operator, POLL_S
from .network import HMI_IP, HIST_IP, Firewall, zone_of
from .plc import PLC
from .process import Plant
from .sis import SIS

DT = 0.5


class Simulation:
    def __init__(self, seed: int = 1, mitigations=(), start_hour: float = 6.0, live: bool = False):
        self.seed = seed
        self.dt = DT
        self.t = 0.0
        self.ticks = 0
        self.live = live
        self.events = EventLog(keep_poll_reads=live, cap=5000 if live else None, modbus_cap=3000 if live else None)
        self.plant = Plant(seed=seed, start_hour=start_hour, dt=DT)
        self.integrity_key = hashlib.sha256(f"ics-sim-telemetry-{seed}".encode()).digest()
        self.plc = PLC(self.events, self.plant.p, self.integrity_key)
        self.plc.on_reject = self._eng_reject
        self.sis = SIS(self.events)
        self.firewall = Firewall()
        self.detector = Detector(self.events)
        self.hmi = HMI(self)
        self.operator = Operator(self)
        self.metrics = ConsequenceTracker(self.events)
        self.mitigations: set[str] = set()
        self.set_mitigations(mitigations)
        self.attack = None
        self.sensor_overrides: dict = {}      # tag -> fn(t, true_value) (field-level spoofing)
        self.hmi_mitm = None                  # object with .relay(sim, adu) -> reply (adversary in the middle)
        self.sis_values: dict = self.plant.sis_sensors()
        self.trend: deque = deque(maxlen=8640)
        self.trend_every = 10.0 if live else 60.0
        self.recorder: list | None = None     # set to a list to capture every request and its policy decision
        self.last_snapshot_t = -1e9

    # --------------------------------------------------------- mitigations
    def set_mitigations(self, names) -> None:
        names = set(names)
        bad = names - set(MITIGATIONS)
        if bad:
            raise ValueError(f"unknown mitigation(s): {', '.join(sorted(bad))}")
        self.mitigations = names
        self.sis.enabled = "sis" in names
        self.firewall.dpi = "firewall" in names
        self.firewall.segmentation = "segmentation" in names
        self.plc.eng_limits = "eng_limits" in names
        self.detector.enabled = "detector" in names
        self.plc.integrity = "integrity" in names
        self.operator.enabled = "operator" in names

    @property
    def integrity_on(self) -> bool:
        return "integrity" in self.mitigations

    def _eng_reject(self, reg, value) -> None:
        self.events.alert(self.t, "eng_limits",
                          f"Engineering limit rejected write {reg.name}={value / reg.scale:g} {reg.unit} "
                          f"(range {reg.eng[0] / reg.scale:g}-{reg.eng[1] / reg.scale:g})", "high")

    # --------------------------------------------------------- network bus
    def request(self, src: str, adu: bytes, transport: str = "sim", count: int = 1, routine: bool = False) -> bytes | None:
        """Route one Modbus/TCP request (or `count` identical flood requests) to unit 1 or 2.

        Order of checks: segmentation, DPI firewall, PLC comms capacity, then the device.
        Returns the reply ADU, or None when the request is dropped (client sees a timeout).
        """
        zone = zone_of(src)
        try:
            tid, unit, pdu = mb.parse_adu(adu)
        except ValueError:
            self.events.modbus_tx(self.t, src, zone, -1, {"fc": None}, "dropped", "malformed frame", transport)
            return None
        info = mb.describe(pdu)
        t = self.t
        allowed, layer, reason = self.firewall.decide(src, 1 if unit in (0, 255) else unit, info, t, count)
        if self.recorder is not None:
            self.recorder.append({"t": t, "src": src, "unit": unit, "adu": adu.hex(), "count": count,
                                  "routine": routine, "allowed": allowed, "layer": layer, "reason": reason})
        if layer == "segmentation":
            self.events.modbus_tx(t, src, zone, unit, info, "blocked", reason, transport, count)
            self._alert_once("segmentation", src, f"Segmentation dropped {count} request(s) from {src} ({zone}): {reason}")
            return None
        if layer == "firewall":
            self.events.modbus_tx(t, src, zone, unit, info, "blocked", reason, transport, count - allowed)
            self._alert_once("firewall", src + reason[:12], f"Firewall blocked {count - allowed} request(s) from {src}: {reason}")
        if allowed == 0:
            return None
        count = allowed
        if unit in (0, 1, 255):
            admitted = self.plc.comm_admit(count)
            if admitted < count:
                self.events.modbus_tx(t, src, zone, unit, info, "dropped", "PLC comms busy", transport, count - admitted, routine)
            if admitted == 0:
                return None
            bank = self.plc.bank
        elif unit == 2:
            bank = self.sis.bank
        else:
            self.events.modbus_tx(t, src, zone, unit, info, "exception", "gateway target failed", transport, count, routine)
            return mb.build_adu(tid, unit, mb.exception_pdu(info["fc"], mb.GATEWAY_TARGET))
        reply = mb.handle_pdu(bank, pdu)
        if reply[0] & 0x80:
            self.events.modbus_tx(t, src, zone, unit, info, "exception", mb.EXC_NAMES.get(reply[1], ""), transport, 1, routine)
        else:
            self.events.modbus_tx(t, src, zone, unit, info, "ok", "", transport, 1, routine)
        return mb.build_adu(tid, unit, reply)

    def _alert_once(self, source: str, key: str, msg: str) -> None:
        """Rate-limit firewall alerts to one per source/reason per minute (floods would spam)."""
        store = self.__dict__.setdefault("_alert_last", {})
        k = (source, key)
        if self.t - store.get(k, -1e9) >= 60.0:
            store[k] = self.t
            self.events.alert(self.t, source, msg, "high")

    def hmi_link(self, adu: bytes) -> bytes | None:
        """The HMI's network path to the PLC; an adversary in the middle can sit here."""
        if self.hmi_mitm is not None:
            return self.hmi_mitm.relay(self, adu)
        return self.request(HMI_IP, adu, routine=True)

    # --------------------------------------------------------------- step
    def step(self) -> None:
        self.t += self.dt
        self.ticks += 1
        t = self.t
        if self.attack is not None:
            self.attack.tick(self, t)
        s = self.plant.sensors()
        for tag, fn in self.sensor_overrides.items():
            s[tag] = fn(t, s[tag])
        self.sis_values = self.plant.sis_sensors()
        self.sis.scan(self.sis_values, self.dt, t)
        self.plc.sis_status = (self.sis.holding_safe_state, self.sis.bypassed)
        self.plc.scan(s, self.dt, t)
        self.plant.step(self.sis.apply(self.plc.outputs))
        n = self.ticks
        if n % int(POLL_S / self.dt) == 0:
            self.hmi.poll(t)
            if n % 20 == 0 and self.live:
                # the historian polls too, so the Modbus log shows more than one client
                self.request(HIST_IP, mb.build_adu(n & 0xFFFF, 1, mb.req_read(4, 0, 30)), routine=True)
        if self.detector.enabled and n % 2 == 0:
            self.detector.check(t, self.plc, self.sis_values, self.sis.bypassed)
        if self.operator.enabled and n % int(self.operator.CHECK_S / self.dt) == 0:
            self.operator.tick(t)
        self.metrics.update(self.plant, self.dt, t)
        if t - self.last_snapshot_t >= self.trend_every:
            self.last_snapshot_t = t
            self.trend.append(self.trend_point())

    def run_for(self, seconds: float) -> None:
        for _ in range(int(round(seconds / self.dt))):
            self.step()

    # --------------------------------------------------------------- views
    def trend_point(self) -> dict:
        p = self.plant
        return {"t": round(self.t, 1), "raw_level": round(p.raw_level, 3), "res_level": round(p.res_level, 3),
                "final_cl": round(p.res_cl, 3), "contact_cl": round(p.s_cl, 3), "final_ph": round(p.ph_final, 3),
                "contact_ph": round(p.ph_contact, 3), "pressure": round(p.pressure, 3), "q_f": round(p.q_f, 1),
                "q_out": round(p.q_out, 1), "demand": round(p.demand, 1), "p201_temp": round(p.p201_temp, 1),
                "hmi_cl": round(self.hmi.values()["AIT303"], 3), "hmi_raw_level": round(self.hmi.values()["LT101"], 3),
                "hmi_res_level": round(self.hmi.values()["LT201"], 3)}

    def clock(self, t: float | None = None) -> str:
        h = self.plant.clock_hours(self.t if t is None else t)
        day = int((self.plant.start_hour * 3600 + (self.t if t is None else t)) // 86400)
        hh, mm, ss = int(h), int((h * 60) % 60), int((h * 3600) % 60)
        return f"D{day + 1} {hh:02d}:{mm:02d}:{ss:02d}"

    def state(self) -> dict:
        """Snapshot for the HUD: HMI view, ground truth, SIS, network and mitigation status."""
        return {
            "t": round(self.t, 1), "clock": self.clock(), "seed": self.seed,
            "mitigations": sorted(self.mitigations),
            "hmi": self.hmi.view(),
            "truth": {k: (round(v, 3) if isinstance(v, float) else v) for k, v in self.plant.truth().items()},
            "plc": {"faulted": self.plc.faulted, "fault_reason": self.plc.fault_reason,
                    "program": self.plc.program, "scan_count": self.plc.scan_count,
                    "eng_limits": self.plc.eng_limits},
            "sis": {"enabled": self.sis.enabled, "tripped": self.sis.tripped, "bypassed": self.sis.bypassed,
                    "cause": self.sis.cause, "trips": self.sis.trip_count,
                    "AIT901": round(self.sis_values["AIT901"], 3), "AIT902": round(self.sis_values["AIT902"], 3)},
            "metrics": self.metrics.summary(),
            "attack": self.attack.status(self) if self.attack is not None else None,
            "counters": dict(self.events.counters),
        }
