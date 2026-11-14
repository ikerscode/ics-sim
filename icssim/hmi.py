"""HMI-01 (Modbus client polling the PLC) and the attended-operator model.

The HMI polls all four PLC tables every 2 s through its network link. What it
receives is "the operator's view", which an adversary-in-the-middle can replay
or forge. With the integrity mitigation on, the HMI verifies the PLC's HMAC
telemetry frame and flags forged, replayed or stale data.
"""

from __future__ import annotations

import hmac
import struct

from . import modbus as mb
from .network import HMI_IP
from .plc import telemetry_mac
from .registers import (ALARM_BITS, C, DI, IR, PLC_COILS, PLC_DIS, PLC_HRS, PLC_IRS, PLC_SIZES,
                        default_coils, default_holding)

POLL_S = 2.0


class HMI:
    def __init__(self, sim):
        self.sim = sim
        self.ip = HMI_IP
        self.tid = 0
        self.ir = [0] * PLC_SIZES["ir"]
        self.hr = default_holding()
        self.coils = default_coils()
        self.di = [0] * PLC_SIZES["di"]
        self.recipe_hr = default_holding()      # operator's known-good setpoints
        self.recipe_coils = default_coils()
        self.last_ok = 0.0
        self.comms_ok = True
        self.ever_ok = False
        self.integrity_state = "off"            # off | ok | forged | replayed | stale
        self.last_seq = -1
        self.flags: dict[str, bool] = {}

    # ----------------------------------------------------------- transport
    def exchange(self, pdu: bytes) -> bytes | None:
        self.tid = (self.tid + 1) & 0xFFFF
        reply = self.sim.hmi_link(mb.build_adu(self.tid, 1, pdu))
        if reply is None:
            return None
        try:
            _, _, rpdu = mb.parse_adu(reply)
        except ValueError:
            return None
        return rpdu

    def _read(self, fc: int, qty: int):
        req = mb.req_read(fc, 0, qty)
        rpdu = self.exchange(req)
        if rpdu is None:
            return None
        try:
            return mb.parse_response(req, rpdu)
        except (mb.ModbusError, ValueError):
            return None

    def poll(self, t: float) -> None:
        ir = self._read(4, 72)
        hr = self._read(3, PLC_SIZES["hr"])
        co = self._read(1, PLC_SIZES["coil"])
        di = self._read(2, PLC_SIZES["di"])
        if None in (ir, hr, co, di):
            self.comms_ok = t - self.last_ok < 10.0
            if not self.comms_ok:
                self._flag(t, "lost", "HMI lost communication with PLC-01 (loss of view)", source="hmi")
                if self.sim.integrity_on:
                    self.integrity_state = "stale"
                    self._flag(t, "int_stale", "Telemetry integrity: no fresh signed frame for 10 s", source="integrity")
            return
        self.ir[:72], self.hr, self.coils, self.di = ir, hr, co, di
        self.last_ok, self.comms_ok, self.ever_ok = t, True, True
        self._clear("lost")
        if self.sim.integrity_on:
            self._verify(t)
        else:
            self.integrity_state = "off"

    def _verify(self, t: float) -> None:
        ir = self.ir
        seq = (ir[IR.TLM_SEQ_HI] << 16) | ir[IR.TLM_SEQ_LO]
        ts = (ir[IR.TLM_TS_HI] << 16) | ir[IR.TLM_TS_LO]
        mac = struct.pack(">8H", *ir[IR.TLM_MAC0:IR.TLM_MAC0 + 8])
        good = telemetry_mac(self.sim.integrity_key, ir, self.hr, self.coils, self.di, seq, ts)
        if seq == 0 and ts == 0:
            state, msg = "stale", "Telemetry integrity: PLC frame not populated"
        elif not hmac.compare_digest(mac, good):
            state, msg = "forged", "Telemetry integrity: HMAC mismatch, HMI data was modified in transit"
        elif seq <= self.last_seq:
            state, msg = "replayed", f"Telemetry integrity: sequence {seq} not newer than {self.last_seq}, replayed data"
        elif t - ts > 10.0:
            state, msg = "stale", f"Telemetry integrity: frame is {t - ts:.0f} s old"
        else:
            state, msg = "ok", ""
        if state == "ok":
            self.last_seq = seq
            for k in ("int_forged", "int_replayed", "int_stale"):
                self._clear(k)
        else:
            self._flag(t, "int_" + state, msg, source="integrity")
        self.integrity_state = state

    def _flag(self, t, key, msg, source):
        if not self.flags.get(key):
            self.flags[key] = True
            if source == "hmi":
                self.sim.events.add(t, "hmi", msg, "warn", "hmi")
            else:
                self.sim.events.alert(t, source, msg, "high")

    def _clear(self, key):
        self.flags[key] = False

    # ----------------------------------------------------------- operator writes
    def write(self, kind: str, addr: int, value: int, update_recipe: bool = True) -> str:
        """Write one coil or holding register from the HMI. Returns 'ok', 'timeout' or the exception text."""
        req = mb.req_write_coil(addr, bool(value)) if kind == "coil" else mb.req_write_register(addr, int(value))
        rpdu = self.exchange(req)
        if rpdu is None:
            return "timeout"
        try:
            mb.parse_response(req, rpdu)
        except mb.ModbusError as e:
            return f"exception {e.code:02d} ({e})"
        if update_recipe and not (kind == "coil" and addr == C.ALARM_ACK):
            (self.recipe_coils if kind == "coil" else self.recipe_hr)[addr] = int(value)
        return "ok"

    # ----------------------------------------------------------- view
    def alarms(self) -> list[str]:
        """Alarms the operator sees: PLC alarm word plus HMI-side limits on displayed values."""
        v = self.values()
        out = [n for i, n in enumerate(ALARM_BITS) if self.ir[IR.ALARM_WORD] >> i & 1]
        hmi_side = [("HMI_RAW_HIGH", v["LT101"] > 4.3), ("HMI_RES_LOW", v["LT201"] < 0.8),
                    ("HMI_CL_HIGH", v["AIT303"] > 2.0), ("HMI_CL_LOW", v["AIT303"] < 0.5),
                    ("HMI_PH_HIGH", v["AIT304"] > 8.5), ("HMI_PH_LOW", v["AIT304"] < 7.0),
                    ("HMI_PRESS_LOW", v["PT201"] < 1.5), ("HMI_P201_HOT", v["P201_TEMP"] > 75.0),
                    ("SIS_TRIPPED", bool(self.di[DI.SIS_TRIPPED])), ("PLC_FAULT", bool(self.di[DI.PLC_FAULT]))]
        out += [n for n, cond in hmi_side if cond]
        if not self.comms_ok:
            out.append("COMMS_LOST")
        if self.integrity_state in ("forged", "replayed", "stale"):
            out.append("TELEMETRY_" + self.integrity_state.upper())
        return out

    def values(self) -> dict:
        return {r.name: self.ir[r.addr] / r.scale for r in PLC_IRS if r.addr < 30}

    def view(self) -> dict:
        return {
            "values": self.values(),
            "setpoints": {r.name: self.hr[r.addr] / r.scale for r in PLC_HRS},
            "coils": {r.name: self.coils[r.addr] for r in PLC_COILS},
            "status": {r.name: self.di[r.addr] for r in PLC_DIS},
            "alarms": self.alarms(), "comms_ok": self.comms_ok, "last_update": self.last_ok,
            "integrity": self.integrity_state,
        }


class Operator:
    """Attended control room: checks the HMI every 30 s and reacts after 5 minutes.

    Playbook: restore setpoints/modes that differ from the known-good recipe;
    if an alarm persists after that, take manual action (stop intake on high
    level, flow-paced manual dosing on chlorine or pH alarms, stop P-201 on low
    reservoir). On loss of view, PLC fault or untrusted telemetry, drive to site
    (30 min) and restore locally.
    """
    CHECK_S = 30.0
    REACT_S = 300.0
    TRAVEL_S = 1800.0

    def __init__(self, sim):
        self.sim = sim
        self.enabled = False
        self.noticed_at: float | None = None
        self.stage = 0
        self.dispatched_at: float | None = None

    def tick(self, t: float) -> None:
        hmi = self.sim.hmi
        if self.dispatched_at is not None:
            if t - self.dispatched_at >= self.TRAVEL_S:
                self._on_site(t)
            return
        issues = []
        blind = (not hmi.comms_ok) or hmi.integrity_state in ("forged", "replayed", "stale") or hmi.di[DI.PLC_FAULT]
        if blind:
            issues.append("no trustworthy view of the plant" if hmi.comms_ok else "loss of view")
        devs_hr = [r.name for r in PLC_HRS if hmi.hr[r.addr] != hmi.recipe_hr[r.addr]]
        devs_co = [r.name for r in PLC_COILS if r.addr != C.ALARM_ACK and hmi.coils[r.addr] != hmi.recipe_coils[r.addr]]
        alarms = [a for a in hmi.alarms() if a not in ("COMMS_LOST",) and not a.startswith("TELEMETRY")]
        if not blind:
            if devs_hr or devs_co:
                issues.append("unexpected setpoint/mode changes: " + ", ".join(devs_hr + devs_co))
            if alarms:
                issues.append("alarms: " + ", ".join(alarms))
        if not issues:
            self.noticed_at, self.stage = None, 0
            return
        if self.noticed_at is None:
            self.noticed_at = t
            self.sim.events.alert(t, "operator", "Operator notices: " + "; ".join(issues), "medium")
            return
        if t - self.noticed_at < self.REACT_S:
            return
        self.noticed_at = t  # next escalation after another reaction time
        if blind:
            self.dispatched_at = t
            self.sim.events.add(t, "operator", "Operator dispatched to site (no trustworthy remote view)", "warn", "operator")
            return
        self._act(t, devs_hr, devs_co, alarms)

    def _act(self, t, devs_hr, devs_co, alarms) -> None:
        hmi, done = self.sim.hmi, []
        for r in PLC_HRS:
            if r.name in devs_hr:
                hmi.write("hr", r.addr, hmi.recipe_hr[r.addr], update_recipe=False)
                done.append(f"{r.name}->{hmi.recipe_hr[r.addr]}")
        for r in PLC_COILS:
            if r.name in devs_co:
                hmi.write("coil", r.addr, hmi.recipe_coils[r.addr], update_recipe=False)
                done.append(f"{r.name}->{hmi.recipe_coils[r.addr]}")
        if not done and alarms:
            self.stage += 1
            done += self._manual_actions(alarms)
        if done:
            self.sim.events.add(t, "operator", "Operator action: " + ", ".join(done), "warn", "operator")

    def _manual_actions(self, alarms) -> list[str]:
        hmi, v, acts = self.sim.hmi, self.sim.hmi.values(), []
        q = max(v["FT102"], 50.0)
        pp = self.sim.plant.p
        if "HMI_RAW_HIGH" in alarms or "RAW_HI" in alarms:
            hmi.write("coil", C.P101_AUTO, 0); hmi.write("coil", C.P101_MAN_RUN, 0)
            acts.append("P-101 to manual OFF")
        if {"HMI_CL_HIGH", "HMI_CL_LOW", "CL_HI", "CL_LO"} & set(alarms):
            rate = int(round(1.5 * q / pp.cl_strength * 100))
            hmi.write("hr", 11, rate); hmi.write("coil", C.CL_AUTO, 0)
            acts.append(f"hypochlorite to manual {rate / 100:.2f} L/h")
        if {"HMI_PH_HIGH", "HMI_PH_LOW", "PH_HI", "PH_LO"} & set(alarms):
            rate = int(round(100 * q / pp.naoh_strength * 10))
            hmi.write("hr", 12, rate); hmi.write("coil", C.NAOH_AUTO, 0)
            acts.append(f"caustic to manual {rate / 10:.1f} L/h")
        if {"HMI_RES_LOW", "P201_CAV", "P201_DRY", "HMI_P201_HOT"} & set(alarms) and hmi.di[DI.P201_RUNNING]:
            hmi.write("coil", C.P201_AUTO, 0); hmi.write("coil", C.P201_MAN_RUN, 0)
            acts.append("P-201 to manual OFF")
        return acts

    def _on_site(self, t: float) -> None:
        """Local actions at the panel: restart a faulted PLC and restore the recipe directly."""
        sim, hmi = self.sim, self.sim.hmi
        sim.plc.reset()
        sim.plc.bank.hr[:] = list(hmi.recipe_hr)
        sim.plc.bank.coils[:] = list(hmi.recipe_coils)
        sim.events.add(t, "operator", "Operator on site: PLC checked/restarted, setpoints and modes restored at the local panel", "warn", "operator")
        self.dispatched_at = None
        self.noticed_at = None
