"""Attack scenarios mapped to MITRE ATT&CK for ICS.

Every scenario acts only on this simulator: Modbus requests go through
`Simulation.request` (the same path the local TCP server uses) and field-level
effects use the simulator's own hooks (sensor overrides, HMI link). Nothing
here opens a socket or targets another system.

A scenario is a timeline of steps relative to the attack start, plus optional
continuous behaviour (spoofing, replay, flooding) in `tick`.
"""

from __future__ import annotations

import json

from . import modbus as mb
from .network import EWS_IP, HMI_IP, HOSTS, zone_of
from .registers import C, HR

ATTACK_AT = 1800.0          # 30 min warm-up before the attack
HORIZON = 3 * 3600.0        # every run lasts 3 simulated hours

TECHNIQUES = {
    "T0822": "External Remote Services", "T0823": "Graphical User Interface", "T0827": "Loss of Control",
    "T0830": "Adversary-in-the-Middle", "T0831": "Manipulation of Control", "T0832": "Manipulation of View",
    "T0836": "Modify Parameter", "T0837": "Loss of Protection", "T0838": "Modify Alarm Settings",
    "T0843": "Program Download", "T0845": "Program Upload", "T0814": "Denial of Service",
    "T0815": "Denial of View", "T0855": "Unauthorized Command Message", "T0856": "Spoof Reporting Message",
    "T0858": "Change Operating Mode", "T0859": "Valid Accounts", "T0861": "Point & Tag Identification",
    "T0878": "Alarm Suppression", "T0879": "Damage to Property", "T0880": "Loss of Safety",
    "T0888": "Remote System Information Discovery", "T0889": "Modify Program", "T0826": "Loss of Availability",
}


class Attacker:
    """Sends Modbus requests from a simulated source address and logs each step."""

    def __init__(self, sim, ip: str):
        self.sim, self.ip, self.tid = sim, ip, 0

    def send(self, pdu: bytes, what: str, techniques: str, unit: int = 1) -> str:
        self.tid = (self.tid + 1) & 0xFFFF
        reply = self.sim.request(self.ip, mb.build_adu(self.tid, unit, pdu))
        if reply is None:
            result = "no response (dropped)"
        else:
            rpdu = reply[7:]
            result = f"exception {rpdu[1]:02d} ({mb.EXC_NAMES.get(rpdu[1], '')})" if rpdu[0] & 0x80 else "ok"
        self.sim.events.add(self.sim.t, "attack", f"{what} -> {result}", "warn", "attacker",
                            src=self.ip, techniques=techniques, result=result)
        return result

    def note(self, what: str, techniques: str = "") -> None:
        self.sim.events.add(self.sim.t, "attack", what, "warn", "attacker", src=self.ip, techniques=techniques)


class Scenario:
    key = ""
    title = ""
    summary = ""
    techniques: list[str] = []
    attacker_ip = ""
    attacker_desc = ""
    target_hazards: tuple = ()
    requires: frozenset = frozenset()
    expected: dict = {}          # mitigation -> "prevented" | "detected" (checked by the tests)
    start_hour = 6.0
    case_study = ""

    def __init__(self):
        self.t0: float | None = None
        self.done: set[int] = set()
        self.atk: Attacker | None = None

    def plan(self) -> list:
        """List of (offset_s, fn(sim, attacker)) steps."""
        return []

    def schedule(self, sim, t0: float) -> None:
        self.t0 = t0
        self.atk = Attacker(sim, self.attacker_ip)
        self.steps = self.plan()
        sim.attack = self

    def tick(self, sim, t: float) -> None:
        if t < self.t0:
            return
        for i, (offset, fn) in enumerate(self.steps):
            if i not in self.done and t >= self.t0 + offset:
                self.done.add(i)
                fn(sim, self.atk)
        self.continuous(sim, t - self.t0)

    def continuous(self, sim, elapsed: float) -> None:
        pass

    def detach(self, sim) -> None:
        sim.sensor_overrides.clear()
        sim.hmi_mitm = None
        sim.attack = None

    def status(self, sim) -> dict:
        return {"key": self.key, "title": self.title, "t0": self.t0,
                "elapsed": None if self.t0 is None else round(sim.t - self.t0, 1),
                "steps_done": len(self.done), "steps": len(getattr(self, "steps", []))}

    @classmethod
    def describe(cls) -> dict:
        return {"key": cls.key, "title": cls.title, "summary": cls.summary,
                "techniques": [{"id": t, "name": TECHNIQUES.get(t, "")} for t in cls.techniques],
                "attacker": {"ip": cls.attacker_ip, "zone": zone_of(cls.attacker_ip) if cls.attacker_ip else "field",
                             "host": HOSTS.get(cls.attacker_ip, cls.attacker_desc), "desc": cls.attacker_desc},
                "target_hazards": list(cls.target_hazards), "requires": sorted(cls.requires),
                "expected": cls.expected, "start_hour": cls.start_hour, "case_study": cls.case_study}


def w_reg(addr, value):
    return mb.req_write_register(addr, value)


def w_coil(addr, on):
    return mb.req_write_coil(addr, on)


# --------------------------------------------------------------------------- 1
class SetpointChange(Scenario):
    key = "setpoint_change"
    title = "Unauthorised setpoint change via Modbus write"
    summary = ("A phished office PC on a flat network discovers the PLC, reads its holding registers "
               "and raises the free chlorine setpoint from 1.0 to 6.0 mg/L with a single FC 6 write.")
    techniques = ["T0888", "T0861", "T0855", "T0836"]
    attacker_ip = "192.168.10.37"
    attacker_desc = "Compromised corporate workstation"
    target_hazards = ("chlorine_overdose",)
    expected = {"segmentation": "prevented", "firewall": "prevented", "eng_limits": "prevented",
                "sis": "prevented", "detector": "detected"}

    def plan(self):
        return [
            (0, lambda s, a: a.send(bytes([17]), "FC17 Report Server ID (discovery)", "T0888")),
            (20, lambda s, a: a.send(mb.req_read(3, 0, 23), "FC3 read holding registers 0-22 (tag discovery)", "T0861")),
            (60, lambda s, a: a.send(w_reg(HR.CL_SP, 600), "FC6 write CL_SP = 6.00 mg/L", "T0855,T0836")),
        ]


# --------------------------------------------------------------------------- 2
class Oldsmar(Scenario):
    key = "oldsmar"
    title = "Oldsmar-style caustic setpoint raise through a remote HMI session"
    summary = ("Someone with the shared password of the remote-access tool on the HMI PC takes over the "
               "operator session and raises the sodium hydroxide setpoint from 100 ppm to 11,100 ppm, as "
               "publicly reported for Oldsmar, Florida (5 February 2021). Nobody reverts it in this run.")
    techniques = ["T0822", "T0859", "T0823", "T0836"]
    attacker_ip = HMI_IP
    attacker_desc = "Remote-access session on HMI-01"
    target_hazards = ("caustic_overdose",)
    expected = {"eng_limits": "prevented", "sis": "prevented", "operator": "prevented", "detector": "detected"}
    case_study = (
        "Publicly reported facts (Pinellas County Sheriff press conference, 8 Feb 2021; CISA alert AA21-042A): "
        "on 5 Feb 2021 an operator at the Oldsmar, FL water treatment plant saw the mouse cursor move on the HMI. "
        "A remote-access session (TeamViewer) changed the sodium hydroxide setpoint from 100 ppm to 11,100 ppm. "
        "The operator reverted it straight away. Officials said it would have taken 24-36 hours to reach the "
        "distribution system and that pH alarms and other checks existed. The advisory noted shared passwords, "
        "an unsupported Windows 7 host and remote access exposed to the internet. In 2023 the city's former "
        "manager said the event may have been an employee error rather than an intrusion; the case is used here "
        "only for its numbers and its control weaknesses. In this simulator the caustic pump's 250 L/h capacity "
        "caps the real dose at a few hundred ppm, which is still enough to push pH above 10.5. Run it with the "
        "'operator' mitigation to see the outcome when the change is caught within minutes.")

    def plan(self):
        return [
            (0, lambda s, a: a.note("Remote-access session opened on HMI-01 with shared credentials", "T0822,T0859")),
            (30, lambda s, a: a.send(mb.req_read(3, HR.NAOH_SP, 1), "HMI screen read: NaOH setpoint", "T0823")),
            (60, lambda s, a: a.send(w_reg(HR.NAOH_SP, 11100), "FC6 write NAOH_SP = 11100 ppm (from 100)", "T0836")),
            (300, lambda s, a: a.note("Remote-access session closed", "T0822")),
        ]


# --------------------------------------------------------------------------- 3
class FalseDataInjection(Scenario):
    key = "fdi_chlorine"
    title = "False data injection on the chlorine control analyser"
    summary = ("A tampered transmitter / field link makes the contact-tank chlorine analyser AIT-301 drift "
               "down to 0.20 mg/L over five minutes (slow enough to dodge naive step checks). The PLC's PID "
               "keeps adding hypochlorite while the real residual climbs.")
    techniques = ["T0856", "T0832", "T0831"]
    attacker_ip = ""
    attacker_desc = "Field device / analyser 4-20 mA or fieldbus link (Level 0/1)"
    target_hazards = ("chlorine_overdose",)
    expected = {"detector": "detected", "sis": "prevented", "operator": "prevented"}

    def plan(self):
        return [(0, lambda s, a: a.note("Analyser AIT-301 signal hijacked at the field link", "T0856,T0832"))]

    def continuous(self, sim, elapsed):
        if "AIT301" not in sim.sensor_overrides:
            start = {"v": None}

            def spoof(t, true_value, start=start, t0=self.t0):
                if start["v"] is None:
                    start["v"] = true_value
                frac = min(1.0, (t - t0) / 300.0)
                return start["v"] + (0.20 - start["v"]) * frac
            sim.sensor_overrides["AIT301"] = spoof


# --------------------------------------------------------------------------- 4
class ReplayMitm:
    """Records HMI<->PLC exchanges, then replays them to the HMI (writes still pass)."""

    def __init__(self, record_s: float, t0: float):
        self.t0, self.record_s = t0, record_s
        self.tape: dict[bytes, list[bytes]] = {}
        self.pos: dict[bytes, int] = {}
        self.announced = False

    def relay(self, sim, adu: bytes):
        tid, unit, pdu = mb.parse_adu(adu)
        is_read = pdu[0] in (1, 2, 3, 4)
        if sim.t - self.t0 < self.record_s or not is_read or pdu[:5] not in self.tape:
            reply = sim.request(HMI_IP, adu, routine=True)
            if is_read and reply is not None and sim.t - self.t0 < self.record_s:
                self.tape.setdefault(pdu[:5], []).append(reply[7:])
            return reply
        if not self.announced:
            self.announced = True
            sim.events.add(sim.t, "attack", "MITM starts replaying recorded telemetry to HMI-01", "warn",
                           "attacker", src="10.10.2.66", techniques="T0832,T0815")
        tape = self.tape[pdu[:5]]
        i = self.pos.get(pdu[:5], 0)
        self.pos[pdu[:5]] = i + 1
        return mb.build_adu(tid, unit, tape[i % len(tape)])


class ReplayMasking(Scenario):
    key = "replay_masking"
    title = "Replay / masking of the HMI view while the process is manipulated (Stuxnet-style)"
    summary = ("An unknown laptop on the control LAN ARP-spoofs between HMI-01 and PLC-01, records ten "
               "minutes of normal telemetry, then loops it back to the HMI. Inside the hijacked HMI session it "
               "closes the filter feed valve and forces P-201 to run flat out in manual, which bypasses the "
               "low-level interlock. The reservoir drains, P-201 cavitates and runs dry while the HMI shows a "
               "healthy plant.")
    techniques = ["T0830", "T0832", "T0815", "T0855", "T0858", "T0831", "T0879"]
    attacker_ip = "10.10.2.66"
    attacker_desc = "Rogue laptop doing ARP spoofing on the supervisory LAN"
    target_hazards = ("pump_damage",)
    expected = {"integrity": "detected", "sis": "prevented", "detector": "detected"}

    def plan(self):
        def start_mitm(s, a):
            a.note("ARP spoofing HMI-01 <-> PLC-01, recording telemetry", "T0830")
            s.hmi_mitm = ReplayMitm(600.0, s.t)

        def inject(s, a):
            hmi_session = Attacker(s, HMI_IP)   # injected into the HMI's own TCP session
            hmi_session.send(w_coil(C.FCV101_AUTO, False), "FC5 FCV101_AUTO = manual (in HMI session)", "T0855,T0858")
            hmi_session.send(w_reg(HR.FCV101_MAN_POS, 0), "FC6 FCV101_MAN_POS = 0 % (close filter feed)", "T0831")
            hmi_session.send(w_reg(HR.P201_MAN_SPEED, 1000), "FC6 P201_MAN_SPEED = 100 %", "T0831")
            hmi_session.send(w_coil(C.P201_MAN_RUN, True), "FC5 P201_MAN_RUN = 1", "T0831")
            hmi_session.send(w_coil(C.P201_AUTO, False), "FC5 P201_AUTO = manual (low-level interlock bypassed)", "T0858")
        return [(0, start_mitm), (620, inject)]


# --------------------------------------------------------------------------- 5
TAMPERED_PROGRAM = {"name": "WTW-MAIN", "version": "1.4.2", "raw_start_override_m": 4.9,
                    "raw_stop_override_m": 5.6, "suppress_alarms": ["RAW_HI"]}


class LogicTamper(Scenario):
    key = "logic_tamper"
    title = "PLC logic tampering: altered hysteresis causes raw tank overflow"
    summary = ("An unknown laptop uses the PLC's engineering service (FC 90) to upload the program, then "
               "downloads a modified one: the intake pump now starts below 4.9 m and stops at 5.6 m (above the "
               "tank top) and the raw-tank high alarm is suppressed. Holding registers still show the normal "
               "2.0/3.8 m levels, so the HMI looks normal.")
    techniques = ["T0845", "T0843", "T0889", "T0878"]
    attacker_ip = "10.10.2.66"
    attacker_desc = "Unknown laptop on the control LAN with the engineering software"
    target_hazards = ("tank_overflow",)
    expected = {"firewall": "prevented", "sis": "prevented", "detector": "detected"}

    def plan(self):
        body = json.dumps(TAMPERED_PROGRAM, sort_keys=True).encode()
        return [
            (0, lambda s, a: a.send(bytes([90, 0x01]), "FC90/0x01 read program info", "T0845")),
            (15, lambda s, a: a.send(bytes([90, 0x02]), "FC90/0x02 upload program", "T0845")),
            (90, lambda s, a: a.send(bytes([90, 0x10]) + body, "FC90/0x10 download modified program", "T0843,T0889,T0878")),
        ]


# --------------------------------------------------------------------------- 6
class ModbusDos(Scenario):
    key = "modbus_dos"
    title = "Modbus flood causing loss of view and loss of control"
    summary = ("A compromised office PC floods the PLC with about 2,000 read requests per second for "
               "20 minutes. The comms processor saturates, HMI polls time out, and the sustained overload trips "
               "the PLC's scan watchdog: the CPU stops and its outputs drop, so P-201 stops and supply pressure "
               "collapses until someone restarts the PLC on site.")
    techniques = ["T0814", "T0815", "T0827", "T0826"]
    attacker_ip = "192.168.10.37"
    attacker_desc = "Compromised corporate workstation running a flooding tool"
    target_hazards = ("supply_outage",)
    expected = {"firewall": "prevented", "segmentation": "prevented", "detector": "detected", "integrity": "detected"}
    FLOOD_S = 1200.0
    PER_TICK = 1000

    def plan(self):
        return [(0, lambda s, a: a.note(f"Flood starts: ~{int(self.PER_TICK * 2)} req/s FC3 from {self.attacker_ip}", "T0814")),
                (self.FLOOD_S, lambda s, a: a.note("Flood stops", "T0814"))]

    def continuous(self, sim, elapsed):
        if elapsed < self.FLOOD_S:
            adu = mb.build_adu(0, 1, mb.req_read(3, 0, 100))
            sim.request(self.attacker_ip, adu, count=self.PER_TICK, routine=True)
            sim.events.counters["flood_requests"] += self.PER_TICK


# --------------------------------------------------------------------------- 7
class SisBypass(Scenario):
    key = "sis_bypass"
    title = "SIS bypass followed by process manipulation"
    summary = ("With the engineering workstation compromised, the attacker reads the SIS maintenance "
               "interface (unit 2), sets the maintenance bypass, widens the chlorine high alarm and then raises "
               "the chlorine setpoint to 6.0 mg/L. The SIS is installed (required for this scenario) but its "
               "outputs are inhibited.")
    techniques = ["T0888", "T0880", "T0837", "T0838", "T0878", "T0836"]
    attacker_ip = EWS_IP
    attacker_desc = "Compromised engineering workstation EWS-01"
    target_hazards = ("chlorine_overdose",)
    requires = frozenset({"sis"})
    expected = {"firewall": "prevented", "segmentation": "prevented", "eng_limits": "prevented", "detector": "detected"}

    def plan(self):
        return [
            (0, lambda s, a: a.send(mb.req_read(1, 0, 2), "FC1 read SIS coils (unit 2)", "T0888", unit=2)),
            (30, lambda s, a: a.send(w_coil(0, True), "FC5 SIS_BYPASS = 1 (unit 2)", "T0880,T0837", unit=2)),
            (60, lambda s, a: a.send(w_reg(HR.CL_HI_ALM, 1000), "FC6 CL_HI_ALM = 10.00 mg/L", "T0838,T0878")),
            (70, lambda s, a: a.send(w_reg(HR.CL_SP, 600), "FC6 CL_SP = 6.00 mg/L", "T0836")),
        ]


# --------------------------------------------------------------------------- 8
class Insider(Scenario):
    key = "insider"
    title = "Insider with valid credentials stops disinfection"
    summary = ("A disgruntled staff member logs into the engineering workstation with their own valid "
               "account, lowers the chlorine low alarm to zero, switches hypochlorite dosing to manual and sets "
               "the manual rate to 0 L/h. Every request comes from an allowlisted host in the right zone.")
    techniques = ["T0859", "T0838", "T0858", "T0836", "T0831"]
    attacker_ip = EWS_IP
    attacker_desc = "Legitimate engineer account on EWS-01"
    target_hazards = ("chlorine_underdose",)
    expected = {"detector": "detected", "sis": "prevented", "eng_limits": "detected", "operator": "prevented"}

    def plan(self):
        return [
            (0, lambda s, a: a.note("Engineer logs into EWS-01 with valid credentials", "T0859")),
            (40, lambda s, a: a.send(w_reg(HR.CL_LO_ALM, 0), "FC6 CL_LO_ALM = 0.00 mg/L", "T0838")),
            (60, lambda s, a: a.send(w_reg(HR.CL_MAN_RATE, 0), "FC6 CL_MAN_RATE = 0 L/h", "T0836")),
            (70, lambda s, a: a.send(w_coil(C.CL_AUTO, False), "FC5 CL_AUTO = manual", "T0858,T0831")),
        ]


SCENARIOS = {cls.key: cls for cls in
             [SetpointChange, Oldsmar, FalseDataInjection, ReplayMasking, LogicTamper, ModbusDos, SisBypass, Insider]}


def get(key: str) -> Scenario:
    if key not in SCENARIOS:
        raise KeyError(f"unknown scenario {key!r}; choose from {', '.join(SCENARIOS)}")
    return SCENARIOS[key]()
