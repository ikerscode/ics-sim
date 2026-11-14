"""Modbus register map: single source of truth for the PLC, the SIS, docs and the HUD.

Addresses are 0-based protocol addresses (what goes on the wire). The classic
1-based "Modicon" reference is shown in docs: coil 00001+, discrete input 10001+,
input register 30001+, holding register 40001+.

Analogue values are scaled integers: engineering value = raw / scale.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from types import SimpleNamespace


@dataclass(frozen=True)
class Reg:
    name: str
    addr: int
    kind: str              # coil | di | ir | hr
    desc: str
    unit: str = ""
    scale: float = 1.0
    default: int = 0
    eng: tuple | None = None   # engineering range (min, max) in raw units, enforced when limits are on
    hmi_write: bool = False    # writable by the HMI role in the firewall policy

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ref"] = {"coil": 1, "di": 10001, "ir": 30001, "hr": 40001}[self.kind] + self.addr
        if self.eng is not None:
            d["eng_min"], d["eng_max"] = self.eng[0] / self.scale, self.eng[1] / self.scale
        return d


# ----------------------------------------------------------------- PLC, unit 1
PLC_COILS = [
    Reg("P101_AUTO", 0, "coil", "Intake pump P-101 auto mode", default=1, hmi_write=True),
    Reg("P101_MAN_RUN", 1, "coil", "Intake pump P-101 manual run command", hmi_write=True),
    Reg("FCV101_AUTO", 2, "coil", "Filter feed valve FCV-101 auto mode", default=1, hmi_write=True),
    Reg("P201_AUTO", 3, "coil", "Distribution pump P-201 auto mode", default=1, hmi_write=True),
    Reg("P201_MAN_RUN", 4, "coil", "Distribution pump P-201 manual run command", hmi_write=True),
    Reg("XV201_OPEN_CMD", 5, "coil", "Works outlet valve XV-201 open command", default=1, hmi_write=True),
    Reg("COAG_AUTO", 6, "coil", "Coagulant dosing DP-101 auto (flow paced)", default=1, hmi_write=True),
    Reg("CL_AUTO", 7, "coil", "Hypochlorite dosing DP-301 auto (PID)", default=1, hmi_write=True),
    Reg("NAOH_AUTO", 8, "coil", "Caustic dosing DP-302 auto (flow paced + pH trim)", default=1, hmi_write=True),
    Reg("ALARM_ACK", 9, "coil", "Write 1 to acknowledge alarms (self-clearing)", hmi_write=True),
    Reg("PLANT_ENABLE", 10, "coil", "Master enable for all PLC outputs", default=1, hmi_write=True),
]

PLC_DIS = [
    Reg("P101_RUNNING", 0, "di", "P-101 running feedback"),
    Reg("P201_RUNNING", 1, "di", "P-201 running feedback"),
    Reg("XV201_OPEN", 2, "di", "XV-201 open limit switch"),
    Reg("P201_CAVITATION", 3, "di", "P-201 cavitation detected (vibration)"),
    Reg("P201_DRY_RUN", 4, "di", "P-201 running dry"),
    Reg("P201_FAULT", 5, "di", "P-201 failed (damaged)"),
    Reg("DP101_RUNNING", 6, "di", "Coagulant pump running"),
    Reg("DP301_RUNNING", 7, "di", "Hypochlorite pump running"),
    Reg("DP302_RUNNING", 8, "di", "Caustic pump running"),
    Reg("ALARM_ACTIVE", 9, "di", "Any PLC alarm active"),
    Reg("SIS_TRIPPED", 10, "di", "SIS trip (hardwired status from SIS)"),
    Reg("SIS_BYPASSED", 11, "di", "SIS in maintenance bypass (hardwired status)"),
    Reg("ENG_LIMITS_ON", 12, "di", "Engineering range limits enforced on writes"),
    Reg("PLC_FAULT", 13, "di", "PLC CPU fault / STOP"),
    Reg("INTEGRITY_ON", 14, "di", "Telemetry HMAC frame enabled"),
]

PLC_IRS = [
    Reg("LT101", 0, "ir", "Raw water tank level", "m", 100),
    Reg("LT201", 1, "ir", "Clear water reservoir level", "m", 100),
    Reg("FT101", 2, "ir", "Intake flow", "m3/h", 10),
    Reg("FT102", 3, "ir", "Filter flow", "m3/h", 10),
    Reg("FT201", 4, "ir", "Distribution flow", "m3/h", 10),
    Reg("AIT101", 5, "ir", "Raw water turbidity", "NTU", 100),
    Reg("AIT102", 6, "ir", "Filtered water turbidity", "NTU", 100),
    Reg("AIT301", 7, "ir", "Free chlorine, contact outlet (control analyser)", "mg/L", 100),
    Reg("AIT302", 8, "ir", "pH, contact outlet (control analyser)", "pH", 100),
    Reg("AIT303", 9, "ir", "Free chlorine, final water", "mg/L", 100),
    Reg("AIT304", 10, "ir", "pH, final water", "pH", 100),
    Reg("PT201", 11, "ir", "Network pressure (critical node)", "bar", 100),
    Reg("P101_CURRENT", 12, "ir", "P-101 motor current", "A", 10),
    Reg("P101_TEMP", 13, "ir", "P-101 bearing temperature", "degC", 10),
    Reg("P201_CURRENT", 14, "ir", "P-201 motor current", "A", 10),
    Reg("P201_TEMP", 15, "ir", "P-201 bearing/seal temperature", "degC", 10),
    Reg("P201_SPEED", 16, "ir", "P-201 VFD speed", "%", 10),
    Reg("FCV101_POS", 17, "ir", "FCV-101 position", "%", 10),
    Reg("DP101_RATE", 18, "ir", "Coagulant pump rate", "L/h", 10),
    Reg("DP301_RATE", 19, "ir", "Hypochlorite pump rate", "L/h", 100),
    Reg("DP302_RATE", 20, "ir", "Caustic pump rate", "L/h", 10),
    Reg("COAG_DOSE", 21, "ir", "Calculated coagulant dose", "mg/L", 10),
    Reg("CL_DOSE", 22, "ir", "Calculated hypochlorite dose", "mg/L", 100),
    Reg("NAOH_DOSE", 23, "ir", "Calculated caustic dose", "ppm", 1),
    Reg("P201_VIBRATION", 24, "ir", "P-201 vibration", "mm/s", 10),
    Reg("ALARM_WORD", 25, "ir", "Alarm bits (see ALARM_BITS)"),
    Reg("SCAN_COUNT", 26, "ir", "PLC scan counter (mod 65536)"),
    Reg("PROG_CRC_HI", 27, "ir", "PLC program CRC32 high word"),
    Reg("PROG_CRC_LO", 28, "ir", "PLC program CRC32 low word"),
    Reg("PLC_STATUS", 29, "ir", "0 = RUN, 1 = FAULT/STOP"),
    Reg("TLM_SEQ_HI", 60, "ir", "Telemetry frame sequence (high)"),
    Reg("TLM_SEQ_LO", 61, "ir", "Telemetry frame sequence (low)"),
    Reg("TLM_TS_HI", 62, "ir", "Telemetry frame time, sim seconds (high)"),
    Reg("TLM_TS_LO", 63, "ir", "Telemetry frame time, sim seconds (low)"),
] + [Reg(f"TLM_MAC{i}", 64 + i, "ir", f"Telemetry HMAC-SHA256 truncated, word {i}") for i in range(8)]

PLC_HRS = [
    Reg("RAW_LVL_START", 0, "hr", "P-101 start level (hysteresis low)", "m", 100, 200, (100, 300), True),
    Reg("RAW_LVL_STOP", 1, "hr", "P-101 stop level (hysteresis high)", "m", 100, 380, (250, 430), True),
    Reg("RES_LVL_SP", 2, "hr", "Reservoir level setpoint", "m", 100, 250, (150, 330), True),
    Reg("CL_SP", 3, "hr", "Free chlorine setpoint (contact outlet)", "mg/L", 100, 100, (50, 200), True),
    Reg("NAOH_SP", 4, "hr", "Caustic (NaOH) dose setpoint", "ppm", 1, 100, (0, 200), True),
    Reg("PH_SP", 5, "hr", "pH trim setpoint", "pH", 100, 780, (700, 850), True),
    Reg("COAG_BASE", 6, "hr", "Coagulant base dose", "mg/L", 10, 150, (0, 400), True),
    Reg("COAG_PER_NTU", 7, "hr", "Coagulant dose per NTU raw turbidity", "mg/L/NTU", 100, 100, (0, 300), True),
    Reg("PRESS_SP", 8, "hr", "Network pressure setpoint", "bar", 100, 300, (150, 400), True),
    Reg("P201_MAN_SPEED", 9, "hr", "P-201 manual speed", "%", 10, 850, (0, 1000), True),
    Reg("FCV101_MAN_POS", 10, "hr", "FCV-101 manual position", "%", 10, 450, (0, 1000), True),
    Reg("CL_MAN_RATE", 11, "hr", "DP-301 manual rate", "L/h", 100, 240, (0, 1000), True),
    Reg("NAOH_MAN_RATE", 12, "hr", "DP-302 manual rate", "L/h", 10, 560, (0, 1500), True),
    Reg("COAG_MAN_RATE", 13, "hr", "DP-101 manual rate", "L/h", 10, 90, (0, 400), True),
    Reg("CL_HI_ALM", 14, "hr", "Final chlorine high alarm", "mg/L", 100, 200, (100, 300)),
    Reg("CL_LO_ALM", 15, "hr", "Final chlorine low alarm", "mg/L", 100, 50, (20, 100)),
    Reg("PH_HI_ALM", 16, "hr", "Final pH high alarm", "pH", 100, 850, (800, 920)),
    Reg("PH_LO_ALM", 17, "hr", "Final pH low alarm", "pH", 100, 700, (680, 750)),
    Reg("RAW_HI_ALM", 18, "hr", "Raw tank high level alarm", "m", 100, 420, (350, 450)),
    Reg("RES_LO_ALM", 19, "hr", "Reservoir low level alarm", "m", 100, 80, (50, 150)),
    Reg("PRESS_LO_ALM", 20, "hr", "Network pressure low alarm", "bar", 100, 150, (100, 250)),
    Reg("CL_KP", 21, "hr", "Chlorine PID gain", "", 100, 30, (0, 500)),
    Reg("CL_TI", 22, "hr", "Chlorine PID integral time", "s", 1, 300, (30, 1800)),
]

ALARM_BITS = ["RAW_HI", "RAW_LO", "RES_HI", "RES_LO", "CL_HI", "CL_LO", "PH_HI", "PH_LO",
              "TURB_HI", "PRESS_LO", "P201_OVERTEMP", "P201_CAV", "P201_DRY", "SIS_TRIP", "P201_FAULT", "NAOH_HI"]

# ----------------------------------------------------------------- SIS, unit 2
SIS_COILS = [
    Reg("SIS_BYPASS", 0, "coil", "Maintenance bypass (trip outputs inhibited)"),
    Reg("SIS_RESET", 1, "coil", "Write 1 to reset a latched trip (only if healthy)"),
]
SIS_DIS = [
    Reg("TRIPPED", 0, "di", "Trip latched (safe state active)"),
    Reg("LSHH901", 1, "di", "Raw tank high-high level switch"),
    Reg("LSLL902", 2, "di", "Reservoir low-low level switch"),
    Reg("CL_HH", 3, "di", "Independent chlorine analyser high-high"),
    Reg("CL_LL", 4, "di", "Independent chlorine analyser low-low"),
    Reg("PH_HH", 5, "di", "Independent pH analyser high-high"),
    Reg("PH_LL", 6, "di", "Independent pH analyser low-low"),
    Reg("BYPASSED", 7, "di", "Bypass active"),
]
SIS_IRS = [
    Reg("AIT901", 0, "ir", "SIS free chlorine analyser, final water", "mg/L", 100),
    Reg("AIT902", 1, "ir", "SIS pH analyser, final water", "pH", 100),
    Reg("TRIP_COUNT", 2, "ir", "Number of trips"),
    Reg("TRIP_CAUSE", 3, "ir", "Bitmask of the first-out trip cause (bit order as DIs 1..6)"),
]

PLC_MAP = {"coil": PLC_COILS, "di": PLC_DIS, "ir": PLC_IRS, "hr": PLC_HRS}
SIS_MAP = {"coil": SIS_COILS, "di": SIS_DIS, "ir": SIS_IRS, "hr": []}

C = SimpleNamespace(**{r.name: r.addr for r in PLC_COILS})
DI = SimpleNamespace(**{r.name: r.addr for r in PLC_DIS})
IR = SimpleNamespace(**{r.name: r.addr for r in PLC_IRS})
HR = SimpleNamespace(**{r.name: r.addr for r in PLC_HRS})
HR_BY_ADDR = {r.addr: r for r in PLC_HRS}
IR_BY_NAME = {r.name: r for r in PLC_IRS}
HR_BY_NAME = {r.name: r for r in PLC_HRS}

PLC_SIZES = {"coil": 16, "di": 16, "ir": 80, "hr": 32}
SIS_SIZES = {"coil": 8, "di": 8, "ir": 8, "hr": 0}
TELEMETRY_IR = (0, 30)   # IR words covered by the HMAC frame (plus HR, coils and DIs)


def default_holding() -> list[int]:
    hr = [0] * PLC_SIZES["hr"]
    for r in PLC_HRS:
        hr[r.addr] = r.default
    return hr


def default_coils() -> list[int]:
    co = [0] * PLC_SIZES["coil"]
    for r in PLC_COILS:
        co[r.addr] = r.default
    return co


def register_map() -> dict:
    """JSON-friendly map used by the HUD and the docs generator."""
    return {
        "plc": {"unit": 1, **{k: [r.to_dict() for r in v] for k, v in PLC_MAP.items()}},
        "sis": {"unit": 2, **{k: [r.to_dict() for r in v] for k, v in SIS_MAP.items()}},
        "alarm_bits": ALARM_BITS,
    }


def register_map_markdown() -> str:
    """Render the register map as Markdown (docs/REGISTER_MAP.md is generated from this)."""
    out = ["# Modbus register map", "",
           "Server: Modbus/TCP on 127.0.0.1:5020. Unit 1 = PLC-01, unit 2 = SIS-01 (maintenance interface).",
           "Addresses are 0-based protocol addresses; `Ref` is the classic 1-based reference.",
           "Analogue values are scaled integers: engineering value = raw / scale.",
           "Engineering limits (raw units) are enforced on writes only when the PLC limits are enabled.",
           "", "Built from icssim/registers.py by `python -m icssim docs`.", ""]
    titles = {"coil": "Coils (FC 1 read, FC 5/15 write)", "di": "Discrete inputs (FC 2)",
              "ir": "Input registers (FC 4)", "hr": "Holding registers (FC 3 read, FC 6/16 write)"}
    for dev, mp, unit in (("PLC-01", PLC_MAP, 1), ("SIS-01", SIS_MAP, 2)):
        for kind, regs in mp.items():
            if not regs:
                continue
            out += [f"## {dev} (unit {unit}): {titles[kind]}", ""]
            if kind == "hr":
                out.append("| Addr | Ref | Name | Description | Unit | Scale | Default | Eng. range | HMI writable |")
                out.append("|---|---|---|---|---|---|---|---|---|")
                for r in regs:
                    rng = f"{r.eng[0]}..{r.eng[1]}" if r.eng else ""
                    out.append(f"| {r.addr} | {r.to_dict()['ref']} | {r.name} | {r.desc} | {r.unit} | {r.scale:g} | {r.default} | {rng} | {'yes' if r.hmi_write else 'no'} |")
            else:
                out.append("| Addr | Ref | Name | Description | Unit | Scale |")
                out.append("|---|---|---|---|---|---|")
                for r in regs:
                    out.append(f"| {r.addr} | {r.to_dict()['ref']} | {r.name} | {r.desc} | {r.unit} | {r.scale:g} |")
            out.append("")
    out += ["## ALARM_WORD bits (IR 25)", "", "| Bit | Alarm |", "|---|---|"]
    out += [f"| {i} | {n} |" for i, n in enumerate(ALARM_BITS)]
    out += ["", "## Extra function codes", "",
            "- FC 17 (0x11) Report Server ID: returns the device name.",
            "- FC 43 / MEI 14 Read Device Identification (basic objects 0-2).",
            "- FC 90 (0x5A) engineering/program service on unit 1, modelled loosely on vendor",
            "  engineering protocols: sub-function 0x01 read program info (CRC32 + name),",
            "  0x02 read program (JSON), 0x10 download program (JSON body). Used by the logic",
            "  tampering scenario (T0889).", ""]
    return "\n".join(out)
