"""PLC-01: scan-cycle control logic for the works, exposed as Modbus unit 1.

Each scan: copy field inputs into the input image, run the control program,
compute alarms, write outputs, then refresh the Modbus tables. Setpoints and
modes live in holding registers and coils, exactly where an attacker with
Modbus access can reach them.

The "program" is a small JSON document of logic options. It can be read and
replaced with FC 90, which stands in for a vendor engineering protocol. A
tampered program can override the hysteresis levels and suppress alarms while
the holding registers (and therefore the HMI) still show the normal values.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import zlib

from .modbus import DataBank, ModbusError, ILLEGAL_VALUE, ILLEGAL_FUNCTION, DEVICE_FAILURE
from .process import Actuators, clamp
from .registers import (C, DI, HR, IR, ALARM_BITS, HR_BY_ADDR, PLC_SIZES, TELEMETRY_IR,
                        default_coils, default_holding)

DEFAULT_PROGRAM = {
    "name": "WTW-MAIN",
    "version": "1.4.2",
    "raw_start_override_m": None,   # if set, replaces RAW_LVL_START in the logic
    "raw_stop_override_m": None,    # if set, replaces RAW_LVL_STOP in the logic
    "suppress_alarms": [],
}
COMM_CAPACITY_PER_SCAN = 50        # requests the comms processor serves per 0.5 s scan
WATCHDOG_LOAD_FACTOR = 10          # sustained offered load above capacity x this faults the CPU
WATCHDOG_SCANS = 10
ALARM_OFF_DELAY_S = 10.0


def program_crc(program: dict) -> int:
    return zlib.crc32(json.dumps(program, sort_keys=True).encode()) & 0xFFFFFFFF


class PID:
    """PI(D) with clamped integral (anti-windup)."""

    def __init__(self, out_min: float, out_max: float):
        self.out_min, self.out_max = out_min, out_max
        self.i = 0.0

    def update(self, err: float, dt: float, kp: float, ti: float, hold: bool = False) -> float:
        if not hold and ti > 0:
            self.i = clamp(self.i + kp * err * dt / ti, self.out_min, self.out_max)
        return clamp(kp * err + self.i, self.out_min, self.out_max)


class PLC:
    def __init__(self, events, plant_params, integrity_key: bytes):
        self.events = events
        self.pp = plant_params
        self.key = integrity_key
        self.bank = DataBank(PLC_SIZES, name="PLC-01 water treatment",
                             ident={"vendor": "seclab", "product": "PLC-01 WTW controller", "revision": "1.4.2"})
        self.bank.hr[:] = default_holding()
        self.bank.coils[:] = default_coils()
        self.bank.validate = self._validate
        self.bank.after_write = self._after_write
        self.bank.extra[90] = self._fc90
        self.bank.before_read = self.refresh
        self._program = dict(DEFAULT_PROGRAM)
        self.program_crc = program_crc(self._program)
        self._dirty = True
        self.eng_limits = False
        self.integrity = False
        self.faulted = False
        self.fault_reason = ""
        self.scan_count = 0
        self.t = 0.0
        self.p101_latch = False
        self.p201_latch = True
        self.cl_pid = PID(-3.0, 10.0)
        self.ph_pid = PID(-0.25, 0.25)
        self.p_pid = PID(-0.5, 0.5)
        self.q_pid = PID(-30.0, 30.0)
        self.inputs: dict = {}
        self.outputs = Actuators()
        self.alarm_word = 0
        self.alarm_last_true = [-1e9] * len(ALARM_BITS)
        self.unacked = 0
        self.comm_load = 0
        self.comm_offered = 0
        self.overload_scans = 0
        self.tlm_seq = 0
        self.sis_status = (False, False)
        self.on_reject = None   # callback(addr, value) for eng-limit rejections

    @property
    def program(self) -> dict:
        return self._program

    @program.setter
    def program(self, prog: dict) -> None:
        self._program = prog
        self.program_crc = program_crc(prog)

    # ------------------------------------------------------------ Modbus hooks
    def _validate(self, kind: str, addr: int, values: list[int]) -> None:
        if self.faulted and kind in ("hr", "coil"):
            raise ModbusError(DEVICE_FAILURE)
        if kind in ("ir", "di"):
            raise ModbusError(ILLEGAL_FUNCTION)
        if kind == "hr" and self.eng_limits:
            for i, v in enumerate(values):
                reg = HR_BY_ADDR.get(addr + i)
                if reg and reg.eng and not reg.eng[0] <= v <= reg.eng[1]:
                    if self.on_reject:
                        self.on_reject(reg, v)
                    raise ModbusError(ILLEGAL_VALUE, f"{reg.name}={v} outside engineering range")

    def _after_write(self, kind: str, addr: int, values: list[int]) -> None:
        if kind == "coil" and addr <= C.ALARM_ACK < addr + len(values) and values[C.ALARM_ACK - addr]:
            self.unacked = 0
            self.bank.coils[C.ALARM_ACK] = 0

    def _fc90(self, pdu: bytes) -> bytes:
        """Engineering service: 0x01 info, 0x02 read program, 0x10 download program."""
        if len(pdu) < 2:
            raise ModbusError(ILLEGAL_VALUE)
        sub = pdu[1]
        if sub == 0x01:
            name = self.program.get("name", "").encode()[:32]
            return bytes([90, 0x01]) + struct.pack(">I", self.program_crc) + name
        if sub == 0x02:
            return bytes([90, 0x02]) + json.dumps(self.program, sort_keys=True).encode()[:240]
        if sub == 0x10:
            try:
                prog = json.loads(pdu[2:].decode())
            except (ValueError, UnicodeDecodeError):
                raise ModbusError(ILLEGAL_VALUE)
            if not isinstance(prog, dict) or set(prog) - set(DEFAULT_PROGRAM):
                raise ModbusError(ILLEGAL_VALUE)
            self.program = {**DEFAULT_PROGRAM, **prog}
            crc = self.program_crc
            self.events.add(self.t, "plc", f"PLC program downloaded (CRC {crc:08x})", "warn", "plc")
            return bytes([90, 0x10]) + struct.pack(">I", crc)
        raise ModbusError(ILLEGAL_VALUE)

    def comm_admit(self, n: int) -> int:
        """Admit up to n requests this scan. Offered load is tracked for the watchdog."""
        self.comm_offered += n
        free = max(0, COMM_CAPACITY_PER_SCAN - self.comm_load)
        k = min(n, free)
        self.comm_load += k
        return k

    def reset(self) -> None:
        """Local restart of a faulted CPU (key switch STOP -> RUN)."""
        if self.faulted:
            self.faulted = False
            self.overload_scans = 0
            self.events.add(self.t, "plc", "PLC restarted (RUN)", "info", "plc")

    # --------------------------------------------------------------- scan
    def scan(self, inp: dict, dt: float, t: float) -> None:
        self.t = t
        self.scan_count += 1
        self.inputs = inp
        # comms watchdog: a flood that keeps the comms processor saturated starves the scan
        if self.comm_offered > COMM_CAPACITY_PER_SCAN * WATCHDOG_LOAD_FACTOR:
            self.overload_scans += 1
            if self.overload_scans >= WATCHDOG_SCANS and not self.faulted:
                self.faulted = True
                self.fault_reason = "scan watchdog: comms overload"
                self.events.add(t, "plc", "PLC CPU FAULT: scan watchdog expired under comms overload, outputs de-energised", "crit", "plc")
        else:
            self.overload_scans = 0
        self.comm_offered = 0
        self.comm_load = 0

        if self.faulted:
            self.outputs = Actuators(p101_run=False, fcv101_pos=0.0, p201_run=False, p201_speed=0.0,
                                     xv201_open=False, coag_rate=0.0, cl_rate=0.0, naoh_rate=0.0)
        else:
            self._logic(inp, dt)
            self._alarms(inp)
        self._dirty = True

    def refresh(self) -> None:
        """Copy the latest scan into the Modbus tables. Called lazily before any read."""
        if self._dirty and self.inputs:
            self._dirty = False
            self._refresh_tables(self.inputs)

    def _logic(self, inp: dict, dt: float) -> None:
        hr, co, prog, pp = self.bank.hr, self.bank.coils, self.program, self.pp
        out = Actuators()
        enable = bool(co[C.PLANT_ENABLE])
        lt101, lt201 = inp["LT101"], inp["LT201"]
        q_f, q_dist = inp["FT102"], inp["FT201"]

        # 1. Raw tank level: intake pump with hysteresis
        start = prog["raw_start_override_m"] or hr[HR.RAW_LVL_START] / 100.0
        stop = prog["raw_stop_override_m"] or hr[HR.RAW_LVL_STOP] / 100.0
        if co[C.P101_AUTO]:
            if lt101 <= start:
                self.p101_latch = True
            elif lt101 >= stop:
                self.p101_latch = False
            out.p101_run = self.p101_latch
        else:
            out.p101_run = bool(co[C.P101_MAN_RUN])

        # 2. Filter feed: flow setpoint from reservoir level (feedforward on outflow), PI on valve
        if co[C.FCV101_AUTO]:
            q_sp = q_dist + 150.0 * (hr[HR.RES_LVL_SP] / 100.0 - lt201)
            if lt101 < 0.3:
                q_sp = 0.0  # protect the raw tank / filter from running empty
            q_sp = clamp(q_sp, 0.0, pp.filter_qmax)
            q_cap = pp.filter_qmax * (max(lt101 - 0.05, 0.01) / pp.filter_href) ** 0.5
            pos_ff = 100.0 * q_sp / max(q_cap, 1.0)
            trim = self.q_pid.update((q_sp - q_f) / max(q_cap, 1.0) * 100.0, dt, 0.3, 60.0, hold=q_sp <= 0)
            out.fcv101_pos = 0.0 if q_sp <= 0 else clamp(pos_ff + trim, 0.0, 100.0)
        else:
            out.fcv101_pos = hr[HR.FCV101_MAN_POS] / 10.0
        flowing = q_f > 5.0

        # 3. Coagulant: flow paced, dose from raw turbidity
        if co[C.COAG_AUTO]:
            dose = hr[HR.COAG_BASE] / 10.0 + hr[HR.COAG_PER_NTU] / 100.0 * inp["AIT101"]
            out.coag_rate = dose * q_f / pp.coag_strength if flowing else 0.0
        else:
            out.coag_rate = hr[HR.COAG_MAN_RATE] / 10.0

        # 4. Hypochlorite: feedforward on flow + estimated demand, PI trim on contact analyser
        if co[C.CL_AUTO]:
            sp = hr[HR.CL_SP] / 100.0
            ff = sp + 0.5 + 0.1 * inp["AIT102"]
            corr = self.cl_pid.update(sp - inp["AIT301"], dt, hr[HR.CL_KP] / 100.0, float(hr[HR.CL_TI]), hold=not flowing)
            out.cl_rate = clamp((ff + corr) * q_f / pp.cl_strength, 0.0, pp.cl_pump_max) if flowing else 0.0
        else:
            out.cl_rate = hr[HR.CL_MAN_RATE] / 100.0

        # 5. Caustic: flow paced at the NaOH dose setpoint with a +-25 % pH trim
        if co[C.NAOH_AUTO]:
            trim = self.ph_pid.update(hr[HR.PH_SP] / 100.0 - inp["AIT302"], dt, 0.05, 900.0, hold=not flowing)
            dose = hr[HR.NAOH_SP] * (1.0 + trim)
            out.naoh_rate = clamp(dose * q_f / pp.naoh_strength, 0.0, pp.naoh_pump_max) if flowing else 0.0
        else:
            out.naoh_rate = hr[HR.NAOH_MAN_RATE] / 10.0

        # 6. Distribution: auto has a low-level interlock with hysteresis; manual bypasses it
        out.xv201_open = bool(co[C.XV201_OPEN_CMD])
        if co[C.P201_AUTO]:
            if lt201 < 0.5:
                self.p201_latch = False
            elif lt201 > 0.8:
                self.p201_latch = True
            out.p201_run = self.p201_latch and out.xv201_open
            sp = hr[HR.PRESS_SP] / 100.0
            out.p201_speed = clamp(0.85 + self.p_pid.update(sp - inp["PT201"], dt, 0.08, 30.0, hold=not out.p201_run), 0.3, 1.0)
        else:
            out.p201_run = bool(co[C.P201_MAN_RUN])
            out.p201_speed = hr[HR.P201_MAN_SPEED] / 1000.0

        if not enable:
            out = Actuators(p101_run=False, fcv101_pos=0.0, p201_run=False, p201_speed=0.0,
                            xv201_open=False, coag_rate=0.0, cl_rate=0.0, naoh_rate=0.0)
        self.outputs = out

    def _alarms(self, inp: dict) -> None:
        hr = self.bank.hr
        conds = {
            "RAW_HI": inp["LT101"] > hr[HR.RAW_HI_ALM] / 100.0,
            "RAW_LO": inp["LT101"] < 0.5,
            "RES_HI": inp["LT201"] > 3.7,
            "RES_LO": inp["LT201"] < hr[HR.RES_LO_ALM] / 100.0,
            "CL_HI": inp["AIT303"] > hr[HR.CL_HI_ALM] / 100.0 or inp["AIT301"] > hr[HR.CL_HI_ALM] / 100.0,
            "CL_LO": inp["AIT303"] < hr[HR.CL_LO_ALM] / 100.0,
            "PH_HI": inp["AIT304"] > hr[HR.PH_HI_ALM] / 100.0,
            "PH_LO": inp["AIT304"] < hr[HR.PH_LO_ALM] / 100.0,
            "TURB_HI": inp["AIT102"] > 0.8,
            "PRESS_LO": inp["PT201"] < hr[HR.PRESS_LO_ALM] / 100.0,
            "P201_OVERTEMP": inp["P201_T"] > 75.0,
            "P201_CAV": bool(inp["P201_CAV"]),
            "P201_DRY": bool(inp["P201_DRY"]),
            "SIS_TRIP": self.sis_status[0],
            "P201_FAULT": bool(inp["P201_FAULT"]),
            "NAOH_HI": hr[HR.NAOH_SP] > 200,
        }
        suppressed = set(self.program.get("suppress_alarms") or [])
        word = 0
        last = self.alarm_last_true
        for i, name in enumerate(ALARM_BITS):
            if conds[name] and name not in suppressed:
                last[i] = self.t
            # 10 s off-delay so a noisy value sitting on a threshold does not chatter
            if self.t - last[i] < ALARM_OFF_DELAY_S and name not in suppressed:
                word |= 1 << i
        new = word & ~self.alarm_word
        if new:
            names = [n for i, n in enumerate(ALARM_BITS) if new >> i & 1]
            self.unacked |= new
            self.events.add(self.t, "alarm", "PLC alarm: " + ", ".join(names), "warn", "plc", alarms=names)
        cleared = self.alarm_word & ~word
        if cleared:
            names = [n for i, n in enumerate(ALARM_BITS) if cleared >> i & 1]
            self.events.add(self.t, "alarm", "PLC alarm cleared: " + ", ".join(names), "info", "plc")
        self.alarm_word = word

    def _refresh_tables(self, inp: dict) -> None:
        ir, di, out = self.bank.ir, self.bank.di, self.outputs

        def put(addr, value, scale):
            v = int(round(value * scale))
            ir[addr] = 0 if v < 0 else 65535 if v > 65535 else v

        put(IR.LT101, inp["LT101"], 100); put(IR.LT201, inp["LT201"], 100)
        put(IR.FT101, inp["FT101"], 10); put(IR.FT102, inp["FT102"], 10); put(IR.FT201, inp["FT201"], 10)
        put(IR.AIT101, inp["AIT101"], 100); put(IR.AIT102, inp["AIT102"], 100)
        put(IR.AIT301, inp["AIT301"], 100); put(IR.AIT302, inp["AIT302"], 100)
        put(IR.AIT303, inp["AIT303"], 100); put(IR.AIT304, inp["AIT304"], 100)
        put(IR.PT201, inp["PT201"], 100)
        put(IR.P101_CURRENT, inp["P101_I"], 10); put(IR.P101_TEMP, inp["P101_T"], 10)
        put(IR.P201_CURRENT, inp["P201_I"], 10); put(IR.P201_TEMP, inp["P201_T"], 10)
        put(IR.P201_SPEED, inp["P201_SPD"], 10); put(IR.FCV101_POS, inp["FCV101_POS"], 10)
        put(IR.DP101_RATE, inp["DP101"], 10); put(IR.DP301_RATE, inp["DP301"], 100); put(IR.DP302_RATE, inp["DP302"], 10)
        qf = max(inp["FT102"], 5.0)
        put(IR.COAG_DOSE, inp["DP101"] * self.pp.coag_strength / qf, 10)
        put(IR.CL_DOSE, inp["DP301"] * self.pp.cl_strength / qf, 100)
        put(IR.NAOH_DOSE, inp["DP302"] * self.pp.naoh_strength / qf, 1)
        put(IR.P201_VIBRATION, inp["P201_VIB"], 10)
        ir[IR.ALARM_WORD] = self.alarm_word
        ir[IR.SCAN_COUNT] = self.scan_count & 0xFFFF
        crc = self.program_crc
        ir[IR.PROG_CRC_HI], ir[IR.PROG_CRC_LO] = crc >> 16, crc & 0xFFFF
        ir[IR.PLC_STATUS] = 1 if self.faulted else 0

        di[DI.P101_RUNNING] = int(inp["P101_RUN"]); di[DI.P201_RUNNING] = int(inp["P201_RUN"])
        di[DI.XV201_OPEN] = int(inp["XV201_OPEN"]); di[DI.P201_CAVITATION] = int(inp["P201_CAV"])
        di[DI.P201_DRY_RUN] = int(inp["P201_DRY"]); di[DI.P201_FAULT] = int(inp["P201_FAULT"])
        di[DI.DP101_RUNNING] = int(inp["DP101"] > 0); di[DI.DP301_RUNNING] = int(inp["DP301"] > 0)
        di[DI.DP302_RUNNING] = int(inp["DP302"] > 0); di[DI.ALARM_ACTIVE] = int(self.alarm_word != 0)
        di[DI.SIS_TRIPPED] = int(self.sis_status[0]); di[DI.SIS_BYPASSED] = int(self.sis_status[1])
        di[DI.ENG_LIMITS_ON] = int(self.eng_limits); di[DI.PLC_FAULT] = int(self.faulted)
        di[DI.INTEGRITY_ON] = int(self.integrity)

        if self.integrity and not self.faulted:
            self.tlm_seq = (self.tlm_seq + 1) & 0xFFFFFFFF
            ts = int(self.t) & 0xFFFFFFFF
            ir[IR.TLM_SEQ_HI], ir[IR.TLM_SEQ_LO] = self.tlm_seq >> 16, self.tlm_seq & 0xFFFF
            ir[IR.TLM_TS_HI], ir[IR.TLM_TS_LO] = ts >> 16, ts & 0xFFFF
            mac = telemetry_mac(self.key, ir, self.bank.hr, self.bank.coils, di, self.tlm_seq, ts)
            ir[IR.TLM_MAC0:IR.TLM_MAC0 + 8] = struct.unpack(">8H", mac)
        elif not self.integrity:
            ir[IR.TLM_SEQ_HI:IR.TLM_MAC0 + 8] = [0] * 12


def telemetry_mac(key: bytes, ir, hr, coils, di, seq: int, ts: int) -> bytes:
    """HMAC-SHA256 over the process values, setpoints, modes, status bits, sequence and time.

    Truncated to 128 bits (8 registers). The HMI recomputes it over what it received:
    a forged value breaks the MAC, a replayed frame has a stale sequence/time.
    """
    lo, hi = TELEMETRY_IR
    msg = (struct.pack(f">{hi - lo}H", *ir[lo:hi]) + struct.pack(f">{len(hr)}H", *hr)
           + bytes(coils) + bytes(di) + struct.pack(">II", seq, ts))
    return hmac.new(key, msg, hashlib.sha256).digest()[:16]
