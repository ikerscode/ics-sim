"""SIS-01: independent safety instrumented system (Modbus unit 2, maintenance interface).

It has its own instruments (level switches and duplicate analysers, see
Plant.sis_sensors), its own logic and the last word on the final elements:
when it trips it stops all dosing, stops the intake pump, closes the works
outlet XV-201 and stops P-201. The trip latches until a reset with healthy
conditions. A maintenance bypass coil inhibits the outputs, which is what the
SIS-bypass scenario abuses.
"""

from __future__ import annotations

from dataclasses import replace

from .modbus import DataBank, ModbusError, ILLEGAL_FUNCTION
from .registers import SIS_SIZES

TRIPS = [  # (key, description, delay seconds)
    ("LSHH901", "raw tank high-high level", 2.0),
    ("LSLL902", "reservoir low-low level", 2.0),
    ("CL_HH", "final chlorine >= 3.0 mg/L", 10.0),
    ("CL_LL", "final chlorine <= 0.3 mg/L", 10.0),
    ("PH_HH", "final pH >= 9.2", 10.0),
    ("PH_LL", "final pH <= 6.8", 10.0),
]
CL_HH, CL_LL, PH_HH, PH_LL = 3.0, 0.3, 9.2, 6.8


class SIS:
    def __init__(self, events):
        self.events = events
        self.enabled = True
        self.bank = DataBank(SIS_SIZES, name="SIS-01 safety controller",
                             ident={"vendor": "seclab", "product": "SIS-01 safety controller", "revision": "2.0.1"})
        self.bank.validate = self._validate
        self.bank.before_read = self._refresh
        self.tripped = False
        self.cause = ""
        self.trip_count = 0
        self.timers = {k: 0.0 for k, _, _ in TRIPS}
        self.active = {k: False for k, _, _ in TRIPS}
        self.t = 0.0
        self.values: dict = {}

    @property
    def bypassed(self) -> bool:
        return bool(self.bank.coils[0])

    def _validate(self, kind, addr, values):
        if kind not in ("coil",):
            raise ModbusError(ILLEGAL_FUNCTION)
        if addr == 0 and values and values[0] != self.bank.coils[0]:
            state = "ON" if values[0] else "OFF"
            self.events.add(self.t, "sis", f"SIS maintenance bypass switched {state} via Modbus", "crit" if values[0] else "info", "sis_device")

    def scan(self, s: dict, dt: float, t: float) -> None:
        self.t = t
        self.values = s
        conds = {
            "LSHH901": s["LSHH901"], "LSLL902": s["LSLL902"],
            "CL_HH": s["AIT901"] >= CL_HH, "CL_LL": s["AIT901"] <= CL_LL,
            "PH_HH": s["AIT902"] >= PH_HH, "PH_LL": s["AIT902"] <= PH_LL,
        }
        for key, desc, delay in TRIPS:
            self.timers[key] = self.timers[key] + dt if conds[key] else 0.0
            self.active[key] = self.timers[key] >= delay
        healthy = not any(self.active.values())
        if self.bank.coils[1]:  # reset request
            self.bank.coils[1] = 0
            if self.tripped and healthy:
                self.tripped = False
                self.events.add(t, "sis", "SIS trip reset", "info", "sis_device")
        if self.enabled and not self.bypassed and not self.tripped and not healthy:
            first = [desc for key, desc, _ in TRIPS if self.active[key]]
            self.tripped = True
            self.trip_count += 1
            self.cause = first[0]
            self.events.alert(t, "sis", f"SIS TRIP: {self.cause}; safe state (dosing off, intake off, outlet closed)", "crit")

    def _refresh(self) -> None:
        di, ir = self.bank.di, self.bank.ir
        di[0] = int(self.tripped)
        for i, (key, _, _) in enumerate(TRIPS):
            di[1 + i] = int(self.active[key])
        di[7] = int(self.bypassed)
        ir[0] = max(0, min(65535, int(round(self.values.get("AIT901", 0) * 100))))
        ir[1] = max(0, min(65535, int(round(self.values.get("AIT902", 0) * 100))))
        ir[2] = self.trip_count & 0xFFFF
        ir[3] = sum(1 << i for i, (k, _, _) in enumerate(TRIPS) if self.active[k]) if self.tripped else 0

    @property
    def holding_safe_state(self) -> bool:
        return self.enabled and self.tripped and not self.bypassed

    def apply(self, out):
        """Override PLC outputs with the safe state while tripped (and not bypassed)."""
        if not self.holding_safe_state:
            return out
        return replace(out, p101_run=False, coag_rate=0.0, cl_rate=0.0, naoh_rate=0.0,
                       xv201_open=False, p201_run=False)

    def reset(self) -> None:
        self.bank.coils[1] = 1
