"""Process anomaly detector: physics and invariant checks on a passive tap.

It reads what the PLC sees (input image, setpoints, outputs) plus the SIS's
independent instruments, not the HMI, so replaying HMI traffic does not blind it.
Each rule must hold for a persistence time before it alerts, and an alert re-arms
only after the rule has been clear for a while. Thresholds are set so a 24 h
baseline run raises no alerts (checked by the tests).
"""

from __future__ import annotations

from collections import deque

from .registers import HR

DEMAND_EST = 0.5  # mg/L chlorine demand assumed by the consistency check (+0.1 x NTU)


class Rule:
    def __init__(self, key: str, persist: float, rearm: float = 600.0):
        self.key, self.persist, self.rearm = key, persist, rearm
        self.on_for = 0.0
        self.off_for = 1e9
        self.fired = False


class Detector:
    PERIOD = 1.0  # seconds between checks

    def __init__(self, events):
        self.events = events
        self.enabled = True
        self.rules = {k: Rule(k, p) for k, p in [
            ("redundant_cl", 60), ("redundant_ph", 60), ("dose_residual", 180), ("cl_dose_envelope", 120),
            ("cl_dose_missing", 120), ("naoh_envelope", 60), ("mass_balance_raw", 30), ("mass_balance_res", 30),
            ("hysteresis", 60), ("pump_protection", 20), ("rate_of_change", 0), ("pressure_loss", 60),
            ("sis_bypass", 0), ("program_crc", 0), ("analyser_disagreement", 300)]}
        self.baseline_crc: int | None = None
        self.hist: deque = deque()   # (t, raw_vol, res_vol, q_in, q_f, q_out)
        self.sums = [0.0, 0.0, 0.0]  # running sums of q_in, q_f, q_out over the window
        self.last_cl: float | None = None
        self.messages: dict = {}

    def check(self, t: float, plc, sis_values: dict, sis_bypassed: bool) -> None:
        inp = plc.inputs
        if not inp:
            return
        hr = plc.bank.hr
        out = plc.outputs
        q_f = inp["FT102"]
        flowing = q_f > 20.0
        pp = plc.pp
        c = {}

        # Redundant sensor disagreement (PLC final analysers vs SIS analysers)
        c["redundant_cl"] = (abs(inp["AIT303"] - sis_values["AIT901"]) > 0.5,
                             f"final chlorine PLC {inp['AIT303']:.2f} vs SIS {sis_values['AIT901']:.2f} mg/L")
        c["redundant_ph"] = (abs(inp["AIT304"] - sis_values["AIT902"]) > 0.5,
                             f"final pH PLC {inp['AIT304']:.2f} vs SIS {sis_values['AIT902']:.2f}")
        # Dose vs flow vs residual consistency
        cl_dose = inp["DP301"] * pp.cl_strength / max(q_f, 5.0)
        expected = cl_dose - DEMAND_EST - 0.1 * inp["AIT102"]
        c["dose_residual"] = (flowing and abs(inp["AIT301"] - expected) > 1.0,
                              f"contact chlorine {inp['AIT301']:.2f} mg/L inconsistent with dose {cl_dose:.2f} mg/L")
        c["cl_dose_envelope"] = (flowing and cl_dose > 4.0, f"hypochlorite dose {cl_dose:.2f} mg/L above envelope")
        c["cl_dose_missing"] = (flowing and cl_dose < 0.6, f"hypochlorite dose {cl_dose:.2f} mg/L with {q_f:.0f} m3/h flowing")
        naoh_dose = inp["DP302"] * pp.naoh_strength / max(q_f, 5.0)
        c["naoh_envelope"] = (flowing and (naoh_dose > 160.0 or inp["AIT302"] > 9.0),
                              f"caustic dose {naoh_dose:.0f} ppm / contact pH {inp['AIT302']:.2f} outside envelope")
        # Contact vs final analyser agreement (slow, catches a spoofed control analyser)
        c["analyser_disagreement"] = (abs(inp["AIT301"] - inp["AIT303"]) > 1.0,
                                      f"contact chlorine {inp['AIT301']:.2f} vs final {inp['AIT303']:.2f} mg/L")
        # Mass balance over a 120 s window
        row = (t, inp["LT101"] * pp.raw_area, inp["LT201"] * pp.res_area, inp["FT101"], q_f, inp["FT201"])
        self.hist.append(row)
        sums = self.sums
        sums[0] += row[3]; sums[1] += row[4]; sums[2] += row[5]
        while t - self.hist[0][0] > 120.0:
            old = self.hist.popleft()
            sums[0] -= old[3]; sums[1] -= old[4]; sums[2] -= old[5]
        mb_raw = mb_res = False
        if len(self.hist) > 60:
            t0, rv0, sv0 = self.hist[0][0], self.hist[0][1], self.hist[0][2]
            span_h = (t - t0) / 3600.0
            n = len(self.hist)
            q_in, q_fm, q_out = sums[0] / n, sums[1] / n, sums[2] / n
            res_raw = ((inp["LT101"] * pp.raw_area - rv0) / span_h) - (q_in - q_fm)
            res_res = ((inp["LT201"] * pp.res_area - sv0) / span_h) - (q_fm - q_out)
            mb_raw, mb_res = abs(res_raw) > 40.0, abs(res_res) > 40.0
            c["mass_balance_raw"] = (mb_raw, f"raw tank mass balance residual {res_raw:+.0f} m3/h (overflow, leak or bad meter)")
            c["mass_balance_res"] = (mb_res, f"reservoir mass balance residual {res_res:+.0f} m3/h")
        # Control-logic invariant: intake must be off above the stop level (in auto)
        stop = hr[HR.RAW_LVL_STOP] / 100.0
        c["hysteresis"] = (plc.bank.coils[0] and out.p101_run and inp["LT101"] > stop + 0.15,
                           f"intake running at {inp['LT101']:.2f} m, above stop setpoint {stop:.2f} m")
        c["pump_protection"] = (inp["P201_RUN"] and (inp["LT201"] < 0.6 or inp["P201_T"] > 70.0),
                                f"P-201 running at reservoir {inp['LT201']:.2f} m, {inp['P201_T']:.0f} degC (cavitation / dry run risk)")
        # Rate of change: a chlorine analyser cannot jump 0.4 mg/L in one second
        cl = inp["AIT301"]
        c["rate_of_change"] = (self.last_cl is not None and abs(cl - self.last_cl) > 0.4,
                               f"contact chlorine changed {0 if self.last_cl is None else cl - self.last_cl:+.2f} mg/L in 1 s")
        self.last_cl = cl
        c["pressure_loss"] = (inp["PT201"] < 1.0, f"network pressure {inp['PT201']:.2f} bar")
        c["sis_bypass"] = (sis_bypassed, "SIS maintenance bypass active while plant in service")
        crc = plc.program_crc
        if self.baseline_crc is None:
            self.baseline_crc = crc
        c["program_crc"] = (crc != self.baseline_crc, f"PLC program CRC changed {self.baseline_crc:08x} -> {crc:08x}")

        for key, (cond, msg) in c.items():
            self._update(t, self.rules[key], bool(cond), msg)

    def _update(self, t: float, r: Rule, cond: bool, msg: str) -> None:
        if cond:
            r.on_for += self.PERIOD
            r.off_for = 0.0
            if not r.fired and r.on_for >= r.persist:
                r.fired = True
                self.events.alert(t, "detector", f"Anomaly [{r.key}]: {msg}", "high", rule=r.key)
        else:
            r.on_for = 0.0
            r.off_for += self.PERIOD
            if r.fired and r.off_for >= r.rearm:
                r.fired = False
