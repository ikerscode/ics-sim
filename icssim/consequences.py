"""Consequence model: hazards, availability, water quality compliance, safety score.

Everything is computed from ground truth (the Plant), never from sensors, so a
spoofed analyser cannot hide a hazard from the scorecard.
"""

from __future__ import annotations

from . import constants as K


class ConsequenceTracker:
    def __init__(self, events, t0: float = 0.0):
        self.events = events
        self.t0 = t0
        self.total_s = 0.0
        self.met_s = 0.0
        self.delivered_m3 = 0.0
        self.compliant_m3 = 0.0
        self.unmet_m3 = 0.0
        self.noncompliant_m3 = 0.0
        self.durations = {k: 0.0 for k in K.HAZARDS}
        self.onset: dict[str, float] = {}
        self.active = {k: False for k in K.HAZARDS}
        self.low_p_for = 0.0
        self.spill0: float | None = None
        self.max_cl = 0.0
        self.min_cl = 99.0
        self.max_ph = 0.0
        self.min_ph = 14.0
        self.max_sodium = 0.0
        self.min_pressure = 99.0
        self.max_raw_level = 0.0
        self.max_p201_temp = 0.0

    def update(self, plant, dt: float, t: float) -> None:
        tr_cl, tr_ph, na = plant.res_cl, plant.ph_final, plant.res_na
        delivered, demand, pressure = plant.q_out, plant.demand, plant.pressure
        hours = dt / 3600.0
        self.total_s += dt
        met = pressure >= K.PRESSURE_MIN and delivered >= K.DEMAND_MET_FRACTION * demand
        if met:
            self.met_s += dt
        self.unmet_m3 += max(0.0, demand - delivered) * hours
        flowing = delivered > 1.0
        compliant = (K.CL_MIN <= tr_cl <= K.CL_MAX and K.PH_MIN <= tr_ph <= K.PH_MAX
                     and plant.res_turb <= K.TURBIDITY_MAX and na <= K.SODIUM_MAX)
        self.delivered_m3 += delivered * hours
        if compliant:
            self.compliant_m3 += delivered * hours
        else:
            self.noncompliant_m3 += delivered * hours

        spill = plant.raw_spill + plant.res_spill
        if self.spill0 is None:
            self.spill0 = spill
        self.low_p_for = self.low_p_for + dt if (pressure < K.PRESSURE_MIN and demand > 0) else 0.0
        flags = {
            "tank_overflow": plant.raw_overflowing or plant.res_overflowing,
            "chlorine_overdose": flowing and tr_cl > K.CL_MAX,
            "chlorine_underdose": flowing and tr_cl < K.CL_MIN,
            "ph_out_of_range": flowing and not (K.PH_MIN <= tr_ph <= K.PH_MAX),
            "caustic_overdose": flowing and (tr_ph >= K.PH_CAUSTIC or na > K.SODIUM_MAX),
            "pump_damage": plant.p201_damaged,
            "supply_outage": self.low_p_for >= K.OUTAGE_GRACE_S,
        }
        for k, on in flags.items():
            if on:
                self.durations[k] += dt
                if k not in self.onset:
                    self.onset[k] = t
                if not self.active[k]:
                    self.events.add(t, "hazard", f"HAZARD: {K.HAZARDS[k][0]}", "crit", "plant", hazard=k)
            elif self.active[k]:
                self.events.add(t, "hazard", f"Hazard cleared: {K.HAZARDS[k][0]}", "info", "plant", hazard=k)
            self.active[k] = on

        if flowing:
            self.max_cl = max(self.max_cl, tr_cl)
            self.min_cl = min(self.min_cl, tr_cl)
            self.max_ph = max(self.max_ph, tr_ph)
            self.min_ph = min(self.min_ph, tr_ph)
            self.max_sodium = max(self.max_sodium, na)
        self.min_pressure = min(self.min_pressure, pressure)
        self.max_raw_level = max(self.max_raw_level, plant.raw_level)
        self.max_p201_temp = max(self.max_p201_temp, plant.p201_temp)
        self._spill_now = spill

    def safety_score(self) -> float:
        score = 100.0
        for k, d in self.durations.items():
            if d > 0:
                score -= K.HAZARDS[k][1] * min(1.0, d / K.HAZARD_FULL_WEIGHT_S)
        return round(max(0.0, score), 1)

    def summary(self, attack_t: float | None = None) -> dict:
        ref = attack_t if attack_t is not None else self.t0
        return {
            "availability_pct": round(100.0 * self.met_s / max(self.total_s, 1e-9), 2),
            "quality_compliance_pct": round(100.0 * self.compliant_m3 / max(self.delivered_m3, 1e-9), 2),
            "safety_score": self.safety_score(),
            "hazards": sorted(k for k, d in self.durations.items() if d > 0),
            "hazard_durations_s": {k: round(d, 1) for k, d in self.durations.items() if d > 0},
            "time_to_hazard_s": {k: round(v - ref, 1) for k, v in sorted(self.onset.items(), key=lambda x: x[1])},
            "delivered_m3": round(self.delivered_m3, 1),
            "noncompliant_m3": round(self.noncompliant_m3, 1),
            "unmet_demand_m3": round(self.unmet_m3, 1),
            "overflow_m3": round(getattr(self, "_spill_now", 0.0) - (self.spill0 or 0.0), 1),
            "max_final_cl": round(self.max_cl, 2), "min_final_cl": round(self.min_cl if self.min_cl < 99 else 0.0, 2),
            "max_final_ph": round(self.max_ph, 2), "min_final_ph": round(self.min_ph if self.min_ph < 14 else 0.0, 2),
            "max_sodium": round(self.max_sodium, 1),
            "min_pressure": round(self.min_pressure, 2), "max_raw_level": round(self.max_raw_level, 2),
            "max_p201_temp": round(self.max_p201_temp, 1),
            "duration_s": round(self.total_s, 1),
        }
