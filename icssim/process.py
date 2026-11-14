"""Physical process model of a small water treatment works (ground truth).

Flow path:
    river -> P-101 intake pump -> T-101 raw water tank -> FCV-101 filter feed valve
    -> coagulant dosing (DP-101) + rapid gravity filter -> NaOCl (DP-301) and NaOH (DP-302)
    dosing -> contact pipe (transport delay) -> T-201 clear water reservoir
    -> XV-201 outlet valve -> P-201 distribution pump (VFD) -> network demand

The model is deterministic for a given seed. Two random streams are used:
one for process disturbances (demand, raw water) and one for sensor noise, so a
baseline run and an attack run see exactly the same demand and raw water.

All simplifications are listed in docs/MODEL.md.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from . import chem
from .constants import PUMP_DAMAGE_TEMP, PUMP_DRY_RUN_LIMIT

# Hourly demand multipliers for a UK-style diurnal curve (morning and evening peaks).
_RAW_PROFILE = [0.55, 0.50, 0.48, 0.47, 0.50, 0.65, 1.00, 1.45, 1.60, 1.40, 1.20, 1.10,
                1.05, 1.00, 0.95, 0.95, 1.00, 1.15, 1.30, 1.40, 1.30, 1.10, 0.85, 0.65]
_MEAN = sum(_RAW_PROFILE) / len(_RAW_PROFILE)
DEMAND_PROFILE = [x / _MEAN for x in _RAW_PROFILE]


# Pre-generated standard normal noise shared by all plants. Drawing from a table is
# several times faster than random.gauss in the inner loop and stays deterministic.
_NOISE_RNG = random.Random(20210205)
NOISE = [_NOISE_RNG.gauss(0.0, 1.0) for _ in range(1 << 18)]
_MASK = (1 << 18) - 1


class NoiseStream:
    """Deterministic gaussian stream: walks the shared table from a seed-dependent offset."""

    def __init__(self, seed: int):
        self.i = (seed * 104729) & _MASK

    def gauss(self, mu: float, sigma: float) -> float:
        self.i = (self.i + 1) & _MASK
        return mu + sigma * NOISE[self.i]


def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


@dataclass
class PlantParams:
    """Plant sizing and chemistry. Units: m, m2, m3/h, s, g/L, mg/L."""
    raw_area: float = 60.0
    raw_height: float = 5.0
    res_area: float = 60.0
    res_height: float = 4.0
    intake_capacity: float = 400.0
    filter_qmax: float = 400.0          # flow at 100 % open and filter_href head
    filter_href: float = 3.0
    shutoff_head_bar: float = 4.6       # distribution pump head at full speed, zero flow
    network_k_bar: float = 1.4          # network friction loss at 300 m3/h
    static_pressure: float = 0.2        # pressure with the pump stopped
    pressure_tau: float = 15.0
    pump_tau: float = 5.0
    valve_tau: float = 5.0
    filter_tau: float = 600.0
    contact_delay: float = 300.0        # transport delay dosing point -> analysers / reservoir
    sample_tau: float = 60.0            # analyser sample line mixing lag
    cl_strength: float = 125.0          # NaOCl 12.5 % (g/L available chlorine)
    naoh_strength: float = 320.0        # NaOH 25 % w/w (g/L)
    coag_strength: float = 480.0        # liquid aluminium sulphate product (g/L)
    cl_pump_max: float = 20.0           # L/h
    naoh_pump_max: float = 250.0
    coag_pump_max: float = 40.0
    cl_decay_per_h: float = 0.03        # bulk decay in the reservoir
    raw_alk: float = 2.58e-3            # eq/L (129 mg/L as CaCO3)
    ct: float = 5.0e-3                  # mol/L total inorganic carbon
    alk_per_coag: float = 1.0e-5        # eq/L consumed per mg/L alum
    sodium_base: float = 20.0
    demand_base: float = 180.0          # mean demand m3/h (about 4.3 ML/d)


@dataclass
class Actuators:
    """Commands that reach the field devices (after the PLC and the SIS)."""
    p101_run: bool = False
    fcv101_pos: float = 45.0      # % open
    p201_run: bool = True
    p201_speed: float = 0.85      # 0..1
    xv201_open: bool = True
    coag_rate: float = 0.0        # L/h
    cl_rate: float = 0.0
    naoh_rate: float = 0.0


class Plant:
    """Ground-truth process state and dynamics."""

    def __init__(self, seed: int = 1, start_hour: float = 6.0, dt: float = 0.5,
                 params: PlantParams | None = None):
        self.p = params or PlantParams()
        self.dt = dt
        self.start_hour = start_hour
        self.rng_proc = random.Random(seed * 7919 + 1)
        self.rng_noise = NoiseStream(seed * 2 + 1)
        self.rng_sis = NoiseStream(seed * 2 + 2 + (1 << 17))
        self.t = 0.0
        # Disturbances: optional storm on raw turbidity, chosen from the seed.
        r = self.rng_proc
        self.storm_at = r.uniform(4 * 3600, 20 * 3600) if r.random() < 0.6 else None
        self.storm_peak = r.uniform(10, 22)
        self.demand_noise = 0.0
        self._init_state()

    # ------------------------------------------------------------------ state
    def _init_state(self) -> None:
        p = self.p
        self.raw_level = 3.0
        self.res_level = 2.5
        self.q_in = 0.0
        self.valve = 45.0
        self.q_f = 180.0
        self.q_out = 180.0
        self.demand = 180.0
        self.pressure = 3.0
        self.p201_speed = 0.85
        self.filt_turb = 0.15
        self.raw_turb = 6.0
        self.p101_temp = 30.0
        self.p201_temp = 50.0
        self.p201_dry_s = 0.0
        self.p201_damaged = False
        self.p201_cav = 0.0
        self.p201_dry = False
        self.p201_running = True
        self.p101_running = False
        self.xv201_open = True
        self.raw_spill = 0.0
        self.res_spill = 0.0
        self.raw_overflowing = False
        self.res_overflowing = False
        self.coag_dose = 22.0
        self.cl_dose = 1.5
        self.naoh_dose = 100.0
        self.rates = (10.0, 2.4, 60.0)
        alk0 = p.raw_alk - 22.0 * p.alk_per_coag + 100.0 / 40000.0
        na0 = p.sodium_base + 100.0 * 0.575 + 1.5 * 0.324
        n = max(1, int(round(p.contact_delay / self.dt)))
        self.dl = [(1.0, alk0, na0, 0.15)] * n
        self.dl_idx = 0
        self.s_cl, self.s_alk = 1.0, alk0
        self.res_cl, self.res_alk, self.res_na, self.res_turb = 0.97, alk0, na0, 0.15
        self._ph_contact = chem.ph_from(alk0, p.ct, 7.8)
        self._ph_res = self._ph_contact

    # ---------------------------------------------------------- disturbances
    def clock_hours(self, t: float | None = None) -> float:
        return (self.start_hour + (self.t if t is None else t) / 3600.0) % 24.0

    def demand_at(self, t: float) -> float:
        """Diurnal demand (m3/h) by linear interpolation of the hourly profile."""
        h = self.clock_hours(t)
        i = int(h)
        frac = h - i
        m = DEMAND_PROFILE[i] * (1 - frac) + DEMAND_PROFILE[(i + 1) % 24] * frac
        return self.p.demand_base * m

    def raw_turbidity_at(self, t: float) -> float:
        base = 6.0 + 1.5 * math.sin(2 * math.pi * t / (30 * 3600))
        if self.storm_at is not None and t > self.storm_at:
            dt_h = (t - self.storm_at) / 3600.0
            rise = min(1.0, dt_h / 1.0)
            base += self.storm_peak * rise * math.exp(-max(0.0, dt_h - 1.0) / 4.0)
        return base

    def raw_alk_at(self, t: float) -> float:
        return self.p.raw_alk * (1 + 0.02 * math.sin(2 * math.pi * t / (40 * 3600)))

    # ------------------------------------------------------------------ step
    def step(self, a: Actuators) -> None:
        """Advance the physics by one tick using the given actuator commands."""
        p, dt = self.p, self.dt
        hours = dt / 3600.0
        self.t += dt
        t = self.t

        # Disturbances (process RNG only)
        self.demand_noise = 0.995 * self.demand_noise + self.rng_proc.gauss(0, 0.002)
        demand = self.demand_at(t) * (1 + clamp(self.demand_noise, -0.1, 0.1))
        self.demand = demand
        raw_turb = self.raw_turb = self.raw_turbidity_at(t)

        # Intake pump: fixed speed, first-order flow ramp
        self.p101_running = bool(a.p101_run)
        q_target = p.intake_capacity if a.p101_run else 0.0
        self.q_in += (q_target - self.q_in) * min(1.0, dt / p.pump_tau)
        t_target = 30.0 + 15.0 * self.q_in / p.intake_capacity if a.p101_run else 15.0
        self.p101_temp += (t_target - self.p101_temp) * min(1.0, dt / 600.0)

        # Filter feed valve and gravity flow out of the raw tank
        self.valve += (clamp(a.fcv101_pos, 0, 100) - self.valve) * min(1.0, dt / p.valve_tau)
        head = max(self.raw_level - 0.05, 0.0)
        q_f = p.filter_qmax * self.valve / 100.0 * math.sqrt(head / p.filter_href)
        q_f = min(q_f, self.q_in + self.raw_level * p.raw_area / hours)
        self.q_f = q_f

        # Raw tank mass balance with overflow weir at the top
        v = self.raw_level * p.raw_area + (self.q_in - q_f) * hours
        vmax = p.raw_height * p.raw_area
        self.raw_overflowing = v > vmax
        if self.raw_overflowing:
            self.raw_spill += v - vmax
            v = vmax
        self.raw_level = max(v, 0.0) / p.raw_area

        # Coagulation + filtration: removal efficiency depends on dose vs optimum
        qd = max(q_f, 5.0)  # dosing into stagnant water is capped, not infinite
        coag_rate = clamp(a.coag_rate, 0, p.coag_pump_max)
        cl_rate = clamp(a.cl_rate, 0, p.cl_pump_max)
        naoh_rate = clamp(a.naoh_rate, 0, p.naoh_pump_max)
        self.rates = (coag_rate, cl_rate, naoh_rate)
        coag_dose = coag_rate * p.coag_strength / qd
        ratio = min(1.0, coag_dose / (10.0 + 1.2 * raw_turb))
        eff = 0.6 + 0.385 * ratio ** 1.5
        target_turb = 0.05 + raw_turb * (1 - eff)
        self.filt_turb += (target_turb - self.filt_turb) * min(1.0, dt / p.filter_tau)

        # Chemical dosing at the head of the contact pipe
        cl_dose = cl_rate * p.cl_strength / qd
        naoh_dose = naoh_rate * p.naoh_strength / qd
        self.coag_dose, self.cl_dose, self.naoh_dose = coag_dose, cl_dose, naoh_dose
        cl_res = max(0.0, cl_dose - (0.5 + 0.1 * self.filt_turb))
        alk = self.raw_alk_at(t) - coag_dose * p.alk_per_coag + naoh_dose / 40000.0
        na = p.sodium_base + naoh_dose * 0.575 + cl_dose * 0.324

        # Transport delay (plug flow, fixed time) then analyser sample lag
        i = self.dl_idx
        c_in, alk_in, na_in, turb_in = self.dl[i]
        self.dl[i] = (cl_res, alk, na, self.filt_turb)
        self.dl_idx = (i + 1) % len(self.dl)
        k = min(1.0, dt / p.sample_tau)
        self.s_cl += (c_in - self.s_cl) * k
        self.s_alk += (alk_in - self.s_alk) * k

        # Distribution pump, cavitation, dry running and network pressure
        self._distribution(a, demand, dt)

        # Clear water reservoir: volume balance + completely mixed concentrations
        v = self.res_level * p.res_area
        out_vol = min(self.q_out * hours, v)
        in_vol = q_f * hours
        v_new = v - out_vol + in_vol
        keep = v - out_vol
        denom = max(v_new, 0.5)
        decay = math.exp(-p.cl_decay_per_h * hours)
        self.res_cl = (self.res_cl * keep + c_in * in_vol) / denom * decay
        self.res_alk = (self.res_alk * keep + alk_in * in_vol) / denom
        self.res_na = (self.res_na * keep + na_in * in_vol) / denom
        self.res_turb = (self.res_turb * keep + turb_in * in_vol) / denom
        vmax = p.res_height * p.res_area
        self.res_overflowing = v_new > vmax
        if self.res_overflowing:
            self.res_spill += v_new - vmax
            v_new = vmax
        self.res_level = max(v_new, 0.0) / p.res_area

        self._ph_contact = chem.ph_from(self.s_alk, p.ct, self._ph_contact)
        self._ph_res = chem.ph_from(self.res_alk, p.ct, self._ph_res)

    def _distribution(self, a: Actuators, demand: float, dt: float) -> None:
        p = self.p
        run = bool(a.p201_run) and not self.p201_damaged
        self.p201_running = run
        self.xv201_open = bool(a.xv201_open)
        self.p201_speed += ((clamp(a.p201_speed, 0, 1) if run else 0.0) - self.p201_speed) * min(1.0, dt / p.pump_tau)
        s = self.p201_speed
        lvl = self.res_level
        cav = clamp((0.6 - lvl) / 0.4, 0.0, 1.0) if run else 0.0
        dry = run and lvl < 0.2
        self.p201_cav, self.p201_dry = cav, dry
        pumping = run and self.xv201_open and not dry
        if pumping:
            p_target = p.shutoff_head_bar * s * s * (1 - 0.7 * cav) - p.network_k_bar * (demand / 300.0) ** 2
            p_target = max(p.static_pressure, p_target)
        else:
            p_target = p.static_pressure
        self.pressure += (p_target - self.pressure) * min(1.0, dt / p.pressure_tau)
        if pumping:
            q = demand * min(1.0, math.sqrt(max(self.pressure, 0.0) / 1.5))
            q = min(q, lvl * p.res_area / (dt / 3600.0))
        else:
            q = 0.0
        self.q_out = q

        load = q / 300.0
        if run and dry:
            target, tau = 160.0, 60.0
            self.p201_dry_s += dt
        elif run:
            target, tau = 38.0 + 22.0 * load + 15.0 * cav, 600.0
        else:
            target, tau = 15.0, 900.0
        self.p201_temp += (target - self.p201_temp) * min(1.0, dt / tau)
        if self.p201_temp >= PUMP_DAMAGE_TEMP or self.p201_dry_s >= PUMP_DRY_RUN_LIMIT:
            self.p201_damaged = True

    # --------------------------------------------------------------- outputs
    @property
    def ph_contact(self) -> float:
        return self._ph_contact

    @property
    def ph_final(self) -> float:
        return self._ph_res

    def sensors(self) -> dict:
        """Field instrument readings seen by the PLC (true value + noise)."""
        g = self.rng_noise.gauss
        p201_load = self.q_out / 300.0
        if self.p201_running:
            cur = 60.0 * (0.35 * self.p201_speed ** 2 if self.p201_dry else 0.3 + 0.7 * p201_load)
            cur *= 1 + 0.15 * self.p201_cav * g(0, 1)
        else:
            cur = 0.0
        return {
            "LT101": self.raw_level + g(0, 0.003),
            "LT201": self.res_level + g(0, 0.003),
            "FT101": max(0.0, self.q_in * (1 + g(0, 0.005))),
            "FT102": max(0.0, self.q_f * (1 + g(0, 0.005))),
            "FT201": max(0.0, self.q_out * (1 + g(0, 0.005))),
            "AIT101": max(0.0, self.raw_turb * (1 + g(0, 0.02))),
            "AIT102": max(0.0, self.filt_turb * (1 + g(0, 0.02))),
            "AIT301": max(0.0, self.s_cl + g(0, 0.01)),
            "AIT302": self._ph_contact + g(0, 0.01),
            "AIT303": max(0.0, self.res_cl + g(0, 0.01)),
            "AIT304": self._ph_res + g(0, 0.01),
            "PT201": max(0.0, self.pressure + g(0, 0.01)),
            "P101_I": (45.0 * (0.85 + 0.15 * self.q_in / self.p.intake_capacity) + g(0, 0.3)) if self.p101_running else 0.0,
            "P101_T": self.p101_temp + g(0, 0.2),
            "P201_I": max(0.0, cur + (g(0, 0.3) if self.p201_running else 0.0)),
            "P201_T": self.p201_temp + g(0, 0.2),
            "P201_SPD": self.p201_speed * 100.0,
            "P201_VIB": 2.0 + 10.0 * self.p201_cav + (8.0 if self.p201_dry else 0.0) + abs(g(0, 0.2)),
            "FCV101_POS": self.valve,
            "P101_RUN": self.p101_running,
            "P201_RUN": self.p201_running,
            "XV201_OPEN": self.xv201_open,
            "P201_CAV": self.p201_cav > 0.05,
            "P201_DRY": self.p201_dry,
            "P201_FAULT": self.p201_damaged,
            "DP101": self.rates[0], "DP301": self.rates[1], "DP302": self.rates[2],
        }

    def sis_sensors(self) -> dict:
        """Independent SIS instruments: level switches and duplicate analysers."""
        g = self.rng_sis.gauss
        return {
            "LSHH901": self.raw_level >= 4.6,
            "LSLL902": self.res_level <= 0.4,
            "AIT901": max(0.0, self.res_cl + g(0, 0.01)),
            "AIT902": self._ph_res + g(0, 0.01),
        }

    def truth(self) -> dict:
        """Ground truth used by the consequence model and the HUD 'truth' view."""
        return {
            "t": self.t, "clock_h": self.clock_hours(),
            "raw_level": self.raw_level, "res_level": self.res_level,
            "q_in": self.q_in, "q_f": self.q_f, "q_out": self.q_out, "demand": self.demand,
            "pressure": self.pressure, "raw_turb": self.raw_turb, "filt_turb": self.filt_turb,
            "final_turb": self.res_turb,
            "contact_cl": self.s_cl, "final_cl": self.res_cl,
            "contact_ph": self._ph_contact, "final_ph": self._ph_res, "sodium": self.res_na,
            "cl_dose": self.cl_dose, "naoh_dose": self.naoh_dose, "coag_dose": self.coag_dose,
            "p201_temp": self.p201_temp, "p201_damaged": self.p201_damaged,
            "p201_dry": self.p201_dry, "p201_cav": self.p201_cav,
            "raw_spill": self.raw_spill, "res_spill": self.res_spill,
        }
