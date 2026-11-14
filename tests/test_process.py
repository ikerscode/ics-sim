"""Physics sanity: chemistry, mass balance, steady state, determinism."""

from icssim import chem
from icssim.process import Actuators, Plant


def test_ph_solver_matches_design_points():
    alk_post_coag = 2.58e-3 - 22 * 1e-5
    assert 7.6 < chem.ph_from(alk_post_coag + 100 / 40000, 5e-3) < 8.0     # normal 100 ppm NaOH
    assert chem.ph_from(alk_post_coag, 5e-3) < 6.5                         # no caustic: acidic
    assert chem.ph_from(alk_post_coag + 11100 / 40000, 5e-3) > 13.0        # Oldsmar setpoint, if deliverable
    for ph in (5.0, 7.0, 9.0, 11.0):
        assert abs(chem.ph_from(chem.alk_from(ph, 5e-3), 5e-3, 7.0) - ph) < 1e-4


def test_raw_tank_mass_balance():
    p = Plant(seed=3)
    a = Actuators(p101_run=True, fcv101_pos=40.0, p201_run=True, p201_speed=0.85)
    v0 = p.raw_level * p.p.raw_area
    net = 0.0
    for _ in range(2400):  # 20 min
        p.step(a)
        net += (p.q_in - p.q_f) * p.dt / 3600.0
    v1 = p.raw_level * p.p.raw_area
    assert abs((v1 - v0) - (net - p.raw_spill)) < 1e-6


def test_reservoir_mass_balance_and_overflow_accounting():
    p = Plant(seed=4)
    a = Actuators(p101_run=True, fcv101_pos=100.0, p201_run=False, xv201_open=False)  # fill with no outflow
    v0 = p.res_level * p.p.res_area
    inflow = 0.0
    for _ in range(7200):  # 1 h
        p.step(a)
        inflow += p.q_f * p.dt / 3600.0
    v1 = p.res_level * p.p.res_area
    assert p.res_spill > 0  # it overflowed
    assert abs((v1 + p.res_spill - v0) - inflow) < 1e-6


def test_steady_state_with_constant_dosing():
    p = Plant(seed=5)
    a = Actuators(p101_run=False, fcv101_pos=0.0, p201_run=False, xv201_open=False, cl_rate=0, naoh_rate=0)
    for _ in range(3600):
        p.step(a)
    lvl = p.raw_level
    for _ in range(600):
        p.step(a)
    assert abs(p.raw_level - lvl) < 1e-9          # no flows -> no level change
    assert p.pressure < 0.3                       # pump stopped -> static pressure only


def test_dry_run_damages_pump():
    p = Plant(seed=6)
    p.res_level, p.valve = 0.15, 0.0
    a = Actuators(p101_run=False, fcv101_pos=0.0, p201_run=True, p201_speed=1.0)
    for _ in range(200):
        p.step(a)
    assert p.p201_damaged and p.p201_dry_s >= 25  # seal fails, pump trips out


def test_deterministic_for_seed():
    def trace(seed):
        p = Plant(seed=seed)
        a = Actuators(p101_run=True, fcv101_pos=45.0, cl_rate=2.4, naoh_rate=60.0, coag_rate=9.0)
        out = []
        for _ in range(500):
            p.step(a)
            out.append(p.sensors()["AIT301"])
        return out
    assert trace(7) == trace(7)
    assert trace(7) != trace(8)
