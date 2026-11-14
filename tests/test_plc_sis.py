"""PLC control keeps the plant in range; SIS trips to the safe state."""

from icssim.registers import C, HR
from icssim.sim import Simulation


def test_baseline_control_holds_levels_and_chemistry():
    sim = Simulation(seed=2, mitigations=["sis", "detector", "integrity", "operator"])
    lo = {"raw": 9, "res": 9, "cl": 9, "ph": 99}
    hi = {"raw": 0, "res": 0, "cl": 0, "ph": 0}
    for _ in range(6 * 60):  # 6 h, sampled each minute
        sim.run_for(60)
        p = sim.plant
        for k, v in (("raw", p.raw_level), ("res", p.res_level), ("cl", p.res_cl), ("ph", p.ph_final)):
            lo[k], hi[k] = min(lo[k], v), max(hi[k], v)
    assert 1.5 < lo["raw"] and hi["raw"] < 4.2
    assert 2.0 < lo["res"] and hi["res"] < 3.0
    assert 0.6 < lo["cl"] and hi["cl"] < 1.4
    assert 7.3 < lo["ph"] and hi["ph"] < 8.3
    m = sim.metrics.summary()
    assert m["hazards"] == [] and m["availability_pct"] == 100.0
    assert sim.events.alerts == []  # no false positives from SIS, detector, integrity or operator


def test_sis_trips_on_raw_tank_high_high():
    sim = Simulation(seed=1, mitigations=["sis"])
    sim.plc.bank.coils[C.P101_AUTO] = 0
    sim.plc.bank.coils[C.P101_MAN_RUN] = 1     # intake forced on
    sim.plc.bank.coils[C.FCV101_AUTO] = 0
    sim.plc.bank.hr[HR.FCV101_MAN_POS] = 0     # and the outlet closed
    sim.run_for(3600)
    assert sim.sis.tripped and "high-high" in sim.sis.cause
    assert not sim.plant.p101_running and not sim.plant.xv201_open
    assert sim.metrics.summary()["overflow_m3"] == 0.0


def test_no_sis_means_overflow():
    sim = Simulation(seed=1, mitigations=[])
    sim.plc.bank.coils[C.P101_AUTO] = 0
    sim.plc.bank.coils[C.P101_MAN_RUN] = 1
    sim.plc.bank.coils[C.FCV101_AUTO] = 0
    sim.plc.bank.hr[HR.FCV101_MAN_POS] = 0
    sim.run_for(3600)
    assert "tank_overflow" in sim.metrics.summary()["hazards"]


def test_sis_trips_on_chlorine_overdose_and_stops_dosing():
    sim = Simulation(seed=1, mitigations=["sis"])
    sim.plc.bank.coils[C.CL_AUTO] = 0
    sim.plc.bank.hr[HR.CL_MAN_RATE] = 2000     # 20 L/h, pump maximum
    sim.run_for(3 * 3600)
    assert sim.sis.tripped and "chlorine" in sim.sis.cause
    assert sim.plant.rates[1] == 0.0
    assert "chlorine_overdose" not in sim.metrics.summary()["hazards"]


def test_sis_bypass_inhibits_trip():
    sim = Simulation(seed=1, mitigations=["sis"])
    sim.sis.bank.coils[0] = 1
    sim.plc.bank.coils[C.CL_AUTO] = 0
    sim.plc.bank.hr[HR.CL_MAN_RATE] = 2000
    sim.run_for(3 * 3600)
    assert not sim.sis.holding_safe_state
    assert "chlorine_overdose" in sim.metrics.summary()["hazards"]


def test_engineering_limits_reject_out_of_range_write():
    from icssim import modbus as mb
    sim = Simulation(seed=1, mitigations=["eng_limits"])
    sim.run_for(2)
    reply = sim.request("10.10.2.10", mb.build_adu(1, 1, mb.req_write_register(HR.NAOH_SP, 11100)))
    assert reply[7] == 0x86 and reply[8] == mb.ILLEGAL_VALUE
    assert sim.plc.bank.hr[HR.NAOH_SP] == 100
    assert sim.events.alerts[-1]["source"] == "eng_limits"
