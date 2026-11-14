"""Firewall/DPI and Purdue segmentation decisions."""

from icssim import modbus as mb
from icssim.network import EWS_IP, HMI_IP, Firewall, zone_of
from icssim.registers import HR
from icssim.sim import Simulation


def info(pdu):
    return mb.describe(pdu)


def test_zones():
    assert zone_of("192.168.10.37") == "enterprise"
    assert zone_of("10.10.2.10") == "supervisory"
    assert zone_of("8.8.8.8") == "unknown"


def test_segmentation_blocks_it_zone_and_non_safety_sis_access():
    fw = Firewall()
    assert fw.check_segmentation("192.168.10.37", 1)
    assert fw.check_segmentation(HMI_IP, 1) is None
    assert fw.check_segmentation(EWS_IP, 2)
    assert fw.check_segmentation("10.10.4.10", 2) is None


def test_dpi_allowlist_fc_filter_and_write_targets():
    fw = Firewall()
    assert fw.check_dpi("10.10.2.66", 1, info(mb.req_read(3, 0, 1)), 0)[0] == 0
    assert "function code 90" in fw.check_dpi(HMI_IP, 1, info(bytes([90, 0x10])), 0)[1]
    assert fw.check_dpi(HMI_IP, 1, info(mb.req_write_register(HR.CL_SP, 120)), 0) == (1, None)
    n, why = fw.check_dpi(HMI_IP, 1, info(mb.req_write_register(HR.CL_HI_ALM, 900)), 0)
    assert n == 0 and "not allowed" in why
    assert fw.check_dpi("10.10.3.5", 1, info(mb.req_write_register(0, 1)), 0)[0] == 0


def test_rate_limit():
    fw = Firewall()
    n, why = fw.check_dpi(HMI_IP, 1, info(mb.req_read(4, 0, 10)), 0.0, count=1000)
    assert n == 40 and "rate limit" in why
    n, _ = fw.check_dpi(HMI_IP, 1, info(mb.req_read(4, 0, 10)), 1.0, count=1000)
    assert n == 20


def test_blocked_requests_are_logged_and_alerted():
    sim = Simulation(seed=1, mitigations=["firewall"])
    sim.run_for(2)
    reply = sim.request("192.168.10.37", mb.build_adu(1, 1, mb.req_write_register(HR.CL_SP, 600)))
    assert reply is None and sim.plc.bank.hr[HR.CL_SP] == 100
    assert sim.events.modbus[-1]["result"] == "blocked"
    assert sim.events.alerts[-1]["source"] == "firewall"
