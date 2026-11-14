"""Containerised gateway: its rule engine must agree with the simulator's own policy code.

fwgate.PolicyEngine is a separate implementation that only sees the exported policy JSON,
so these tests compare it with network.Firewall.decide over many requests.
"""

import asyncio
import itertools
import struct

import pytest

from icssim import fwgate
from icssim import modbus as mb
from icssim import netmode
from icssim.network import DPI_POLICY, HOSTS, Firewall, export_policy
from icssim.registers import HR


def sim_fw(segmentation=True, dpi=True):
    fw = Firewall()
    fw.segmentation, fw.dpi = segmentation, dpi
    return fw


def corpus():
    """Many request PDUs: reads, writes to every kind of target, FC 17/43/90 and truncated ones."""
    pdus = [mb.req_read(fc, a, q) for fc in (1, 2, 3, 4) for a, q in ((0, 1), (0, 72), (20, 3))]
    pdus += [mb.req_write_register(a, 100) for a in (0, HR.CL_SP, HR.CL_HI_ALM, HR.NAOH_SP, 31)]
    pdus += [mb.req_write_coil(a, True) for a in range(0, 16, 3)]
    pdus += [mb.req_write_registers(HR.CL_SP, [100, 200]), mb.req_write_registers(0, [1] * 6),
             mb.req_write_coils(0, [1, 0, 1]), mb.req_write_coils(4, [1] * 12)]
    pdus += [bytes([17]), bytes([43, 14, 1, 0]), bytes([90, 1]), bytes([90, 2]), bytes([90, 0x10]) + b"{}", bytes([8, 0, 0])]
    pdus += [bytes([6, 0, 3]), bytes([3, 0]), bytes([16, 0, 0, 0, 4, 8, 0, 1]), bytes([15, 0, 0, 0, 20, 3, 1])]
    return pdus


SOURCES = list(HOSTS) + ["192.168.10.99", "172.16.0.20", "8.8.8.8", "10.10.1.254"]


@pytest.mark.parametrize("seg,dpi", [(True, True), (True, False), (False, True)])
def test_engine_matches_simulator_policy_on_every_request(seg, dpi):
    engine = fwgate.PolicyEngine(export_policy(), segmentation=seg, dpi=dpi)
    ref = sim_fw(seg, dpi)
    checked = 0
    # t advances slowly enough that the rate limiter never triggers here (tested below).
    for k, (src, unit, pdu) in enumerate(itertools.product(SOURCES, (0, 1, 2, 3), corpus())):
        t = k * 0.1
        mapped = 1 if unit in (0, 255) else unit
        allowed, layer, reason = ref.decide(src, mapped, mb.describe(pdu), t)
        got = engine.evaluate(src, unit, pdu, t)
        assert got == (allowed == 1, layer, reason), (src, unit, pdu.hex())
        checked += 1
    assert checked > 2000


def test_rate_limiter_matches_on_irregular_bursts():
    engine = fwgate.PolicyEngine(export_policy())
    ref = sim_fw()
    pdu = mb.req_read(4, 0, 10)
    times = [0.0] * 50 + [i * 0.01 for i in range(100)] + [3.0 + i * 0.07 for i in range(80)]
    decisions = []
    for t in times:
        a, layer, reason = ref.decide("10.10.2.10", 1, mb.describe(pdu), t)
        assert engine.evaluate("10.10.2.10", 1, pdu, t) == (a == 1, layer, reason)
        decisions.append(a)
    assert 0 < sum(decisions) < len(times)            # some allowed, some rate limited


def test_policy_export_covers_the_dpi_table():
    pol = export_policy()
    assert set(pol["dpi"]) == set(DPI_POLICY)
    assert pol["dpi"]["10.10.2.20"]["hr"] == "all" and pol["segment_allowed"]["2"] == ["operations", "safety"]


def test_simulator_dpi_drops_truncated_writes_instead_of_crashing():
    n, why = sim_fw(False, True).check_dpi("10.10.2.10", 1, mb.describe(bytes([6, 0, 3])), 0.0)
    assert n == 0 and why == "malformed request"


def test_proxy_v1_parsing():
    assert mb.parse_proxy_v1(b"PROXY TCP4 10.10.2.10 10.10.1.10 40000 5020\r\n") == "10.10.2.10"
    assert mb.parse_proxy_v1(b"PROXY UNKNOWN\r\n") is None
    for bad in (b"PROXY TCP4 10.10.2.10 10.10.1.10 40000\r\n", b"PROXY TCP4 x 10.10.1.10 1 2\r\n",
                b"GET / HTTP/1.1\r\n", b"PROXY TCP4 10.10.2.10 10.10.1.10 1 99999\r\n", b"PROXY TCP4 1.1.1.1 2.2.2.2 1 2"):
        with pytest.raises(ValueError):
            mb.parse_proxy_v1(bad)


def test_reevaluate_and_match_items_on_a_synthetic_log():
    plan = {"scenario": "x", "items": [
        {"i": 0, "src": "192.168.10.37", "service": "labclient", "kind": "attack", "count": 1,
         "adu": mb.build_adu(0, 1, mb.req_write_register(HR.CL_SP, 600)).hex(),
         "sim": {"allowed": False, "allowed_n": 0, "layer": "segmentation",
                 "reason": "zone enterprise may not reach unit 1 (Purdue policy)"}},
        {"i": 1, "src": "10.10.2.10", "service": "hmi", "kind": "hmi_poll", "count": 1,
         "adu": mb.build_adu(0, 1, mb.req_read(4, 0, 72)).hex(),
         "sim": {"allowed": True, "allowed_n": 1, "layer": None, "reason": None}}]}
    log = [
        {"t": 1.0, "src": "192.168.10.37", "sport": 5000, "tid": 1, "unit": 1, "pdu": mb.req_write_register(HR.CL_SP, 600).hex(),
         "decision": "block", "layer": "segmentation", "reason": "zone enterprise may not reach unit 1 (Purdue policy)"},
        {"t": 1.5, "src": "10.10.2.10", "sport": 6000, "tid": 1, "unit": 1, "pdu": mb.req_read(4, 0, 72).hex(),
         "decision": "allow", "layer": None, "reason": None},
    ]
    results = [{"i": 0, "src": "192.168.10.37", "sport": 5000, "tids": [1, 1], "replies": 0},
               {"i": 1, "src": "10.10.2.10", "sport": 6000, "tids": [1, 1], "replies": 1}]
    re_ = netmode.reevaluate(log)
    assert re_["agree"] == re_["checked"] == 2
    m = netmode.match_items(plan, results, log)
    assert m["agree"] == 2 and m["logged"] == 2 and m["client_consistent"] == 2
    log[0]["decision"], log[0]["layer"], log[0]["reason"] = "allow", None, None      # a gateway that got it wrong
    assert netmode.reevaluate(log)["agree"] == 1
    assert netmode.match_items(plan, results, log)["agree"] == 1


def test_gateway_forwards_allowed_requests_with_proxy_header_and_drops_blocked():
    """End to end on loopback: client -> gateway -> PLC listener that trusts the gateway."""
    policy = export_policy()
    policy["zones"].insert(0, {"key": "supervisory", "cidr": "127.0.0.0/8"})   # loopback plays the HMI LAN
    policy["dpi"]["127.0.0.1"] = policy["dpi"]["10.10.2.10"]                   # with the HMI's DPI rule
    seen = []

    def plc(src, adu, proxied=False):
        seen.append((src, proxied))
        tid, unit, pdu = mb.parse_adu(adu)
        return mb.build_adu(tid, unit, bytes([pdu[0], 2, 0, 42]))

    class Sink:
        lines = []

        def write(self, s):
            self.lines.append(s)

        def flush(self):
            pass

    async def scenario():
        plc_srv = await mb.serve_tcp(plc, "127.0.0.1", 0, trusted_proxies={"127.0.0.1"})
        engine = fwgate.PolicyEngine(policy)
        gw = fwgate.Gateway(engine, plc_srv.sockets[0].getsockname()[:2], out=Sink())
        gw_srv = await asyncio.start_server(gw.client, "127.0.0.1", 0)
        r, w = await asyncio.open_connection(*gw_srv.sockets[0].getsockname()[:2])
        w.write(mb.build_adu(7, 1, mb.req_read(3, 0, 1)))                         # allowed
        await w.drain()
        reply = await asyncio.wait_for(r.readexactly(11), 3)
        w.write(mb.build_adu(8, 1, mb.req_write_register(HR.CL_HI_ALM, 900)))     # blocked: write target
        await w.drain()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(r.readexactly(7), 0.3)
        w.close()
        gw_srv.close()
        plc_srv.close()
        return reply

    reply = asyncio.run(scenario())
    assert struct.unpack(">H", reply[:2])[0] == 7 and reply[-2:] == b"\x00\x2a"
    assert seen == [("127.0.0.1", True)]                       # only the allowed request reached the PLC
    entries = netmode.parse_fw_log("".join(Sink.lines))
    assert [e["decision"] for e in entries] == ["allow", "block"]
    assert entries[1]["reason"] == "write to hr 14 not allowed for HMI"
