"""Modbus/TCP server over a real socket: every function code and the exception paths."""

import asyncio
import json
import threading

import pytest

from icssim import modbus as mb
from icssim.network import LAB_CLIENT_IP
from icssim.registers import C, HR, IR
from icssim.sim import Simulation


@pytest.fixture(scope="module")
def server():
    sim = Simulation(seed=1, mitigations=["sis"])
    sim.run_for(10)
    loop = asyncio.new_event_loop()
    srv = loop.run_until_complete(mb.serve_tcp(lambda ip, adu: sim.request(LAB_CLIENT_IP, adu, transport="tcp"), "127.0.0.1", 0))
    port = srv.sockets[0].getsockname()[1]
    th = threading.Thread(target=loop.run_forever, daemon=True)
    th.start()
    yield sim, port
    loop.call_soon_threadsafe(srv.close)
    loop.call_soon_threadsafe(loop.stop)


@pytest.fixture
def client(server):
    sim, port = server
    with mb.ModbusTcpClient("127.0.0.1", port) as c:
        yield sim, c


def test_fc1_fc5_fc15_coils(client):
    sim, c = client
    assert c.read_coils(0, 11)[C.PLANT_ENABLE] == 1
    c.write_coil(C.P101_MAN_RUN, True)
    assert sim.plc.bank.coils[C.P101_MAN_RUN] == 1
    c.write_coils(C.P101_MAN_RUN, [0])
    assert c.read_coils(C.P101_MAN_RUN, 1) == [0]


def test_fc2_discrete_inputs(client):
    _, c = client
    di = c.read_discrete_inputs(0, 15)
    assert len(di) == 15 and di[1] == 1  # P-201 running


def test_fc3_fc6_fc16_holding(client):
    sim, c = client
    assert c.read_holding(HR.CL_SP, 1) == [100]
    c.write_register(HR.PRESS_SP, 290)
    assert sim.plc.bank.hr[HR.PRESS_SP] == 290
    c.write_registers(HR.PRESS_SP, [300, 780])
    assert c.read_holding(HR.PRESS_SP, 1) == [300]


def test_fc4_input_registers(client):
    _, c = client
    ir = c.read_input(0, 30)
    assert 100 < ir[IR.LT101] < 450 and 700 < ir[IR.AIT304] < 860


def test_fc17_and_fc43_identification(client):
    _, c = client
    assert b"PLC-01" in c.raw(bytes([17]))
    assert b"seclab" in c.raw(bytes([43, 0x0E, 0x01, 0x00]))


def test_fc90_program_info(client):
    sim, c = client
    resp = c.raw(bytes([90, 0x02]))
    assert json.loads(resp[2:])["name"] == "WTW-MAIN"


def test_exception_illegal_function(client):
    _, c = client
    with pytest.raises(mb.ModbusError) as e:
        c.request(bytes([0x08, 0, 0, 0, 0]))
    assert e.value.code == mb.ILLEGAL_FUNCTION


def test_exception_illegal_address(client):
    _, c = client
    with pytest.raises(mb.ModbusError) as e:
        c.read_holding(30, 10)
    assert e.value.code == mb.ILLEGAL_ADDRESS


def test_exception_illegal_value(client):
    _, c = client
    with pytest.raises(mb.ModbusError) as e:
        c.read_holding(0, 0)
    assert e.value.code == mb.ILLEGAL_VALUE
    with pytest.raises(mb.ModbusError) as e:
        c.request(mb.req_write_coil(0, True)[:3] + b"\x12\x34")  # coil value must be FF00/0000
    assert e.value.code == mb.ILLEGAL_VALUE
    bad16 = bytes([16, 0, 8, 0, 2, 3, 0, 1, 0])  # byte count does not match quantity
    with pytest.raises(mb.ModbusError) as e:
        c.request(bad16)
    assert e.value.code == mb.ILLEGAL_VALUE


def test_exception_gateway_target_and_sis_unit(client):
    _, c = client
    with pytest.raises(mb.ModbusError) as e:
        c.read_coils(0, 1, unit=9)
    assert e.value.code == mb.GATEWAY_TARGET
    assert c.read_discrete_inputs(0, 8, unit=2)[7] == 0  # SIS not bypassed


def test_eng_limits_exception_over_tcp(client):
    sim, c = client
    sim.plc.eng_limits = True
    try:
        with pytest.raises(mb.ModbusError) as e:
            c.write_register(HR.CL_SP, 600)
        assert e.value.code == mb.ILLEGAL_VALUE
    finally:
        sim.plc.eng_limits = False
