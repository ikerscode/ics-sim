"""Minimal Modbus/TCP implementation (server side, client side and a parser for DPI).

Written from the spec (Modbus Application Protocol v1.1b3 and Modbus Messaging on
TCP/IP v1.0b) instead of pulling in pymodbus, so the firewall can inspect the exact
bytes and the simulator can route requests through simulated network zones.

Supported function codes: 1, 2, 3, 4, 5, 6, 15, 16, 17 and 43/14, plus a
device-specific hook for extra codes (the PLC registers FC 90).
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Callable

ILLEGAL_FUNCTION = 0x01
ILLEGAL_ADDRESS = 0x02
ILLEGAL_VALUE = 0x03
DEVICE_FAILURE = 0x04
GATEWAY_PATH = 0x0A
GATEWAY_TARGET = 0x0B

EXC_NAMES = {1: "illegal function", 2: "illegal data address", 3: "illegal data value",
             4: "server device failure", 0x0A: "gateway path unavailable", 0x0B: "gateway target failed to respond"}
FC_NAMES = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
            5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils",
            16: "Write Multiple Registers", 17: "Report Server ID", 43: "Read Device Identification",
            90: "Engineering / program service"}
WRITE_FCS = {5, 6, 15, 16, 90}


class ModbusError(Exception):
    """A Modbus exception response (server side raise, client side receive)."""

    def __init__(self, code: int, msg: str = ""):
        super().__init__(msg or EXC_NAMES.get(code, f"exception {code}"))
        self.code = code


# ------------------------------------------------------------------ framing
def build_adu(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, unit & 0xFF) + pdu


def parse_adu(adu: bytes) -> tuple[int, int, bytes]:
    """Return (transaction id, unit id, pdu). Raises ValueError on a malformed frame."""
    if len(adu) < 8:
        raise ValueError("frame too short")
    tid, pid, length, unit = struct.unpack(">HHHB", adu[:7])
    if pid != 0 or length != len(adu) - 6 or length < 2:
        raise ValueError("bad MBAP header")
    return tid, unit, adu[7:]


def exception_pdu(fc: int, code: int) -> bytes:
    return bytes([fc | 0x80, code])


def pack_bits(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def unpack_bits(data: bytes, count: int) -> list[int]:
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]


# ------------------------------------------------------------ request build
def req_read(fc: int, addr: int, qty: int) -> bytes:
    return struct.pack(">BHH", fc, addr, qty)


def req_write_coil(addr: int, on: bool) -> bytes:
    return struct.pack(">BHH", 5, addr, 0xFF00 if on else 0x0000)


def req_write_register(addr: int, value: int) -> bytes:
    return struct.pack(">BHH", 6, addr, value & 0xFFFF)


def req_write_coils(addr: int, bits: list[int]) -> bytes:
    data = pack_bits(bits)
    return struct.pack(">BHHB", 15, addr, len(bits), len(data)) + data


def req_write_registers(addr: int, values: list[int]) -> bytes:
    return struct.pack(">BHHB", 16, addr, len(values), 2 * len(values)) + struct.pack(f">{len(values)}H", *[v & 0xFFFF for v in values])


def parse_response(req_pdu: bytes, resp_pdu: bytes):
    """Decode a response for the given request. Raises ModbusError on exception responses."""
    fc = req_pdu[0]
    if not resp_pdu:
        raise ValueError("empty response")
    if resp_pdu[0] == fc | 0x80:
        raise ModbusError(resp_pdu[1])
    if resp_pdu[0] != fc:
        raise ValueError("function code mismatch")
    if fc in (1, 2):
        qty = struct.unpack(">H", req_pdu[3:5])[0]
        return unpack_bits(resp_pdu[2:2 + resp_pdu[1]], qty)
    if fc in (3, 4):
        n = resp_pdu[1] // 2
        return list(struct.unpack(f">{n}H", resp_pdu[2:2 + 2 * n]))
    if fc in (5, 6, 15, 16):
        return struct.unpack(">HH", resp_pdu[1:5])
    return resp_pdu[1:]


# ------------------------------------------------------------- DPI decoding
def describe(pdu: bytes) -> dict:
    """Decode the interesting fields of a request PDU without executing it (used by the firewall/log)."""
    info = {"fc": pdu[0] if pdu else 0, "addr": None, "qty": None, "values": None, "kind": None}
    fc = info["fc"]
    try:
        if fc in (1, 2, 3, 4):
            info["addr"], info["qty"] = struct.unpack(">HH", pdu[1:5])
            info["kind"] = {1: "coil", 2: "di", 3: "hr", 4: "ir"}[fc]
        elif fc == 5:
            a, v = struct.unpack(">HH", pdu[1:5])
            info.update(addr=a, qty=1, values=[1 if v == 0xFF00 else 0], kind="coil")
        elif fc == 6:
            a, v = struct.unpack(">HH", pdu[1:5])
            info.update(addr=a, qty=1, values=[v], kind="hr")
        elif fc == 15:
            a, q = struct.unpack(">HH", pdu[1:5])
            info.update(addr=a, qty=q, values=unpack_bits(pdu[6:], q), kind="coil")
        elif fc == 16:
            a, q = struct.unpack(">HH", pdu[1:5])
            info.update(addr=a, qty=q, values=list(struct.unpack(f">{q}H", pdu[6:6 + 2 * q])), kind="hr")
        elif fc == 90 and len(pdu) > 1:
            info["sub"] = pdu[1]
    except (struct.error, IndexError):
        info["malformed"] = True
    info["write"] = fc in WRITE_FCS and not (fc == 90 and info.get("sub") in (1, 2))
    return info


# ------------------------------------------------------------------ server
class DataBank:
    """The four Modbus tables of one device plus optional hooks.

    validate(kind, addr, values) may raise ModbusError before a write is applied
    (the PLC uses it for engineering range limits). after_write(kind, addr, values)
    runs after a successful write. extra maps function code -> handler(pdu) -> pdu.
    """

    def __init__(self, sizes: dict, name: str = "device", ident: dict | None = None):
        self.coils = [0] * sizes["coil"]
        self.di = [0] * sizes["di"]
        self.ir = [0] * sizes["ir"]
        self.hr = [0] * sizes["hr"]
        self.name = name
        self.ident = ident or {"vendor": "seclab", "product": name, "revision": "0.1.0"}
        self.validate: Callable | None = None
        self.after_write: Callable | None = None
        self.extra: dict[int, Callable[[bytes], bytes]] = {}
        self.before_read: Callable | None = None   # lets a device refresh its tables lazily

    def table(self, kind: str) -> list[int]:
        return {"coil": self.coils, "di": self.di, "ir": self.ir, "hr": self.hr}[kind]


def _read_bits(table, pdu, fc):
    if len(pdu) != 5:
        raise ModbusError(ILLEGAL_VALUE)
    addr, qty = struct.unpack(">HH", pdu[1:5])
    if not 1 <= qty <= 2000:
        raise ModbusError(ILLEGAL_VALUE)
    if addr + qty > len(table):
        raise ModbusError(ILLEGAL_ADDRESS)
    data = pack_bits(table[addr:addr + qty])
    return bytes([fc, len(data)]) + data


def _read_regs(table, pdu, fc):
    if len(pdu) != 5:
        raise ModbusError(ILLEGAL_VALUE)
    addr, qty = struct.unpack(">HH", pdu[1:5])
    if not 1 <= qty <= 125:
        raise ModbusError(ILLEGAL_VALUE)
    if addr + qty > len(table):
        raise ModbusError(ILLEGAL_ADDRESS)
    return bytes([fc, 2 * qty]) + struct.pack(f">{qty}H", *table[addr:addr + qty])


def _write(bank: DataBank, kind: str, addr: int, values: list[int]) -> None:
    table = bank.table(kind)
    if addr + len(values) > len(table):
        raise ModbusError(ILLEGAL_ADDRESS)
    if bank.validate:
        bank.validate(kind, addr, values)
    table[addr:addr + len(values)] = values
    if bank.after_write:
        bank.after_write(kind, addr, values)


def handle_pdu(bank: DataBank, pdu: bytes) -> bytes:
    """Execute one request PDU against a DataBank and return the response PDU."""
    if not pdu:
        return exception_pdu(0, ILLEGAL_FUNCTION)
    fc = pdu[0]
    if bank.before_read is not None:
        bank.before_read()
    try:
        if fc in (1, 2):
            return _read_bits(bank.coils if fc == 1 else bank.di, pdu, fc)
        if fc in (3, 4):
            return _read_regs(bank.hr if fc == 3 else bank.ir, pdu, fc)
        if fc == 5:
            if len(pdu) != 5:
                raise ModbusError(ILLEGAL_VALUE)
            addr, val = struct.unpack(">HH", pdu[1:5])
            if val not in (0xFF00, 0x0000):
                raise ModbusError(ILLEGAL_VALUE)
            _write(bank, "coil", addr, [1 if val == 0xFF00 else 0])
            return pdu
        if fc == 6:
            if len(pdu) != 5:
                raise ModbusError(ILLEGAL_VALUE)
            addr, val = struct.unpack(">HH", pdu[1:5])
            _write(bank, "hr", addr, [val])
            return pdu
        if fc == 15:
            if len(pdu) < 6:
                raise ModbusError(ILLEGAL_VALUE)
            addr, qty, nbytes = struct.unpack(">HHB", pdu[1:6])
            if not 1 <= qty <= 1968 or nbytes != (qty + 7) // 8 or len(pdu) != 6 + nbytes:
                raise ModbusError(ILLEGAL_VALUE)
            _write(bank, "coil", addr, unpack_bits(pdu[6:], qty))
            return pdu[:5]
        if fc == 16:
            if len(pdu) < 6:
                raise ModbusError(ILLEGAL_VALUE)
            addr, qty, nbytes = struct.unpack(">HHB", pdu[1:6])
            if not 1 <= qty <= 123 or nbytes != 2 * qty or len(pdu) != 6 + nbytes:
                raise ModbusError(ILLEGAL_VALUE)
            _write(bank, "hr", addr, list(struct.unpack(f">{qty}H", pdu[6:6 + nbytes])))
            return pdu[:5]
        if fc == 17:
            sid = bank.name.encode()
            return bytes([17, len(sid) + 1]) + sid + b"\xff"
        if fc == 43:
            return _device_id(bank, pdu)
        if fc in bank.extra:
            return bank.extra[fc](pdu)
        raise ModbusError(ILLEGAL_FUNCTION)
    except ModbusError as e:
        return exception_pdu(fc, e.code)


def _device_id(bank: DataBank, pdu: bytes) -> bytes:
    if len(pdu) < 4 or pdu[1] != 0x0E:
        raise ModbusError(ILLEGAL_FUNCTION)
    if pdu[2] not in (1, 2, 3, 4):
        raise ModbusError(ILLEGAL_VALUE)
    objs = [bank.ident["vendor"], bank.ident["product"], bank.ident["revision"]]
    body = bytearray([43, 0x0E, pdu[2], 0x01, 0x00, 0x00, len(objs)])
    for i, s in enumerate(objs):
        b = s.encode()[:60]
        body += bytes([i, len(b)]) + b
    return bytes(body)


# ------------------------------------------------------------- TCP server
async def serve_tcp(handler: Callable[[str, bytes], bytes | None], host: str = "127.0.0.1",
                    port: int = 5020) -> asyncio.base_events.Server:
    """Start a Modbus/TCP listener. handler(peer_ip, adu) returns the reply ADU or None (dropped)."""

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "?"
        try:
            while True:
                head = await reader.readexactly(7)
                length = struct.unpack(">H", head[4:6])[0]
                if length < 2 or length > 254:
                    break
                body = await reader.readexactly(length - 1)
                reply = handler(peer_ip, head + body)
                if reply is not None:
                    writer.write(reply)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(client, host, port)


# ------------------------------------------------------------- TCP client
class ModbusTcpClient:
    """Small blocking client used by tests, the CLI and tools/read_plant.py."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5020, unit: int = 1, timeout: float = 2.0):
        self.host, self.port, self.unit, self.timeout = host, port, unit, timeout
        self.sock: socket.socket | None = None
        self.tid = 0

    def connect(self) -> "ModbusTcpClient":
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        return self

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    def request(self, pdu: bytes, unit: int | None = None):
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(build_adu(self.tid, self.unit if unit is None else unit, pdu))
        head = self._recv(7)
        length = struct.unpack(">H", head[4:6])[0]
        body = self._recv(length - 1)
        return parse_response(pdu, body)

    def raw(self, pdu: bytes, unit: int | None = None) -> bytes:
        """Send a PDU and return the raw response PDU (no decoding)."""
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(build_adu(self.tid, self.unit if unit is None else unit, pdu))
        head = self._recv(7)
        return self._recv(struct.unpack(">H", head[4:6])[0] - 1)

    def read_coils(self, addr, qty, unit=None):
        return self.request(req_read(1, addr, qty), unit)

    def read_discrete_inputs(self, addr, qty, unit=None):
        return self.request(req_read(2, addr, qty), unit)

    def read_holding(self, addr, qty, unit=None):
        return self.request(req_read(3, addr, qty), unit)

    def read_input(self, addr, qty, unit=None):
        return self.request(req_read(4, addr, qty), unit)

    def write_coil(self, addr, on, unit=None):
        return self.request(req_write_coil(addr, on), unit)

    def write_register(self, addr, value, unit=None):
        return self.request(req_write_register(addr, value), unit)

    def write_coils(self, addr, bits, unit=None):
        return self.request(req_write_coils(addr, bits), unit)

    def write_registers(self, addr, values, unit=None):
        return self.request(req_write_registers(addr, values), unit)
