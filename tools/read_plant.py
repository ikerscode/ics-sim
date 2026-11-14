#!/usr/bin/env python3
"""Standalone Modbus/TCP client that reads the simulated plant (no dependencies).

Usage:
    python3 tools/read_plant.py [--host 127.0.0.1] [--port 5020] [--watch 2]

It only talks to the local simulator. Handy next to other tools, for example:
    mbtget -r4 -a 0 -n 12 -p 5020 127.0.0.1
    nmap -p 5020 --script modbus-discover --script-args modbus-discover.aggressive=true 127.0.0.1
"""

import argparse
import socket
import struct
import time

# (address, name, scale, unit) for input registers 0-24 of PLC-01 (unit 1)
INPUTS = [
    (0, "LT101 raw tank level", 100, "m"), (1, "LT201 reservoir level", 100, "m"),
    (2, "FT101 intake flow", 10, "m3/h"), (3, "FT102 filter flow", 10, "m3/h"), (4, "FT201 distribution flow", 10, "m3/h"),
    (5, "AIT101 raw turbidity", 100, "NTU"), (6, "AIT102 filtered turbidity", 100, "NTU"),
    (7, "AIT301 contact chlorine", 100, "mg/L"), (8, "AIT302 contact pH", 100, "pH"),
    (9, "AIT303 final chlorine", 100, "mg/L"), (10, "AIT304 final pH", 100, "pH"), (11, "PT201 pressure", 100, "bar"),
    (12, "P-101 current", 10, "A"), (13, "P-101 temp", 10, "degC"), (14, "P-201 current", 10, "A"),
    (15, "P-201 temp", 10, "degC"), (16, "P-201 speed", 10, "%"), (17, "FCV-101 position", 10, "%"),
    (18, "DP-101 coagulant rate", 10, "L/h"), (19, "DP-301 hypochlorite rate", 100, "L/h"),
    (20, "DP-302 caustic rate", 10, "L/h"), (21, "coagulant dose", 10, "mg/L"), (22, "chlorine dose", 100, "mg/L"),
    (23, "caustic dose", 1, "ppm"), (24, "P-201 vibration", 10, "mm/s"),
]
SETPOINTS = ["RAW_LVL_START", "RAW_LVL_STOP", "RES_LVL_SP", "CL_SP", "NAOH_SP", "PH_SP"]
SP_SCALE = [100, 100, 100, 100, 1, 100]
COILS = ["P101_AUTO", "P101_MAN_RUN", "FCV101_AUTO", "P201_AUTO", "P201_MAN_RUN", "XV201_OPEN_CMD",
         "COAG_AUTO", "CL_AUTO", "NAOH_AUTO", "ALARM_ACK", "PLANT_ENABLE"]


class Client:
    def __init__(self, host, port, timeout=3.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.tid = 0

    def call(self, unit, pdu):
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(struct.pack(">HHHB", self.tid, 0, len(pdu) + 1, unit) + pdu)
        head = self._recv(7)
        body = self._recv(struct.unpack(">H", head[4:6])[0] - 1)
        if body[0] & 0x80:
            raise RuntimeError(f"Modbus exception {body[1]} for function {body[0] & 0x7F}")
        return body

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def registers(self, fc, addr, qty, unit=1):
        body = self.call(unit, struct.pack(">BHH", fc, addr, qty))
        return list(struct.unpack(f">{qty}H", body[2:2 + 2 * qty]))

    def bits(self, fc, addr, qty, unit=1):
        body = self.call(unit, struct.pack(">BHH", fc, addr, qty))
        return [(body[2 + i // 8] >> (i % 8)) & 1 for i in range(qty)]


def show(c):
    ident = c.call(1, bytes([17]))
    print("Server ID:", ident[2:-1].decode(errors="replace"))
    ir = c.registers(4, 0, 30)
    for addr, name, scale, unit in INPUTS:
        print(f"  {name:28s} {ir[addr] / scale:10.2f} {unit}")
    print(f"  alarm word 0x{ir[25]:04x}, scan {ir[26]}, program CRC {ir[27]:04x}{ir[28]:04x}, status {'FAULT' if ir[29] else 'RUN'}")
    hr = c.registers(3, 0, 6)
    print("Setpoints:", ", ".join(f"{n}={v / s:g}" for n, v, s in zip(SETPOINTS, hr, SP_SCALE)))
    co = c.bits(1, 0, len(COILS))
    print("Coils:", ", ".join(f"{n}={v}" for n, v in zip(COILS, co)))
    sis = c.bits(2, 0, 8, unit=2)
    print(f"SIS (unit 2): tripped={sis[0]} bypassed={sis[7]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020)
    ap.add_argument("--watch", type=float, default=0, help="repeat every N seconds")
    a = ap.parse_args()
    c = Client(a.host, a.port)
    while True:
        show(c)
        if not a.watch:
            break
        time.sleep(a.watch)
        print()


if __name__ == "__main__":
    main()
