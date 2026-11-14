"""Client agent for the containerised network mode (runs inside the client containers).

    python -m icssim.netagent idle              # keep the container up, do nothing
    python -m icssim.netagent hmi-poll          # HMI polling loop through the gateway (every 2 s)
    python -m icssim.netagent replay < plan.json
    python -m icssim.netagent burst N           # N back-to-back FC4 reads (rate limit check)
    python -m icssim.netagent probe HOST PORT   # can this container open a TCP connection there?

`replay` reads a list of {"i", "adu" (hex), "count"} items, sends each to the gateway
from this container's own address and prints one JSON result line per item. The agent
only ever talks to the lab's own gateway (AGENT_GATEWAY), never to anything else.
Standard library only.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

GATEWAY = os.environ.get("AGENT_GATEWAY", "10.10.2.254:5020")
REPLY_TIMEOUT = 0.4


def _gateway() -> tuple[str, int]:
    host, _, port = GATEWAY.rpartition(":")
    return host, int(port)


class Link:
    """One TCP connection to the gateway; replies are matched to requests by transaction id."""

    def __init__(self, tid_base: int = 1):
        self.sock = socket.create_connection(_gateway(), timeout=3)
        self.local = self.sock.getsockname()
        self.tid = tid_base
        self.buf = b""
        self.pending: dict[int, bytes] = {}

    def next_tid(self) -> int:
        self.tid = (self.tid % 0x7FFF) + 1
        return self.tid

    def send(self, adu: bytes) -> int:
        tid = self.next_tid()
        self.sock.sendall(struct.pack(">H", tid) + adu[2:])
        return tid

    def _read_some(self, deadline: float) -> None:
        self.sock.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            chunk = self.sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return
        if not chunk:
            raise ConnectionError("gateway closed the connection")
        self.buf += chunk
        while len(self.buf) >= 7:
            length = struct.unpack(">H", self.buf[4:6])[0]
            if len(self.buf) < 6 + length:
                break
            frame, self.buf = self.buf[:6 + length], self.buf[6 + length:]
            self.pending[struct.unpack(">H", frame[:2])[0]] = frame

    def wait(self, tids, timeout: float = REPLY_TIMEOUT) -> dict[int, bytes]:
        deadline = time.monotonic() + timeout
        want = set(tids)
        while not want <= set(self.pending) and time.monotonic() < deadline:
            self._read_some(deadline)
        return {t: self.pending.pop(t) for t in want if t in self.pending}


def replay(items: list[dict]) -> None:
    link = Link()
    for it in items:
        adu = bytes.fromhex(it["adu"])
        n = int(it.get("count", 1))
        t_send = time.time()
        tids = [link.send(adu) for _ in range(n)]
        got = link.wait(tids, REPLY_TIMEOUT + (0.2 if n > 1 else 0.0))
        first = got.get(tids[0])
        print(json.dumps({"i": it["i"], "src": link.local[0], "sport": link.local[1], "tids": [tids[0], tids[-1]],
                          "sent": n, "replies": len(got), "ts": t_send,
                          "reply": first[7:].hex() if first else None}), flush=True)


def burst(n: int) -> None:
    link = Link()
    adu = struct.pack(">HHHB", 0, 0, 6, 1) + struct.pack(">BHH", 4, 0, 10)
    replies = 0
    for _ in range(n):
        tid = link.send(adu)
        replies += bool(link.wait([tid], 0.15))
    print(json.dumps({"src": link.local[0], "sport": link.local[1], "sent": n, "replies": replies}), flush=True)


def hmi_poll() -> None:
    """Read IR 0-71, all holding registers, coils and discrete inputs every 2 s, as HMI-01 does."""
    reads = [(4, 72), (3, 32), (1, 16), (2, 16)]
    polls = 0
    while True:
        try:
            link = Link(tid_base=0x4000)
            while True:
                ok = 0
                for fc, qty in reads:
                    pdu = struct.pack(">BHH", fc, 0, qty)
                    tid = link.send(struct.pack(">HHHB", 0, 0, len(pdu) + 1, 1) + pdu)
                    ok += bool(link.wait([tid], 1.0))
                polls += 1
                if polls % 30 == 1:
                    print(json.dumps({"hmi_poll": polls, "replies": ok, "of": len(reads)}), flush=True)
                time.sleep(2.0)
        except OSError as exc:
            print(json.dumps({"hmi_poll_error": str(exc)}), flush=True)
            time.sleep(2.0)


def probe(host: str, port: int) -> None:
    t = time.monotonic()
    try:
        socket.create_connection((host, port), timeout=2).close()
        result = "connected"
    except OSError as exc:
        result = f"failed: {exc.__class__.__name__}: {exc}"
    print(json.dumps({"target": f"{host}:{port}", "result": result, "ms": round(1000 * (time.monotonic() - t))}),
          flush=True)


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "idle"
    if cmd == "idle":
        while True:
            time.sleep(3600)
    if cmd == "hmi-poll":
        hmi_poll()
    elif cmd == "replay":
        replay(json.load(sys.stdin))
    elif cmd == "burst":
        burst(int(argv[1]))
    elif cmd == "probe":
        probe(argv[1], int(argv[2]))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
