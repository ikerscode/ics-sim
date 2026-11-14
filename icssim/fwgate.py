"""Modbus firewall gateway for the containerised network mode.

This process sits between the Purdue networks in docker compose (Enterprise IT, DMZ,
Control). It is the only container attached to all three, so it is the only path from
a client to the PLC. Each client connection is checked request by request:

  1. segmentation: may the client's zone (from its real source address) reach this unit?
  2. DPI: source allowlist, units, function codes, write targets, token-bucket rate limit.

Allowed requests are forwarded to the PLC on the control network over one upstream
connection per client, preceded by a PROXY v1 header so the PLC knows the original
source. Blocked requests are dropped (the client sees a timeout, as in the simulator).
Every decision is printed as one JSON line on stdout (`docker compose logs fw`).

Why an application-layer gateway and not a packet filter: the containers run with
cap_drop ALL, so nothing can use NET_ADMIN or raw sockets. A Modbus-aware proxy needs
neither, and it is also how most commercial Modbus firewalls work.

The rule engine is written separately from icssim.network on purpose. It reads the
policy JSON exported by `python -m icssim export-policy`, so both use the same
policy data but different code. tests/test_fwgate.py checks they agree.
Standard library only, no imports from the rest of the package.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import struct
import sys
import time

WRITE_TARGET_FCS = {5: "coil", 6: "hr", 15: "coil", 16: "hr"}
READ_FCS = {1, 2, 3, 4}


def decode(pdu: bytes) -> dict:
    """Fields the rules need: fc, addr, qty, table kind and whether the PDU is truncated."""
    out = {"fc": pdu[0] if pdu else 0, "addr": None, "qty": None, "kind": None, "malformed": False}
    fc = out["fc"]
    if fc in READ_FCS or fc in (5, 6, 15, 16):
        if len(pdu) < 5:
            out["malformed"] = True
            return out
        addr, second = struct.unpack(">HH", pdu[1:5])
        if fc in READ_FCS:
            out.update(addr=addr, qty=second)
        elif fc in (5, 6):
            out.update(addr=addr, qty=1, kind=WRITE_TARGET_FCS[fc])
        else:
            data = pdu[6:]
            need = (second + 7) // 8 if fc == 15 else 2 * second
            if len(data) < need:
                out["malformed"] = True
                return out
            out.update(addr=addr, qty=second, kind=WRITE_TARGET_FCS[fc])
    return out


class PolicyEngine:
    """Zone lookup, segmentation table and DPI rules loaded from the exported policy JSON."""

    def __init__(self, policy: dict, segmentation: bool = True, dpi: bool = True):
        self.zones = [(ipaddress.ip_network(z["cidr"]), z["key"]) for z in policy["zones"]]
        self.segment = {int(u): set(z) for u, z in policy["segment_allowed"].items()}
        self.dpi_rules = policy["dpi"]
        self.rate, self.burst = float(policy["rate_per_s"]), float(policy["burst"])
        self.segmentation, self.dpi = segmentation, dpi
        self.tokens: dict[str, tuple[float, float]] = {}

    def zone(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        for net, key in self.zones:
            if addr in net:
                return key
        return "unknown"

    @staticmethod
    def _permits(rule, value) -> bool:
        return rule == "all" or value in rule

    def evaluate(self, src: str, unit: int, pdu: bytes, t: float) -> tuple[bool, str | None, str | None]:
        """Decide one request. Returns (allowed, layer, reason); layer is segmentation/firewall/None."""
        unit = 1 if unit in (0, 255) else unit
        if self.segmentation:
            zone = self.zone(src)
            if zone not in self.segment.get(unit, set()):
                return False, "segmentation", f"zone {zone} may not reach unit {unit} (Purdue policy)"
        if not self.dpi:
            return True, None, None
        rule = self.dpi_rules.get(src)
        if rule is None:
            return False, "firewall", "source not in allowlist"
        if not self._permits(rule["units"], unit):
            return False, "firewall", f"{rule['role']} may not address unit {unit}"
        f = decode(pdu)
        if not self._permits(rule["fcs"], f["fc"]):
            return False, "firewall", f"function code {f['fc']} not allowed for {rule['role']}"
        if f["malformed"]:
            return False, "firewall", "malformed request"
        if f["kind"] is not None:
            allowed = rule[f["kind"]]
            if allowed != "all":
                for a in range(f["addr"], f["addr"] + (f["qty"] or 1)):
                    if a not in allowed:
                        return False, "firewall", f"write to {f['kind']} {a} not allowed for {rule['role']}"
        return self._take_token(src, t)

    def _take_token(self, src: str, t: float) -> tuple[bool, str | None, str | None]:
        tokens, last = self.tokens.get(src, (self.burst, t))
        tokens = min(self.burst, tokens + (t - last) * self.rate)
        ok = tokens >= 1.0
        self.tokens[src] = (tokens - 1.0 if ok else tokens, t)
        if ok:
            return True, None, None
        return False, "firewall", f"rate limit {self.rate:.0f} req/s exceeded"


# ---------------------------------------------------------------- network side
def proxy_line(src: str, sport: int, dst: str, dport: int) -> bytes:
    fam = "TCP6" if ":" in src else "TCP4"
    return f"PROXY {fam} {src} {dst} {sport} {dport}\r\n".encode()


class Gateway:
    def __init__(self, engine: PolicyEngine, upstream: tuple[str, int], out=sys.stdout):
        self.engine, self.upstream, self.out = engine, upstream, out
        self.t0 = time.monotonic()

    def log(self, **entry) -> None:
        # One line per decision, written synchronously right after the decision so the
        # log order is the evaluation order (the verifier replays the log in this order).
        self.out.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self.out.flush()

    async def client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        src, sport = writer.get_extra_info("peername")[:2]
        dst, dport = writer.get_extra_info("sockname")[:2]
        up: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        try:
            while True:
                head = await reader.readexactly(7)
                tid, pid, length, unit = struct.unpack(">HHHB", head)
                if pid != 0 or not 2 <= length <= 254:
                    self.log(ts=time.time(), src=src, sport=sport, event="bad frame, connection closed")
                    break
                pdu = await reader.readexactly(length - 1)
                t = time.monotonic() - self.t0
                allowed, layer, reason = self.engine.evaluate(src, unit, pdu, t)
                f = decode(pdu)
                self.log(ts=time.time(), t=t, src=src, sport=sport, zone=self.engine.zone(src), tid=tid,
                         unit=unit, fc=f["fc"], addr=f["addr"], qty=f["qty"], pdu=pdu.hex(),
                         decision="allow" if allowed else "block", layer=layer, reason=reason)
                if not allowed:
                    continue
                if up is None:
                    up = await asyncio.open_connection(*self.upstream)
                    up[1].write(proxy_line(src, sport, dst, dport))
                reply = await self._forward(up, head + pdu)
                if reply is None:
                    self.log(ts=time.time(), src=src, sport=sport, tid=tid, event="no reply from PLC")
                    continue
                writer.write(reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            if up is not None:
                up[1].close()

    @staticmethod
    async def _forward(up, adu: bytes) -> bytes | None:
        r, w = up
        w.write(adu)
        await w.drain()
        try:
            head = await asyncio.wait_for(r.readexactly(7), 2.0)
            body = await asyncio.wait_for(r.readexactly(struct.unpack(">H", head[4:6])[0] - 1), 2.0)
        except asyncio.TimeoutError:
            return None
        return head + body


async def relay(reader, writer, target: tuple[str, int]) -> None:
    """Plain TCP relay (used only for the PLC HUD on the host-only edge network)."""
    try:
        ur, uw = await asyncio.open_connection(*target)
    except OSError:
        writer.close()
        return

    async def pipe(a, b):
        try:
            while data := await a.read(65536):
                b.write(data)
                await b.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            b.close()
    await asyncio.gather(pipe(reader, uw), pipe(ur, writer))


def _addr(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


async def main() -> None:
    with open(os.environ.get("FW_POLICY", "/app/policy.json")) as fh:
        policy = json.load(fh)
    engine = PolicyEngine(policy, segmentation=os.environ.get("FW_SEGMENTATION", "1") == "1",
                          dpi=os.environ.get("FW_DPI", "1") == "1")
    gw = Gateway(engine, _addr(os.environ.get("FW_UPSTREAM", "10.10.1.10:5020")))
    servers = []
    for item in filter(None, os.environ.get("FW_LISTEN", "").split(",")):
        host, port = _addr(item.strip())
        servers.append(await asyncio.start_server(gw.client, host, port))
    for item in filter(None, os.environ.get("FW_RELAY", "").split(",")):
        listen, target = item.strip().split("=")
        host, port = _addr(listen)
        tgt = _addr(target)
        servers.append(await asyncio.start_server(lambda r, w, tgt=tgt: relay(r, w, tgt), host, port))
    gw.log(ts=time.time(), event="gateway up", listen=os.environ.get("FW_LISTEN", ""),
           segmentation=engine.segmentation, dpi=engine.dpi)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
