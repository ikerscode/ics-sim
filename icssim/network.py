"""Simulated OT network: Purdue zones, hosts, the Modbus firewall/DPI and segmentation.

Real TCP clients and simulated hosts both reach the PLC through `Bus.request` in
sim.py, which calls the checks below. Nothing here touches a real network
interface; source IPs are simulated labels.
"""

from __future__ import annotations

import ipaddress

from .registers import HR_BY_ADDR, PLC_COILS

ZONES = [
    {"key": "enterprise", "level": "L4/5", "name": "Enterprise IT", "cidr": "192.168.10.0/24"},
    {"key": "dmz", "level": "L3.5", "name": "IT/OT DMZ", "cidr": "172.16.0.0/24"},
    {"key": "operations", "level": "L3", "name": "Site operations (historian)", "cidr": "10.10.3.0/24"},
    {"key": "supervisory", "level": "L2", "name": "Supervisory control (HMI, EWS)", "cidr": "10.10.2.0/24"},
    {"key": "control", "level": "L1", "name": "Basic control (PLC)", "cidr": "10.10.1.0/24"},
    {"key": "safety", "level": "SIS", "name": "Safety zone (SIS + SIS EWS)", "cidr": "10.10.4.0/24"},
]
_NETS = [(ipaddress.ip_network(z["cidr"]), z["key"]) for z in ZONES]

HOSTS = {
    "10.10.1.10": "PLC-01",
    "10.10.4.11": "SIS-01",
    "10.10.2.10": "HMI-01 (operator HMI, also runs remote-access software)",
    "10.10.2.20": "EWS-01 (engineering workstation)",
    "10.10.2.50": "LAB-CLIENT (your external Modbus tools)",
    "10.10.2.66": "Unknown laptop on the control LAN",
    "10.10.3.5": "HIST-01 (historian)",
    "10.10.4.10": "SIS-EWS (safety engineering workstation)",
    "172.16.0.20": "RA-GW (remote access gateway)",
    "192.168.10.37": "CORP-WS-37 (phished office PC)",
}
HMI_IP, EWS_IP, HIST_IP, SIS_EWS_IP = "10.10.2.10", "10.10.2.20", "10.10.3.5", "10.10.4.10"
LAB_CLIENT_IP = "10.10.2.50"

_zone_cache: dict[str, str] = {}


def zone_of(ip: str) -> str:
    z = _zone_cache.get(ip)
    if z is None:
        z = "unknown"
        try:
            addr = ipaddress.ip_address(ip)
            for net, key in _NETS:
                if addr in net:
                    z = key
                    break
        except ValueError:
            pass
        _zone_cache[ip] = z
    return z


HMI_HR = {a for a, r in HR_BY_ADDR.items() if r.hmi_write}
HMI_COILS = {r.addr for r in PLC_COILS if r.hmi_write}
ALL = "all"

# DPI policy: who may talk to which unit with which function codes and write targets.
DPI_POLICY = {
    HMI_IP: {"role": "HMI", "units": {1}, "fcs": {1, 2, 3, 4, 5, 6, 15, 16}, "hr": HMI_HR, "coil": HMI_COILS},
    EWS_IP: {"role": "EWS", "units": {1}, "fcs": {1, 2, 3, 4, 5, 6, 15, 16, 17, 43, 90}, "hr": ALL, "coil": ALL},
    HIST_IP: {"role": "Historian", "units": {1, 2}, "fcs": {1, 2, 3, 4}, "hr": set(), "coil": set()},
    SIS_EWS_IP: {"role": "SIS EWS", "units": {2}, "fcs": {1, 2, 3, 4, 5, 15}, "hr": set(), "coil": ALL},
}
RATE_PER_S = 20.0
BURST = 40.0

# Segmentation policy (Purdue): which zones may reach which Modbus unit at all.
SEGMENT_ALLOWED = {1: {"supervisory", "operations", "control"}, 2: {"safety", "operations"}}


class Firewall:
    """Modbus-aware firewall in front of the PLC/SIS gateway.

    Two independent features, toggled separately:
      * segmentation: zone-level Purdue policy (drops IT/DMZ traffic and anything
        outside the safety zone that targets the SIS unit);
      * dpi: per-source allowlist, function-code filter, write-target allowlist
        and a token-bucket rate limit per source.
    """

    def __init__(self):
        self.segmentation = False
        self.dpi = False
        self.buckets: dict[str, list[float]] = {}

    def check_segmentation(self, src: str, unit: int) -> str | None:
        zone = zone_of(src)
        allowed = SEGMENT_ALLOWED.get(unit, set())
        if zone not in allowed:
            return f"zone {zone} may not reach unit {unit} (Purdue policy)"
        return None

    def check_dpi(self, src: str, unit: int, info: dict, t: float, count: int = 1) -> tuple[int, str | None]:
        """Return (number of requests allowed, reason for blocking the rest)."""
        pol = DPI_POLICY.get(src)
        if pol is None:
            return 0, "source not in allowlist"
        if unit not in pol["units"]:
            return 0, f"{pol['role']} may not address unit {unit}"
        fc = info["fc"]
        if fc not in pol["fcs"]:
            return 0, f"function code {fc} not allowed for {pol['role']}"
        if info.get("write") and fc in (5, 6, 15, 16):
            allowed = pol[info["kind"]]
            if allowed != ALL:
                addrs = range(info["addr"], info["addr"] + (info["qty"] or 1))
                bad = [a for a in addrs if a not in allowed]
                if bad:
                    return 0, f"write to {info['kind']} {bad[0]} not allowed for {pol['role']}"
        # token bucket rate limit
        tokens, last = self.buckets.get(src, [BURST, t])
        tokens = min(BURST, tokens + (t - last) * RATE_PER_S)
        n = min(count, int(tokens))
        tokens -= n
        self.buckets[src] = [tokens, t]
        if n < count:
            return n, f"rate limit {RATE_PER_S:.0f} req/s exceeded"
        return n, None


def policy_table() -> list[dict]:
    rows = []
    for ip, p in DPI_POLICY.items():
        def fmt(v):
            return "any" if v == ALL else (", ".join(str(x) for x in sorted(v)) or "none")
        rows.append({"source": ip, "host": HOSTS.get(ip, ""), "role": p["role"], "units": fmt(p["units"]),
                     "function_codes": fmt(p["fcs"]), "holding_writes": fmt(p["hr"]), "coil_writes": fmt(p["coil"])})
    return rows
