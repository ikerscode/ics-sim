"""Event log: Modbus transactions, alarms, detector alerts, SIS trips, attack steps, hazards.

Alerts carry a `source` equal to the mitigation that raised them (sis, firewall,
segmentation, eng_limits, detector, integrity, operator). The scenario engine uses
that field to work out which mitigation detected an attack and when.
"""

from __future__ import annotations

from collections import deque


class EventLog:
    def __init__(self, keep_poll_reads: bool = True, cap: int | None = None, modbus_cap: int | None = None):
        self.keep_poll_reads = keep_poll_reads
        self.events: deque | list = deque(maxlen=cap) if cap else []
        self.modbus: deque | list = deque(maxlen=modbus_cap) if modbus_cap else []
        self.alerts: list[dict] = []          # never trimmed: needed for detection timing
        self.counters = {"modbus_total": 0, "modbus_blocked": 0, "modbus_dropped": 0, "flood_requests": 0}
        self.seq = 0

    def add(self, t: float, kind: str, message: str, severity: str = "info", source: str = "", **data) -> dict:
        self.seq += 1
        ev = {"id": self.seq, "t": round(t, 1), "kind": kind, "severity": severity, "source": source,
              "message": message, **data}
        self.events.append(ev)
        if kind == "alert":
            self.alerts.append(ev)
        return ev

    def alert(self, t: float, source: str, message: str, severity: str = "high", **data) -> dict:
        return self.add(t, "alert", message, severity, source, **data)

    def modbus_tx(self, t: float, src: str, zone: str, unit: int, info: dict, result: str,
                  reason: str = "", transport: str = "sim", count: int = 1, routine: bool = False) -> None:
        self.counters["modbus_total"] += count
        if result == "blocked":
            self.counters["modbus_blocked"] += count
        elif result == "dropped":
            self.counters["modbus_dropped"] += count
        if routine and result == "ok" and not info.get("write") and not self.keep_poll_reads:
            return
        self.seq += 1
        self.modbus.append({
            "id": self.seq, "t": round(t, 1), "src": src, "zone": zone, "unit": unit, "fc": info.get("fc"),
            "addr": info.get("addr"), "qty": info.get("qty"),
            "value": (info.get("values") or [None])[0] if info.get("values") else info.get("sub"),
            "write": bool(info.get("write")), "result": result, "reason": reason,
            "transport": transport, "count": count,
        })
