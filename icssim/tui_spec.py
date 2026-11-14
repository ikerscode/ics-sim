"""Terminal HUD spec for ics-sim: the same live API the web HUD uses, drawn with termhud.

Run with `python -m icssim tui` (needs the server from ./run.sh on 127.0.0.1:8104).
"""

from __future__ import annotations

from .constants import MITIGATIONS

SPEC = {
    "title": "ICS-SIM",
    "views": [
        {"name": "Plant", "endpoint": "/api/state", "path": "hmi"},
        {"name": "Scenarios", "endpoint": "/api/meta", "rows": "scenarios",
         "columns": [["key", 16], ["title", 40], ["start_hour", 10], ["target_hazards", 24]]},
        {"name": "Reports", "endpoint": "/api/runs", "rows": "",
         "columns": [["id", 22], ["scenario", 16], ["mode", 9], ["mitigations", 28], ["outcome", 16],
                     ["availability_pct", 8]],
         "detail": "/api/runs/{id}"},
        {"name": "Matrix", "endpoint": "/api/matrix/cells", "rows": "rows",
         "columns": [["scenario", 16], ["column", 13], ["label", 34], ["agree", 6], ["ttd_s", 8],
                     ["availability_pct", 8]]},
        {"name": "Modbus", "endpoint": "/api/modbus", "rows": "rows",
         "columns": [["t", 8], ["src", 14], ["zone", 10], ["fc", 4], ["addr", 6], ["value", 8],
                     ["result", 10], ["reason", 24]]},
    ],
    "actions": [
        {"key": "f", "label": "oldsmar none", "method": "POST", "endpoint": "/api/scenarios/run",
         "body": {"key": "oldsmar", "mitigations": [], "mode": "fast"}},
        {"key": "m", "label": "oldsmar all", "method": "POST", "endpoint": "/api/scenarios/run",
         "body": {"key": "oldsmar", "mitigations": list(MITIGATIONS), "mode": "fast"}},
        {"key": "x", "label": "matrix 5 seeds", "method": "POST", "endpoint": "/api/matrix/run",
         "body": {"seeds": 5}, "confirm": True},
        {"key": "s", "label": "matrix 1 seed", "method": "POST", "endpoint": "/api/matrix/run",
         "body": {"seeds": 1}, "confirm": True},
        {"key": "z", "label": "reset plant", "method": "POST", "endpoint": "/api/sim",
         "body": {"action": "reset"}, "confirm": True},
        {"key": "a", "label": "ack alarms", "method": "POST", "endpoint": "/api/sim",
         "body": {"action": "ack"}},
    ],
    "refresh": 2,
}
