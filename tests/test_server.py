"""API smoke test and the generated register map staying in sync."""

import os
from pathlib import Path

os.environ.setdefault("ICSSIM_MODBUS_PORT", "0")

from fastapi.testclient import TestClient  # noqa: E402

from icssim.registers import register_map_markdown  # noqa: E402
from icssim.server import app  # noqa: E402


def test_api_health_state_and_control():
    with TestClient(app) as c:
        assert c.get("/api/health").json() == {"status": "ok", "name": "ics-sim", "version": "0.1.0"}
        st = c.get("/api/state").json()
        assert "hmi" in st and "truth" in st
        r = c.post("/api/control", json={"name": "PRESS_SP", "value": 2.9}).json()
        assert r["result"] == "ok"
        meta = c.get("/api/meta").json()
        assert len(meta["scenarios"]) == 8 and meta["registers"]["plc"]["hr"]
        assert c.get("/").status_code == 200


def test_register_map_doc_in_sync():
    doc = Path(__file__).resolve().parent.parent / "docs" / "REGISTER_MAP.md"
    assert doc.read_text() == register_map_markdown()
