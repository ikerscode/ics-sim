"""Terminal HUD spec: every view answers, row views hold lists, actions point at real routes."""

import os

os.environ.setdefault("ICSSIM_MODBUS_PORT", "0")

from fastapi.testclient import TestClient  # noqa: E402

from icssim import termhud  # noqa: E402
from icssim.server import app  # noqa: E402
from icssim.tui_spec import SPEC  # noqa: E402


def test_every_view_endpoint_answers_and_rows_are_lists():
    with TestClient(app, headers={"host": "127.0.0.1"}) as c:
        for view in SPEC["views"]:
            r = c.get(view["endpoint"])
            assert r.status_code == 200, (view["name"], r.status_code)
            data = r.json()
            if "rows" in view:
                assert isinstance(termhud.dig(data, view["rows"]), list), view["name"]
            else:
                assert termhud.dig(data, view.get("path")) is not None, view["name"]


def test_action_endpoints_are_real_routes():
    routes = {getattr(r, "path", None) for r in app.routes}
    keys = [a["key"] for a in SPEC["actions"]]
    for action in SPEC["actions"]:
        assert action["endpoint"] in routes, action["endpoint"]
        assert len(action["key"]) == 1 and action["key"].isalpha() and action["key"] != "q", action["key"]
    assert len(keys) == len(set(keys)), "action keys must be unique"


def test_clean_strips_clear_screen_sequence():
    out = termhud.clean("a\x1b[2Jb")
    assert "\x1b" not in out
    assert "\x1b[2J" not in out
    assert out == "a?[2Jb"
