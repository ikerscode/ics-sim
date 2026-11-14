"""SQLite index of runs and the latest matrix; report files live in data/reports/."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

from .report import md_to_html, matrix_markdown, scenario_markdown

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REPORTS = DATA / "reports"


def _db() -> sqlite3.Connection:
    REPORTS.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DATA / "icssim.db")
    con.execute("""CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created REAL, scenario TEXT,
                   mitigations TEXT, mode TEXT, outcome TEXT, summary TEXT)""")
    con.execute("CREATE TABLE IF NOT EXISTS matrix (id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, data TEXT)")
    return con


def save_run(data: dict, mode: str = "fast") -> str:
    """Store a run_with_baseline result: JSON + Markdown + HTML report. Returns the run id."""
    REPORTS.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    md = scenario_markdown(run_id, data)
    (REPORTS / f"{run_id}.md").write_text(md)
    (REPORTS / f"{run_id}.html").write_text(md_to_html(md, f"ics-sim {data['scenario']['key']}"))
    (REPORTS / f"{run_id}.json").write_text(json.dumps(data, default=str))
    atk = data["attack"]
    summary = {"metrics": atk["metrics"], "baseline": data["baseline"]["metrics"], "per_mitigation": data["per_mitigation"],
               "target_hit": data["target_hit"], "title": data["scenario"]["title"]}
    with _db() as con:
        con.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
                    (run_id, time.time(), data["scenario"]["key"], ",".join(atk["mitigations"]), mode,
                     data["outcome"], json.dumps(summary)))
    return run_id


def list_runs(limit: int = 50) -> list[dict]:
    with _db() as con:
        rows = con.execute("SELECT id, created, scenario, mitigations, mode, outcome, summary FROM runs "
                           "ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        s = json.loads(r[6])
        out.append({"id": r[0], "created": r[1], "scenario": r[2], "mitigations": r[3], "mode": r[4], "outcome": r[5],
                    "availability_pct": s["metrics"]["availability_pct"], "safety_score": s["metrics"]["safety_score"],
                    "hazards": s["metrics"]["hazards"]})
    return out


def load_run(run_id: str) -> dict | None:
    p = REPORTS / f"{run_id}.json"
    if not p.is_file() or "/" in run_id or ".." in run_id:
        return None
    return json.loads(p.read_text())


def save_matrix(mx: dict) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    md = matrix_markdown(mx)
    (REPORTS / "matrix.md").write_text(md)
    (REPORTS / "matrix.html").write_text(md_to_html(md, "ics-sim matrix"))
    with _db() as con:
        con.execute("INSERT INTO matrix (created, data) VALUES (?, ?)", (time.time(), json.dumps(mx)))


def latest_matrix() -> dict | None:
    with _db() as con:
        row = con.execute("SELECT data FROM matrix ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def list_reports() -> list[dict]:
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(REPORTS.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        first = p.read_text().split("\n", 1)[0].lstrip("# ")
        out.append({"name": p.stem, "title": first, "modified": p.stat().st_mtime})
    return out


def report_path(name: str, ext: str) -> Path | None:
    if ext not in ("md", "html", "json") or not name.replace("-", "").replace("_", "").isalnum():
        return None
    p = REPORTS / f"{name}.{ext}"
    return p if p.is_file() else None
