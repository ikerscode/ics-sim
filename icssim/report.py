"""Markdown and HTML reports for scenario runs and the mitigation matrix."""

from __future__ import annotations

import html
import re

from .constants import HAZARDS, MITIGATION_LABELS

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _fmt_s(s) -> str:
    if s is None:
        return "-"
    s = float(s)
    if abs(s) < 120:
        return f"{s:.0f} s"
    return f"{s / 60:.1f} min"


def _row(cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |"


def scenario_markdown(run_id: str, data: dict) -> str:
    """data is the output of runner.run_with_baseline."""
    sc, atk, base = data["scenario"], data["attack"], data["baseline"]
    mits = atk["mitigations"]
    out = [f"# Scenario report: {sc['title']}", "",
           f"- Run id: `{run_id}`", f"- Scenario key: `{sc['key']}`", f"- Seed: {atk['seed']}",
           f"- Simulated window: {atk['start_clock']} to {atk['end_clock']} ({atk['horizon_s'] / 3600:.1f} h), "
           f"attack starts at +{atk['attack_at_s'] / 60:.0f} min",
           f"- Mitigations enabled: {', '.join(MITIGATION_LABELS[m] for m in mits) or 'none'}",
           f"- Outcome: **{data['outcome']}**", "",
           "## Scenario", "", sc["summary"], "",
           f"Attacker: {sc['attacker']['host'] or sc['attacker']['desc']} ({sc['attacker']['ip'] or 'field level'}, zone {sc['attacker']['zone']})", "",
           "| ATT&CK for ICS | Technique |", "|---|---|"]
    out += [_row([f"[{t['id']}]({ATTACK_URL.format(t['id'])})", t["name"]]) for t in sc["techniques"]]
    out += ["", f"Target hazard(s): {', '.join(HAZARDS[h][0] for h in sc['target_hazards'])}", ""]

    out += ["## Consequences vs baseline", "",
            "Baseline = same seed, same mitigations, no attack.", "",
            "| Metric | Baseline | Attack run |", "|---|---|---|"]
    bm, am = base["metrics"], atk["metrics"]
    rows = [("Availability (% time demand met at >= 1 bar)", "availability_pct"),
            ("Water quality compliance (% of delivered volume)", "quality_compliance_pct"),
            ("Safety score (100 = no hazard)", "safety_score"),
            ("Non-compliant water delivered (m3)", "noncompliant_m3"),
            ("Unmet demand (m3)", "unmet_demand_m3"), ("Overflow (m3)", "overflow_m3"),
            ("Max final free chlorine (mg/L)", "max_final_cl"), ("Min final free chlorine (mg/L)", "min_final_cl"),
            ("Max final pH", "max_final_ph"), ("Max sodium (mg/L)", "max_sodium"),
            ("Min network pressure (bar)", "min_pressure"), ("Max raw tank level (m)", "max_raw_level"),
            ("Max P-201 temperature (degC)", "max_p201_temp")]
    out += [_row([label, bm[k], am[k]]) for label, k in rows]
    out += [_row(["Hazards", ", ".join(bm["hazards"]) or "none", ", ".join(am["hazards"]) or "none"])]
    out += ["", "Time to hazard (from attack start):", ""]
    if am["time_to_hazard_s"]:
        out += [f"- {HAZARDS[h][0]}: {_fmt_s(v)} (lasted {_fmt_s(am['hazard_durations_s'][h])})"
                for h, v in am["time_to_hazard_s"].items()]
    else:
        out.append("- no hazard occurred")
    out.append("")

    out += ["## Detection and prevention", "", "| Mitigation | Detected | Time to detect | First alert |", "|---|---|---|---|"]
    for m in mits:
        d = data["per_mitigation"][m]
        out.append(_row([MITIGATION_LABELS[m], "yes" if d["detected"] else "no", _fmt_s(d["ttd_s"]), d["message"]]))
    if not mits:
        out.append(_row(["(none enabled)", "", "", ""]))
    out.append("")

    out += ["## Timeline", "", "| Sim time | T+ | Kind | Source | Event |", "|---|---|---|---|---|"]
    t0 = atk["attack_at_s"]
    shown = [e for e in atk["timeline"] if e["kind"] != "alarm" or "cleared" not in e["message"]]
    for e in shown[:150]:
        out.append(_row([e["clock"], _fmt_s(e["t"] - t0), e["kind"], e["source"], e["message"]]))
    if len(shown) > 150:
        out.append(f"\n({len(shown) - 150} more events not shown)")
    out.append("")

    if atk["modbus_notable"]:
        out += ["## Notable Modbus transactions", "", "Writes, blocked or dropped requests and non-routine sources.", "",
                "| Sim t | Source | Zone | Unit | FC | Addr | Value | Result | Reason | Count |", "|---|---|---|---|---|---|---|---|---|---|"]
        for m in atk["modbus_notable"][:80]:
            out.append(_row([m["t"], m["src"], m["zone"], m["unit"], m["fc"], m["addr"], m["value"], m["result"], m["reason"], m["count"]]))
        out.append("")
    if sc.get("case_study"):
        out += ["## Case study notes", "", sc["case_study"], ""]
    out += ["## Model caveats", "",
            "Simulated plant with simplified physics (see docs/MODEL.md). Times and magnitudes show mechanisms "
            "and relative effect of controls, not predictions for a real works.", ""]
    return "\n".join(out)


def _span(med, lo, hi, fmt) -> str:
    """'60 s' when every seed agrees, else '60 s [40 s-90 s]' (median [min-max])."""
    if med is None:
        return "-"
    if lo is None or fmt(lo) == fmt(hi):
        return fmt(med)
    return f"{fmt(med)} [{fmt(lo)}-{fmt(hi)}]"


def _pct(v) -> str:
    return f"{v:.0f}"


def matrix_cell_text(cell: dict) -> str:
    """One Markdown table cell: majority outcome with its seed count, median [min-max] times, availability."""
    o, n = cell["outcome"], cell.get("n_seeds", 1)
    k = cell.get("outcome_counts", {o: n}).get(o, n)
    frac = f" {k}/{n}" if n > 1 else ""
    ttd = _span(cell["ttd_s"], cell.get("ttd_min_s"), cell.get("ttd_max_s"), _fmt_s)
    if o == "hazard":
        txt = f"**HAZARD**{frac} in " + _span(cell["tth_s"], cell.get("tth_min_s"), cell.get("tth_max_s"), _fmt_s)
    elif o == "prevented":
        txt = f"**PREVENTED**{frac}" + (f" ({ttd})" if cell["ttd_s"] is not None else "")
    elif o == "detected":
        txt = f"**DETECTED**{frac} {ttd}"
    else:
        txt = f"{o}{frac}"
    if n > 1 and cell.get("ttd_s") is not None and cell.get("ttd_n", n) < n and o != "hazard":
        txt += f" (alert in {cell['ttd_n']}/{n})"
    txt += " av " + _span(cell["availability_pct"], cell.get("availability_min_pct"),
                          cell.get("availability_max_pct"), _pct)
    if not cell.get("agree", True):
        txt = "MIXED " + txt + " (" + cell["outcome_label"] + ")"
    return txt


def matrix_markdown(mx: dict) -> str:
    cols = mx["columns"]
    seeds = mx.get("seeds", [mx["seed"]])
    seed_txt = (f"seeds {seeds[0]}-{seeds[-1]} ({len(seeds)} per cell)" if len(seeds) > 1 else f"seed {seeds[0]}")
    out = ["# Scenario x mitigation matrix", "",
           f"Run on {mx['generated']}, {seed_txt}, each cell a {mx['horizon_s'] / 3600:.0f} h fast-forward run "
           f"with the attack at +{mx['attack_at_s'] / 60:.0f} min. "
           f"{mx.get('runs', '')} runs on {mx.get('workers', 2)} workers, wall time {mx['wall_s']} s"
           + (f" ({mx['sim_run_s']} s of simulation)." if "sim_run_s" in mx else "."), "",
           "Legend: **HAZARD** = target hazard occurred with no mitigation; **PREVENTED** = target hazard did not occur; "
           "**DETECTED** = hazard occurred but the mitigation raised an alert (time to detect from attack start); "
           "**not detected** = hazard occurred, no alert from that mitigation. `av` = availability %. "
           "Scenarios marked (SIS required) always run with the SIS installed.", ""]
    if len(seeds) > 1:
        out += [f"Each cell shows the majority outcome and how many of the {len(seeds)} seeds gave it, then the median "
                "time and availability with the range over seeds in brackets as [min-max] (no brackets when every "
                "seed gave the same number). Times to detect are medians over the seeds that raised an alert. "
                "**MIXED** marks a cell where seeds gave different outcomes; ties are reported as the worse "
                "outcome. The seed changes demand noise, the storm timing and sensor noise; operator reaction times "
                "are fixed.", ""]
    head = ["Scenario"] + list(cols)
    out += [_row(head), "|" + "---|" * len(head)]
    for sc in mx["scenarios"]:
        cells = mx["cells"][sc["key"]]
        row = [sc["key"] + (" (SIS required)" if sc["requires"] else "")]
        row += [matrix_cell_text(cells[c]) for c in cols]
        out.append(_row(row))

    if len(seeds) > 1:
        out += ["", "## Cells where seeds disagree", ""]
        mixed = mx.get("disagreements", [])
        if not mixed:
            out.append(f"None: every cell gave the same outcome for all {len(seeds)} seeds.")
        else:
            out += ["| Scenario | Column | Outcomes | Per seed |", "|---|---|---|---|"]
            for d in mixed:
                per = mx["cells"][d["scenario"]][d["column"]]["per_seed"]
                txt = "; ".join(f"{p['seed']}: {p['outcome']}" + (f" ({_fmt_s(p['ttd_s'])})" if p["ttd_s"] is not None else "")
                                for p in per)
                out.append(_row([d["scenario"], d["column"], d["label"], txt]))
        if seeds[0] == 1:
            out += ["", "## Compared with the single-seed table (seed 1 only)", ""]
            changed = []
            for sc in mx["scenarios"]:
                for c in cols:
                    cell = mx["cells"][sc["key"]][c]
                    s1 = next((p for p in cell["per_seed"] if p["seed"] == 1), None)
                    if s1 and s1["outcome"] != cell["outcome"]:
                        changed.append(_row([sc["key"], c, s1["outcome"], cell["outcome_label"]]))
            if changed:
                out += ["| Scenario | Column | Seed 1 alone | Over all seeds |", "|---|---|---|---|"] + changed
            else:
                out.append("No cell's majority outcome differs from its seed 1 outcome.")

    out += ["", "## Baseline false positives (no attack, same horizon)", ""]
    n = len(seeds)
    out += [f"Totals over {n} baseline runs per column." if n > 1 else "", "",
            "| Column | Alerts | Hazards | Availability % (worst seed) |", "|---|---|---|---|"]
    for c in cols:
        b = mx["baseline"][c]
        out.append(_row([c, b["false_alerts"], ", ".join(b["hazards"]) or "none", b["availability_pct"]]))
    out += ["", "## Scenarios", ""]
    for sc in mx["scenarios"]:
        tech = ", ".join(f"{t['id']} {t['name']}" for t in sc["techniques"])
        out += [f"- `{sc['key']}`: {sc['title']}. ATT&CK: {tech}."]
    out += ["", "## Mitigations", ""] + [f"- `{k}`: {v}" for k, v in MITIGATION_LABELS.items()]
    out.append("")
    return "\n".join(out)


# ------------------------------------------------------------ tiny Markdown -> HTML
_CSS = """body{background:#0b0b0d;color:#dcd8cc;font:14px/1.5 'DejaVu Sans Mono',monospace;max-width:1200px;margin:24px auto;padding:0 16px}
a{color:#4f8fb8}h1,h2{border-bottom:1px dashed #2b2a31;padding-bottom:4px}h2{font-size:15px;text-transform:uppercase;letter-spacing:.1em;color:#8b877d}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}th,td{border-bottom:1px solid #24232a;padding:4px 6px;text-align:left;vertical-align:top}
th{color:#8b877d;font-weight:normal}code{background:#141418;padding:0 4px}strong{color:#fff}"""


def _inline(text: str) -> str:
    t = html.escape(text, quote=False)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', t)
    return t


def md_to_html(md: str, title: str = "report") -> str:
    """Enough Markdown for our own reports: headings, lists, tables, paragraphs."""
    lines, out, i = md.split("\n"), [], 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|(\s*-+\s*\|)+\s*$", lines[i + 1].replace("---", "-")):
            head = [c.strip() for c in ln.strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue
        m = re.match(r"^(#{1,3}) (.*)", ln)
        if m:
            n = len(m.group(1))
            out.append(f"<h{n}>{_inline(m.group(2))}</h{n}>")
        elif ln.startswith("- "):
            out.append("<ul>")
            while i < len(lines) and lines[i].startswith("- "):
                out.append(f"<li>{_inline(lines[i][2:])}</li>")
                i += 1
            out.append("</ul>")
            continue
        elif ln.strip():
            out.append(f"<p>{_inline(ln)}</p>")
        i += 1
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<style>{_CSS}</style></head><body>" + "\n".join(out) + "</body></html>")
