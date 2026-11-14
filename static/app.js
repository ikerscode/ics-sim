// ics-sim HUD: three tabs (Plant, Scenarios, Matrix & Log). Uses window.hud from hud.js.
(() => {
const { api, toast, initTabs, renderTable, severityTag, lineChart, every, esc } = window.hud;
let META = null;
let STATE = null;
let current = "plant";

const TRUTH = { LT101: "raw_level", LT201: "res_level", FT101: "q_in", FT102: "q_f", FT201: "q_out", AIT101: "raw_turb",
  AIT102: "filt_turb", AIT301: "contact_cl", AIT302: "contact_ph", AIT303: "final_cl", AIT304: "final_ph",
  PT201: "pressure", P201_TEMP: "p201_temp" };
const LIMITS = { LT101: [0.5, 4.3], LT201: [0.8, 3.7], AIT102: [null, 1.0], AIT301: [0.2, 4.0], AIT303: [0.2, 4.0],
  AIT302: [6.5, 9.5], AIT304: [6.5, 9.5], PT201: [1.0, null], P201_TEMP: [null, 75] };
const COIL_CONTROLS = ["P101_AUTO", "P101_MAN_RUN", "FCV101_AUTO", "P201_AUTO", "P201_MAN_RUN", "XV201_OPEN_CMD",
  "COAG_AUTO", "CL_AUTO", "NAOH_AUTO", "PLANT_ENABLE"];

const fmt = (v, d = 2) => (typeof v === "number" ? v.toFixed(d) : esc(v));
const outOf = (name, v) => { const l = LIMITS[name]; return l && ((l[0] !== null && v < l[0]) || (l[1] !== null && v > l[1])); };

function mitBoxes(target, selected, prefix) {
  document.querySelector(target).innerHTML = META.mitigations.map((m) =>
    `<label><input type="checkbox" id="${prefix}-${m.key}" ${selected.includes(m.key) ? "checked" : ""}> ${esc(m.label)}</label>`).join("<br>");
}
const checkedMits = (prefix) => META.mitigations.filter((m) => document.getElementById(`${prefix}-${m.key}`).checked).map((m) => m.key);

// ------------------------------------------------------------------ Plant
function renderValues() {
  const s = STATE, v = s.hmi.values, truth = s.truth, showTruth = document.getElementById("showTruth").checked;
  const irs = META.registers.plc.ir.filter((r) => r.addr < 25);
  const rows = irs.map((r) => {
    const hv = v[r.name], tv = TRUTH[r.name] ? truth[TRUTH[r.name]] : null;
    return { tag: r.name, desc: r.desc, hmi: hv, truth: tv, unit: r.unit };
  });
  rows.push({ tag: "AIT901 (SIS)", desc: "SIS chlorine analyser, final water", hmi: s.sis.AIT901, truth: truth.final_cl, unit: "mg/L" });
  rows.push({ tag: "AIT902 (SIS)", desc: "SIS pH analyser, final water", hmi: s.sis.AIT902, truth: truth.final_ph, unit: "pH" });
  rows.push({ tag: "sodium", desc: "Final water sodium (lab, truth only)", hmi: "", truth: truth.sodium, unit: "mg/L" });
  rows.push({ tag: "demand", desc: "Network demand (truth only)", hmi: "", truth: truth.demand, unit: "m3/h" });
  const cols = [
    { key: "tag", label: "Tag" }, { key: "desc", label: "Description" },
    { key: "hmi", label: "HMI value", render: (x, r) => `<span class="${outOf(r.tag, x) ? "bad" : ""}">${fmt(x)}</span>` },
  ];
  if (showTruth) cols.push({ key: "truth", label: "Ground truth", render: (x, r) => x === null ? "" :
    `<span class="${outOf(TRUTH_KEY(r.tag), x) ? "bad" : ""}">${fmt(x)}</span>${typeof r.hmi === "number" && Math.abs(r.hmi - x) > 0.3 * Math.max(1, Math.abs(x)) ? ' <span class="tag crit">differs</span>' : ""}` });
  cols.push({ key: "unit", label: "Unit" });
  renderTable("#values", rows, cols);
}
const TRUTH_KEY = (tag) => tag.split(" ")[0].replace("AIT901", "AIT303").replace("AIT902", "AIT304");

function renderStatus() {
  const s = STATE;
  const live = s.live_scenario ? `<span class="tag crit">attack running: ${esc(s.live_scenario.key)}</span>` : '<span class="tag ok">no attack</span>';
  document.getElementById("status").innerHTML = `
    <div class="stat">${esc(s.clock)}<small>sim clock · ${esc(s.speed)}x ${s.paused ? "(paused)" : ""}</small></div>
    <div>${live}</div>
    <div>PLC: ${s.plc.faulted ? `<span class="tag crit">FAULT ${esc(s.plc.fault_reason)}</span>` : '<span class="tag ok">RUN</span>'}
      program ${esc(s.plc.program.name)} v${esc(s.plc.program.version)}</div>
    <div>SIS: ${!s.sis.enabled ? '<span class="tag info">disabled</span>' : s.sis.tripped ? `<span class="tag crit">TRIPPED ${esc(s.sis.cause)}</span>` : '<span class="tag ok">healthy</span>'}
      ${s.sis.bypassed ? '<span class="tag crit">BYPASSED</span>' : ""}</div>
    <div>HMI comms: ${s.hmi.comms_ok ? '<span class="tag ok">ok</span>' : '<span class="tag crit">lost</span>'}
      integrity: ${severityTag(s.hmi.integrity === "ok" ? "ok" : s.hmi.integrity === "off" ? "off" : "critical")} ${esc(s.hmi.integrity)}</div>
    <div class="muted">external Modbus clients appear as ${esc(s.ext_ip)}</div>`;
  const m = s.metrics;
  document.getElementById("since").textContent = `since ${s.metrics_since}`;
  renderTable("#metrics", [
    { k: "Availability", v: m.availability_pct + " %" }, { k: "Quality compliance", v: m.quality_compliance_pct + " %" },
    { k: "Safety score", v: m.safety_score }, { k: "Hazards", v: m.hazards.join(", ") || "none" },
  ], [{ key: "k", label: "Metric" }, { key: "v", label: "Value" }]);
  const al = s.hmi.alarms;
  document.getElementById("alarms").innerHTML = al.length ? al.map((a) => `<span class="tag crit">${esc(a)}</span>`).join(" ") : '<span class="muted">none</span>';
  document.getElementById("viewinfo").textContent = s.hmi.comms_ok ? "" : "(HMI view stale)";
}

function renderControls() {
  const s = STATE;
  document.getElementById("coils").innerHTML = COIL_CONTROLS.map((name) => {
    const on = s.hmi.coils[name];
    return `<div class="row"><span style="width:150px">${esc(name)}</span><span class="tag ${on ? "ok" : "info"}">${on ? "ON" : "OFF"}</span>
      <button class="btn" data-coil="${esc(name)}" data-val="1">On</button><button class="btn" data-coil="${esc(name)}" data-val="0">Off</button></div>`;
  }).join("");
}

function renderSetpoints() {
  const s = STATE;
  const rows = META.registers.plc.hr.map((r) => ({ ...r, cur: s.hmi.setpoints[r.name] }));
  renderTable("#setpoints", rows, [
    { key: "name", label: "Setpoint" }, { key: "desc", label: "Description" },
    { key: "cur", label: "Now", render: (x) => fmt(x) }, { key: "unit", label: "Unit" },
    { key: "eng_min", label: "Eng. range", render: (x, r) => r.eng_min === undefined ? "" : `${r.eng_min}-${r.eng_max}` },
    { key: "name", label: "New", render: (x) => `<input id="sp-${esc(x)}"> <button class="btn" data-sp="${esc(x)}">Set</button>` },
  ]);
}

async function writePoint(name, value) {
  try {
    const r = await api("/api/control", { method: "POST", body: { name, value } });
    toast(`${name} = ${value}: ${r.result}`);
    refreshPlant(true);
  } catch (e) { toast(e.message); }
}

async function renderTrend() {
  const pts = await api("/api/trend?n=360");
  const sel = document.getElementById("trendSel").value;
  const x = (p) => p.t / 3600;
  const S = (name, key) => ({ name, points: pts.map((p) => [x(p), p[key]]) });
  const cfg = {
    cl: [[S("contact Cl", "contact_cl"), S("final Cl", "final_cl"), S("final Cl as seen on HMI", "hmi_cl")],
      [{ value: 4.0, label: "4.0 overdose" }, { value: 0.2, label: "0.2 underdose", color: "#d49a1e" }], "mg/L"],
    ph: [[S("contact pH", "contact_ph"), S("final pH", "final_ph")], [{ value: 9.5, label: "pH 9.5" }, { value: 6.5, label: "pH 6.5" }], "pH"],
    lvl: [[S("raw tank", "raw_level"), S("reservoir", "res_level"), S("raw tank on HMI", "hmi_raw_level")],
      [{ value: 5.0, label: "raw overflow" }, { value: 0.2, label: "dry run" }], "m"],
    press: [[S("pressure", "pressure")], [{ value: 1.0, label: "1.0 bar min" }], "bar"],
    flow: [[S("filter", "q_f"), S("delivered", "q_out"), S("demand", "demand")], [], "m3/h"],
    temp: [[S("P-201", "p201_temp")], [{ value: 90, label: "damage" }], "degC"],
  }[sel];
  lineChart("#trend", cfg[0], { thresholds: cfg[1], yLabel: cfg[2], xFormat: (h) => `${h.toFixed(1)} h` });
}

async function renderEvents() {
  const kind = document.getElementById("evKind").value;
  const evs = await api(`/api/events?limit=150&kind=${encodeURIComponent(kind)}`);
  renderTable("#events", evs, [
    { key: "clock", label: "Sim time" }, { key: "kind", label: "Kind" },
    { key: "severity", label: "Sev", render: (x) => severityTag(x) }, { key: "source", label: "Source" },
    { key: "message", label: "Message" },
  ], { empty: "No events yet." });
}

let lastStatic = 0;
async function refreshPlant(force) {
  STATE = await api("/api/state");
  renderStatus();
  renderValues();
  if (force || Date.now() - lastStatic > 5000 || !document.getElementById("setpoints").innerHTML) {
    lastStatic = Date.now();
    renderControls();
    if (!document.activeElement || !document.activeElement.id.startsWith("sp-")) renderSetpoints();
  }
  renderTrend();
  renderEvents();
}

// ------------------------------------------------------------------ Scenarios
function renderScenarioInfo() {
  const sc = META.scenarios.find((s) => s.key === document.getElementById("scSel").value);
  document.getElementById("scInfo").innerHTML = `
    <p>${esc(sc.summary)}</p>
    <p>${sc.techniques.map((t) => `<a class="tag info" target="_blank" href="https://attack.mitre.org/techniques/${esc(t.id)}/">${esc(t.id)} ${esc(t.name)}</a>`).join(" ")}</p>
    <p class="muted">Attacker: ${esc(sc.attacker.host || sc.attacker.desc)} (${esc(sc.attacker.ip || "field level")}, zone ${esc(sc.attacker.zone)}).
      Target hazard: ${esc(sc.target_hazards.join(", "))}. ${sc.requires.length ? "Always runs with: " + esc(sc.requires.join(", ")) + "." : ""}</p>
    <p class="muted">Expected: ${Object.entries(sc.expected).map(([k, v]) => `${esc(k)} ${esc(v)}`).join(", ")}</p>
    ${sc.case_study ? `<details><summary>Case study</summary><p>${esc(sc.case_study)}</p></details>` : ""}`;
}

function renderResult(r) {
  const a = r.attack, b = r.baseline, am = a.metrics;
  const keys = [["availability_pct", "Availability %"], ["quality_compliance_pct", "Quality compliance %"], ["safety_score", "Safety score"],
    ["noncompliant_m3", "Non-compliant water m3"], ["unmet_demand_m3", "Unmet demand m3"], ["overflow_m3", "Overflow m3"],
    ["max_final_cl", "Max final Cl mg/L"], ["min_final_cl", "Min final Cl mg/L"], ["max_final_ph", "Max final pH"],
    ["max_sodium", "Max sodium mg/L"], ["min_pressure", "Min pressure bar"], ["max_raw_level", "Max raw level m"], ["max_p201_temp", "Max P-201 degC"]];
  const tth = Object.entries(am.time_to_hazard_s).map(([k, v]) => `${esc(k)} after ${(v / 60).toFixed(1)} min`).join(", ") || "none";
  document.getElementById("result").innerHTML = `
    <p>Outcome: <span class="tag ${r.outcome === "prevented" ? "ok" : r.outcome.includes("hazard") ? "crit" : "info"}">${esc(r.outcome)}</span>
      Mitigations: ${esc(a.mitigations.join(", ") || "none")} · ${esc(a.start_clock)} to ${esc(a.end_clock)}
      ${r.id ? ` · report <a target="_blank" href="/api/reports/${esc(r.id)}.html">html</a> <a href="/api/reports/${esc(r.id)}.md">md</a>` : ""}</p>
    <p>Hazards: ${esc(am.hazards.join(", ") || "none")} · time to hazard: ${tth}</p>
    <div id="scoreTbl"></div><h2 style="margin-top:10px">Detection</h2><div id="detTbl"></div>
    <h2 style="margin-top:10px">Timeline</h2><div id="tlTbl" class="scroll"></div>`;
  renderTable("#scoreTbl", keys.map(([k, l]) => ({ m: l, base: b[k], atk: am[k] })),
    [{ key: "m", label: "Metric" }, { key: "base", label: "Baseline" }, { key: "atk", label: "Attack run" }]);
  renderTable("#detTbl", Object.entries(r.per_mitigation).map(([m, d]) => ({ m, ...d })), [
    { key: "m", label: "Mitigation" }, { key: "detected", label: "Detected", render: (x) => x ? '<span class="tag ok">yes</span>' : '<span class="tag info">no</span>' },
    { key: "ttd_s", label: "Time to detect", render: (x) => x === null ? "-" : `${(x / 60).toFixed(1)} min` }, { key: "message", label: "First alert" },
  ], { empty: "No mitigations enabled." });
  renderTable("#tlTbl", a.timeline, [{ key: "clock", label: "Sim time" }, { key: "kind", label: "Kind" },
    { key: "source", label: "Source" }, { key: "message", label: "Event" }]);
}

async function renderRuns() {
  const runs = await api("/api/runs");
  renderTable("#runs", runs, [
    { key: "id", label: "Run", render: (x) => `<a href="#" data-run="${esc(x)}">${esc(x)}</a>` },
    { key: "scenario", label: "Scenario" }, { key: "mode", label: "Mode" }, { key: "mitigations", label: "Mitigations" },
    { key: "outcome", label: "Outcome" }, { key: "availability_pct", label: "Avail %" }, { key: "safety_score", label: "Safety" },
    { key: "id", label: "Report", render: (x) => `<a target="_blank" href="/api/reports/${esc(x)}.html">html</a> <a href="/api/reports/${esc(x)}.md">md</a>` },
  ], { empty: "No runs yet." });
}

// ------------------------------------------------------------------ Matrix & Log
async function renderMatrix() {
  const { job, matrix } = await api("/api/matrix");
  document.getElementById("mxStatus").textContent = job.running ? `running ${job.done}/${job.total}` :
    job.error ? `error: ${job.error}` : matrix ? `last run ${matrix.generated}, ${matrix.wall_s} s` : "no matrix yet";
  if (!matrix) { document.getElementById("mx").innerHTML = '<p class="muted">Run the matrix to fill this table.</p>'; return; }
  const cls = { hazard: "cell-hazard", prevented: "cell-prevented", detected: "cell-detected", "not detected": "cell-not" };
  const mins = (s) => s === null ? "" : s < 120 ? `${s.toFixed(0)} s` : `${(s / 60).toFixed(1)} min`;
  const head = "<tr><th>Scenario</th>" + matrix.columns.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr>";
  const body = matrix.scenarios.map((sc) => "<tr><td>" + esc(sc.key) + "</td>" + matrix.columns.map((c) => {
    const x = matrix.cells[sc.key][c];
    const extra = x.outcome === "hazard" ? ` in ${mins(x.tth_s)}` : x.ttd_s !== null ? ` ${mins(x.ttd_s)}` : "";
    return `<td class="${cls[x.outcome] || ""}" title="hazards: ${esc(x.hazards.join(", ") || "none")}; detected by ${esc(x.detected_by || "-")}">${esc(x.outcome.toUpperCase())}${esc(extra)}<br><span class="muted">av ${esc(x.availability_pct.toFixed(0))}%</span></td>`;
  }).join("") + "</tr>").join("");
  const fp = "<tr><td class='muted'>baseline false alerts</td>" + matrix.columns.map((c) => `<td class="muted">${esc(matrix.baseline[c].false_alerts)}</td>`).join("") + "</tr>";
  document.getElementById("mx").innerHTML = `<table><thead>${head}</thead><tbody>${body}${fp}</tbody></table>`;
  return job.running;
}

async function renderLog() {
  const d = await api("/api/modbus?limit=150");
  const c = d.counters;
  document.getElementById("mbCount").textContent = `total ${c.modbus_total} · blocked ${c.modbus_blocked} · dropped ${c.modbus_dropped} · flood ${c.flood_requests}`;
  renderTable("#mblog", d.rows, [
    { key: "t", label: "t (s)" }, { key: "src", label: "Source" }, { key: "zone", label: "Zone" }, { key: "unit", label: "Unit" },
    { key: "fc", label: "FC" }, { key: "addr", label: "Addr" }, { key: "value", label: "Value" },
    { key: "result", label: "Result", render: (x) => severityTag(x === "ok" ? "ok" : x === "exception" ? "warn" : "critical") + (x !== "ok" ? esc(x) : "") },
    { key: "reason", label: "Reason" }, { key: "transport", label: "Via" },
  ], { empty: "No transactions yet." });
}

function renderNetwork() {
  renderTable("#zones", META.zones, [{ key: "level", label: "Purdue level" }, { key: "name", label: "Zone" }, { key: "cidr", label: "Subnet" }]);
  renderTable("#policy", META.policy, [{ key: "source", label: "Allowlisted source" }, { key: "role", label: "Role" },
    { key: "units", label: "Units" }, { key: "function_codes", label: "FCs" }, { key: "holding_writes", label: "HR writes" }, { key: "coil_writes", label: "Coil writes" }]);
  document.getElementById("extIp").innerHTML = META.hosts.filter((h) => !["10.10.1.10", "10.10.4.11"].includes(h.ip))
    .map((h) => `<option value="${esc(h.ip)}">${esc(h.ip)} ${esc(h.host)} [${esc(h.zone)}]</option>`).join("");
  renderRegs();
}

function renderRegs() {
  const dev = document.getElementById("regDev").value, kind = document.getElementById("regKind").value;
  renderTable("#regs", META.registers[dev][kind], [
    { key: "addr", label: "Addr" }, { key: "ref", label: "Ref" }, { key: "name", label: "Name" }, { key: "desc", label: "Description" },
    { key: "unit", label: "Unit" }, { key: "scale", label: "Scale" }, { key: "default", label: "Default" },
    { key: "eng_min", label: "Eng. range", render: (x, r) => r.eng_min === undefined ? "" : `${r.eng_min}-${r.eng_max}` },
    { key: "hmi_write", label: "HMI writable", render: (x) => x ? "yes" : "" },
  ], { empty: "None for this device." });
}

// ------------------------------------------------------------------ wiring
document.addEventListener("click", async (ev) => {
  const t = ev.target;
  if (t.dataset.coil) writePoint(t.dataset.coil, Number(t.dataset.val));
  if (t.dataset.sp) {
    const v = parseFloat(document.getElementById(`sp-${t.dataset.sp}`).value);
    if (Number.isNaN(v)) return toast("enter a number");
    writePoint(t.dataset.sp, v);
  }
  if (t.dataset.sim) {
    if (t.dataset.sim === "reset" && !confirm("Reset the live plant?")) return;
    await api("/api/sim", { method: "POST", body: { action: t.dataset.sim } });
    toast(t.dataset.sim); refreshPlant(true);
  }
  if (t.dataset.run) {
    ev.preventDefault();
    const r = await api(`/api/runs/${encodeURIComponent(t.dataset.run)}`);
    renderResult(r);
    window.scrollTo(0, 0);
  }
});

async function main() {
  META = await api("/api/meta");
  document.getElementById("scSel").innerHTML = META.scenarios.map((s) => `<option value="${esc(s.key)}">${esc(s.title)}</option>`).join("");
  mitBoxes("#scMits", [], "sc");
  STATE = await api("/api/state");
  mitBoxes("#liveMits", STATE.mitigations, "live");
  renderScenarioInfo();
  renderNetwork();
  document.getElementById("extIp").value = STATE.ext_ip;

  document.getElementById("scSel").addEventListener("change", renderScenarioInfo);
  document.getElementById("showTruth").addEventListener("change", renderValues);
  document.getElementById("trendSel").addEventListener("change", renderTrend);
  document.getElementById("evKind").addEventListener("change", renderEvents);
  document.getElementById("regDev").addEventListener("change", renderRegs);
  document.getElementById("regKind").addEventListener("change", renderRegs);
  document.getElementById("setSpeed").addEventListener("click", async () => {
    await api("/api/sim", { method: "POST", body: { action: "speed", speed: Number(document.getElementById("speed").value) } });
    toast("speed set");
  });
  document.getElementById("applyMits").addEventListener("click", async () => {
    const r = await api("/api/mitigations", { method: "POST", body: { mitigations: checkedMits("live") } });
    toast("live mitigations: " + (r.mitigations.join(", ") || "none"));
  });
  document.getElementById("setExt").addEventListener("click", async () => {
    const r = await api("/api/network/client", { method: "POST", body: { ip: document.getElementById("extIp").value } });
    toast(`external clients now appear as ${r.ext_ip} (${r.zone})`);
  });
  const runMsg = document.getElementById("runMsg");
  document.getElementById("runFast").addEventListener("click", async (e) => {
    e.target.disabled = true; runMsg.textContent = "running 3 simulated hours plus baseline...";
    try {
      const r = await api("/api/scenarios/run", { method: "POST", body: { key: document.getElementById("scSel").value, mitigations: checkedMits("sc"), mode: "fast" } });
      renderResult(r); runMsg.textContent = `done, run ${r.id}`; renderRuns();
    } catch (err) { runMsg.textContent = err.message; }
    e.target.disabled = false;
  });
  document.getElementById("runLive").addEventListener("click", async () => {
    const r = await api("/api/scenarios/run", { method: "POST", body: { key: document.getElementById("scSel").value, mitigations: checkedMits("sc"), mode: "realtime" } });
    runMsg.textContent = `started on the live plant (mitigations ${r.mitigations.join(", ") || "none"}); watch the Plant tab. Raise the speed to 60x or 300x to see it unfold.`;
  });
  document.getElementById("stopLive").addEventListener("click", async () => {
    const r = await api("/api/scenarios/stop", { method: "POST" });
    runMsg.textContent = r.id ? `stopped, report ${r.id}` : "no real-time scenario running"; renderRuns();
  });
  document.getElementById("runMatrix").addEventListener("click", async () => {
    await api("/api/matrix/run", { method: "POST" });
    const timer = setInterval(async () => { if (!(await renderMatrix())) clearInterval(timer); }, 2000);
  });

  initTabs((id) => {
    current = id;
    if (id === "scenarios") renderRuns();
    if (id === "matrix") { renderMatrix(); renderLog(); }
  });
  every(2000, () => {
    if (current === "plant") refreshPlant(false).catch((e) => console.error(e));
    if (current === "matrix") renderLog().catch(() => {});
  });
}
main().catch((e) => toast(e.message));
})();
