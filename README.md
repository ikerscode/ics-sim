# ics-sim

A simulated drinking water treatment works with its control system, built to study how attacks on
the control system affect safety and availability, and which mitigations actually help.

It has a process model (intake, raw tank, coagulation and filtration, hypochlorite and caustic dosing,
reservoir, distribution pump and network), a scan-cycle PLC exposed over Modbus/TCP on
127.0.0.1:5020, an independent safety instrumented system, an HMI, eight attack scenarios mapped to
MITRE ATT&CK for ICS, seven switchable mitigations and a consequence model that scores every run.
Everything runs locally and the attacks only ever touch this simulator.

## Architecture

```
                         +-----------------------------  HUD (browser) 127.0.0.1:8104  -----------------+
                         |  Plant tab: values, controls, trend   Scenarios tab   Matrix & Log tab       |
                         +------------------------------------------+-------------------------------------+
                                                                    | FastAPI (icssim/server.py)
   real Modbus tools  ---- TCP 127.0.0.1:5020 ---+                  |
   (read_plant.py, nmap,                         |                  v
    mbtget, ...)                                 |   +------------------------------------------------------+
                                                 +-->|  Simulation (sim.py), 0.5 s tick                      |
   simulated hosts:                                  |                                                       |
   CORP-WS-37 192.168.10.37 (IT)  --+                |  Bus.request:  segmentation -> DPI firewall ->       |
   HMI-01 10.10.2.10 (L2)  ---------+--- Modbus ADU->|                PLC comms capacity -> unit 1 / unit 2  |
   EWS-01 10.10.2.20 (L2)  ---------+                |                                                       |
   HIST-01 10.10.3.5 (L3)  ---------+                |  PLC-01 (plc.py)        SIS-01 (sis.py)               |
   SIS-EWS 10.10.4.10 (safety) -----+                |  setpoints in HR,       own LSHH/LSLL + analysers,    |
                                                     |  modes in coils, PID,   trips to safe state            |
   scenario engine (scenarios.py) -> attacker steps  |  alarms, FC 90 program        |                       |
                                                     |        |  outputs  ------------+--> SIS override       |
   HMI-01 (hmi.py) polls via hmi_link (MITM hook) -->|        v                                              |
   operator model reacts to what the HMI shows       |  Plant (process.py, chem.py): ground truth physics     |
   anomaly detector taps PLC + SIS sensors           |        |                                              |
                                                     |        v                                              |
                                                     |  ConsequenceTracker: hazards, availability, quality   |
                                                     +------------------------------------------------------+
                                                       runner.py: fast-forward runs, baseline, matrix
                                                       storage.py: SQLite + Markdown/HTML reports in data/
```

## Quick start

```
./run.sh                      # creates .venv if needed, serves http://127.0.0.1:8104/ and Modbus on 127.0.0.1:5020
```

CLI (from the project directory, with `.venv/bin/python` or the venv activated):

```
python -m icssim list                                   # scenarios, ATT&CK IDs, mitigations
python -m icssim baseline --hours 24                    # 24 h with all mitigations, must stay safe and quiet
python -m icssim run-scenario oldsmar --fast            # fast-forward, no mitigations, report in data/reports/
python -m icssim run-scenario oldsmar --fast --mitigations eng_limits,sis
python -m icssim run-scenario replay_masking            # real time: starts on the running server (watch the HUD)
python -m icssim matrix --write-docs                    # every scenario x mitigation, about 50 s with 2 workers
python -m icssim report                                 # list reports; `report <run-id>` prints one
python -m icssim serve                                  # same as run.sh without the venv setup
python -m icssim docs                                   # regenerate docs/REGISTER_MAP.md
python tools/read_plant.py --watch 2                    # standalone Modbus client, no dependencies
```

Poking the PLC with your own tools (it only listens on localhost):

```
nmap -Pn -p 5020 --script +modbus-discover --script-args modbus-discover.aggressive=true 127.0.0.1
mbtget -r4 -a 0 -n 12 -p 5020 127.0.0.1
```

The `+` in `+modbus-discover` makes nmap run the script on a non-standard port. It finds unit 1
(PLC-01) and unit 2 (SIS-01). External TCP clients are treated as the simulated host chosen on the
Matrix & Log tab (default LAB-CLIENT 10.10.2.50 on the supervisory LAN). With the firewall on, that host
is not allowlisted, so your tools time out. Switch it to EWS-01 and they work again.

Tests: `.venv/bin/python -m pytest -q` (68 tests, about 30 s).

## HUD tour

The HUD has three tabs and every core feature has its own button.

- **Plant**: process values as the HMI sees them, with ground truth next to them so masking and
  spoofing are visible. There are buttons for every pump, mode and the outlet valve, a setpoint table
  where each write goes out as a Modbus write from HMI-01 (so the firewall and limits apply), one trend
  chart with a picker and alarm thresholds, active alarms, live mitigation toggles, speed, pause, reset,
  alarm acknowledge, SIS reset and PLC restart, the consequence scorecard, and the event log
  (alerts, alarms, attack steps, hazards, SIS trips, operator actions).
- **Scenarios**: pick a scenario (summary, ATT&CK tags, attacker, expected results, case study) and the
  mitigations, then "Run fast-forward" (3 simulated hours plus a baseline, a few seconds) or "Run
  real-time on live plant" (watch it on the Plant tab, then "Stop real-time" to write the report). It
  shows the result scorecard against the baseline, the detection table and the timeline, plus past runs
  with HTML and Markdown report links.
- **Matrix & Log**: "Run matrix" fills the scenario x mitigation table, with baseline false-alert counts
  and links to matrix.html and matrix.md. Below that are the live Modbus transaction log (source, zone,
  unit, function code, address, value, allowed/blocked/dropped and why), the mapping for external TCP
  clients, the Purdue zones and firewall policy, and the register map for both units.

## Terminal HUD

A curses view of the same live API, for working over SSH or from a second terminal. Start the server
with `./run.sh` first, then:

    python -m icssim tui                      # http://127.0.0.1:8104 by default
    python -m icssim tui --url http://127.0.0.1:8104 --once

The views are Plant (HMI values and alarms, refreshed every 2 s), Scenarios, Reports (Enter opens a
run's JSON) and Modbus log. The spec lives in `icssim/tui_spec.py`.

- Keys: `1`-`9` or Tab switch view, Up/Down/PgUp/PgDn move, Enter opens a detail, Esc or Backspace
  goes back, `q` quits.
- Action keys: `f` oldsmar fast-forward with no mitigations, `m` oldsmar with all mitigations,
  `x` run the matrix (asks first), `z` reset the plant (asks first), `a` acknowledge alarms.
- `--once` prints every view as plain text and exits, which suits SSH sessions without a usable
  terminal or scripted checks. It exits 1 if any view cannot reach the server.

## How each requirement is met

| Requirement | Where |
|---|---|
| Deterministic process model, 0.5 s tick, acceleration | `process.py`, `chem.py`, `sim.py`; documented with simplifications in [docs/MODEL.md](docs/MODEL.md) |
| First-order lags, transport delay, noise, dry run overheating, cavitation | `process.py` (`_distribution`, delay line, sample lag, `NoiseStream`) |
| PLC scan logic, hysteresis, chlorine PID, pH control, alarms, auto/manual, setpoints in HR, engineering limits | `plc.py` |
| Modbus/TCP on 127.0.0.1:5020, FC 1/2/3/4/5/6/15/16 with exceptions (plus 17, 43/14, 90) | `modbus.py` (own implementation, see below), `server.py` |
| Register map in docs and HUD | `registers.py` -> [docs/REGISTER_MAP.md](docs/REGISTER_MAP.md) and the Matrix & Log tab |
| Independent SIS with redundant sensors, toggleable | `sis.py`, `Plant.sis_sensors` |
| Hazards, availability, compliance, safety score, time to hazard, cited limits | `consequences.py`, `constants.py`, [docs/REFERENCES.md](docs/REFERENCES.md) |
| Eight ATT&CK-mapped scenarios, real-time or fast-forward, reports vs baseline | `scenarios.py`, `runner.py`, `report.py`, `storage.py` |
| Mitigations toggled individually; matrix from real runs under 2 minutes | `sim.set_mitigations`, `network.py`, `detector.py`, `hmi.py`; `runner.matrix` (about 45-50 s) |
| Event log: Modbus transactions, alarms, detector alerts, SIS trips | `events.py` |
| HUD | `static/index.html`, `static/app.js`, shared `hud.js`/`hud.css` |
| CLI and example client | `icssim/__main__.py`, `tools/read_plant.py` |
| Tests | `tests/` |

pymodbus 3.16 would install on Python 3.14, but the firewall needs to see the exact request bytes and
the simulator needs to route requests through simulated source addresses and zones. A small spec-based
implementation (about 300 lines) made that simpler and removed a dependency.

## Scenarios

| Key | What happens | ATT&CK for ICS |
|---|---|---|
| `setpoint_change` | Phished office PC on a flat network writes CL_SP 1.0 -> 6.0 mg/L | T0888, T0861, T0855, T0836 |
| `oldsmar` | Remote-access session on the HMI PC raises NaOH 100 -> 11 100 ppm (case study numbers) | T0822, T0859, T0823, T0836 |
| `fdi_chlorine` | Control analyser AIT-301 drifts down to 0.2 mg/L at the field link; PID overdoses | T0856, T0832, T0831 |
| `replay_masking` | MITM records and replays HMI telemetry, closes filter feed and forces P-201 in manual; pump runs dry | T0830, T0832, T0815, T0855, T0858, T0831, T0879 |
| `logic_tamper` | FC 90 program upload/download changes the intake hysteresis to 4.9/5.6 m and suppresses RAW_HI | T0845, T0843, T0889, T0878 |
| `modbus_dos` | 2 000 req/s flood from IT starves comms, trips the PLC watchdog, outputs drop | T0814, T0815, T0827, T0826 |
| `sis_bypass` | Compromised EWS sets the SIS maintenance bypass, widens the alarm, raises CL_SP | T0888, T0880, T0837, T0838, T0878, T0836 |
| `insider` | Valid engineer account lowers CL_LO_ALM, switches hypochlorite to manual at 0 L/h | T0859, T0838, T0858, T0836, T0831 |

## Mitigations

| Key | What it does here |
|---|---|
| `sis` | Independent trips on high-high/low-low level, final chlorine and pH; safe state closes the outlet |
| `firewall` | Modbus DPI in front of PLC/SIS: source allowlist, per-role function codes, write-target allowlist, 20 req/s token bucket |
| `segmentation` | Purdue policy: IT and DMZ cannot reach L1; only the safety zone reaches the SIS unit |
| `eng_limits` | PLC rejects out-of-range setpoint writes with exception 03 |
| `detector` | Passive tap: redundant sensor disagreement, dose/flow/residual consistency, mass balance, hysteresis invariant, rate of change, pump protection, pressure loss, SIS bypass, program CRC |
| `integrity` | PLC HMAC-SHA256 telemetry frame (sequence + time), verified by the HMI; flags forged, replayed and stale data |
| `operator` | Attended control room: checks the HMI every 30 s, reacts after 5 min, restores the known-good recipe, takes manual action, goes to site when the view is lost or untrusted |

## Results

The full matrix with times is in [docs/MATRIX.md](docs/MATRIX.md) (regenerate with `python -m icssim matrix --write-docs`).
Some findings:

- No single mitigation covers everything. Segmentation and the firewall stop attacks from the wrong
  place but do nothing against the Oldsmar remote session, the insider or field-level spoofing, because
  those arrive from allowed hosts or never cross the network.
- Engineering limits are cheap and stop every "write a crazy number" attack (setpoint change, Oldsmar,
  the SIS bypass follow-up), but not logic changes, spoofing or a legitimate-looking 0 L/h.
- The SIS prevents every safety hazard it has a sensor for, but it does so by closing the outlet. That
  turns a quality incident into a supply outage, with availability between 22 % and 58 % in those runs.
  It cannot help against the DoS, and it is useless once bypassed.
- The HMAC integrity check is the only control that spots the replay quickly (10 min, the moment replay
  starts). It sees nothing when the PLC itself is fooled (FDI) or reprogrammed.
- The physics-based detector raises an alert in every scenario, with no false alerts in 3 h or 24 h
  baselines, but it only detects. Its replay detection comes late (about 37 min) because closing a valve
  is physically consistent until the pump starts cavitating.
- The attended operator does well when changes are visible and is blind to the replay. That is the point
  of Stuxnet-style masking.

## Safety and isolation

- The HUD and Modbus server bind to 127.0.0.1 only.
- Attack scenarios send Modbus frames into `Simulation.request` in-process, or use simulator hooks for
  field-level effects. They never open sockets and never target any other system. The source IPs are
  labels inside the simulation.
- No exploit code, no malware, no network scanning beyond what you run yourself against localhost.
- Data (SQLite index and reports) stays in `data/` and is gitignored.

## Limitations

- The physics is deliberately simple (see the simplifications list in docs/MODEL.md): perfectly mixed
  tanks, fixed transport delay, simple chlorine demand, 25 degC carbonate equilibrium, one network node.
  Times to hazard show mechanisms and relative differences, not predictions for a real works.
- Plant sizing and tuning were chosen so attacks play out in a three-hour window.
- The PLC comms watchdog is a stylised model. Many modern PLCs would not fault under a read flood.
- The operator is a scripted playbook with fixed reaction times.
- Each matrix cell is a single seed. Results near a threshold (for example the operator saving the FDI
  case) could flip with other seeds or reaction times.
- Firewall DPI checks function codes and write targets but not value ranges. Some commercial ICS
  firewalls can also check values, which would make them behave like the engineering limits here.
- Real-time scenario reports compare against a fast-forward baseline started at the same clock time,
  not against the exact live history.
- The telemetry HMAC is modelled as a PLC feature. Real PLCs rarely offer this; in practice it would come
  from a secure protocol (Modbus/TCP Security with TLS, OPC UA signing) or a bump-in-the-wire device.

## Ideas for extension

- Monte Carlo over seeds and operator reaction times to put confidence intervals on the matrix.
- Modbus/TCP Security (TLS, port 802) as a further mitigation.
- A second PLC and a network model with latency and packet loss.
- Storm and demand events in the scenario timeline, and attacks that time themselves to them.
- Train a small anomaly model on baseline runs and compare it with the rule-based detector.

## References

IEC 62443-3-2 and 62443-3-3; NCSC Cyber Assessment Framework (water sector OES under the NIS
Regulations 2018, DWI as competent authority); NIST SP 800-82 Rev. 3 (2023); MITRE ATT&CK for ICS;
WHO Guidelines for Drinking-water Quality (4th ed. with addenda, 2022); Water Supply (Water Quality)
Regulations 2016; US EPA MRDL (40 CFR 141.65); Ofwat DG2; CISA AA21-042A. Details and which number came
from where are in [docs/REFERENCES.md](docs/REFERENCES.md).
