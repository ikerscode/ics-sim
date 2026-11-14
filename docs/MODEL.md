# Process, control and consequence model

This page describes what the simulator computes and, just as important, what it leaves out.
Code references are to `icssim/`.

## Time base

- Fixed tick of 0.5 s of simulated time (`sim.DT`). The PLC scans once per tick, the SIS once per tick,
  the HMI polls every 2 s, the anomaly detector checks every 1 s and the operator model looks every 30 s.
- Live mode steps the same model against the wall clock with an acceleration factor (1x to 600x).
  Fast-forward runs step it in a tight loop, about 10 000 ticks per second on the development laptop.
- Determinism: two pseudo-random streams per seed. Process disturbances (demand noise, storm timing)
  come from one, sensor noise from a fixed table walked from a seed-dependent offset. The same seed gives
  identical demand and raw water in a baseline run and an attack run.

## Plant (`process.py`)

A small works of about 4.3 ML/d (mean demand 180 m3/h).

| Unit | Model |
|---|---|
| P-101 intake pump | Fixed speed, 400 m3/h, first-order flow ramp (5 s). Draws from a river, so it cannot run dry. |
| T-101 raw water tank | 60 m2 x 5.0 m. Volume balance. Anything above 5.0 m spills over the weir and is counted as overflow. |
| FCV-101 filter feed valve | First-order actuator (5 s). Gravity flow `Q = 400 * pos * sqrt(h / 3 m)`. |
| Coagulation + filtration | Removal efficiency `0.6 + 0.385 * min(1, dose/opt)^1.5`, `opt = 10 + 1.2 * raw NTU` mg/L alum. Filtered turbidity follows with a 10 min first-order lag. Each mg/L of alum consumes 0.01 meq/L alkalinity. |
| DP-301 hypochlorite | 12.5 % NaOCl (125 g/L available chlorine), pump max 20 L/h. Dose = rate x strength / flow. Instant chlorine demand `0.5 + 0.1 x NTU` mg/L. |
| DP-302 caustic | 25 % NaOH (320 g/L), pump max 250 L/h. Adds alkalinity (1 mg/L NaOH = 0.025 meq/L) and sodium (0.575 mg Na per mg NaOH). |
| Contact pipe | Plug-flow transport delay of 300 s from dosing point to analysers and reservoir, then a 60 s first-order sample-line lag for AIT-301/302. |
| T-201 clear water reservoir | 60 m2 x 4.0 m. Completely mixed tank: chlorine, alkalinity, sodium and turbidity mixed by mass; chlorine bulk decay 0.03 /h. |
| XV-201 outlet valve | On/off. Closing it isolates the works from the network. |
| P-201 distribution pump | VFD. Head `4.6 bar x speed^2 x (1 - 0.7 x cavitation)` minus network loss `1.4 bar x (Q/300)^2`, pressure lag 15 s, 0.2 bar static when stopped. Delivered flow falls with `sqrt(P / 1.5 bar)` below 1.5 bar. |
| Cavitation / dry run | Cavitation grows linearly as the reservoir drops from 0.6 m to 0.2 m (head loss, current and vibration noise). Below 0.2 m the pump runs dry: no flow, temperature heads to 160 degC with a 60 s time constant. Damage latches at 90 degC or 30 s cumulative dry running. |
| Demand | 24 hourly multipliers (night 0.5, morning peak 1.6, evening peak 1.4), linear interpolation, plus slow AR(1) noise of a few percent. |
| Raw water | Turbidity about 6 NTU with a slow cycle and, for some seeds, a storm peak of 10-22 NTU. Alkalinity 2.58 meq/L +-2 %. |

### Chemistry (`chem.py`)

pH comes from a closed carbonate system charge balance
`Alk = C_T (a1 + 2 a2) + Kw/[H+] - [H+]` with pK1 6.35, pK2 10.33, pKw 14.0 (25 degC), solved by
Newton's method with a warm start. The raw water is a soft, CO2-rich water (C_T 5 mM) chosen so that
the normal caustic dose is 100 ppm, the same unit and number as the Oldsmar HMI, giving pH 7.8.
Without caustic the final water would be pH 6.3. At the pump's maximum caustic rate the final water
goes above pH 11, and the 11 100 ppm setpoint, if it could be delivered, would give pH 13.4.

Because alkalinity and C_T are tracked (they mix linearly) rather than pH (which does not), mixing a
small slug of high-pH water into the reservoir behaves realistically: it is buffered until the
carbonate buffer runs out.

### Sensors

Each field reading is the true value plus Gaussian noise (levels 3 mm, flows 0.5 %, turbidity 2 %,
chlorine 0.01 mg/L, pH 0.01, pressure 0.01 bar, temperature 0.2 degC). The SIS reads independent
instruments with their own noise: LSHH-901 (raw tank >= 4.6 m), LSLL-902 (reservoir <= 0.4 m), AIT-901
(final chlorine) and AIT-902 (final pH).

## PLC (`plc.py`)

Scan sequence: input image, logic, alarms, outputs. Modbus tables are refreshed lazily before each read.

1. Intake hysteresis: P-101 starts at RAW_LVL_START (2.0 m) and stops at RAW_LVL_STOP (3.8 m).
2. Filter feed: flow setpoint = distribution flow + 150 m3/h per metre of reservoir level error, zero if
   the raw tank is below 0.3 m. Valve position from feedforward on the gravity curve plus a PI trim.
3. Coagulant: flow paced, dose = COAG_BASE + COAG_PER_NTU x raw turbidity.
4. Hypochlorite: feedforward (setpoint + estimated demand) times flow, plus a PI trim on the contact
   analyser AIT-301 (Kp 0.3, Ti 300 s, clamped). No dosing without flow.
5. Caustic: flow paced at NAOH_SP ppm with a +-25 % PI trim on contact pH.
6. Distribution: PI on network pressure (3.0 bar). In auto P-201 stops below 0.5 m reservoir level and
   restarts above 0.8 m. In manual it does not. This "manual bypasses the interlock" weakness is
   deliberate and is what the replay scenario abuses.
7. Alarms with a 10 s off-delay into an alarm word; a program can suppress named alarms.
8. Engineering limits (toggle): out-of-range holding register writes get Modbus exception 03.
9. Program: a small JSON document (hysteresis overrides, suppressed alarms) that FC 90 can read and replace.
   Its CRC32 is published in IR 27-28.
10. Comms: 50 requests per scan. Offered load above 10x that for 10 consecutive scans trips the scan
    watchdog. The CPU stops and all outputs drop until a local restart.
11. Telemetry integrity (toggle): every refresh writes a sequence number, a timestamp and a 128-bit
    truncated HMAC-SHA256 over IR 0-29, all holding registers, coils and discrete inputs into IR 60-71.

## SIS (`sis.py`)

Independent sensors and logic, last word on the final elements. Trips (with 2 s delay for switches and
10 s for analysers): raw tank high-high, reservoir low-low, final chlorine >= 3.0 or <= 0.3 mg/L,
final pH >= 9.2 or <= 6.8. Safe state: all dosing off, intake off, outlet XV-201 closed and P-201 off.
The trip latches until a reset with healthy inputs. A maintenance bypass coil on unit 2 inhibits the
outputs.

## Consequence model (`consequences.py`)

Computed from ground truth, never from sensors.

| Hazard | Condition | Score weight |
|---|---|---|
| Tank overflow | raw tank or reservoir above its top | 15 |
| Chlorine overdose | water delivered (> 1 m3/h) with final free chlorine > 4.0 mg/L | 25 |
| Chlorine underdose | water delivered with final free chlorine < 0.2 mg/L | 20 |
| pH out of range | water delivered with pH outside 6.5-9.5 | 15 |
| Caustic overdose | water delivered with pH >= 10.5 or sodium > 200 mg/L | 30 |
| Pump damage | P-201 damage latched (90 degC or 30 s dry running) | 20 |
| Supply outage | network pressure < 1.0 bar for at least 60 s with demand present | 10 |

- Availability = share of time with pressure >= 1.0 bar and delivered flow >= 95 % of demand.
- Water quality compliance = share of delivered volume meeting chlorine 0.2-4.0 mg/L, pH 6.5-9.5,
  turbidity <= 1 NTU and sodium <= 200 mg/L.
- Safety score = 100 minus each hazard's weight scaled by `min(1, duration / 10 min)`.
- Time to hazard = first onset after the attack starts.

Quality hazards only count while water is actually delivered. When the SIS closes the outlet,
contaminated water stays in the reservoir and the cost shows up as lost availability instead.

## Simplifications (known and deliberate)

- One analyser location per quantity, perfect mixing in the reservoir, and a fixed transport delay that
  does not change with flow.
- Chlorine chemistry is "dose minus instant demand" plus first-order decay. No breakpoint
  chlorination, chloramines, temperature effect or HOCl/OCl- speciation; hypochlorite's own effect on
  pH and alkalinity is ignored.
- 25 degC equilibrium constants, closed carbonate system (no CO2 exchange with air), no ionic strength
  correction. Coagulant pH depression is a fixed alkalinity consumption per mg/L.
- Filtration is a single efficiency curve with a lag. No backwash cycles, filter ripening or breakthrough.
- The network is one critical node with a quadratic loss curve. No service reservoirs, leakage, pipe
  bursts or water age. Customers do not "see" the works outlet quality until it leaves the reservoir, but
  the travel time through the network is not modelled.
- Pump thermal model is one first-order temperature. Damage thresholds are lab choices, not
  manufacturer data.
- The PLC's comms limit and watchdog are a stylised version of real behaviour (some older PLCs do fault
  under heavy traffic, many modern ones do not).
- The operator model is a fixed playbook with fixed reaction times; real people are better at spotting
  odd trends and worse at night, under alarm floods or with poor HMI design.
- Numbers such as tank sizes, pump capacities and gains were tuned so that both normal operation and the
  attacks play out inside a three-hour window. They are plausible for a small works but not taken from
  any real site.
