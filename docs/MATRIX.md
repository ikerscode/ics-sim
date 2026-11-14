# Scenario x mitigation matrix

Run on 2026-11-14 18:24:43, seeds 1-5 (5 per cell), each cell a 3 h fast-forward run with the attack at +30 min. 405 runs on 2 workers, wall time 344.4 s (608.2 s of simulation).

Legend: **HAZARD** = target hazard occurred with no mitigation; **PREVENTED** = target hazard did not occur; **DETECTED** = hazard occurred but the mitigation raised an alert (time to detect from attack start); **not detected** = hazard occurred, no alert from that mitigation. `av` = availability %. Scenarios marked (SIS required) always run with the SIS installed.

Each cell shows the majority outcome and how many of the 5 seeds gave it, then the median time and availability with the range over seeds in brackets as [min-max] (no brackets when every seed gave the same number). Times to detect are medians over the seeds that raised an alert. **MIXED** marks a cell where seeds gave different outcomes; ties are reported as the worse outcome. The seed changes demand noise, the storm timing and sensor noise; operator reaction times are fixed.

| Scenario | none | sis | firewall | segmentation | eng_limits | detector | integrity | operator | all |
|---|---|---|---|---|---|---|---|---|---|
| setpoint_change | **HAZARD** 5/5 in 32.5 min [32.4 min-32.8 min] av 100 | **PREVENTED** 5/5 (20.6 min [20.6 min-20.8 min]) av 28 | **PREVENTED** 5/5 (0 s) av 100 | **PREVENTED** 5/5 (0 s) av 100 | **PREVENTED** 5/5 (60 s) av 100 | **DETECTED** 5/5 3.0 min av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (60 s) av 100 | **PREVENTED** 5/5 (0 s) av 100 |
| oldsmar | **HAZARD** 5/5 in 41.9 min [41.4 min-42.4 min] av 100 | **PREVENTED** 5/5 (9.3 min [9.3 min-9.4 min]) av 22 | not detected 5/5 av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (60 s) av 100 | **DETECTED** 5/5 2.0 min av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (60 s) av 100 | **PREVENTED** 5/5 (60 s) av 100 |
| fdi_chlorine | **HAZARD** 5/5 in 95.9 min [95.8 min-96.0 min] av 100 | **PREVENTED** 5/5 (74.4 min [74.2 min-74.5 min]) av 58 | not detected 5/5 av 100 | not detected 5/5 av 100 | not detected 5/5 av 100 | **DETECTED** 5/5 7.3 min [7.3 min-7.4 min] av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (49.0 min) av 100 | **PREVENTED** 5/5 (7.3 min [7.3 min-7.4 min]) av 100 |
| replay_masking | **HAZARD** 5/5 in 43.2 min [43.1 min-43.5 min] av 39 | **PREVENTED** 5/5 (39.5 min [39.5 min-39.9 min]) av 39 | not detected 5/5 av 39 | not detected 5/5 av 39 | not detected 5/5 av 39 | **DETECTED** 5/5 37.3 min [37.1 min-37.6 min] av 39 | **DETECTED** 5/5 10.0 min av 39 | not detected 5/5 av 39 | **PREVENTED** 5/5 (10.0 min) av 39 |
| logic_tamper | **HAZARD** 5/5 in 61.8 min [61.5 min-62.7 min] av 100 | **PREVENTED** 5/5 (50.3 min [49.8 min-51.0 min]) av 45 [44-45] | **PREVENTED** 5/5 (0 s) av 100 | not detected 5/5 av 100 | not detected 5/5 av 100 | **DETECTED** 5/5 90 s av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (42.5 min [41.5 min-43.0 min]) av 87 [84-87] | **PREVENTED** 5/5 (0 s) av 100 |
| modbus_dos | **HAZARD** 5/5 in 82 s av 17 | not detected 5/5 av 17 | **PREVENTED** 5/5 (0 s) av 100 | **PREVENTED** 5/5 (0 s) av 100 | not detected 5/5 av 17 | **DETECTED** 5/5 83 s [82 s-83 s] av 17 | **DETECTED** 5/5 6 s av 17 | **DETECTED** 5/5 30 s av 80 | **PREVENTED** 5/5 (0 s) av 100 |
| sis_bypass (SIS required) | **HAZARD** 5/5 in 32.7 min [32.5 min-32.9 min] av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (0 s) av 28 | **PREVENTED** 5/5 (0 s) av 28 | **PREVENTED** 5/5 (60 s) av 100 | **DETECTED** 5/5 30 s av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (60 s) av 100 | **PREVENTED** 5/5 (0 s) av 100 |
| insider | **HAZARD** 5/5 in 59.5 min [59.3 min-59.6 min] av 100 | **PREVENTED** 5/5 (47.8 min [47.3 min-48.5 min]) av 43 [43-44] | not detected 5/5 av 100 | not detected 5/5 av 100 | **DETECTED** 5/5 40 s av 100 | **DETECTED** 5/5 3.2 min av 100 | not detected 5/5 av 100 | **PREVENTED** 5/5 (60 s) av 100 | **PREVENTED** 5/5 (40 s) av 100 |

## Cells where seeds disagree

None: every cell gave the same outcome for all 5 seeds.

## Compared with the single-seed table (seed 1 only)

No cell's majority outcome differs from its seed 1 outcome.

## Baseline false positives (no attack, same horizon)

Totals over 5 baseline runs per column.

| Column | Alerts | Hazards | Availability % (worst seed) |
|---|---|---|---|
| none | 0 | none | 100.0 |
| sis | 0 | none | 100.0 |
| firewall | 0 | none | 100.0 |
| segmentation | 0 | none | 100.0 |
| eng_limits | 0 | none | 100.0 |
| detector | 0 | none | 100.0 |
| integrity | 0 | none | 100.0 |
| operator | 0 | none | 100.0 |
| all | 0 | none | 100.0 |

## Scenarios

- `setpoint_change`: Unauthorised setpoint change via Modbus write. ATT&CK: T0888 Remote System Information Discovery, T0861 Point & Tag Identification, T0855 Unauthorized Command Message, T0836 Modify Parameter.
- `oldsmar`: Oldsmar-style caustic setpoint raise through a remote HMI session. ATT&CK: T0822 External Remote Services, T0859 Valid Accounts, T0823 Graphical User Interface, T0836 Modify Parameter.
- `fdi_chlorine`: False data injection on the chlorine control analyser. ATT&CK: T0856 Spoof Reporting Message, T0832 Manipulation of View, T0831 Manipulation of Control.
- `replay_masking`: Replay / masking of the HMI view while the process is manipulated (Stuxnet-style). ATT&CK: T0830 Adversary-in-the-Middle, T0832 Manipulation of View, T0815 Denial of View, T0855 Unauthorized Command Message, T0858 Change Operating Mode, T0831 Manipulation of Control, T0879 Damage to Property.
- `logic_tamper`: PLC logic tampering: altered hysteresis causes raw tank overflow. ATT&CK: T0845 Program Upload, T0843 Program Download, T0889 Modify Program, T0878 Alarm Suppression.
- `modbus_dos`: Modbus flood causing loss of view and loss of control. ATT&CK: T0814 Denial of Service, T0815 Denial of View, T0827 Loss of Control, T0826 Loss of Availability.
- `sis_bypass`: SIS bypass followed by process manipulation. ATT&CK: T0888 Remote System Information Discovery, T0880 Loss of Safety, T0837 Loss of Protection, T0838 Modify Alarm Settings, T0878 Alarm Suppression, T0836 Modify Parameter.
- `insider`: Insider with valid credentials stops disinfection. ATT&CK: T0859 Valid Accounts, T0838 Modify Alarm Settings, T0858 Change Operating Mode, T0836 Modify Parameter, T0831 Manipulation of Control.

## Mitigations

- `sis`: Safety instrumented system
- `firewall`: Modbus firewall / DPI
- `segmentation`: Purdue segmentation
- `eng_limits`: PLC engineering limits
- `detector`: Process anomaly detector
- `integrity`: HMI telemetry integrity (HMAC)
- `operator`: Attended operator
