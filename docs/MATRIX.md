# Scenario x mitigation matrix

Run on 2026-11-14 04:25:46, seed 1, each cell a 3 h fast-forward run with the attack at +30 min. Wall time 40.5 s.

Legend: **HAZARD** = target hazard occurred with no mitigation; **PREVENTED** = target hazard did not occur; **DETECTED** = hazard occurred but the mitigation raised an alert (time to detect from attack start); **not detected** = hazard occurred, no alert from that mitigation. `av` = availability %. Scenarios marked (SIS required) always run with the SIS installed.

| Scenario | none | sis | firewall | segmentation | eng_limits | detector | integrity | operator | all |
|---|---|---|---|---|---|---|---|---|---|
| setpoint_change | **HAZARD** in 32.8 min av 100 | **PREVENTED** (20.6 min) av 28 | **PREVENTED** (0 s) av 100 | **PREVENTED** (0 s) av 100 | **PREVENTED** (60 s) av 100 | **DETECTED** 3.0 min av 100 | not detected av 100 | **PREVENTED** (60 s) av 100 | **PREVENTED** (0 s) av 100 |
| oldsmar | **HAZARD** in 41.4 min av 100 | **PREVENTED** (9.3 min) av 22 | not detected av 100 | not detected av 100 | **PREVENTED** (60 s) av 100 | **DETECTED** 2.0 min av 100 | not detected av 100 | **PREVENTED** (60 s) av 100 | **PREVENTED** (60 s) av 100 |
| fdi_chlorine | **HAZARD** in 95.8 min av 100 | **PREVENTED** (74.4 min) av 58 | not detected av 100 | not detected av 100 | not detected av 100 | **DETECTED** 7.3 min av 100 | not detected av 100 | **PREVENTED** (49.0 min) av 100 | **PREVENTED** (7.3 min) av 100 |
| replay_masking | **HAZARD** in 43.5 min av 39 | **PREVENTED** (39.9 min) av 39 | not detected av 39 | not detected av 39 | not detected av 39 | **DETECTED** 37.5 min av 39 | **DETECTED** 10.0 min av 39 | not detected av 39 | **PREVENTED** (10.0 min) av 39 |
| logic_tamper | **HAZARD** in 61.8 min av 100 | **PREVENTED** (49.8 min) av 44 | **PREVENTED** (0 s) av 100 | not detected av 100 | not detected av 100 | **DETECTED** 90 s av 100 | not detected av 100 | **PREVENTED** (41.5 min) av 84 | **PREVENTED** (0 s) av 100 |
| modbus_dos | **HAZARD** in 82 s av 17 | not detected av 17 | **PREVENTED** (0 s) av 100 | **PREVENTED** (0 s) av 100 | not detected av 17 | **DETECTED** 83 s av 17 | **DETECTED** 6 s av 17 | **DETECTED** 30 s av 80 | **PREVENTED** (0 s) av 100 |
| sis_bypass (SIS required) | **HAZARD** in 32.9 min av 100 | not detected av 100 | **PREVENTED** (0 s) av 28 | **PREVENTED** (0 s) av 28 | **PREVENTED** (60 s) av 100 | **DETECTED** 30 s av 100 | not detected av 100 | **PREVENTED** (60 s) av 100 | **PREVENTED** (0 s) av 100 |
| insider | **HAZARD** in 59.6 min av 100 | **PREVENTED** (48.3 min) av 44 | not detected av 100 | not detected av 100 | **DETECTED** 40 s av 100 | **DETECTED** 3.2 min av 100 | not detected av 100 | **PREVENTED** (60 s) av 100 | **PREVENTED** (40 s) av 100 |

## Baseline false positives (no attack, same horizon)

| Column | Alerts | Hazards | Availability % |
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
