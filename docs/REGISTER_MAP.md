# Modbus register map

Server: Modbus/TCP on 127.0.0.1:5020. Unit 1 = PLC-01, unit 2 = SIS-01 (maintenance interface).
Addresses are 0-based protocol addresses; `Ref` is the classic 1-based reference.
Analogue values are scaled integers: engineering value = raw / scale.
Engineering limits (raw units) are enforced on writes only when the PLC limits are enabled.

Built from icssim/registers.py by `python -m icssim docs`.

## PLC-01 (unit 1): Coils (FC 1 read, FC 5/15 write)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 1 | P101_AUTO | Intake pump P-101 auto mode |  | 1 |
| 1 | 2 | P101_MAN_RUN | Intake pump P-101 manual run command |  | 1 |
| 2 | 3 | FCV101_AUTO | Filter feed valve FCV-101 auto mode |  | 1 |
| 3 | 4 | P201_AUTO | Distribution pump P-201 auto mode |  | 1 |
| 4 | 5 | P201_MAN_RUN | Distribution pump P-201 manual run command |  | 1 |
| 5 | 6 | XV201_OPEN_CMD | Works outlet valve XV-201 open command |  | 1 |
| 6 | 7 | COAG_AUTO | Coagulant dosing DP-101 auto (flow paced) |  | 1 |
| 7 | 8 | CL_AUTO | Hypochlorite dosing DP-301 auto (PID) |  | 1 |
| 8 | 9 | NAOH_AUTO | Caustic dosing DP-302 auto (flow paced + pH trim) |  | 1 |
| 9 | 10 | ALARM_ACK | Write 1 to acknowledge alarms (self-clearing) |  | 1 |
| 10 | 11 | PLANT_ENABLE | Master enable for all PLC outputs |  | 1 |

## PLC-01 (unit 1): Discrete inputs (FC 2)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 10001 | P101_RUNNING | P-101 running feedback |  | 1 |
| 1 | 10002 | P201_RUNNING | P-201 running feedback |  | 1 |
| 2 | 10003 | XV201_OPEN | XV-201 open limit switch |  | 1 |
| 3 | 10004 | P201_CAVITATION | P-201 cavitation detected (vibration) |  | 1 |
| 4 | 10005 | P201_DRY_RUN | P-201 running dry |  | 1 |
| 5 | 10006 | P201_FAULT | P-201 failed (damaged) |  | 1 |
| 6 | 10007 | DP101_RUNNING | Coagulant pump running |  | 1 |
| 7 | 10008 | DP301_RUNNING | Hypochlorite pump running |  | 1 |
| 8 | 10009 | DP302_RUNNING | Caustic pump running |  | 1 |
| 9 | 10010 | ALARM_ACTIVE | Any PLC alarm active |  | 1 |
| 10 | 10011 | SIS_TRIPPED | SIS trip (hardwired status from SIS) |  | 1 |
| 11 | 10012 | SIS_BYPASSED | SIS in maintenance bypass (hardwired status) |  | 1 |
| 12 | 10013 | ENG_LIMITS_ON | Engineering range limits enforced on writes |  | 1 |
| 13 | 10014 | PLC_FAULT | PLC CPU fault / STOP |  | 1 |
| 14 | 10015 | INTEGRITY_ON | Telemetry HMAC frame enabled |  | 1 |

## PLC-01 (unit 1): Input registers (FC 4)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 30001 | LT101 | Raw water tank level | m | 100 |
| 1 | 30002 | LT201 | Clear water reservoir level | m | 100 |
| 2 | 30003 | FT101 | Intake flow | m3/h | 10 |
| 3 | 30004 | FT102 | Filter flow | m3/h | 10 |
| 4 | 30005 | FT201 | Distribution flow | m3/h | 10 |
| 5 | 30006 | AIT101 | Raw water turbidity | NTU | 100 |
| 6 | 30007 | AIT102 | Filtered water turbidity | NTU | 100 |
| 7 | 30008 | AIT301 | Free chlorine, contact outlet (control analyser) | mg/L | 100 |
| 8 | 30009 | AIT302 | pH, contact outlet (control analyser) | pH | 100 |
| 9 | 30010 | AIT303 | Free chlorine, final water | mg/L | 100 |
| 10 | 30011 | AIT304 | pH, final water | pH | 100 |
| 11 | 30012 | PT201 | Network pressure (critical node) | bar | 100 |
| 12 | 30013 | P101_CURRENT | P-101 motor current | A | 10 |
| 13 | 30014 | P101_TEMP | P-101 bearing temperature | degC | 10 |
| 14 | 30015 | P201_CURRENT | P-201 motor current | A | 10 |
| 15 | 30016 | P201_TEMP | P-201 bearing/seal temperature | degC | 10 |
| 16 | 30017 | P201_SPEED | P-201 VFD speed | % | 10 |
| 17 | 30018 | FCV101_POS | FCV-101 position | % | 10 |
| 18 | 30019 | DP101_RATE | Coagulant pump rate | L/h | 10 |
| 19 | 30020 | DP301_RATE | Hypochlorite pump rate | L/h | 100 |
| 20 | 30021 | DP302_RATE | Caustic pump rate | L/h | 10 |
| 21 | 30022 | COAG_DOSE | Calculated coagulant dose | mg/L | 10 |
| 22 | 30023 | CL_DOSE | Calculated hypochlorite dose | mg/L | 100 |
| 23 | 30024 | NAOH_DOSE | Calculated caustic dose | ppm | 1 |
| 24 | 30025 | P201_VIBRATION | P-201 vibration | mm/s | 10 |
| 25 | 30026 | ALARM_WORD | Alarm bits (see ALARM_BITS) |  | 1 |
| 26 | 30027 | SCAN_COUNT | PLC scan counter (mod 65536) |  | 1 |
| 27 | 30028 | PROG_CRC_HI | PLC program CRC32 high word |  | 1 |
| 28 | 30029 | PROG_CRC_LO | PLC program CRC32 low word |  | 1 |
| 29 | 30030 | PLC_STATUS | 0 = RUN, 1 = FAULT/STOP |  | 1 |
| 60 | 30061 | TLM_SEQ_HI | Telemetry frame sequence (high) |  | 1 |
| 61 | 30062 | TLM_SEQ_LO | Telemetry frame sequence (low) |  | 1 |
| 62 | 30063 | TLM_TS_HI | Telemetry frame time, sim seconds (high) |  | 1 |
| 63 | 30064 | TLM_TS_LO | Telemetry frame time, sim seconds (low) |  | 1 |
| 64 | 30065 | TLM_MAC0 | Telemetry HMAC-SHA256 truncated, word 0 |  | 1 |
| 65 | 30066 | TLM_MAC1 | Telemetry HMAC-SHA256 truncated, word 1 |  | 1 |
| 66 | 30067 | TLM_MAC2 | Telemetry HMAC-SHA256 truncated, word 2 |  | 1 |
| 67 | 30068 | TLM_MAC3 | Telemetry HMAC-SHA256 truncated, word 3 |  | 1 |
| 68 | 30069 | TLM_MAC4 | Telemetry HMAC-SHA256 truncated, word 4 |  | 1 |
| 69 | 30070 | TLM_MAC5 | Telemetry HMAC-SHA256 truncated, word 5 |  | 1 |
| 70 | 30071 | TLM_MAC6 | Telemetry HMAC-SHA256 truncated, word 6 |  | 1 |
| 71 | 30072 | TLM_MAC7 | Telemetry HMAC-SHA256 truncated, word 7 |  | 1 |

## PLC-01 (unit 1): Holding registers (FC 3 read, FC 6/16 write)

| Addr | Ref | Name | Description | Unit | Scale | Default | Eng. range | HMI writable |
|---|---|---|---|---|---|---|---|---|
| 0 | 40001 | RAW_LVL_START | P-101 start level (hysteresis low) | m | 100 | 200 | 100..300 | yes |
| 1 | 40002 | RAW_LVL_STOP | P-101 stop level (hysteresis high) | m | 100 | 380 | 250..430 | yes |
| 2 | 40003 | RES_LVL_SP | Reservoir level setpoint | m | 100 | 250 | 150..330 | yes |
| 3 | 40004 | CL_SP | Free chlorine setpoint (contact outlet) | mg/L | 100 | 100 | 50..200 | yes |
| 4 | 40005 | NAOH_SP | Caustic (NaOH) dose setpoint | ppm | 1 | 100 | 0..200 | yes |
| 5 | 40006 | PH_SP | pH trim setpoint | pH | 100 | 780 | 700..850 | yes |
| 6 | 40007 | COAG_BASE | Coagulant base dose | mg/L | 10 | 150 | 0..400 | yes |
| 7 | 40008 | COAG_PER_NTU | Coagulant dose per NTU raw turbidity | mg/L/NTU | 100 | 100 | 0..300 | yes |
| 8 | 40009 | PRESS_SP | Network pressure setpoint | bar | 100 | 300 | 150..400 | yes |
| 9 | 40010 | P201_MAN_SPEED | P-201 manual speed | % | 10 | 850 | 0..1000 | yes |
| 10 | 40011 | FCV101_MAN_POS | FCV-101 manual position | % | 10 | 450 | 0..1000 | yes |
| 11 | 40012 | CL_MAN_RATE | DP-301 manual rate | L/h | 100 | 240 | 0..1000 | yes |
| 12 | 40013 | NAOH_MAN_RATE | DP-302 manual rate | L/h | 10 | 560 | 0..1500 | yes |
| 13 | 40014 | COAG_MAN_RATE | DP-101 manual rate | L/h | 10 | 90 | 0..400 | yes |
| 14 | 40015 | CL_HI_ALM | Final chlorine high alarm | mg/L | 100 | 200 | 100..300 | no |
| 15 | 40016 | CL_LO_ALM | Final chlorine low alarm | mg/L | 100 | 50 | 20..100 | no |
| 16 | 40017 | PH_HI_ALM | Final pH high alarm | pH | 100 | 850 | 800..920 | no |
| 17 | 40018 | PH_LO_ALM | Final pH low alarm | pH | 100 | 700 | 680..750 | no |
| 18 | 40019 | RAW_HI_ALM | Raw tank high level alarm | m | 100 | 420 | 350..450 | no |
| 19 | 40020 | RES_LO_ALM | Reservoir low level alarm | m | 100 | 80 | 50..150 | no |
| 20 | 40021 | PRESS_LO_ALM | Network pressure low alarm | bar | 100 | 150 | 100..250 | no |
| 21 | 40022 | CL_KP | Chlorine PID gain |  | 100 | 30 | 0..500 | no |
| 22 | 40023 | CL_TI | Chlorine PID integral time | s | 1 | 300 | 30..1800 | no |

## SIS-01 (unit 2): Coils (FC 1 read, FC 5/15 write)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 1 | SIS_BYPASS | Maintenance bypass (trip outputs inhibited) |  | 1 |
| 1 | 2 | SIS_RESET | Write 1 to reset a latched trip (only if healthy) |  | 1 |

## SIS-01 (unit 2): Discrete inputs (FC 2)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 10001 | TRIPPED | Trip latched (safe state active) |  | 1 |
| 1 | 10002 | LSHH901 | Raw tank high-high level switch |  | 1 |
| 2 | 10003 | LSLL902 | Reservoir low-low level switch |  | 1 |
| 3 | 10004 | CL_HH | Independent chlorine analyser high-high |  | 1 |
| 4 | 10005 | CL_LL | Independent chlorine analyser low-low |  | 1 |
| 5 | 10006 | PH_HH | Independent pH analyser high-high |  | 1 |
| 6 | 10007 | PH_LL | Independent pH analyser low-low |  | 1 |
| 7 | 10008 | BYPASSED | Bypass active |  | 1 |

## SIS-01 (unit 2): Input registers (FC 4)

| Addr | Ref | Name | Description | Unit | Scale |
|---|---|---|---|---|---|
| 0 | 30001 | AIT901 | SIS free chlorine analyser, final water | mg/L | 100 |
| 1 | 30002 | AIT902 | SIS pH analyser, final water | pH | 100 |
| 2 | 30003 | TRIP_COUNT | Number of trips |  | 1 |
| 3 | 30004 | TRIP_CAUSE | Bitmask of the first-out trip cause (bit order as DIs 1..6) |  | 1 |

## ALARM_WORD bits (IR 25)

| Bit | Alarm |
|---|---|
| 0 | RAW_HI |
| 1 | RAW_LO |
| 2 | RES_HI |
| 3 | RES_LO |
| 4 | CL_HI |
| 5 | CL_LO |
| 6 | PH_HI |
| 7 | PH_LO |
| 8 | TURB_HI |
| 9 | PRESS_LO |
| 10 | P201_OVERTEMP |
| 11 | P201_CAV |
| 12 | P201_DRY |
| 13 | SIS_TRIP |
| 14 | P201_FAULT |
| 15 | NAOH_HI |

## Extra function codes

- FC 17 (0x11) Report Server ID: returns the device name.
- FC 43 / MEI 14 Read Device Identification (basic objects 0-2).
- FC 90 (0x5A) engineering/program service on unit 1, modelled loosely on vendor
  engineering protocols: sub-function 0x01 read program info (CRC32 + name),
  0x02 read program (JSON), 0x10 download program (JSON body). Used by the logic
  tampering scenario (T0889).
