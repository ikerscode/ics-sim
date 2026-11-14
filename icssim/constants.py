"""Regulatory reference values and lab thresholds used by the consequence model.

Every number here is documented with its source in docs/REFERENCES.md. Where a
value is a lab choice rather than a regulatory limit, the comment says so.
"""

# Free chlorine leaving the works (mg/L as Cl2).
CL_MAX = 4.0          # US EPA MRDL is 4.0 mg/L; WHO guideline value is 5 mg/L
CL_MIN = 0.2          # WHO: at least 0.2 mg/L residual at the point of delivery

# pH (UK Water Supply (Water Quality) Regulations 2016, indicator parameter 6.5 - 9.5)
PH_MIN = 6.5
PH_MAX = 9.5
PH_CAUSTIC = 10.5     # lab threshold for "caustic overdose"; WHO notes irritation above pH 11

SODIUM_MAX = 200.0    # mg/L, UK prescribed concentration or value (PCV)
TURBIDITY_MAX = 1.0   # NTU leaving the treatment works (UK indicator value)

PRESSURE_MIN = 1.0    # bar at the critical node, about Ofwat DG2 reference level (10 m head)
DEMAND_MET_FRACTION = 0.95
OUTAGE_GRACE_S = 60.0  # pressure must stay below PRESSURE_MIN this long to count as an outage

# Pump damage model (lab choices, see docs/MODEL.md)
PUMP_DAMAGE_TEMP = 90.0   # deg C
PUMP_DRY_RUN_LIMIT = 30.0  # seconds of cumulative dry running before the seal is assumed failed

# Hazard catalogue: key -> (label, weight in the safety score)
HAZARDS = {
    "tank_overflow": ("Tank overflow", 15),
    "chlorine_overdose": (f"Chlorine overdose (> {CL_MAX} mg/L delivered)", 25),
    "chlorine_underdose": (f"Chlorine underdose (< {CL_MIN} mg/L delivered)", 20),
    "ph_out_of_range": (f"pH outside {PH_MIN}-{PH_MAX} delivered", 15),
    "caustic_overdose": (f"Caustic overdose (pH >= {PH_CAUSTIC} or Na > {SODIUM_MAX:.0f} mg/L)", 30),
    "pump_damage": ("Pump damage (dry run / overheat)", 20),
    "supply_outage": (f"Supply outage (pressure < {PRESSURE_MIN} bar)", 10),
}
HAZARD_FULL_WEIGHT_S = 600.0  # a hazard lasting 10 min or more costs its full weight

MITIGATIONS = ["sis", "firewall", "segmentation", "eng_limits", "detector", "integrity", "operator"]
MITIGATION_LABELS = {
    "sis": "Safety instrumented system",
    "firewall": "Modbus firewall / DPI",
    "segmentation": "Purdue segmentation",
    "eng_limits": "PLC engineering limits",
    "detector": "Process anomaly detector",
    "integrity": "HMI telemetry integrity (HMAC)",
    "operator": "Attended operator",
}
