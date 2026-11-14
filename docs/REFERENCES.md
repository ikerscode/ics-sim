# References and where each number comes from

## Water quality and service levels

| Value used | Source | Note |
|---|---|---|
| Chlorine overdose above 4.0 mg/L | US EPA maximum residual disinfectant level (MRDL) for chlorine, 4.0 mg/L as Cl2 (40 CFR 141.65, Stage 1 D/DBP Rule). WHO Guidelines for Drinking-water Quality, 4th ed. incorporating the 1st and 2nd addenda (2022): health-based guideline value for free chlorine 5 mg/L. | The UK regulations set no limit for chlorine. 4.0 mg/L is the stricter of the two published values. |
| Chlorine underdose below 0.2 mg/L | WHO GDWQ (2022) and WHO/WEDC technical notes on drinking water: a free chlorine residual of at least 0.2 mg/L at the point of delivery; at least 0.5 mg/L after 30 min contact at pH < 8 for effective disinfection. | Applied at the works outlet, which is lenient. Real works aim higher. |
| pH 6.5 to 9.5 | The Water Supply (Water Quality) Regulations 2016 (SI 2016/614, England), Schedule 2 indicator parameters, hydrogen ion 6.5-9.5. Same range in the 2018 Wales regulations. DWI guidance on the regulations. | |
| Caustic overdose pH >= 10.5 | Lab threshold. WHO's pH background document notes eye and skin irritation above about pH 11. | Chosen with margin below 11; not a regulatory value. |
| Sodium 200 mg/L | Water Supply (Water Quality) Regulations 2016, Schedule 1 Table B, prescribed concentration or value for sodium. | Caustic dosing raises sodium, so this is a second caustic indicator. |
| Turbidity 1 NTU leaving the works | Water Supply (Water Quality) Regulations 2016, Schedule 2 indicator value for water leaving treatment works (4 NTU applies at consumers' taps). | Used for quality compliance only. |
| Supply pressure 1.0 bar | Ofwat DG2 reference level: 10 m head (about 1 bar) at 9 L/min at the boundary stop tap. | Applied to one modelled critical node. |
| Oldsmar numbers (100 to 11 100 ppm NaOH, 5 Feb 2021, 24-36 h to reach supply) | Pinellas County Sheriff's Office press conference, 8 Feb 2021; CISA Alert AA21-042A "Compromise of U.S. Water Treatment Facility" (Feb 2021). | 2023 press reports quoted the former city manager saying it may have been employee error. The scenario uses the numbers, not the attribution. |

## Security frameworks

- IEC 62443 series, in particular 62443-3-2 (security risk assessment, zones and conduits) and 62443-3-3
  (system security requirements and security levels). The segmentation, firewall and SIS separation
  mitigations follow its zone and conduit model.
- NCSC Cyber Assessment Framework (CAF), used by the Drinking Water Inspectorate as competent authority
  for water sector operators of essential services under the NIS Regulations 2018. The mitigations map
  roughly to objectives B (protecting against attack: B4 system security, B2 identity and access control)
  and C (detecting events: C1 security monitoring, C2 proactive discovery).
- NIST SP 800-82 Rev. 3, Guide to Operational Technology (OT) Security (September 2023). Used for the
  defence-in-depth framing, the Purdue model reference architecture and the note that network scans and
  floods can disrupt older control devices.
- MITRE ATT&CK for ICS (attack.mitre.org), technique IDs listed per scenario in the README and reports.
- Purdue Enterprise Reference Architecture (T. J. Williams, 1992) and ISA-95 for the level numbering.
- Modbus Application Protocol Specification v1.1b3 and Modbus Messaging on TCP/IP Implementation Guide
  v1.0b (Modbus Organization) for the protocol implementation.
- Falliere, Murchu and Chien, "W32.Stuxnet Dossier" (Symantec, 2011) for the replay-and-manipulate
  pattern. Dragos and Mandiant public reports on TRITON/TRISIS (2017) for the SIS bypass pattern.
