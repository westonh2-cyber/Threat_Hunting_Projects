# CLAUDE.md — Threat_Hunting_Projects

Written threat-hunt investigations. Documentation, not code — six markdown
reports and a README index.

**Status:** stable. Last commit 2025-12-23.

## Contents

`Discovered_pivoting_and_exfil_of_financial_and_secrets.md`,
`Suspected_intrustion_of_VM.md`, `ThreatHunt_SupportTool_Misdirection.md`,
`Threat_Hunt_Scenario_TOR.md`, `Threat_Hunt_Unauthorized_TOR_Use.md`.

Note `Suspected_intrustion_of_VM.md` carries a typo in the filename. Renaming it
breaks any external link to it; leave it unless asked.

## Report structure

Each report documents one threat event with: the adversary's (or simulated bad
actor's) steps, Indicators of Compromise and log artifacts, the relevant
Microsoft Defender for Endpoint telemetry tables, the KQL queries used for
detection and correlation, and validation plus analyst commentary.

Match that structure when adding a report. The analyst commentary is what makes
these worth reading — a report that lists queries without reasoning does not fit.

## Note

`Discovered_pivoting_and_exfil_of_financial_and_secrets.md` has "secrets" in the
filename and will surface in secret scans. It contains investigation narrative,
not credentials.
