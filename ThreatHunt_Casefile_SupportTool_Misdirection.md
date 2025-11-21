## Introduction
This case study documents a full, end-to-end threat-hunting investigation into suspicious activity identified on the endpoint **gab-intern-vm**. What initially appeared to be a routine remote support interaction quickly revealed a chain of actions that did not align with legitimate troubleshooting behavior. As the investigation unfolded, a clear pattern emerged, one involving staged tamper indicators, host reconnaissance, persistence mechanisms, and attempted outbound data transfer.

### Starting Point
The hunt began with several early warning signs across the environment. During the first half of October, multiple machines in the department were observed spawning processes directly from the **Downloads** directory. This was an uncommon and high-risk behavior that immediately warranted further inspection. On top of this, several endpoints exhibited a cluster of files containing similar keywords such as **“desk,” “help,” “support,”** and **“tool.”**

The overlap in filenames and execution sources suggested a shared origin or coordinated activity rather than isolated user behavior. The fact that multiple **intern-operated machines** were among the affected systems further narrowed the scope and raised the possibility of targeted misuse, credential exposure, or social engineering.

Based on this initial intelligence, **gab-intern-vm** emerged as the most active and anomalous endpoint. The host displayed the earliest and most complete sequence of suspicious events, making it the logical pivot point for building a full behavioral timeline.

The purpose of this write-up is:  
1. **Demonstrate an applied, structured threat-hunting methodology**—from the first anomalous indicator to the complete reconstruction of attacker activity.  
2. **Showcase my ability to analyze, correlate, and narratively explain complex host telemetry** using Microsoft Defender for Endpoint and Azure Log Analytics as my primary investigative tools.

This report serves as a comprehensive casefile of the activity discovered on **gab-intern-vm**, detailing the attacker’s misdirection-based theme (“support tool” assistance), their step-by-step execution flow, and the evidence that substantiated each investigative finding. The final outcome reflects practical threat-hunting tradecraft grounded in real visibility, logic, and analytical reasoning.

## Scenario Overview
The activity uncovered on **gab-intern-vm** centered around a pattern of actions that, at first glance, resembled a remote support or IT troubleshooting session. However, the sequence, timing, and intent of these operations deviated significantly from legitimate administrative behavior. Instead of resolving a user issue, the operator conducted a methodical progression of reconnaissance, capability testing, persistence placement, and simulated data staging.

The behavior followed a clear and deliberate flow:

- **Initial foothold** using PowerShell executed from the Downloads directory  
- **Attempts to mask intent** through staged Defender tamper artifacts  
- **Rapid data probing**, including clipboard access  
- **Host and user enumeration** to understand the operating environment  
- **Drive and storage identification** to locate potential data of interest  
- **Network and DNS resolution checks** to validate outbound reachability  
- **Session, process, and privilege discovery** to assess available access  
- **Staging of collected information** into a compressed archive  
- **Outbound HTTP attempts** consistent with upload or exfiltration testing  
- **Placement of persistence mechanisms** via scheduled tasks and autorun keys  
- **Creation of a misleading “support chat” log** intended to justify the activity

Every action aligned with a recognizable stage of an intrusion kill chain, but delivered under the guise of a benign “support tool” narrative. The operator’s use of familiar terms such as *support*, *help*, *desk*, and *tool*, combined with file naming patterns and shortcut artifacts, suggested intentional misdirection designed to obscure the true purpose of the activity.

Through log correlation across multiple data sources in Microsoft Defender for Endpoint and Azure Log Analytics—particularly `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, and `DeviceRegistryEvents`—a complete timeline of the intrusion was reconstructed. This overview sets the stage for the detailed flag-by-flag breakdown and the full analytical timeline presented in the sections that follow.

## Full Timeline of Observed Activity

| Time (UTC) | Analytic Finding | Stage of Intrusion | Event / Artifact |
|------------|------------------|--------------------|------------------|
| **12:22** | Initial Host Identification | Initial Scope Identification | Host selected for investigation after anomalous activity surfaced → **gab-intern-vm** |
| **12:22** | Suspicious Script Execution | Initial Execution | Script launched from Downloads using bypassed execution policy → `SupportTool.ps1` |
| **12:34** | Tamper-Like Artifact Creation | Defense Deception | Fake Defender tamper indicator created and accessed → `DefenderTamperArtifact.lnk` |
| **12:50** | Clipboard Access Detected | Data Probe | PowerShell used to read clipboard contents → `Get-Clipboard` |
| **12:51** | Session Enumeration Activity | Session Discovery | User session inspection via `qwinsta` / `query session` |
| **12:52** | Privilege Enumeration | Privilege Discovery | Group membership and privilege check using `whoami /groups` |
| **12:53** | Storage Surface Enumeration | Storage Mapping | Disk and volume information queried via `wmic logicaldisk` |
| **12:55** | Outbound Connectivity Validation | Connectivity & Egress Validation | First outbound network test observed → `www.msftconnecttest.com` |
| **12:56** | Runtime Application Inventory | Runtime Inventory | Active process list queried → `tasklist.exe` |
| **12:58** | Recon Artifact Staging | Staging & Bundling | Archive created for potential collection → `C:\Users\Public\ReconArtifacts.zip` |
| **12:59** | Outbound Data Transfer Attempt | Exfiltration Attempt | HTTPS request to external host → `100.29.147.161` |
| **13:01** | Scheduled Task Persistence Added | Persistence (Primary) | Recurring execution mechanism created → `SupportToolUpdater` |
| **13:01–13:02** | Autorun Key Persistence Added | Persistence (Fallback) | Registry-based autorun persistence created → `RemoteAssistUpdater` |
| **13:02** | Narrative Artifact Creation | Cover Tracks / Misdirection | Deceptive support-themed log created → `SupportChat_log.lnk` |

## Analytic Finding 1 — Starting Point Identification

### **Objective**
Determine which endpoint should serve as the primary focus of the investigation by identifying systems that executed suspicious support-themed files from the Downloads directory during the early-October activity window. The goal is to isolate the earliest and most relevant host tied to the initial execution of potentially unauthorized tooling.

### **Finding**
The endpoint **gab-intern-vm** emerged as the strongest candidate for the investigation starting point. This system showed:

- A **support-themed executable** within the Downloads folder  
- File naming patterns matching early intelligence (“support,” “tool”)  
- Activity occurring within the **October 1–15** timeframe  
- Alignment with indicators suggesting **intern-operated systems** were affected  
- Early artifacts later correlated with subsequent stages of the intrusion  

Among all hosts evaluated, **gab-intern-vm** demonstrated the clearest combination of temporal alignment, keyword-matching file names, and execution sourcing from Downloads.

### **Evidence**
Reviewing file activity from October 1–15 revealed:

- A file matching **`support` + `tool`** naming patterns existed in the Downloads directory on **gab-intern-vm**  
- The file’s presence directly aligned with organizational intel pointing toward support-themed tooling  
- Other intern-associated hosts displayed partial matches, but none presented the same consistency or timing  
- This endpoint was the earliest to show such activity, making it the logical pivot for deeper investigation  

### **Query Used**
```kql
let Start = datetime(2025-10-01);
let End   = datetime(2025-10-15);
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where FileName contains "support"
  and FileName contains "tool"
  and FolderPath contains "Download"
| where DeviceName contains "intern"
| project TimeGenerated, SHA256, DeviceName, FileName, FolderPath

https://github.com/westonh2-cyber/Threat_Hunting_Projects/blob/9312445c0bbc292caea585c0ae5fd0be6266e533/Screenshots/vm_discovery.png
