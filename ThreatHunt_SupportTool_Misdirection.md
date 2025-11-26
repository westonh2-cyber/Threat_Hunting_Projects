# Table of Contents

- [Introduction](#introduction)
- [Scenario Overview](#scenario-overview)
- [Full Timeline](#full-timeline-of-observed-activity)

## Analytic Findings
- [Starting Point - Identification](#starting-point---identification)
- [Finding 1 — Initial Execution Detection](#analytic-finding-1--initial-execution-detection-entry-point-identification)
- [Finding 2 — Tamper-Like Artifact Creation](#analytic-finding-2--tamper-like-artifact-creation-defense-deception)
- [Finding 3 — Clipboard Probe](#analytic-finding-3--clipboard-probe-quick-data-check)
- [Finding 4 — Session Recon](#analytic-finding-4--session-recon-active-user--session-enumeration)
- [Finding 5 — Storage Surface Mapping](#analytic-finding-5--storage-surface-mapping-logical-disk-enumeration)
- [Finding 6 — Connectivity--name-resolution-check](#analytic-finding-6--connectivity--name-resolution-check-dns--network-reachability)
- [Finding 7 — Interactive Session Discovery](#analytic-finding-7--interactive-session-discovery-user--session-awareness-checks)
- [Finding 8 — Runtime Application Inventory](#analytic-finding-8--runtime-application-inventory-process--service-enumeration)
- [Finding 9 — Privilege Surface Check](#analytic-finding-9--privilege-surface-check-identity--group-enumeration)
- [Finding 10 — Proof-of-Access & Egress Validation](#analytic-finding-10--proof-of-access--egress-validation-outbound-reachability--data-capture-readiness)
- [Finding 11 — Bundling--staging-artifacts](#analytic-finding-11--bundling--staging-artifacts-reconartifactszip-creation)
- [Finding 12 — Outbound Transfer Attempt](#analytic-finding-12--outbound-transfer-attempt-simulated-exfiltration-to-external-host)
- [Finding 13 — Scheduled Re-Execution Persistence](#analytic-finding-13--scheduled-re-execution-persistence-supporttoolupdater-task)
- [Finding 14 — Autorun Fallback Persistence](#analytic-finding-14--autorun-fallback-persistence-remoteassistupdater-registry-run-key)
- [Finding 15 — Planted Narrative Artifact](#analytic-finding-15--planted-narrative-artifact-supportchat_loglnk)

## MITRE Sections
- [MITRE ATT&CK Mapping Table](#mitre-attck-mapping-table)
- [MITRE Summary by Tactic](#mitre-summary-by-tactic)
- [MITRE ATT&CK Narrative](#mitre-attck-narrative)

## Recommendations & Wrap-Up
- [After-Action Recommendations](#after-action-recommendations)
- [Summary](#summary)
- [Conclusion](#conclusion)


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

## Starting Point - Identification

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
```
### **Query Result**
<img width="1412" height="235" alt="vm_discovery" src="https://github.com/user-attachments/assets/f0247d46-722d-4e5e-b5af-d2f37e6eca0f" />

## Analytic Finding 1 — Initial Execution Detection (Entry Point Identification)

### **Objective**
Detect the earliest anomalous execution that could represent an entry point into the system. The goal is to identify activity that deviates from normal user behavior and anchors the intrusion timeline.

### **Finding**
The first confirmed anomalous execution occurred on **gab-intern-vm**, where the intern-operated account **g4bri3lintern** launched a script named **SupportTool.ps1** from the Downloads directory. The script was executed using:
`-ExecutionPolicy Bypass`

This behavior deviated significantly from expected baseline activity. The naming convention (e.g., *support*, *tool*) also aligned with indicators observed on other affected machines, marking this as the earliest actionable point in the intrusion chain.

Because this event involved both **execution policy bypassing** and **support-themed script names**, it was identified as the true **entry point** for the threat hunt.

### **Evidence**
On October 9th at around 12:22 P.M.:

- Process activity showed direct execution of `SupportTool.ps1`  
- The file originated from the user’s **Downloads** directory  
- The responsible account was an **intern**, matching early scoping intel  
- Multiple parent processes (CMD/PowerShell) were observed initiating script execution  
- A command-line argument extraction revealed the **first suspicious parameter**, confirming intentional script invocation  

This execution was the earliest evidence of suspicious tooling and became the foundation for reconstructing the attack sequence.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents 
| where TimeGenerated between(start .. end)
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "SupportTool.ps1"
| where InitiatingProcessFileName has_any ("cmd.exe","powershell.exe","python.exe","wscript.exe","cscript.exe")
| extend FirstParam = extract(@"(\s+[-/]{1,2}[A-Za-z0-9\-_]+)", 1, ProcessCommandLine)
| where isnotempty(FirstParam)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FirstParam
| order by TimeGenerated asc
```
### **Query Result**
<img width="1162" height="235" alt="Flag_1" src="https://github.com/user-attachments/assets/c89af505-4b4c-4eb7-9f0f-e8704b48254e" />

### **Why This Matters**
Accurately identifying the first anomalous execution is critical because it:

- Establishes the **true origin** of the intrusion  
- Ensures the investigation follows the correct **parent/child process chain**  
- Prevents misalignment in the activity timeline  
- Enables accurate scoping of impacted accounts and systems  
- Forms the baseline for all subsequent analysis  

This analytic finding anchored the investigation and established **gab-intern-vm** as the starting point for the intrusion storyline.

## Analytic Finding 2 — Tamper-Like Artifact Creation (Defense Deception)

### **Objective**
Identify activity intended to simulate security tampering or mislead defenders into believing that Microsoft Defender for Endpoint (MDE) or local protection mechanisms were disabled or manipulated. The goal is to determine whether the actor intentionally placed deceptive artifacts designed to alter the investigative narrative.

### **Finding**
Shortly after the initial suspicious script execution, the actor created and accessed a decoy file named **`DefenderTamperArtifact.lnk`** on **gab-intern-vm**. This artifact mimicked the behavior of a legitimate Defender tampering event but contained no actual configuration changes. The execution chain indicated:

- A PowerShell command *referencing* `Set-MpPreference -DisableRealtimeMonitoring $true`, but  
- The command was never executed as a system modification—only **written as plain text** to a file  
- Immediately afterward, a **shortcut (.lnk)** file referencing this staged artifact appeared in the user’s *Recent Items* directory  
- The `.lnk` file was opened by **Explorer.exe**, signaling intentional user interaction consistent with staging and misdirection

These elements show the actor was attempting to **plant evidence**, not actually disable Defender.

### **Evidence**
Telemetry from `DeviceFileEvents` and `DeviceProcessEvents` revealed:

- A PowerShell command generating a *fake* tamper instruction:
Write-Output 'Set-MpPreference -DisableRealtimeMonitoring $true' |
Out-File -FilePath 'C:\Users\Public\DefenderTamperArtifact.txt' -Encoding ASCII -Append

- This text file was quickly followed by the creation of a shortcut:
C:\Users<profile>\AppData\Roaming\Microsoft\Windows\Recent\DefenderTamperArtifact.lnk
- The initiating process was:
Explorer.exe
- No corresponding Defender tamper events were found in MDE, confirming the action was staged

This sequence demonstrates deliberate deception aimed at shaping the investigative narrative.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-15);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName contains "tamper"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, FolderPath
```
### **Query Result**
<img width="1400" height="318" alt="Flag_2" src="https://github.com/user-attachments/assets/f262e802-5fc3-477d-b5ee-f84d352732d7" />

### **Why This Matters**
The discovery of this staged tamper artifact is critical because it demonstrates a clear intent by the actor to **manipulate the interpretation of the incident**. By planting a file that resembles a Defender tampering event, the actor:

- Attempts to **mislead analysts** into thinking real security controls were modified  
- Creates **false indicators of compromise**, complicating triage  
- Crafts a narrative to justify future suspicious actions as “support” or “troubleshooting”  
- Seeks to waste analyst time by redirecting investigation into non-existent tampering  
- Exhibits tradecraft aligned with **deception and misdirection**, not accidental misuse  

Recognizing this deception early ensures the investigation remains focused on facts rather than fabricated artifacts and prevents analysts from losing time to false leads.

## Analytic Finding 3 — Clipboard Probe (Quick Data Check)

### **Objective**
Identify brief, opportunistic attempts to access transient data sources—specifically clipboard contents—that may contain sensitive information such as passwords, tokens, notes, or recently copied data. These actions often occur early in intrusions, before deeper reconnaissance or persistence is established.

### **Finding**
On **gab-intern-vm**, the actor executed a short-lived PowerShell command designed to quietly probe the system clipboard. The command:
"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"
This action executed within milliseconds and captured **no output**, indicating the actor’s goal was simply to determine **whether clipboard contents existed**, not necessarily to steal them at this stage. Clipboard enumeration is a well-known attacker behavior during early “quick win” checks for credentials or sensitive text.

### **Evidence**
Using a restricted time window around suspicious activity, telemetry revealed:

- The command was executed under the intern account  
- The process ran in a **single-threaded apartment (STA)** PowerShell context, required for clipboard APIs  
- The actor suppressed errors and output using `try { … } catch { }` and `| Out-Null`  
- This behavior appeared as part of a sequence of rapid reconnaissance actions (query session, qwinsta, net use, ipconfig, etc.)  

Clipboard access attempts in close proximity to other environmental probes strongly indicate **intentional data sampling**.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName contains "clip.exe"
 or ProcessCommandLine has_any (
    "clip","Get-Clipboard","Set-Clipboard"
)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

### **Query Result**
<img width="1367" height="311" alt="Flag_3" src="https://github.com/user-attachments/assets/5911e2a9-1920-4835-85ba-1ab9796dbd69" />

### **Why This Matters**
Clipboard harvesting is a high-value reconnaissance technique because it provides attackers with an immediate chance to obtain:

- Passwords copied from password managers  
- MFA codes  
- Notes containing credentials  
- URLs, tokens, or internal system paths  
- Sensitive text the user recently interacted with  

Even if nothing is captured, the attempt itself confirms:

- The actor is performing **quick-win data discovery**  
- They are assessing whether the user’s clipboard is a viable exfiltration source  
- The activity fits into a broader pattern of **rapid situational awareness gathering**  
- The intrusion is progressing beyond initial execution and into **targeted reconnaissance**

Detecting clipboard probing early helps analysts identify an attacker’s intent, stage of operation, and potential risk of credential theft or data exposure.

## Analytic Finding 4 — Session Recon (Active User & Session Enumeration)

### **Objective**
Detect reconnaissance activity used to identify which users are logged in, which sessions are active, and whether interactive access is present. Attackers commonly enumerate session information early to determine:

- Who is currently using the machine  
- Whether an elevated or privileged session is available  
- Whether lateral movement or session hijacking is viable  

### **Finding**
During the reconnaissance phase, the actor executed commands consistent with user and session enumeration on **gab-intern-vm**. The most notable sequence included:

`"cmd.exe" /c qwinsta`
`"cmd.exe" /c query session`

These commands reveal:

- Which Windows sessions exist  
- Whether users are active, disconnected, or idle  
- Associated session IDs  
- Session types (console, RDP, etc.)

Telemetry showed the actor querying session state. This is a strong behavioral indicator of **session awareness reconnaissance**, a precursor to privilege escalation or interactive takeover attempts.

### **Evidence**
Within the active intrusion window:

- Both `qwinsta` and `query session` were executed sequentially  
- The commands originated from `cmd.exe`, triggered via PowerShell  
- The same parent process ID was shared with other reconnaissance actions (ipconfig, net use, wmic)  
- The actor conducted this check immediately after clipboard probing and initial system reconnaissance  

The tight timing shows this was part of a **systematic information-gathering routine**.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where ProcessCommandLine has_any ("qwinsta", "query session", "quser")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

### **Query Result**
<img width="1165" height="270" alt="Flag_4" src="https://github.com/user-attachments/assets/496c900c-7a4b-4373-a1ad-83a648e0a748" />

### **Why This Matters**
Session enumeration provides attackers with critical insight into:

- Which users are logged in  
- Whether privileged accounts are active  
- Which sessions could be hijacked or observed  
- Whether remote interactive access is possible  

This type of recon is a known precursor to:

- Privilege escalation  
- Credential theft  
- Lateral movement  
- Interactive remote access  

Because the actor executed these commands immediately after other reconnaissance actions, it confirms an intentional effort to map **who is present on the system** and **what level of access they may have**. Identifying session recon early helps defenders understand attacker intent and prevent escalation paths before they are exploited.

## Analytic Finding 5 — Storage Surface Mapping (Logical Disk Enumeration)

### **Objective**
Identify reconnaissance activity used to enumerate local or network storage surfaces, including mounted drives, share paths, free space, and overall storage capacity. Attackers commonly perform this step to locate potential data repositories and assess whether the system holds valuable information worth collecting or staging.

### **Finding**
During mid-intrusion reconnaissance on **gab-intern-vm**, the actor enumerated all logical disks using:

`"cmd.exe" /c wmic logicaldisk get name,freespace,size`

This command returns:

- Drive letters (C:, D:, network-mounted drives)  
- Free space available  
- Total size of each volume  

This provides an immediate overview of potential data locations and available room for staging artifacts (e.g., ZIP archives or exfil bundles). The enumeration occurred shortly after session recon and clipboard probing, aligning with the attacker’s structured reconnaissance workflow.

### **Evidence**
Telemetry showed:

- The command was executed at **2025-10-09T12:51:18Z**  
- It originated from `cmd.exe`, launched by PowerShell  
- The event appeared between other environmental recon commands (`net use`, `ipconfig`, `qwinsta`)  
- The timing and structure indicate a systematic sweep of system resources  

This aligns with behavior seen in intrusion playbooks where storage awareness is needed before creating compressed archives or identifying data storage targets.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where ProcessCommandLine contains "wmic"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**
<img width="1387" height="272" alt="Flag_5" src="https://github.com/user-attachments/assets/6bea5f63-ec05-443c-8896-d6930d477c74" />

### **Why This Matters**
Session enumeration provides attackers with critical insight into:

- Which users are logged in  
- Whether privileged accounts are active  
- Which sessions could be hijacked or observed  
- Whether remote interactive access is possible  

This type of recon is a known precursor to:

- Privilege escalation  
- Credential theft  
- Lateral movement  
- Interactive remote access  

Because the actor executed these commands immediately after other reconnaissance actions, it confirms an intentional effort to map **who is present on the system** and **what level of access they may have**. Identifying session recon early helps defenders understand attacker intent and prevent escalation paths before they are exploited.


## Analytic Finding 6 — Connectivity & Name Resolution Check (DNS + Network Reachability)

### **Objective**
Identify attempts to verify network connectivity, DNS resolution functionality, and outbound communication capability. These actions help an attacker confirm whether the system can reach external hosts—information critical for command-and-control, exfiltration tests, staged upload workflows, or external telemetry beacons.

### **Finding**
During the intrusion on **gab-intern-vm**, the actor executed network resolution commands intended to validate outbound DNS and general connectivity. The most relevant activity identified was an execution of:

`"cmd.exe" /c nslookup helpdesk-telemetry.remoteassist.invalid`


This command checks:

- Whether DNS queries are properly resolving  
- Whether the host can make outbound connections  
- Whether a fabricated domain (here, a “remote support”-themed fake domain) returns any information  

The use of a **nonexistent, support-themed test domain** strongly suggests the actor was validating whether they could perform *external* lookups under the guise of a support workflow.

The initiating parent process was confirmed to be:

`powershell.exe`


which matches the same parent responsible for numerous other recon and validation commands in this time window.

### **Evidence**
Event telemetry showed:

- The nslookup command was executed shortly after clipboard, session, and storage recon  
- The domain queried (`helpdesk-telemetry.remoteassist.invalid`) matches the attacker’s misdirection theme  
- The command was run by `cmd.exe`, but initiated from **PowerShell**, indicating a scripted workflow  
- The DNS query served as a lightweight connectivity check—as later confirmed by successful outbound HTTPS reachability events (Flag 10)

This action aligns with early-stage attacker behavior used to ensure that DNS functionality and external communication paths are operational.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where ProcessCommandLine contains "nslookup"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1357" height="238" alt="Flag_6" src="https://github.com/user-attachments/assets/78783be5-e796-451c-91a3-0ca015022549" />

### **Why This Matters**

Storage surface mapping is a strong indicator of an attacker preparing for data discovery or exfiltration. By enumerating logical disks, the actor can:

- Identify where sensitive data might reside  
- Determine whether large files or archives can be created  
- Locate user-mounted network shares  
- Understand the system’s storage layout for staging artifacts  

This activity typically occurs before data collection or archive creation. In this case, the logical disk check directly preceded the creation of **ReconArtifacts.zip**, confirming that the actor was evaluating storage before bundling collected material. Detecting this step provides defenders with insight into the attacker’s intent and operational progression.

## Analytic Finding 7 — Interactive Session Discovery (User & Session Awareness Checks)

### **Objective**
Identify attempts to enumerate active or interactive user sessions on the host. Attackers perform this reconnaissance to determine:

- Which users are logged in  
- Whether privileged accounts are active  
- Whether an interactive session could be hijacked  
- Whether the system is safe to run additional tooling without immediate user detection  

### **Finding**
On **gab-intern-vm**, the actor executed commands specifically designed to enumerate active Windows sessions. The observed commands included:

`"cmd.exe" /c query session`
`"cmd.exe" /c qwinsta`


Both utilities return information about:

- Current logged-in users  
- Session IDs and session states  
- Whether sessions are active, disconnected, or idle  
- Whether a console or RDP session is present  

Telemetry confirmed that these commands shared the same **InitiatingProcessUniqueId: `2533274790397065`**, linking them to the same PowerShell-driven reconnaissance chain used throughout the intrusion.

The execution timestamp for the primary session enumeration event was:

**2025-10-09T12:51:44Z**

Right around the time all of the other suspicious activity was taking place.

### **Evidence**
Key observations from log telemetry:

- The commands originated from `cmd.exe` but were triggered by **PowerShell**, consistent with scripted recon  
- Session enumeration occurred immediately after clipboard probing and environment discovery  
- The same initiating process was responsible for multiple recon commands, indicating a coordinated reconnaissance script  
- The actor appeared to be checking whether any interactive sessions were present that could be leveraged or monitored  

This step is a known behavioral precursor to privilege escalation or lateral movement planning.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where ProcessCommandLine has_any ("query session", "qwinsta", "quser")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

### **Query Result**

<img width="1308" height="420" alt="Flag_7" src="https://github.com/user-attachments/assets/228556eb-624d-4033-b0ec-7ff92274e864" />

### **Why This Matters**
Session discovery is a pivotal step in understanding attacker intent, because it reveals whether the actor is preparing for:

- Session hijacking  
- Privilege escalation  
- Credential theft opportunities  
- Timing their activity around user presence  
- Identifying privileged interactive sessions  

The actor’s deliberate execution of `query session` and `qwinsta`, paired with the shared initiating process ID, demonstrates a systematic attempt to map **who is currently on the machine** and **what access levels they may have**.  

This behavior, especially when combined with clipboard probing and network recon, signals a transition from passive observation to **active decision-making about privilege and opportunity**—a key escalation point in the intrusion chain.

## Analytic Finding 8 — Runtime Application Inventory (Process & Service Enumeration)

### **Objective**
Identify attempts to enumerate running applications, background processes, and system services. This step allows an attacker to understand what defenses, monitoring agents, or high-value applications are active at the time of intrusion.

### **Finding**
During the reconnaissance phase on **gab-intern-vm**, the actor executed **`tasklist.exe`**, a built-in Windows utility that enumerates all currently running processes. The observed command was:

`tasklist.exe`


This action produces a comprehensive snapshot including:

- Process names  
- PIDs  
- Memory usage  
- Session associations  
- Running user context  

Telemetry indicated this enumeration occurred shortly after network, session, and storage recon—clearly forming part of a structured information-gathering workflow.

### **Evidence**
The runtime application inventory event showed:

- Executed under the same PowerShell-initiated recon chain as prior findings  
- Occurred within the same minute-level window as other reconnaissance commands  
- Provided the actor with visibility into:
  - Defender components  
  - Endpoint monitoring agents  
  - Active business-critical applications  
  - Privileged system processes  

This sequence aligns with multi-stage reconnaissance activity where attackers validate what defenses and processes are present before attempting persistence or data staging.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName =~ "tasklist.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1412" height="256" alt="Flag_8" src="https://github.com/user-attachments/assets/6913482c-73c1-495b-aaf6-65efd60258d1" />

### **Why This Matters**
Enumerating running processes is a foundational reconnaissance technique because it allows attackers to:

- Identify security tooling that may detect or block their actions  
- Determine whether EDR, antivirus, or monitoring agents are active  
- Locate high-value applications and services of interest  
- Understand system load and user activity patterns  
- Inform decisions about persistence methods and follow-on actions  

In this intrusion, `tasklist.exe` was launched immediately after other recon steps (clipboard probing, session checks, DNS/network validation). This timing confirms the actor was building a **complete operational picture** of the system before moving into staging, exfiltration testing, and persistence creation.

Detecting runtime inventory behavior helps defenders map attacker intent and intervene before deeper compromise occurs.

## Analytic Finding 9 — Privilege Surface Check (Identity & Group Enumeration)

### **Objective**
Identify attempts to determine the privileges, group memberships, and security context of the current user. Attackers perform this to assess whether:

- The current account holds elevated privileges  
- Privilege escalation is necessary  
- Specific group memberships allow lateral movement  
- The session provides adequate permissions for staging or exfiltration activities  

### **Finding**
On **gab-intern-vm**, the actor executed:

`"cmd.exe" /c whoami /groups`


This command enumerates:

- The full group membership of the current user  
- Privilege-associated roles (e.g., Administrators, Remote Desktop Users, Backup Operators)  
- Token-level privilege indicators  
- Whether the account is subject to administrative restrictions  

The event occurred at **2025-10-09T12:52:14Z**, immediately following session enumeration commands and preceding network connectivity testing—showing a deliberate investigator-style escalation of reconnaissance.

The initiating process that triggered this command shared the same **InitiatingProcessUniqueId: 2533274790397065** used across previous recon steps, confirming consistency in the execution chain.

### **Evidence**
Telemetry confirmed:

- The command was launched from PowerShell via `cmd.exe`  
- The actor performed this check *after* identifying logged-in users and sessions  
- No privilege escalation attempts occurred immediately afterward—suggesting the actor used this step to verify whether the intern account provided meaningful access  
- The privilege set was likely used to plan subsequent persistence and data staging steps  

Privilege reconnaissance is a critical step that bridges environmental scanning with operational decision-making.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where ProcessCommandLine contains "whoami /groups"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1407" height="346" alt="Flag_9" src="https://github.com/user-attachments/assets/30595743-4c9e-429e-a203-f970cb09abb4" />

### **Why This Matters**
Privilege enumeration is a key inflection point in an intrusion. By running `whoami /groups`, an attacker can determine:

- Whether the current account has administrative or sensitive privileges  
- Whether escalation is necessary for their objectives  
- Which ACL-protected resources may be accessible  
- Whether persistence mechanisms will succeed under the current token  
- Opportunities for lateral movement based on group membership  

In this case, the actor executed this command in the middle of a tightly timed recon sequence. This establishes clear intent: they were not “exploring” or “troubleshooting”—they were strategically evaluating privilege posture before continuing with artifact staging, exfiltration attempts, and persistence creation.

Detecting privilege surface checks helps defenders recognize when reconnaissance transitions from discovery to mission-oriented planning.

## Analytic Finding 10 — Proof-of-Access & Egress Validation (Outbound Reachability & Data Capture Readiness)

### **Objective**
Identify activity that both validates outbound network reachability and demonstrates the actor’s ability to observe, capture, or stage host data for potential exfiltration. Attackers often combine outbound connectivity checks with proof-of-access artifacts to ensure they can remove data if needed.

### **Finding**
On **gab-intern-vm**, the actor performed an outbound connectivity test by generating a network request to an external Microsoft connectivity validation domain:

`www.msftconnecttest.com`


The event occurred at:

**2025-10-09T12:55:05Z**

Telemetry classified the action as:

`ActionType: ConnectionSuccess`


This domain is legitimately used by Windows network stack diagnostics, but in this case, it was triggered during a sequence of attacker-driven reconnaissance and staging steps—not by system processes.

The outbound test confirmed:

- DNS resolution was functioning  
- HTTPS connectivity over port 443 was available  
- The system could reach external destinations without filtering or egress restrictions  

This event directly preceded file staging (ReconArtifacts.zip) and later exfiltration testing, indicating the actor validated **egress capability** before attempting data movement.

### **Evidence**
The relevant DeviceNetworkEvents logs showed:

- RemoteUrl: `www.msftconnecttest.com`  
- RemoteIP: *(Microsoft-owned address)*  
- Port: 443  
- InitiatingProcessCommandLine: `"powershell.exe"`  
- The event aligned with a chain of scripted reconnaissance activities  
- Outbound connectivity validation was completed before the actor tested an actual external upload (`httpbin.org`, Flag 12)

The timing and context confirm this was not a passive system event, but an intentional egress verification.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where RemoteUrl contains "msftconnecttest"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine, ActionType
| order by TimeGenerated asc
```

### **Query Result**

<img width="1445" height="243" alt="Flag_10" src="https://github.com/user-attachments/assets/46be7427-844e-4fd3-8f59-6d72684e0309" />

### **Why This Matters**
Outbound connectivity validation is a pivotal step in an attacker’s workflow because it confirms whether data can leave the network successfully. By reaching out to `www.msftconnecttest.com`, the actor validated:

- DNS resolution  
- Firewall egress permissions  
- TLS/HTTPS outbound capability  
- Network path availability for exfiltration  

This type of check is especially suspicious when performed:

- Immediately after system reconnaissance  
- Prior to artifact staging  
- Outside normal Windows auto-detection patterns  
- From user-initiated PowerShell, not system processes  

In this case, the outbound connection occurred **minutes before the attacker created ReconArtifacts.zip and attempted an upload to 100.29.147.161 (`httpbin.org`)**.

This sequence shows intent: the attacker was preparing the network path for exfiltration. Detecting this behavior provides defenders with a clear escalation point in the intrusion timeline.

## Analytic Finding 11 — Bundling & Staging Artifacts (ReconArtifacts.zip Creation)

### **Objective**
Identify the moment the attacker consolidated collected information into a single location or package. Bundling artifacts is a preparatory step for exfiltration, enabling an attacker to efficiently move data off-host or test upload mechanisms.

### **Finding**
Shortly after completing reconnaissance and outbound connectivity checks, the actor created a ZIP archive named:

`ReconArtifacts.zip`

The file was dropped into a highly accessible public directory:

C:\Users\Public\


The timestamp of the creation event was:

**2025-10-09T12:58:00Z** *(rounded from event logs)*

This file path is notable because `C:\Users\Public\` is:

- Writable by standard users  
- Readable by all local accounts  
- Commonly abused by attackers for staging shared or temporary data  
- Seldom used by legitimate applications for sensitive output  

The timing aligns with the structured intruder workflow: reconnaissance → outbound validation → **artifact bundling** → exfil attempt.

### **Evidence**
Event telemetry identified:

- FileName: `ReconArtifacts.zip`  
- FolderPath: `C:\Users\Public\`  
- ActionType: File creation / modification events consistent with archive generation  
- InitiatingProcessFileName: likely `powershell.exe` or `cmd.exe` (from narrative chain)  
- Occurring immediately before the outbound transfer attempt to `httpbin.org`  

This strongly indicates the attacker packaged reconnaissance outputs (clipboard probes, session info, storage mapping results, etc.) for exfiltration.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName contains "zip"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1382" height="316" alt="Flag_11" src="https://github.com/user-attachments/assets/3506ff35-193b-4942-a804-b66ae9f0329d" />

### **Why This Matters**
Bundling collected data into a single archive is one of the clearest indicators of imminent exfiltration. By creating `ReconArtifacts.zip`, the attacker demonstrated:

- **Intent to consolidate reconnaissance outputs**  
- **Preparation for transfer** to an external system  
- **Awareness of host storage layouts** (having previously enumerated logical disks)  
- **A shift from reconnaissance to operational execution**  

Attackers rarely create ZIP archives casually; the action almost always precedes:

- Data exfiltration  
- Lateral movement (staging for transfer to another host)  
- Persistence-related artifact caching  

This event, appearing just before the attempted upload to `httpbin.org`, represents a **pivotal escalation** from information gathering to attempted data theft. Recognizing staging behavior like this enables defenders to intervene before exfiltration is successful.

## Analytic Finding 12 — Outbound Transfer Attempt (Simulated Exfiltration to External Host)

### **Objective**
Detect attempts to move collected data off-host or validate whether the environment permits outbound uploads. Attackers frequently test exfiltration channels before attempting a full data transfer, often using benign external endpoints to avoid immediate detection.

### **Finding**
Shortly after bundling reconnaissance data into `ReconArtifacts.zip`, the actor attempted an outbound HTTPS connection to an external service commonly used for testing uploads:

`httpbin.org`

The associated IP observed in telemetry was:

`100.29.147.16`1

This connection was logged at:

**2025-10-09T13:00:40Z**

The initiating process was:

`powershell.exe`


This behavior strongly aligns with exfiltration testing. `httpbin.org` offers endpoints capable of receiving uploads and returning structured responses—making it a known tool for validating outbound POST capabilities without using attacker-controlled infrastructure.

### **Evidence**
DeviceNetworkEvents showed:

- RemoteUrl: `httpbin.org`  
- RemoteIP: `100.29.147.161`  
- RemotePort: 443  
- ActionType: `ConnectionAttempt` / `ConnectionSuccess`  
- InitiatingProcessCommandLine: `"powershell.exe"`  

This connection immediately followed the creation of `ReconArtifacts.zip`, indicating:

- The actor likely intended to test whether the file could be uploaded  
- If successful, the next step would have been transferring staged data  

The event represents a clear transition from reconnaissance and staging to **active outbound data movement**.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1321" height="247" alt="Flag_12" src="https://github.com/user-attachments/assets/a9c8ec4b-e4e0-4f77-ac56-ffd305653762" />

### **Why This Matters**
Outbound transfer attempts are one of the most critical detection points in an intrusion. This particular event matters because:

- It occurred **immediately after** reconnaissance data was bundled into `ReconArtifacts.zip`  
- It used a service (`httpbin.org`) commonly leveraged for **testing exfiltration pipelines**  
- It confirmed the attacker’s ability to reach external networks via HTTPS  
- It demonstrated an intention to move data off the system  
- It marked a shift from passive reconnaissance to **active data theft behavior**

Stopping or detecting this step can prevent further data exposure, allowing defenders to intervene before real exfiltration occurs. Early identification of such exfiltration tests provides crucial insight into attacker intent and helps prioritize response actions.

## Analytic Finding 13 — Scheduled Re-Execution Persistence (SupportToolUpdater Task)

### **Objective**
Identify mechanisms created by the actor to ensure their tooling automatically re-executes at future login events or system reuse. Scheduled tasks are a common attacker persistence technique because they are stealthy, reliable, and survive user logoff or reboot.

### **Finding**
After completing reconnaissance and simulated exfiltration testing, the actor established persistence on **gab-intern-vm** by creating a scheduled task named:

`SupportToolUpdater`

This task was configured to re-trigger the attacker’s tooling, ensuring continued execution without requiring manual user action. The appearance of this custom task—especially with a support-themed name—fits the adversary’s pattern of blending into IT workflows while maintaining long-term access.

The task was discovered via telemetry showing:

- FileName: `schtasks.exe`
- ProcessCommandLine containing:  

`/Create /TN SupportToolUpdater`

- Initiating Process: `powershell.exe`
- Execution Time: shortly after recon and exfil attempts, during the transition into persistence activity

This marks one of the clearest signs of malicious intent in the intrusion.

### **Evidence**
Event logs revealed:

- The attacker invoked `schtasks.exe` to **create** a new scheduled task  
- The task name (`SupportToolUpdater`) aligns with the narrative theme of a “support tool”  
- The process execution followed artifact staging and outbound transfer attempts  
- The event shared lineage with the same PowerShell-driven execution chain seen across prior steps  
- No legitimate administrative maintenance or IT workflows matched this task name or creation timing  

This activity fits the MITRE ATT&CK technique **T1053 — Scheduled Task/Job**.

### **Query Used**
```kql
let start = datetime(2025-10-09);
let end   = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "SupportToolUpdater"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1383" height="240" alt="13" src="https://github.com/user-attachments/assets/b76d1fe2-a218-4e61-8cf2-322ebf89df9a" />

### **Why This Matters**
Scheduled tasks are one of the most reliable and widely abused persistence mechanisms. This finding is significant because:

- `SupportToolUpdater` was **intentionally named to appear legitimate**, blending into a support narrative  
- The task guarantees **re-execution** of attacker tooling after reboot or sign-in  
- It links directly to the attacker’s staged artifacts and previous activity  
- The persistence mechanism demonstrates the actor planned **continued access**, not just opportunistic exploration  
- This behavior transitions the intrusion from reconnaissance and testing into **established foothold**  

Identifying this scheduled task is critical because it highlights the moment the attacker moved from probing the environment to **ensuring long-term operational capability**. Without detection, this persistence mechanism would have allowed repeated execution of malicious scripts under the guise of a support tool.

## Analytic Finding 14 — Autorun Fallback Persistence (RemoteAssistUpdater Registry Run Key)

### **Objective**
Identify lightweight, user-scope persistence mechanisms designed to re-launch attacker tooling at logon. When attackers establish scheduled tasks (primary persistence), they often deploy a secondary or “fallback” persistence method to ensure continuity if the main mechanism fails or is removed.

### **Finding**
Following the creation of the scheduled task `SupportToolUpdater`, telemetry indicated the presence of a secondary persistence mechanism: a **Run key value** named:

`RemoteAssistUpdater`

Although the registry table did not return the event (as noted in the exercise instructions), the provided intelligence confirmed this value existed under a user-scope autorun location such as:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`


This aligns with the attacker’s operational pattern:

- Use of support-themed naming conventions (“SupportTool”, “RemoteAssist”, etc.)
- Persistence established immediately after reconnaissance and exfil tests
- Redundancy added through multiple re-execution mechanisms

The creation of the `RemoteAssistUpdater` Run key further reinforces the actor’s intent to maintain **ongoing access** to the compromised intern workstation.

### **Evidence**
Although the registry key was not surfaced directly in `DeviceRegistryEvents`, the exercise’s intelligence provided the confirmation required:

- Registry Value Name: `RemoteAssistUpdater`
- Persistence Scope: User Logon (HKCU Run Key)
- Behavioral Link: Mirrors attacker tool branding (“Assist”, “Support”)
- Sequence Position: Immediately after scheduled task creation, consistent with fallback persistence tradecraft

Combined with the scheduled task, this Run key forms a layered persistence model.

### **Query Used**
*(Registry events did not surface during the hunt, but the standard detection query—shown below—is included for completeness.)*

```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName contains "RemoteAssistUpdater"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```


This aligns with the attacker’s operational pattern:

- Use of support-themed naming conventions (“SupportTool”, “RemoteAssist”, etc.)
- Persistence established immediately after reconnaissance and exfil tests
- Redundancy added through multiple re-execution mechanisms

The creation of the `RemoteAssistUpdater` Run key further reinforces the actor’s intent to maintain **ongoing access** to the compromised intern workstation.

### **Evidence**
Although the registry key was not surfaced directly in `DeviceRegistryEvents`, the exercise’s intelligence provided the confirmation required:

- Registry Value Name: `RemoteAssistUpdater`
- Persistence Scope: User Logon (HKCU Run Key)
- Behavioral Link: Mirrors attacker tool branding (“Assist”, “Support”)
- Sequence Position: Immediately after scheduled task creation, consistent with fallback persistence tradecraft

Combined with the scheduled task, this Run key forms a layered persistence model.

### **Query Used**
*(Registry events did not surface during the hunt, but the standard detection query—shown below—is included for completeness.)*

```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName contains "RemoteAssistUpdater"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### **Why This Matters**
Autorun registry keys are one of the most common persistence techniques because they:

- Execute automatically at every user logon  
- Require minimal permissions to create  
- Blend easily with legitimate software entries  
- Provide attackers with reliable, repeated access  

The `RemoteAssistUpdater` value is significant because:

- It mirrors the attacker’s social engineering theme (“remote assist,” “support tool”)  
- It acts as **redundant persistence**, ensuring the actor’s tooling runs even if the scheduled task is removed  
- It demonstrates the attacker has shifted from reconnaissance to **long-term foothold establishment**  
- It represents a lightweight but highly effective persistence mechanism favored in real-world intrusions  

The presence of this Run key confirms persistent intent and strengthens the case that the actor planned to revisit the host repeatedly—not just perform one-off reconnaissance.

## Analytic Finding 15 — Planted Narrative Artifact (SupportChat_log.lnk)

### **Objective**
Identify user-facing artifacts intentionally created by the actor to manipulate the investigative narrative. These may include fake logs, staged “support” files, or explanatory documents meant to justify suspicious activity or disguise malicious behavior as legitimate troubleshooting.

### **Finding**
During the final phase of the intrusion, the actor created a shortcut file named:

`SupportChat_log.lnk`

This artifact was discovered in the user’s **Recent Items** directory, indicating it had been manually opened or interacted with:

`C:\Users<user>\AppData\Roaming\Microsoft\Windows\Recent\SupportChat_log.lnk`

The naming convention mimics a chat transcript or helpdesk conversation, matching the attacker’s broader deception technique of blending malicious actions beneath a fabricated support scenario. The timing of this artifact—created near the end of the intrusion and after persistence was established—strongly suggests it was meant to **justify prior activity** or provide a false explanation for suspicious tooling observed on the system.

### **Evidence**
Hunt telemetry and exercise intelligence showed:

- FileName: `SupportChat_log.lnk`  
- FolderPath: User’s Windows Recent directory  
- InitiatingProcessFileName: `Explorer.exe` (confirming it had been opened)  
- The artifact appeared directly after persistence mechanisms were configured  
- No legitimate support workflows or IT processes produced this type of file  

The `.lnk` file was clearly staged to appear as a benign log from a support interaction, reinforcing the actor’s misdirection strategy used across the intrusion.

### **Query Used**
*(The Recent Items directory is captured historically via file events. Query includes time scoping for completeness.)*

```kql
let start = datetime(2025-10-09T12:49:00Z);
let end   = datetime(2025-10-10T12:00:00Z);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| where FileName contains "SupportChat_log.lnk"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### **Query Result**

<img width="1431" height="322" alt="Flag_15" src="https://github.com/user-attachments/assets/febd91b9-57fe-4376-9d99-0e3e108b9c6b" />

### **Why This Matters**
Planted artifacts are one of the clearest indicators of intentional deception inside an intrusion. `SupportChat_log.lnk` matters because:

- It attempts to **rewrite the narrative**, making malicious actions appear to be part of a support session  
- It is manually opened, confirming deliberate interaction  
- It aligns with earlier deception artifacts (e.g., DefenderTamperArtifact)  
- It signals the attacker is concerned about being discovered  
- It may mislead inexperienced analysts into believing suspicious actions were legitimate  

This behavior demonstrates a high level of intentionality and awareness. The actor did not simply run malicious commands—they attempted to **control the interpretation** of their activity.

In real-world intrusions, narrative manipulation is a tactic used by advanced threat actors to delay detection, frustrate responders, and obscure intent. Detecting this planted artifact is crucial because it exposes the attacker’s attempt to conceal their true objectives.

## MITRE ATT&CK Mapping Table

| Analytic Finding | ATT&CK Tactic | Technique | Technique ID | Description |
|------------------|---------------|-----------|---------------|-------------|
| **0 — Starting Point Identification** | Reconnaissance | Gather Victim Host Information | T1592 | Identifying potential targets and machines of interest from file characteristics and execution patterns. |
| **1 — Initial Execution Detection** | Execution | Command and Scripting Interpreter | T1059 | Execution of PowerShell with flags (`-ExecutionPolicy Bypass`) to run suspicious support-themed scripts. |
| **2 — Tamper Artifact Creation** | Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 (Simulated) | Actor staged fake tamper evidence to mislead investigators about Defender status. |
| **3 — Clipboard Probe (Quick Data Check)** | Collection | Clipboard Data | T1115 | Attempt to read clipboard contents using PowerShell (`Get-Clipboard`). |
| **4 — Session Recon (User/Session Enumeration)** | Discovery | System Owner/User Discovery | T1033 | Commands like `qwinsta` and `query session` enumerate logged-in users and session states. |
| **5 — Storage Surface Mapping** | Discovery | System Information Discovery | T1082 | `wmic logicaldisk` used to enumerate drives, free space, and storage surfaces. |
| **6 — DNS/Connectivity Validation** | Discovery / Command & Control | Application Layer Protocol | T1071 | `nslookup` used to validate DNS resolution and outbound connectivity. |
| **7 — Interactive Session Discovery** | Discovery | Remote System Discovery | T1018 | Determining session availability, active users, and session types for potential hijacking. |
| **8 — Runtime Application Inventory** | Discovery | Process Discovery | T1057 | `tasklist.exe` used to enumerate running applications and services. |
| **9 — Privilege Surface Check** | Discovery | Permission Groups Discovery | T1069.001 | `whoami /groups` used to enumerate user privilege level and group memberships. |
| **10 — Outbound Reachability & Proof-of-Access** | Exfiltration / C2 | Exfiltration Over Web Services | T1567.002 | External connectivity checks to `msftconnecttest.com` preparing for data exfiltration paths. |
| **11 — Bundling & Staging (ReconArtifacts.zip)** | Collection | Archive Collected Data | T1560 | Creating `ReconArtifacts.zip` to consolidate captured data for exfiltration. |
| **12 — Outbound Transfer Attempt (httpbin.org)** | Exfiltration | Exfiltration Over Unencrypted/Encrypted Web Protocol | T1041 / T1567 | Simulated data upload to `httpbin.org` to test exfiltration capability. |
| **13 — Scheduled Re-Execution Persistence** | Persistence | Scheduled Task/Job | T1053.005 | Creation of `SupportToolUpdater` scheduled task ensuring tool re-execution. |
| **14 — Autorun Fallback Persistence** | Persistence | Registry Run Keys/Startup Folder | T1547.001 | Creation of `RemoteAssistUpdater` Run key for user-scope persistence. |
| **15 — Planted Narrative Artifact** | Defense Evasion | Hide Artifacts | T1564 | Actor placed `SupportChat_log.lnk` to mislead responders and shape narrative. |

# MITRE Summary by Tactic

### **Execution**
- `T1059.001` – PowerShell execution via custom support script.

### **Privilege & Session Discovery**
- `T1087`, `T1069`, `T1049`, `T1016` – User, group, session, and network configuration discovery.

### **Defense Evasion**
- `T1036` / `T1036.004` – Decoy artifacts and support-themed misdirection.

### **Credential Access**
- `T1115` – Clipboard content probing.

### **Discovery**
- `T1083`, `T1057` – Storage and process enumeration.
- `T1016` – Network configuration validation.

### **Collection**
- `T1074` – Data staged in ZIP format.

### **Exfiltration**
- `T1567.002`, `T1041`, `T1048` – Outbound channel testing and simulated exfiltration.

### **Persistence**
- `T1053.005` – Scheduled task persistence.
- `T1547.001` – Autorun registry persistence.

---

# MITRE ATT&CK Narrative

The activity observed on **gab-intern-vm** aligns closely with multiple stages of the MITRE ATT&CK framework, particularly within the Execution, Discovery, Persistence, Defense Evasion, and Exfiltration tactics. The following narrative outlines how the attacker’s actions map to ATT&CK techniques and how those behaviors fit into a coherent intrusion chain.

The intrusion began with the execution of a support-themed PowerShell script (`SupportTool.ps1`) delivered and run from the **Downloads** directory. This behavior corresponds to **T1059.001 – PowerShell**, as the actor used command-line parameters (`-ExecutionPolicy Bypass`) to override built-in protections and execute untrusted code.

Immediately following initial execution, the actor conducted a series of **Discovery** activities. This included:

- **Clipboard probing** (`Get-Clipboard`) aligning with **T1115 – Clipboard Data**  
- **Session enumeration** using `qwinsta` and `quser`, aligning with **T1087 / T1033 – Account & System Owner/User Discovery**
- **Privilege inspection** using `whoami /groups`, mapping to **T1069 – Permission Groups Discovery**
- **Storage enumeration** using `wmic logicaldisk`, mapping to **T1083 – File and Directory Discovery**
- **Process enumeration** with `tasklist.exe`, matching **T1057 – Process Discovery**

These actions formed a structured recon phase intended to determine the system’s state, privileges, available data sources, and running defenses.

In parallel, the actor validated outbound connectivity using requests to **`www.msftconnecttest.com`**, blending real-world egress tests into routine system traffic. This activity maps to **T1046 – Network Service Scanning** and **T1016 – System Network Configuration Discovery**, supporting later exfiltration attempts.

The attacker then prepared for data removal through **staging**, compressing reconnaissance artifacts into `ReconArtifacts.zip` under the **Public** directory. This behavior aligns with **T1074 – Data Staged**, indicating intent to consolidate materials for transfer. This was followed by a simulated outbound transfer attempt to external IP **100.29.147.161**, mapping to **T1041 – Exfiltration Over C2 Channel** or **T1567.002 – Exfiltration to Cloud Storage** depending on the categorization used.

Persistence mechanisms were established through a scheduled task named **SupportToolUpdater**, mapping to **T1053.005 – Scheduled Task**, and a backup autorun entry **RemoteAssistUpdater**, mapping to **T1547.001 – Registry Run Keys / Startup Folder**. These dual persistence mechanisms ensured the malicious tooling would continue to run even after reboot or user logon.

Finally, the attacker deployed deceptive artifacts—**DefenderTamperArtifact.lnk** and **SupportChat_log.lnk**—designed to establish a false narrative of remote support assistance. This activity aligns with **T1036 – Masquerading**, as the attacker used naming and placement strategies to disguise malicious intent and mislead analysts.

Overall, the sequence of observed behaviors reflects a deliberate, methodical intrusion workflow involving initial execution, layered reconnaissance, persistence establishment, data staging, exfiltration validation, and deception—each mapping cleanly to well-defined MITRE ATT&CK techniques.

---

# After-Action Recommendations

The investigation into the support-themed intrusion on **gab-intern-vm** revealed several gaps in monitoring, configuration, and user security posture that enabled the attacker to execute reconnaissance, stage artifacts, and establish persistence. The following recommendations outline actionable steps to reduce the likelihood of similar incidents and strengthen endpoint resilience.

---

## 1. Enhance PowerShell Logging and Restrict Execution Policies

### Recommendation
Enable advanced PowerShell logging and prevent unverified scripts from running by default.

### Actions
- Enforce `AllSigned` or `RemoteSigned` execution policies via GPO.
- Enable:
  - Module Logging  
  - Script Block Logging  
  - PowerShell Transcription  
- Forward PowerShell logs to SIEM for real-time alerting.

### Rationale
The attacker used PowerShell with `-ExecutionPolicy` to bypass restrictions. Improved logging and enforcement would allow earlier detection and prevention of unauthorized script execution.

---

## 2. Harden User Download Folders and Block Script Execution

### Recommendation
Prevent execution of scripts directly from user-controlled directories such as `Downloads`.

### Actions
- Enforce WDAC (Windows Defender Application Control) or AppLocker policies:
  - Block `.ps1`, `.bat`, `.cmd` outside approved paths.
- Implement Protected Folders for high-risk directories.

### Rationale
The initial intrusion originated from a script executed directly from the Downloads folder. Blocking execution reduces common user-error attack paths.

---

## 3. Improve Endpoint Protection Configuration and Detection Rules

### Recommendation
Ensure Defender and EDR settings are fully enabled and monitored for tamper-themed behavior.

### Actions
- Enable Tamper Protection.
- Create alerting rules for:
  - Suspicious `.lnk` creation
  - Execution of system-recon commands (`whoami`, `qwinsta`, etc.)
  - Disk enumeration commands (`wmic logicaldisk`)
- Monitor for abnormal scheduled task creation.

### Rationale
The attacker planted fake tamper artifacts and added persistence via scheduled tasks. Improved detection logic would flag these behaviors.

---

## 4. Restrict User Privileges and Enforce Least Privilege

### Recommendation
Limit user rights to reduce the impact of account compromise.

### Actions
- Review membership in local groups (e.g., Users, Remote Desktop Users).
- Standardize least-privilege profiles for intern endpoints.
- Enforce MFA for privileged operations.

### Rationale
The compromised account was able to execute recon commands and persistence actions without elevation. Least privilege would reduce this attack surface.

---

## 5. Improve Network Egress Controls and Monitoring

### Recommendation
Implement stricter control and monitoring of outbound network activity.

### Actions
- Restrict outbound traffic to approved domains.
- Log and alert on:
  - Outbound connections to unknown IPs
  - HTTP traffic to non-corporate servers
- Enable DNS logging and anomaly detection.

### Rationale
The attacker tested outbound connectivity (`msftconnecttest.com`) and attempted exfiltration (`100.29.147.161`). Stronger egress controls would have detected or blocked this.

---

## 6. Monitor for File Staging and Public Directory Usage

### Recommendation
Detect and prevent the staging of large files or archives in public-accessible directories.

### Actions
- Monitor `C:\Users\Public` for new ZIP or data aggregation artifacts.
- Enforce access controls restricting write access to shared directories.
- Implement automated scanning for suspicious archive creation.

### Rationale
The attacker created `ReconArtifacts.zip` in the Public directory, a predictable and writable path. Monitoring this location reduces risk of unnoticed staging.

---

## 7. Strengthen User Security Awareness and Training

### Recommendation
Educate users about risks related to unsolicited support tools and suspicious downloads.

### Actions
- Train users to:
  - Avoid running scripts from Downloads
  - Recognize common social engineering patterns
  - Report unexpected “support” activity
- Provide simulated phishing and support impersonation exercises.

### Rationale
The intrusion leveraged a support/helpdesk theme, a common form of user impersonation. Awareness training can reduce vulnerability to these tactics.

---

## 8. Improve Log Retention Policies for Endpoint Telemetry

### Recommendation
Ensure telemetry retention is long enough to support full forensic investigation.

### Actions
- Extend MDE/EDR retention from the minimum to at least 30–90 days.
- Route logs to SIEM or cloud storage to preserve data for hunts.
- Enable long-term archival for key event types.

### Rationale
Some registry events (e.g., autorun persistence) were missing due to log retention expiration. Extended retention improves investigation fidelity.

---

## 9. Implement Automated Alerting for Persistence Mechanisms

### Recommendation
Deploy monitoring and alerting for scheduled tasks and autorun entries.

### Actions
- Enable detection rules for:
  - `schtasks /Create`
  - Registry modifications under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Enforce baseline comparisons to identify new or modified startup items.

### Rationale
The attacker created `SupportToolUpdater` (scheduled task) and `RemoteAssistUpdater` (autorun). Automated detection helps prevent unnoticed re-entry points.

---

# Summary

By implementing these recommendations—strengthening endpoint controls, improving telemetry, limiting user permissions, and enhancing user awareness—the organization can significantly reduce the likelihood of similar support-themed intrusions and improve detection capabilities across early recon, staging, and persistence phases.

---

# Conclusion

The investigation into the support-themed intrusion on **gab-intern-vm** revealed a deliberate and methodical sequence of attacker actions designed to blend malicious activity into what appeared to be a routine remote-assistance session. By consistently using naming conventions associated with IT support workflows—*SupportTool, RemoteAssistUpdater, SupportChat_log*—the actor effectively masked reconnaissance, staging, and persistence steps behind a plausible operational narrative.

Analysis confirmed that the intrusion progressed through a complete and coherent attack chain:

- Initial access via script execution in an untrusted user directory  
- Host, privilege, and session reconnaissance  
- Storage and runtime enumeration  
- Data staging in a publicly accessible directory  
- Outbound communication testing and simulated exfiltration  
- Multi-layer persistence (scheduled tasks + autorun registry keys)  
- Placement of decoy artifacts intended to justify or mislead  

Throughout the timeline, the attacker demonstrated a strong preference for **living-off-the-land techniques**, leveraging native Windows utilities such as *PowerShell, whoami, qwinsta, WMIC,* and *tasklist*. This approach minimized their detection footprint and aligned closely with early-stage hands-on-keyboard intrusion patterns.

Although the exfiltration attempt did not result in confirmed data loss, the presence of a staged ZIP archive and outbound transfer attempts shows clear intent to extract reconnaissance data. Combined with both primary and fallback persistence mechanisms, the actor was positioned to regain access to the endpoint if left uninterrupted.

Overall, this situation highlights the importance of monitoring user-context script execution, detecting reconnaissance behaviors early, and correlating subtle artifacts such as deceptive log files or naming conventions into a holistic narrative. Effective detection relies not only on individual alerts but on understanding how sequential low-signal events build toward a clearly malicious operational pattern.
