


# CorpHealth — Operations Activity Review (WIP)

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

2025-11-23T03:46:25.5255093Z

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where AccountName != "system" 
| where AccountName != "local service" 
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, FolderPath, InitiatingProcessCommandLine

"powershell.exe" -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAbwBrAGUAbgAtADYARAA1AEUANABFAEUAMAA4ADIAMgA3ACcA 
- Could be a session ID, implant identifier, or C2 handshake value
- Decoded looks like = Write-Output 'token-6D5E4EE08227' 


2025-11-23T03:46:37.9339195Z

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where AccountName != "system" 
| where AccountName != "local service" 
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, FolderPath, InitiatingProcessCommandLine

"cmd.exe" /c echo powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force > ".cli" 
- Excluding folder path from de
