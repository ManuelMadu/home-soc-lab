# Incident Report 001 - Encoded PowerShell Execution

**Severity:** Medium
**Date/Time detected:** 2026-04-18 11:32 UTC
**Analyst:** Manuel Madubugini
**Detection rule:** T1059.001 - Encoded PowerShell Execution
**Affected host:** DESKTOP-OTH20VH
**Affected user:** labuser

## 1. Preparation
I configured the environment with Sysmon using the SwiftOnSecurity config,
enabled command-line process auditing (Event ID 4688), and set up a Splunk
Universal Forwarder to ship both log sources to my central Splunk instance.
I created a search against `index=win_events` for `EncodedCommand` in
process creation events.

## 2. Identification
My alert fired with 3 matching events. When I reviewed them in Splunk I found:
- Parent process: powershell.exe (interactive session)
- Child: powershell.exe -EncodedCommand <base64 blob>
- I decoded the Base64 (in PowerShell:
  `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b))`)
  and it revealed: `Write-Host 'hello from an attacker'`
- I checked for network connections from the child process (Sysmon Event ID 3)
  and found none
- I checked for file writes (Sysmon Event ID 11) and found none

The decoded command is benign, but the technique matches MITRE T1059.001
and is heavily used by Emotet, Cobalt Strike, and living-off-the-land actors.

## 3. Triage decision
Because the payload is benign and came from an interactive user session on
my lab host, I assessed this as a true positive for the technique but a
false positive for malicious intent. In a production environment I would:
- Pivot on `user` to see other activity in the last 24h
- Pivot on `host` for follow-on Sysmon events (DNS, network, file writes)
- Check EDR for the parent process tree
- Contact the user to verify whether the activity was legitimate

## 4. Containment (hypothetical, for a genuinely malicious case)
If this were a real incident, I would:
- Isolate the host via EDR network-containment
- Disable the user account pending investigation
- Preserve evidence: memory image, Sysmon logs, PowerShell ScriptBlock
  logs (Event ID 4104) if enabled

## 5. Eradication
I would then:
- Kill the offending process tree
- Remove any persistence mechanisms (scheduled tasks, Run keys, services)
  installed by the decoded payload
- Reset credentials for the affected user if compromise were suspected

## 6. Recovery
To recover, I would:
- Re-image the host if rootkit or kernel-level indicators were present,
  otherwise perform a validated clean-up and monitored return to service
- Verify Sysmon, EDR, and the forwarder remain healthy post-recovery

## 7. Lessons learned
From this exercise, I identified several improvements:
- I should enable PowerShell ScriptBlock Logging (Event ID 4104) alongside
  4688. It captures the decoded script content, which would make triage
  much faster.
- I should consider Constrained Language Mode or AppLocker / WDAC policies
  to limit what PowerShell can do for non-admin users.
- I need to tune the detection further: enrich with parent process, exclude
  known-good signed binaries (SCCM, Intune), and add risk scoring when the
  decoded string contains red-flag tokens like `IEX`, `DownloadString`, or
  `FromBase64String`.
