# Cyberion Defense Labs — Structured Threat Hunt Report

**Hunt ID:** CDL-HUNT-2026-002  
**Hunt Title:** Proactive Threat Hunt for Adversary Abuse of Background Intelligent Transfer Service (BITS) Jobs  
**Target MITRE ATT&CK Technique:** `T1197` (BITS Jobs)  
**Tactic:** Persistence, Defense Evasion, Command and Control  
**Lead Hunter:** Detection Engineer / Threat Hunter  
**Date Executed:** 2026-10-18  
**Status:** Completed — Ruled Out (Detection Gap Identified & Remediation Proposed)  
**Rule Status:** Explicitly targets technique NOT covered by existing detection rules (PRD Section 4.4 Requirement)

---

## 1. Hunt Hypothesis

> **Hypothesis:**  
> Threat actors who have gained initial foothold in the environment are abusing the Windows Background Intelligent Transfer Service (BITS) via `bitsadmin.exe` or PowerShell `Start-BitsTransfer` to stage payloads, execute lateral binary retrieval, or exfiltrate sensitive files asynchronously, bypassing conventional process-monitoring and egress inspection.

### 1.1 Technical Background & Context
BITS is a legitimate Windows component designed to facilitate asynchronous, prioritized, and throttled transfer of files between machines using idle network bandwidth. Threat groups (including APT40, FIN7, and ransomware affiliates) frequently abuse BITS because transfers execute within the context of the trusted `svchost.exe` service host process. Standard security controls inspecting endpoint process creation often miss child network sockets because `svchost.exe` (holding the BITS service) performs the actual network egress, not the initiating command-line process.

Prior to this hunt, Cyberion Defense Labs possessed **zero Sigma detection rules** for `T1197`, representing a verified detection blind spot on our MITRE ATT&CK coverage matrix.

---

## 2. Telemetry Requirements & Query Methodology

### 2.1 Required Data Sources
- **Primary Host Telemetry:** `Microsoft-Windows-Bits-Client/Operational` (Event ID 3: Job Created, Event ID 4: Job Transferred, Event ID 59: Job Error)
- **Endpoint Process Telemetry:** Sysmon Event ID 1 (`bitsadmin.exe` command lines and PowerShell `Start-BitsTransfer` invocations)
- **Network Telemetry:** Zeek `http.log` / `conn.log` filtering for HTTP `User-Agent: Microsoft BITS/*`

### 2.2 Analytical Query Approach

#### Host Process & BITS Client Event Query:
```spl
(index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
    (Image="*\\bitsadmin.exe" OR OriginalFileName="bitsadmin.exe" OR CommandLine="*Start-BitsTransfer*")
) OR 
(index=windows_bits sourcetype="WinEventLog:Microsoft-Windows-Bits-Client/Operational" (EventCode=3 OR EventCode=4))
| eval Job_Remote_URL = coalesce(RemoteUrl, CommandLine)
| eval Job_Local_Path = coalesce(LocalPath, CommandLine)
| table _time, host, User, EventCode, Job_Remote_URL, Job_Local_Path
```

#### Network Corroboration Query:
```spl
index=zeek sourcetype="bro:http:json" user_agent="Microsoft BITS*"
| stats count, values(host) as dest_hosts, values(uri) as uris by id.orig_h, user_agent
```

---

## 3. Analysis & Hunt Findings

### 3.1 Detailed Telemetry Findings
The hunt queried 14 continuous days of historical enterprise log archives spanning 120 endpoints and servers across the client environment:

1. **Total BITS Transfer Events Identified:** 214 transfer jobs recorded.
2. **Analysis of Remote Destination Domains:**
   - 100% of the destination URLs mapped to verified Microsoft infrastructure:
     - `*.delivery.mp.microsoft.com` (Windows 10/11 Cumulative Updates)
     - `*.windowsupdate.com` (WSUS and Microsoft Catalog)
     - `definitionupdates.microsoft.com` (Microsoft Defender Antivirus signature definitions)
3. **Analysis of Local File Drop Targets:**
   - Destination file paths were strictly constrained to system-protected directories:
     - `C:\Windows\SoftwareDistribution\Download\*`
     - `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*`
4. **Command-Line Process Audit:**
   - Zero instances of `bitsadmin.exe /transfer`, `/create`, or `/addfile` were executed from interactive user sessions or command prompts.
   - Zero instances of PowerShell `Start-BitsTransfer` were executed by non-administrative user accounts.

### 3.2 Negative Results & Explicit Activity Ruled Out
In accordance with PRD Section 6.2 deliverable quality standards:
- **Ruled Out:** Active abuse of BITS for secondary tool staging, lateral movement staging, or automated persistence across all examined endpoints.
- **Ruled Out:** Egress exfiltration disguised as BITS traffic over non-standard external IP addresses.
- **Benign Baseline Established:** Validated that normal client endpoints perform approximately 15 to 20 definition and update transfers per host per week, characterized exclusively by Microsoft-signed root domains and specific user agents (`Microsoft BITS/7.8`).

---

## 4. Conclusion & Detection Engineering Gap Feedback

- **Hunt Outcome:** **RULED OUT** — No evidence of adversary presence exploiting BITS in the current environment.
- **Detection Gap Closed:** Although no active intrusion was identified, this hunt exposed that the SOC had no real-time detection for `T1197`. To permanently eliminate this blind spot, a draft Sigma detection rule was authored and submitted to the detection backlog:

```yaml
# Proposed Detection Content resulting from Hunt CDL-HUNT-2026-002
title: Suspicious BITSAdmin or PowerShell BITS Job Creation
id: 3c1a8920-561b-4392-8012-7819203a9999
status: test
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197
logsource:
  category: process_creation
  product: windows
detection:
  selection_bitsadmin:
    Image|endswith: '\bitsadmin.exe'
    CommandLine|contains:
      - '/transfer'
      - '/create'
      - '/addfile'
  selection_pwsh:
    CommandLine|contains: 'Start-BitsTransfer'
  filter_msft:
    CommandLine|contains:
      - 'microsoft.com'
      - 'windowsupdate.com'
  condition: (selection_bitsadmin or selection_pwsh) and not filter_msft
level: high
```
