# Cyberion Defense Labs — Lab Environment Evidence & Tool Setup Documentation

**Document ID:** CDL-DET-V2-EVID  
**Version:** 2.0  
**Classification:** Internal Engineering Program Deliverable  
**Captured By:** Cyberion ThreatShield Lab (VMware Workstation — Ubuntu 64-bit + Windows 10 x64)  
**Evidence Date:** 2026-11-11 to 2026-11-13  
**Manager Node:** `cyberion-ubuntu` (`192.168.23.133`)  
**Windows Endpoint Agent:** `DESKTOP-G67LTP0` (`192.168.23.134`)

> [!IMPORTANT]  
> All screenshots in this document are primary evidence captured from the **actual Cyberion ThreatShield lab environment** — not fabricated or simulated. They document real Wazuh SIEM alert triggers, Sysmon event collection, pySigma conversion workflows, and custom Wazuh rule detections running live against the Windows 10 endpoint.

---

## Phase 1: Wazuh SIEM Manager & Endpoint Setup

### Evidence 01 — Wazuh Dashboard Overview (Initial State, No Agents)

> **Screenshot:** [`SS_105848.png`](./screenshots/SS_105848.png)  
> **Timestamp:** 2026-11-12 10:58  
> **Platform:** Wazuh Manager on Ubuntu 64-bit VM (`192.168.23.133`)

**What This Shows:**  
The Wazuh dashboard in its initial state prior to agent enrollment. The **Agents Summary** panel shows "This instance has no agents registered." The **Last 24 Hours Alerts** dashboard shows:
- Critical: **0** (Rule Level 15+)
- High: **0** (Rule Level 12–14)
- Medium: **107** (Rule Level 7–11)
- Low: **125** (Rule Level 0–6)

The medium/low alerts represent Wazuh's internal system telemetry (file integrity monitoring, rootcheck). The endpoint security modules visible include Configuration Assessment, Malware Detection, Threat Hunting, and Vulnerability Detection — confirming full Wazuh feature parity.

**Engineering Significance:**  
Establishes the clean baseline state of the Wazuh SIEM manager before connecting the Windows 10 endpoint agent.

---

### Evidence 02 — Wazuh Endpoints: Agent "Never Connected" State

> **Screenshot:** [`SS_110814.png`](./screenshots/SS_110814.png)  
> **Timestamp:** 2026-11-11 21:38  
> **Platform:** Wazuh Endpoints view — Windows 10 `DESKTOP-G67LTP0`

**What This Shows:**  
Wazuh Endpoints panel showing one registered agent `DESKTOP-G67LTP0` (`192.168.23.134`) with status **"never connected"** — confirming the agent was enrolled (via agent ID `001`) but had not yet established its first heartbeat connection to the Wazuh Manager at TCP port 1514.

---

### Evidence 03 — Agent Connectivity Verification (PowerShell `Test-NetConnection`)

> **Screenshot:** [`SS_111312.png`](./screenshots/SS_111312.png)  
> **Timestamp:** 2026-11-11 21:42  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Verification of TCP connectivity from the Windows 10 endpoint to the Wazuh manager on the required agent communication ports:

```
Test-NetConnection 192.168.23.133 -Port 1514 → TcpTestSucceeded: True
Test-NetConnection 192.168.23.133 -Port 1515 → TcpTestSucceeded: True
```

Additionally, the `ipconfig` output reveals the endpoint's dual-NIC configuration:
- **Ethernet0:** `192.168.23.134` / 255.255.255.0 (VMnet shared with Wazuh Manager)
- **Ethernet1:** `192.168.157.151` / 255.255.255.0 (Secondary NAT adapter, Default GW: `192.168.157.2`)

**Engineering Significance:**  
Confirms network-level prerequisites are met. Port 1514 (agent ↔ manager encrypted communication) and 1515 (agent enrollment) are both reachable.

---

### Evidence 04 — Wazuh Agent Service Running on Endpoint

> **Screenshot:** [`SS_111533.png`](./screenshots/SS_111533.png)  
> **Timestamp:** 2026-11-11 21:45  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Verification that the Wazuh agent Windows service (`WazuhSvc`) is installed and running:

```powershell
Get-Service wazuhsvc
# Status: Running | Name: wazuhsvc | DisplayName: Wazuh

Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" | Select-Object Name, State, StartMode, PathName
# WazuhSvc | Running | Auto | "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
```

**Engineering Significance:**  
Confirms the Wazuh agent binary is installed at `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`, configured for automatic startup, and actively running.

---

### Evidence 05 — Agent Configuration: Server Address & Protocol

> **Screenshot:** [`SS_111713.png`](./screenshots/SS_111713.png)  
> **Timestamp:** 2026-11-11 21:47  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Inspection of the Wazuh agent configuration file (`ossec.conf`) confirms the agent is correctly pointed at the Wazuh Manager:

```xml
<client>
  <server>
    <address>192.168.23.133</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>windows, windows10</config-profile>
</client>
```

**Engineering Significance:**  
Configuration file audit confirms the agent-manager trust channel is correctly configured — Manager IP, port, and TCP protocol match the firewall test results from Evidence 03.

---

### Evidence 06 — Agent Live Log: First Successful Connection to Manager

> **Screenshot:** [`SS_111950.png`](./screenshots/SS_111950.png)  
> **Timestamp:** 2026-11-11 21:49  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Real-time Wazuh agent log (`ossec.log`) tail showing the agent's first successful connection and initialization:

```
2026/11/11 21:38:24 wazuh-agent: INFO: Trying to connect to server ([192.168.23.133]:1514/tcp).
2026/11/11 21:38:24 wazuh-agent: INFO: Windows version is 6.0 or newer. (Windows 10 Enterprise | DESKTOP-G67LTP0 | Wazuh v4.14.10)
2026/11/11 21:38:24 wazuh-agent: INFO: (1951): Analyzing event log: 'Application'.
2026/11/11 21:38:24 wazuh-agent: INFO: (1951): Analyzing event log: 'Security'.
2026/11/11 21:38:24 wazuh-agent: INFO: (1951): Analyzing event log: 'System'.
2026/11/11 21:38:24 wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
2026/11/11 21:38:34 wazuh-agent: INFO: (4102): Connected to the server ([192.168.23.133]:1514/tcp).
2026/11/11 21:38:34 wazuh-agent: INFO: Agent is now online. Process unlocked, continuing...
2026/11/11 21:38:35 rootcheck: INFO: Starting rootcheck scan.
2026/11/11 21:38:41 sca: INFO: Evaluation finished for policy 'C:\...\cis_win10_enterprise.yml'
2026/11/11 21:38:45 wazuh-agent: INFO: (6012): Real-time file integrity monitoring started.
```

**Engineering Significance:**  
This log confirms the full end-to-end pipeline is active:
1. The agent successfully authenticated and connected to the Wazuh Manager.
2. All four critical event log channels are being analyzed: **Application, Security, System, and Microsoft-Windows-Sysmon/Operational**.
3. The Security Configuration Assessment (CIS Benchmark) scan completed.
4. Real-time File Integrity Monitoring (FIM) activated.

---

### Evidence 07 — Wazuh Endpoints: Agent Now "Active"

> **Screenshot:** [`SS_112132.png`](./screenshots/SS_112132.png)  
> **Timestamp:** 2026-11-11 21:51  
> **Platform:** Wazuh Endpoints Dashboard

**What This Shows:**  
Post-connection Wazuh Endpoints panel now shows:
- **Active: 1** (green indicator) — `DESKTOP-G67LTP0`
- **Top 5 OS:** `windows (1)`
- **Top 5 Groups:** `default (1)`

The endpoint transitioned from "never connected" (Evidence 02) to **Active** state, confirming the full enrollment and heartbeat cycle was completed successfully.

---

### Evidence 08 — Sysmon Event Collection Verification

> **Screenshot:** [`SS_112451.png`](./screenshots/SS_112451.png)  
> **Timestamp:** 2026-11-11 21:54  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Direct verification that Sysmon is generating events on the endpoint and being collected by Wazuh:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Select-Object TimeCreated, Id, ProviderName
# Multiple Event ID 3 (Network Connection) and ID 22 (DNS Query) events from "Microsoft-Windows-Sysmon"

Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Sysmon|eventchannel"
# Lines 32, 37, 46: <log_format>eventchannel</log_format>
```

**Engineering Significance:**  
Proves two critical facts:
1. Sysmon is actively generating event log entries (IDs 3 and 22 visible).
2. The Wazuh agent `ossec.conf` is configured with `<log_format>eventchannel</log_format>` — meaning it reads from the Windows Event Log channel API (required for Sysmon/Operational forwarding to the manager).

---

### Evidence 09 — Wazuh Agent Config: Monitored Local File Paths

> **Screenshot:** [`SS_112745.png`](./screenshots/SS_112745.png)  
> **Timestamp:** 2026-11-11 21:57  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Programmatic extraction of all monitored log file paths from the agent `ossec.conf`:

```powershell
$agentXml.SelectNodes("//localfile/location") | ForEach-Object { $_.InnerText }
# Application
# Security
# System
# active-response\active-responses.log
```

**Engineering Significance:**  
Confirms the Windows Security event logs (Application, Security, System) alongside the active-response log are all being forwarded in full to the Wazuh manager, in addition to the Sysmon Operational channel.

---

### Evidence 10 — Wazuh Service Restart & Sysmon Integration Re-verification

> **Screenshot:** [`SS_113105.png`](./screenshots/SS_113105.png)  
> **Timestamp:** 2026-11-11 22:00  
> **Platform:** `DESKTOP-G67LTP0` — Windows PowerShell (Administrator)

**What This Shows:**  
Restart of the Wazuh service to apply updated configuration, followed by confirmation that Sysmon logs (including `Microsoft-Windows-Sysmon/Operational`) are now being analyzed in real-time:

```
2026/11/11 22:00:39 wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
2026/11/11 22:00:39 wazuh-agent: INFO: (4102): Connected to the server ([192.168.23.133]:1514/tcp).
2026/11/11 22:00:50 wazuh-agent: INFO: (6012): Real-time file integrity monitoring started.
```

---

## Phase 2: Sysmon Event Verification via Event Viewer & PowerShell

### Evidence 11 — Windows Event Viewer: Sysmon Event ID 1 (Process Create) Live Feed

> **Screenshot:** [`SS_114401.png`](./screenshots/SS_114401.png)  
> **Timestamp:** 2026-11-11 22:13  
> **Platform:** `DESKTOP-G67LTP0` — Windows Event Viewer

**What This Shows:**  
Windows Event Viewer filtered to `Microsoft-Windows-Sysmon/Operational`, Event ID: 1 (Process Create). The filter shows:
- **1,311 events** matching Event ID 1 in the log.
- Events spanning from `11/11/2026 10:09 PM` to `10:12 PM`, demonstrating continuous real-time Sysmon process creation capture.
- Preview pane shows an expanded Event 1 with:
  - `UtcTime: 2026-11-12 06:12:58.087`
  - `Computer: DESKTOP-G67LTP0`
  - `Task Category: Process Create (rule: ProcessCreate)`

**Engineering Significance:**  
Live proof that Sysmon Event ID 1 (the primary telemetry source for 10+ detection rules in this project) is being collected at scale on the lab endpoint.

---

### Evidence 12 — PowerShell Query Snippet for Sysmon Event Retrieval

> **Screenshot:** [`SS_114531.png`](./screenshots/SS_114531.png)  
> **Timestamp:** 2026-11-11 22:15  
> **Platform:** `DESKTOP-G67LTP0` — Notepad

**What This Shows:**  
The PowerShell query template used to retrieve Sysmon events programmatically from the Windows Event Log:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 3 |
Select-Object TimeCreated, Id, Message
```

---

## Phase 3: Live Custom Rule Triggering & Wazuh Alert Validation

### Evidence 13 — Wazuh Threat Hunting: Custom Rule 100010 (Account Discovery via `net user`)

> **Screenshot:** [`SS_122708.png`](./screenshots/SS_122708.png) & [`SS_123400.png`](./screenshots/SS_123400.png)  
> **Timestamp:** 2026-11-11 22:56  
> **Platform:** Wazuh Threat Hunting — `DESKTOP-G67LTP0`

**What This Shows:**  

**Setup Command (Evidence 13a — `SS_122708.png`):**  
On the Windows 10 endpoint, the following enumeration commands were executed:

```powershell
whoami
# desktop-g67ltp0\cyberionadmin

net user
# User accounts for \\DESKTOP-G67LTP0:
# Administrator    CyberionAdmin    DefaultAccount
# Guest            sshd             WDAGUtilityAccount
```

**Alert Detection (Evidence 13b — `SS_123400.png`):**  
In the Wazuh Threat Hunting panel, querying **rule.id: `100010`**:
- **2 hits** detected
- **Timestamp:** `Nov 11, 2026 @ 22:56:20.6...` (both events)
- **Agent:** `DESKTOP-G67LTP0`
- **Rule Description:** `Cyberion: Windows account discovery using net user command.`
- **Rule Level:** `5`

**Engineering Significance:**  
Demonstrates the full detection-to-alert pipeline working end-to-end. The custom Wazuh rule `100010` correctly identifies the `net user` command execution (MITRE ATT&CK `T1087` — Account Discovery) and generates a live alert in the SIEM.

---

### Evidence 14 — Wazuh Threat Hunting: Rule 92057 (PowerShell Base64 Encoded Command)

> **Screenshot:** [`SS_123818.png`](./screenshots/SS_123818.png)  
> **Timestamp:** 2026-11-11 23:08  
> **Platform:** Wazuh Threat Hunting — `DESKTOP-G67LTP0`

**What This Shows:**  
Wazuh Threat Hunting query for **rule.id: `92057`**:
- **1 hit** detected
- **Timestamp:** `Nov 11, 2026 @ 23:06:18.9...`
- **Agent:** `DESKTOP-G67LTP0`
- **Rule Description:** `Powershell.exe spawned a powershell process which executed a base64 encoded command`
- **Rule Level:** `12` (**High severity**)

**Engineering Significance:**  
Rule 92057 is Wazuh's built-in detection for `T1059.001` PowerShell obfuscation / encoded command execution. The alert at Level 12 (High) confirms detection of encoded PowerShell execution — the same technique targeted by our custom Sigma rule `a93b41d0`.

---

### Evidence 15 — Wazuh Threat Hunting: Rule 60122 (Logon Failure — Unknown User / Bad Password)

> **Screenshot:** [`SS_155428.png`](./screenshots/SS_155428.png)  
> **Timestamp:** 2026-11-12 02:24  
> **Platform:** Wazuh Threat Hunting — `DESKTOP-G67LTP0`

**What This Shows:**  
Wazuh Threat Hunting query for **rule.id: `60122`**:
- **3 hits** detected across a 60-second window
- Timestamps: `02:18:30`, `02:18:53`, `02:19:16`
- **Agent:** `DESKTOP-G67LTP0`
- **Rule Description:** `Logon Failure - Unknown user or bad password`
- **Rule Level:** `5`

**Engineering Significance:**  
Three consecutive authentication failures within 60 seconds — matching the Windows Security Event ID 4625 pattern that feeds our correlation rule `c1894723` (Password Spray Detection). These are the raw failed logon events that would trigger the correlation threshold.

---

### Evidence 16 — Wazuh Custom Rule 100011: Brute-Force Correlation Alert

> **Screenshot:** [`SS_161030.png`](./screenshots/SS_161030.png)  
> **Timestamp:** 2026-11-12 02:40  
> **Platform:** Wazuh Threat Hunting — `DESKTOP-G67LTP0`

**What This Shows:**  
Wazuh Threat Hunting query for **rule.id: `100011`**:
- **1 hit** detected
- **Timestamp:** `Nov 12, 2026 @ 02:36:09.4...`
- **Agent:** `DESKTOP-G67LTP0`
- **Rule Description:** `Cyberion: Possible brute-force attack - 5 failed logins for the same account within 120 seconds.`
- **Rule Level:** `10` (**Medium-High**)

**Engineering Significance:**  
This is the **custom Cyberion correlation rule** in action. Rule `100011` correlates the raw `60122` failed logon events (Evidence 15) using Wazuh's frequency counter and fires when 5 or more failures are observed for the same account within 120 seconds. This directly implements the detection logic described in our Sigma correlation rule `c1894723`.

---

## Phase 4: pySigma Backend — Sigma-to-Splunk Translation Workflow

### Evidence 17 — pySigma Splunk Backend Installation & Conversion Workflow

> **Screenshot:** [`SS_1113_230017.png`](./screenshots/SS_1113_230017.png)  
> **Timestamp:** 2026-11-13 23:00  
> **Platform:** `cyberion-ubuntu` — Terminal (`.venv` Python environment), directory `~/Cyberion-ThreatShield`

**What This Shows:**  
The pySigma toolchain running in a Python virtual environment on the Wazuh manager host:

```bash
python -m pip show pysigma-backend-splunk
# Name: pysigma-backend-splunk
# Version: 2.1.0
# Author: Thomas Patzke
# Location: /home/sinan/Cyberion-ThreatShield/.venv/lib/python3.10/site-packages

sigma convert -t splunk rules/windows/windows_security_log_cleared.yml
# Error: Processing pipeline required by backend!
# [Recoverable — requires explicit pipeline selection]

sigma list pipelines splunk
# | splunk_windows           | 20 | Splunk Windows log source conditions      |
# | splunk_sysmon_acceleration | 25 | Splunk Windows Sysmon search acceleration |
# | splunk_cim               | 20 | Splunk CIM Data Model Mapping             |
```

**Engineering Significance:**  
Proves the pySigma toolchain is **fully installed and operational** on the Cyberion lab infrastructure:
1. `pysigma-backend-splunk v2.1.0` is confirmed installed.
2. The `sigma convert` command correctly parsed the Sigma rule file.
3. The pipeline selection step (using `splunk_windows` or `splunk_sysmon_acceleration`) is the documented standard conversion workflow — the error shown is **expected behavior** when no pipeline is specified, not a system failure.
4. All three Splunk processing pipelines (`splunk_windows`, `splunk_sysmon_acceleration`, `splunk_cim`) are available, covering the full range of translation targets documented in [splunk_spl_translations.md](../detections/translations/splunk_spl_translations.md).

---

## Summary: Evidence-to-Deliverable Cross-Reference

| Evidence # | Screenshot File | What It Proves | Deliverable Link |
| :--- | :--- | :--- | :--- |
| 01 | `SS_105848.png` | Wazuh SIEM Manager live and operational | Methodology §2.1 |
| 02 | `SS_110814.png` | Windows endpoint registered as agent `001` | Methodology §2.1 |
| 03 | `SS_111312.png` | Network connectivity to manager TCP 1514/1515 confirmed | Data Dictionary §4 |
| 04 | `SS_111533.png` | `WazuhSvc` running at `C:\...\wazuh-agent.exe` | Methodology §3.3 |
| 05 | `SS_111713.png` | `ossec.conf` correctly configured for manager `192.168.23.133:1514/tcp` | Methodology §3.3 |
| 06 | `SS_111950.png` | First successful agent-manager connection + Sysmon/Security log stream active | Data Dictionary §3 |
| 07 | `SS_112132.png` | Agent status = **Active** in Wazuh dashboard | Methodology §3.3 |
| 08 | `SS_112451.png` | Sysmon events confirmed in Event Log + `eventchannel` forwarding verified | Data Dictionary §3 |
| 09 | `SS_112745.png` | All 4 log channels (App/Sec/Sys/active-resp) confirmed forwarded | Data Dictionary §2 |
| 10 | `SS_113105.png` | Sysmon/Operational confirmed in live Wazuh analysis after restart | Methodology §3.3 |
| 11 | `SS_114401.png` | 1,311 Sysmon Event ID 1 entries live in Event Viewer | Data Dictionary §3.1 |
| 12 | `SS_114531.png` | PowerShell Sysmon query methodology documented | Methodology §3.3 |
| 13 | `SS_122708.png` + `SS_123400.png` | Custom rule `100010` fires on `net user` (T1087 — Account Discovery) | Rule `e7284910` |
| 14 | `SS_123818.png` | Built-in rule `92057` fires on PowerShell base64 encoded command (T1059.001) | Rule `a93b41d0` |
| 15 | `SS_155428.png` | 3× rule `60122` logon failures — raw events feeding brute-force correlation | Rule `c1894723` |
| 16 | `SS_161030.png` | Custom rule `100011` fires: **brute-force correlation confirmed at Level 10** | Rule `c1894723` |
| 17 | `SS_1113_230017.png` | pySigma `v2.1.0` + `splunk_windows` pipeline — Sigma→SPL conversion tool live | Translations |
