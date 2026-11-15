# Cyberion Defense Labs — Telemetry Data Dictionary

**Document ID:** CDL-DET-V2-DICT  
**Version:** 2.0  
**Classification:** Internal Engineering Program Deliverable  
**Log Sources Analyzed:** Windows Security Auditing (Security.evtx), Microsoft Sysmon (Sysmon/Operational), Zeek Network Security Monitoring

---

## 1. Overview & Telemetry Architecture

Effective detection engineering requires an intimate understanding of log schemas, field semantics, data types, and telemetry blind spots. This data dictionary defines the structure and detection value of the three core telemetry sources utilized across the Cyberion Defense Labs detection content library:

1. **Microsoft Windows Security Event Log (`Microsoft-Windows-Security-Auditing`)**
2. **Microsoft Sysmon (`Microsoft-Windows-Sysmon/Operational`)**
3. **Zeek Network Security Monitor (`conn.log`, `dns.log`, `http.log`, `ssl.log`)**

---

## 2. Source 1: Windows Security Event Log

Windows Security auditing captures authentication, privilege assignment, object access, policy changes, and system process operations recorded by the Local Security Authority Subsystem Service (LSASS).

### 2.1 Key Monitored Event IDs

| Event ID | Standard Description | MITRE ATT&CK Mapping | Detection Engineering Significance |
| :--- | :--- | :--- | :--- |
| **4624** | An account was successfully logged on | T1078 (Valid Accounts), T1021 (Remote Services) | Critical for establishing logon sessions, identifying anomalous remote interactive sessions (Logon Type 10), network logons (Type 3), and batch jobs (Type 4). |
| **4625** | An account failed to log on | T1110 (Brute Force, Password Spraying) | Key for identifying authentication attacks, account enumeration, credential guessing bursts, and locked accounts. |
| **4672** | Special privileges assigned to new logon | T1078 (Valid Accounts), T1068 (Privilege Escalation) | Indicates administrative rights (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`). Critical for privilege escalation detection. |
| **4688** | A new process has been created | T1059 (Command & Scripting Interpreter) | Requires command-line auditing policy. Provides process creation, parent process name, and full token elevation indicators. |
| **4697** | A service was installed in the system | T1543.003 (Windows Service) | Logged when a new service binary is registered, common in PsExec, Cobalt Strike lateral movement, and persistence mechanisms. |
| **4698** | A scheduled task was created | T1053.005 (Scheduled Task) | Critical persistence indicator. Contains full XML task definition including execution trigger and binary actions. |
| **4720** | A user account was created | T1136.001 (Local Account), T1136.002 (Domain Account) | Rogue account creation detection for backdoor persistence in local SAM or Active Directory. |
| **4769** | A Kerberos service ticket was requested | T1558.003 (Kerberoasting) | Primary telemetry for Kerberoasting attacks when Ticket Encryption Type is `0x17` (RC4-HMAC) for high-privilege service accounts. |
| **7045** | Service Control Manager: A service was installed | T1543.003 (Windows Service) | Logged in System channel, complements 4697. Captures ServiceName, ImagePath, ServiceType, and StartType. |
| **1102** | The audit log was cleared | T1070.001 (Clear Windows Event Logs) | High-fidelity defense evasion indicator. Generated whenever the Security log is purged. |

### 2.2 Field Definitions & Detection Meaning

| Field Name | Type | Description | Detection Meaning & Analytic Utility |
| :--- | :--- | :--- | :--- |
| `TargetUserName` | String | User account for which logon or action occurred. | Correlated against service account baselines, administrative naming conventions, or known compromised accounts. |
| `TargetDomainName` | String | Domain of the target user account. | Differentiates local machine accounts (`WORKSTATION6`) from domain accounts (`CYBERION`). |
| `LogonType` | Integer | Numerical representation of logon session type. | **Logon Type 2:** Interactive (local console).<br>**Logon Type 3:** Network (SMB, PsExec, RPC, Kerberos ticket negotiation).<br>**Logon Type 7:** Unlock workstation.<br>**Logon Type 8:** NetworkCleartext (IIS, basic auth).<br>**Logon Type 9:** NewCredentials (RunAs / `runas /netonly`, Mimikatz PTH).<br>**Logon Type 10:** RemoteInteractive (RDP). |
| `IpAddress` | String | Originating network IP address of the logon request. | Identifies external ingress points, internal pivot sources, and subnet hopping during lateral movement. |
| `IpPort` | Integer | Source port of the connecting entity. | Ephemeral source port analysis; useful for session tracking across firewall logs. |
| `Status` / `SubStatus` | Hex / Int | NTSTATUS error code indicating failure reason in 4625. | `0xC000006A`: Bad password.<br>`0xC0000064`: User name does not exist (user enumeration).<br>`0xC0000234`: Account locked out.<br>`0xC0000072`: Account disabled. |
| `PrivilegeList` | String | Privileges assigned during logon (Event 4672). | Looking for sensitive rights: `SeDebugPrivilege` (allows memory scraping / LSASS injection), `SeImpersonatePrivilege`, `SeLoadDriverPrivilege`. |
| `NewProcessName` | String | Full path to the executable launched (Event 4688). | Used to identify anomalous binaries, masquerading file names, and execution from suspicious paths (`\AppData\`, `\Temp\`, `\Users\Public\`). |
| `CommandLine` | String | Command string including arguments (Event 4688). | Primary target for Sigma string matching, regex extraction, encoded PowerShell, and LOLBAS flag parsing. |
| `ParentProcessName` | String | Process that spawned the new process. | Critical for lineage checks: identifies suspicious parentage such as `winword.exe` spawning `powershell.exe`, or `sqlservr.exe` spawning `cmd.exe`. |
| `TicketEncryptionType`| Hex | Kerberos encryption cipher in Event 4769. | `0x17` indicates RC4-HMAC encryption, susceptible to offline dictionary cracking (Kerberoasting). `0x12` indicates AES-256. |
| `ServiceName` | String | Name of newly installed service (4697 / 7045). | Detects randomly generated 7-character PsExec / Cobalt Strike service names (e.g., `PSEXESVC`, `a8f9c2d`). |
| `ImagePath` | String | Binary path of installed service. | Detects execution directly from `%TEMP%`, admin shares (`C$\admin$`), or suspicious script interpreters (`cmd.exe /c ...`). |

---

## 3. Source 2: Microsoft Sysmon (System Monitor)

Sysmon provides granular host activity monitoring by hooking into Windows kernel drivers (`SysmonDrv`), capturing process creations, network connections, file access, memory tampering, and raw driver loads.

### 3.1 Key Sysmon Event IDs

| Event ID | Standard Description | MITRE ATT&CK Mapping | Detection Engineering Significance |
| :--- | :--- | :--- | :--- |
| **Event ID 1** | Process Creation | T1059, T1105, T1218, T1047 | Gold standard for endpoint process lineage. Captures parent process GUID, process GUID, full command line, user, hashes (SHA256, IMPHASH), and integrity levels. |
| **Event ID 3** | Network Connection | T1071 (Application Layer Protocol), T1043 | Correlates outbound/inbound TCP/UDP network connections directly to the initiating PID and binary path. |
| **Event ID 7** | Image Loaded | T1073 (DLL Side-Loading), T1574 | Detects unauthorized DLLs loaded by sensitive binaries, unsigned driver loads, or malicious module injection. |
| **Event ID 8** | CreateRemoteThread | T1055.002 (Process Injection) | High-fidelity indicator of memory injection across process boundaries (e.g. Cobalt Strike injecting into `explorer.exe`). |
| **Event ID 10** | ProcessAccess | T1003.001 (LSASS Memory) | Detects processes opening handles to target processes. Essential for detecting credential dumpers (Mimikatz, ProcDump) requesting `PROCESS_VM_READ` (0x0010) on `lsass.exe`. |
| **Event ID 11** | FileCreate | T1105 (Ingress Tool Transfer) | Captures file write operations, drop locations, download staging (`certutil` output files), and ransomware file drops. |
| **Event ID 12/13/14** | RegistryEvent | T1547.001 (Run Keys), T1112 | Captures registry key creation, modification, deletion, and value assignments (persistence keys, UAC bypass keys). |
| **Event ID 22** | DNSEvent | T1071.004 (DNS C2), T1568 | Endpoint-level DNS resolution logs, directly tying domain lookups to the specific initiating PID and binary executable. |

### 3.2 Field Definitions & Detection Meaning

| Field Name | Type | Description | Detection Meaning & Analytic Utility |
| :--- | :--- | :--- | :--- |
| `ProcessGuid` | GUID | Unique identifier assigned to the process instance by Sysmon. | Solves PID recycling issues; enables deterministic process tree traversal across hours or days. |
| `ProcessId` | Integer | OS-level Process ID. | Used to cross-reference with Windows Security logs or live triage tools. |
| `Image` | String | Full path of the executing binary. | Identifies unauthorized binaries, paths, and LOLBAS executions. |
| `CommandLine` | String | Full arguments passed to the executable. | Unpacks base64 strings, URL parameters, obfuscated commands, and malicious switches. |
| `ParentProcessGuid` | GUID | Unique identifier of the spawning process. | Links child to parent; enables upstream root cause tracing. |
| `ParentImage` | String | Full path of the spawning binary. | Evaluates execution context (e.g., `cmd.exe` spawned by `w3wp.exe` indicating web shell activity). |
| `ParentCommandLine` | String | Command line of the spawning process. | Essential for contextual evaluation and false-positive filtering. |
| `User` | String | User security context under which the process executes. | Identifies privilege context (`NT AUTHORITY\SYSTEM`, domain admin, service accounts). |
| `IntegrityLevel` | String | Mandatory Integrity Control level (`Low`, `Medium`, `High`, `System`). | Evaluates whether process has successfully bypassed UAC or escalated privileges. |
| `Hashes` | String | Cryptographic hashes (`MD5=...,SHA256=...,IMPHASH=...`). | Feeds automated threat intelligence lookup and hash matching against known malware families. |
| `SourceIp` / `DestinationIp` | String | Network endpoints in Event ID 3. | Correlates endpoint process execution with network C2 traffic. |
| `DestinationPort` | Integer | Destination network port. | Identifies non-standard port communications (e.g., HTTPS over port 8080 or port 4444). |
| `TargetImage` | String | Target process in Event ID 8 & Event ID 10. | Target of injection or memory handle request (e.g., `C:\Windows\System32\lsass.exe`). |
| `GrantedAccess` | Hex | Bitmask of requested permissions on target process. | `0x1010` (VM_READ \| QUERY_LIMITED_INFORMATION) and `0x1F0FFF` (PROCESS_ALL_ACCESS) to `lsass.exe` indicate credential theft. |
| `CallTrace` | String | Stack trace of API call. | Reveals originating DLLs and unbacked memory regions indicative of shellcode execution. |

---

## 4. Source 3: Zeek Network Security Monitoring (NSM)

Zeek translates raw network packet streams into structured, stateful transaction logs at protocol layers (L4–L7), providing independent corroboration of host telemetry.

### 4.1 Key Zeek Log Types

| Log File | Purpose | MITRE ATT&CK Mapping | Detection Engineering Significance |
| :--- | :--- | :--- | :--- |
| `conn.log` | L4 connection state, duration, bytes | T1071 (C2 Protocol), T1048 (Exfiltration) | Foundation of network flow analysis. Enables statistical beaconing analysis, long-lived sessions, and asymmetric byte transfers. |
| `dns.log` | DNS requests, responses, TTLs | T1071.004 (DNS C2), T1568 (Dynamic Resolution) | Detects fast flux domains, high-entropy DGA domains, DNS tunneling exfiltration, and newly registered domains (NRDs). |
| `http.log` | Layer 7 HTTP requests and responses | T1071.001 (Web Protocols) | Detailed inspection of HTTP methods, URIs, User-Agents, host headers, status codes, and mime-types. |
| `ssl.log` | TLS/SSL handshakes, certificates | T1573 (Encrypted Channel), T1071.001 | Analyzes JA3/JA3S client/server SSL fingerprints, self-signed certificates, issuer anomalies, and expired certs. |

### 4.2 Field Definitions & Detection Meaning

| Field Name | Type | Description | Detection Meaning & Analytic Utility |
| :--- | :--- | :--- | :--- |
| `ts` | Float / Timestamp | Epoch timestamp with microsecond resolution. | Used to calculate Inter-Arrival Time (IAT) deltas between consecutive connections to detect periodic beaconing loops. |
| `uid` | String | Unique connection identifier. | Joins `conn.log` records to protocol-specific logs (`http.log`, `ssl.log`, `dns.log`). |
| `id.orig_h` | IP Address | Source IP address initiating connection. | Identifies internal source host. Correlated against internal endpoint IP inventory. |
| `id.orig_p` | Port | Source ephemeral port. | Tracks connection states and local port allocations. |
| `id.resp_h` | IP Address | Destination IP address receiving connection. | Cross-referenced against external threat intel feeds, Tor nodes, and bulletproof hosting providers. |
| `id.resp_p` | Port | Destination service port. | Highlights outbound traffic traversing abnormal ports (e.g. HTTP traffic on TCP 8443 or TCP 4444). |
| `proto` | String | Transport layer protocol (`tcp`, `udp`, `icmp`). | Determines connection state machine expectations. |
| `duration` | Float | Duration of connection in seconds. | Identifies continuous, long-lived persistent interactive C2 sessions (e.g. Cobalt Strike interactive shells). |
| `orig_bytes` | Integer | Total payload bytes transmitted by client. | High `orig_bytes` relative to `resp_bytes` indicates data staging, exfiltration, or upload activity. |
| `resp_bytes` | Integer | Total payload bytes returned by server. | High `resp_bytes` relative to `orig_bytes` indicates file downloads, payload staging, or tool ingestion. |
| `conn_state` | String | Connection state summary (e.g., `SF`, `S0`, `REJ`, `RSTO`). | `SF`: Normal SYN-FIN completion.<br>`S0`: Connection attempted, no reply (port scanning / host down).<br>`REJ`: Connection rejected (closed port / active firewall). |
| `query` | String | Domain name queried in `dns.log`. | Evaluated for entropy (Shannon entropy > 3.8 indicates DGA or DNS tunneling), label length, and top-level domain anomalies. |
| `qtype_name` | String | DNS record type (`A`, `AAAA`, `TXT`, `CNAME`, `MX`). | High volume of `TXT` queries indicates DNS data exfiltration or C2 payload staging. |
| `answers` | List of Strings | IP or text records returned in DNS response. | Detects external sinkholes, loopback redirects, or dynamic C2 resolution IPs. |
| `method` | String | HTTP verb (`GET`, `POST`, `PUT`, `DELETE`). | Frequent `POST` requests without corresponding browsing activity indicates C2 check-in / data staging. |
| `host` | String | HTTP `Host` header or TLS SNI. | Detects missing host headers, direct IP access (`http://198.51.100.42`), or domain fronting. |
| `uri` | String | Requested Uniform Resource Identifier. | Identifies default tool paths (e.g., `/api/v1/update`, `/news.php`, Cobalt Strike Malleable C2 profile URI patterns). |
| `user_agent` | String | Client HTTP User-Agent string. | Detects anomalous strings, default tool agents (`curl/7.68.0`, `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`), or missing headers. |
| `ja3` / `ja3s` | String | MD5 hash of TLS client/server Hello parameters. | Fingerprints specific TLS clients (Cobalt Strike, Sliver, Meterpreter, Emotet) regardless of destination IP or port encryption. |

---

## 5. Cross-Telemetry Source Correlation Matrix

Detection engineering achieves highest defensibility when detections correlate host and network telemetry.

```
+---------------------------------------------------------------------------------------------------+
|  ADVERSARY ACTION       | WIN SECURITY EVENT LOG | SYSMON OPERATIONAL     | ZEEK NETWORK LOG      |
+---------------------------------------------------------------------------------------------------+
|  Payload Download       | Event 4688 (certutil)  | Event 1 (ProcessCreate)| http.log / conn.log   |
|  (T1105)                | NewProcessName         | Event 11 (FileCreate)  | uri, id.resp_h, bytes |
+-------------------------+------------------------+------------------------+-----------------------+
|  LSASS Credential Dump  | Event 4672 (SeDebug)   | Event 10 (ProcessAccess| N/A (Local Memory)    |
|  (T1003.001)            | Event 4688 (procdump)  | GrantedAccess 0x1010   |                       |
+-------------------------+------------------------+------------------------+-----------------------+
|  Remote Service Lateral | Event 4624 (Logon 3)   | Event 1 (services.exe) | conn.log (TCP 445)    |
|  Movement (T1021.002)   | Event 7045 / 4697      | Event 11 (PSEXESVC.exe)| SMB named pipe traffic|
+-------------------------+------------------------+------------------------+-----------------------+
|  C2 Network Beaconing   | N/A                    | Event 3 (NetworkConnect| conn.log (periodic ts)|
|  (T1071.001 / T1001)    |                        | Image = rundll32.exe   | ssl.log (JA3 hash)    |
+-------------------------+------------------------+------------------------+-----------------------+
```
