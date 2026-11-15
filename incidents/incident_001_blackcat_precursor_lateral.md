# Cyberion Defense Labs — Incident Case Report

**Incident Case ID:** CDL-IR-2026-001  
**Incident Title:** Multi-Stage Ransomware Precursor & Lateral Movement on Core SQL Cluster  
**Affected Client:** Cyberion Simulated Financial Services (`CYBERION.LOCAL`)  
**Lead Investigator:** Detection Engineer / Incident Response Handler  
**Incident Date:** 2026-10-14  
**Classification:** **True Positive (Critical Severity)**  
**Target Hosts:** `DC01.cyberion.local` (`10.0.1.10`), `SQL01.cyberion.local` (`10.0.1.30`)  
**Compromised Identity:** `CYBERION\admin_sec`  
**Threat Actor Alignment:** FIN7 / BlackCat (ALPHV) Ransomware Affiliate Precursor Tradecraft

---

## 1. Executive Summary

On October 14, 2026, Cyberion SOC automated detections and correlation rules identified an active intrusion sequence targeting core domain infrastructure. The attack commenced with an external password spraying campaign targeting administrative Active Directory accounts from an untrusted public IP (`203.0.113.88`), successfully compromising the high-privilege credentials of `CYBERION\admin_sec`. 

Within 33 minutes of authentication, the threat actor pivoted to the financial database cluster (`SQL01.cyberion.local`), installed an unauthorized remote service (`PSEXESVC.exe`), executed volume shadow copy deletion commands (`vssadmin.exe delete shadows /all /quiet`) to inhibit disaster recovery, and attempted forensic anti-analysis by clearing the Windows Security Event Log.

Corroborating telemetry from Windows Security Auditing (Security.evtx), System Event Log (System.evtx), and Sysmon Operational logs confirmed a full-lifecycle intrusion. The incident was contained and eradicated prior to data encryption or bulk exfiltration.

---

## 2. Root Cause Analysis (RCA)

1. **Initial Vector:** Password spraying attack (`T1110.003`) originating from external Tor egress proxy `203.0.113.88` targeting exposed NTLM endpoints on the perimeter.
2. **Vulnerability / Root Cause:**
   - **Weak Administrative Password Policy:** The compromised administrative account `CYBERION\admin_sec` was configured with a predictable seasonal passphrase (`P@ssw0rd2026!`) that satisfied complexity but failed entropy guidelines.
   - **Absence of Multi-Factor Authentication (MFA):** External administrative network authentication pathways lacked enforced FIDO2 / TOTP MFA controls for remote services.
   - **Overprivileged Service Account:** `admin_sec` possessed unrestricted interactive and network logon privileges across both domain controllers and database tiers without Tier-0 / Tier-1 Administrative Tiering separation.

---

## 3. Reconstructed Forensic Timeline of Events

All events reconstructed directly from raw forensic logs stored in `data/sample_telemetry/`:

| Timestamp (UTC) | Hostname | Source IP | Event Source & ID | User Context | Process / Command Line / Details | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **13:58:10** | `DC01` | `203.0.113.88` | WinSec 4625 | `admin_backup` | Failed logon (Status: `0xC000006D`, SubStatus: `0xC000006A`, Logon Type: 3) | `T1110.003` (Password Spraying) |
| **13:58:12** | `DC01` | `203.0.113.88` | WinSec 4625 | `admin_helpdesk` | Failed logon (Status: `0xC000006D`, SubStatus: `0xC000006A`, Logon Type: 3) | `T1110.003` (Password Spraying) |
| **13:58:15** | `DC01` | `203.0.113.88` | WinSec 4625 | `admin_sec` | Failed logon (Status: `0xC000006D`, SubStatus: `0xC000006A`, Logon Type: 3) | `T1110.003` (Password Spraying) |
| **13:59:02** | `DC01` | `203.0.113.88` | WinSec 4624 | `admin_sec` | Successful network authentication (Logon Type 3, NTLM auth, AuthPackage: `NtLmSsp`) | `T1078` (Valid Accounts) |
| **13:59:02** | `DC01` | Local | WinSec 4672 | `admin_sec` | Special privileges assigned (`SeSecurityPrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege`) | `T1078` (Valid Accounts) |
| **14:31:02** | `WORKSTATION6` | `10.0.2.106` | Sysmon ID 1 | `admin_sec` | `wmic.exe /node:10.0.1.30 /user:CYBERION\admin_sec process call create "cmd.exe ..."` | `T1047` (WMI) |
| **14:32:05** | `SQL01` | `10.0.2.106` | System 7045 / WinSec 4697 | `LocalSystem` | New service installed: ServiceName: `PSEXESVC`, ImagePath: `%SystemRoot%\PSEXESVC.exe` | `T1543.003` (Windows Service), `T1021.002` (SMB) |
| **14:33:40** | `WORKSTATION6` | Local | Sysmon ID 1 | `NT AUTHORITY\SYSTEM` | `vssadmin.exe delete shadows /all /quiet` (PID: 8216, Parent PID: 5980) | `T1490` (Inhibit System Recovery) |
| **14:38:00** | `WORKSTATION6` | Local | WinSec 1102 | `Administrator` | The audit log was cleared (SubjectLogonId: `0x3E7`) | `T1070.001` (Clear Event Logs) |

---

## 4. Corroborating Telemetry Evidence Across Sources

In compliance with PRD Section 6.3 (requiring corroboration from at least two sources):

1. **Authentication & Identity Source:** Windows Security Event Log on `DC01` confirmed external NTLM network authentication (`Event ID 4624`, Logon ID: `0x4A12B8`, Source IP: `203.0.113.88`).
2. **System Service Infrastructure Source:** Windows System Event Log on `SQL01` confirmed service registration (`Event ID 7045`, ServiceName: `PSEXESVC`, ServiceAccount: `LocalSystem`), exactly matched by Security Event `4697` logged simultaneously with SubjectUserName: `admin_sec`.
3. **Endpoint Process Creation Source:** Sysmon Event ID 1 on endpoint confirmed process tree lineage showing `cmd.exe` (PID: 5980) spawning `vssadmin.exe delete shadows /all /quiet` (PID: 8216) under elevated token integrity `System`.

---

## 5. Impact Assessment

- **Confidentiality:** **Low to Moderate.** No database dump or bulk file exfiltration was observed. However, administrative domain credentials for `admin_sec` were fully compromised.
- **Integrity:** **Moderate.** Local volume shadow copies on `WORKSTATION6` were deleted. Service registry keys on `SQL01` were modified to install `PSEXESVC`.
- **Availability:** **Low.** The intrusion was terminated prior to the deployment of ransomware encryption binaries. Core SQL database operations remained functional.
- **Assets at Risk:** High-value SQL database cluster storing financial transaction records (`SQL01`), Active Directory domain authentication infrastructure (`DC01`).

---

## 6. Closure Classification & Justification

- **Closure Classification:** **TRUE POSITIVE**
- **Justification:**  
  The activity matches verified malicious tradecraft across all kill-chain phases:
  1. External NTLM logon preceded by failed password attempts across multiple accounts.
  2. Execution of PsExec remote service binary across network boundaries.
  3. Execution of destructive ransomware precursor commands (`vssadmin delete shadows /all /quiet`).
  4. Deliberate clearing of security audit logs.  
  No authorized change management ticket or sanctioned penetration testing exercise corresponded with these operations.

---

## 7. Containment, Remediation & Playbook Alignment

1. **Playbook Triggered:** `Cyberion Incident Response Playbook CDL-IRP-002: Lateral Movement via Remote Services` and `CDL-IRP-001: Compromised Credentials`.
2. **Immediate Containment Actions:**
   - Disabled compromised Active Directory account `CYBERION\admin_sec` and revoked all active Kerberos TGT sessions across the domain.
   - Quarantined host `WORKSTATION6.cyberion.local` via EDR network isolation.
   - Blocked external adversary IP `203.0.113.88` across all perimeter firewalls.
   - Terminated `PSEXESVC.exe` process on `SQL01.cyberion.local` and removed the registered service registry keys (`HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC`).
3. **Remediation & Hardening:**
   - Enforced MFA on all administrative logon pathways.
   - Implemented Microsoft LAPS (Local Administrator Password Solution).
   - Restricted SMB TCP port 445 cross-workstation communication via host-based Windows Defender Firewall rules.

---

## 8. Detection Gaps Revealed

- **Detection Gap:** Initial NTLM password spraying was identified via correlation rule after 3 attempts, but external brute force at the perimeter firewall was not dynamically rate-limited before reaching the Domain Controller.
- **Remediation:** Implement edge IP threat intelligence banning and Active Directory Smart Lockout policies.
