# Incident Case Report 02: LSASS Credential Dumping Attempt

## 1. Overview & Metadata
- **Case ID:** INC-2026-002
- **Severity:** Critical
- **Closure Classification:** True Positive - Resolved
- **Affected Host:** `WKSTN-DEV-108` (IP: `192.168.1.115`)

## 2. Evidence & Telemetry Sources
- **Sysmon:** Event ID 10 (Process Access - `lsass.exe` handle requests) and Event ID 1 (Process Creation).
- **Windows Security Log:** Event ID 4688 (New Process Created) with command-line auditing enabled.

## 3. Detailed Investigation Timeline
- **14:10:05 UTC:** Execution of unverified binary from user-writable directory (`C:\Users\Public\update_util.exe`, SHA-256: `8a97425f190e87d10e1183234d7d8e24c18b76fa3d20128cbbf8e62d469446f2`).
- **14:10:12 UTC:** Target process requests handle access to `lsass.exe` with permission mask `0x1F3FFF` (Sysmon Event ID 10 match).
- **14:12:00 UTC:** Threat Hunt 02 correlation alerts on abnormal memory interaction.
- **14:18:00 UTC:** Security operations team terminates the offending process and initiates host quarantine.

## 4. Impact Assessment & Root Cause
- **Impact:** High severity threat targeting domain credentials; proactive detection and rapid isolation stopped credential extraction before lateral propagation occurred.
- **Root Cause Analysis:** Stolen user credentials enabled interactive logon followed by manual deployment of credential harvesting utilities from public staging directories.

## 5. MITRE ATT&CK Mapping
- **T1003.001** (OS Credential Dumping: LSASS Memory)
- **T1078** (Valid Accounts)

## 6. Closure & Remediation
- Isolated endpoint, purged binary from `C:\Users\Public\`, reset affected user domain password, and mandated multi-factor authentication re-enrollment.
