# Incident Case Report 02: LSASS Credential Dumping Attempt

## 1. Overview & Metadata
- **Case ID:** INC-2026-002
- **Severity:** Critical
- **Closure Classification:** True Positive

## 2. Timeline of Events
- **14:10:05 UTC:** Execution of suspicious binary from `C:\Users\Public\` folder.
- **14:10:12 UTC:** Process requests handle access to `lsass.exe` with permission mask `0x1F3FFF` (Sysmon Event ID 10).
- **14:12:00 UTC:** Threat Hunt 02 flags abnormal memory interaction pattern.

## 3. Root Cause Analysis
An internal user workstation was compromised via stolen credentials, allowing the threat actor to drop and execute credential harvesting tools to escalate privileges.

## 4. MITRE ATT&CK Mapping
- **T1003.001** (OS Credential Dumping: LSASS Memory)
- **T1078** (Valid Accounts)

## 5. Closure & Remediation
- Terminated the offending process immediately.
- Reset the affected user's domain password and enforced MFA.
- Validated detection coverage via Rule #8 (`windows_credential_dumping_lsass.io.yml`).
