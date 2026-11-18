# Incident Case Report 01: C2 Beaconing and Outbound Exfiltration

## 1. Overview & Metadata
- **Case ID:** INC-2026-001
- **Severity:** High
- **Closure Classification:** True Positive - Resolved
- **Affected Host:** `WKSTN-FIN-042` (IP: `192.168.1.50`)

## 2. Evidence & Telemetry Sources
- **Sysmon:** Event ID 3 (Network Connection) and Event ID 1 (Process Creation).
- **Zeek Logs:** `conn.log` and `dns.log` capturing periodic outbound sessions to external IP `185.220.101.5`.

## 3. Detailed Investigation Timeline
- **02:15:00 UTC:** User downloads an obfuscated archive from an external source; a scheduled task (`windows_suspicious_scheduled_task_at.yml`) is registered locally.
- **02:18:30 UTC:** Encoded PowerShell download cradle executes, establishing periodic TCP connections every 60 seconds to external C2 infrastructure (`185.220.101.5`).
- **02:25:00 UTC:** Threat Hunt 01 flags regular temporal delta patterns in network telemetry.
- **02:35:00 UTC:** SOC analyst isolates `WKSTN-FIN-042` and revokes active user session tokens.

## 4. Impact Assessment & Root Cause
- **Impact:** Moderate risk of internal reconnaissance and potential data staging; containment prevented secondary payload download and exfiltration.
- **Root Cause Analysis:** Initial compromise via spear-phishing leading to unauthorized local scheduled task creation and automated beaconing.

## 5. MITRE ATT&CK Mapping
- **T1053.005** (Scheduled Task / Job: Scheduled Task)
- **T1071.004** (Application Layer Protocol: DNS)

## 6. Closure & Remediation
- Terminated lingering process trees, removed unauthorized scheduled tasks, and enforced perimeter blocking for IP `185.220.101.5` and domain `update-core-services.internal-sync.net`.
