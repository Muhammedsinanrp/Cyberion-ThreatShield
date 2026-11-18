# Incident Case Report 01: C2 Beaconing and Outbound Exfiltration

## 1. Overview & Metadata
- **Case ID:** INC-2026-001
- **Severity:** High
- **Closure Classification:** True Positive

## 2. Timeline of Events
- **02:15:00 UTC:** Initial scheduled task execution (`windows_scheduled_task_created.yml`) triggers an encoded loader script.
- **02:18:30 UTC:** Process initiates high-frequency DNS requests and periodic TCP connections to external IP `203.0.113.45`.
- **02:25:00 UTC:** Threat hunt ID 01 flags regular heartbeat traffic intervals.

## 3. Root Cause Analysis
An unauthenticated external payload dropped via a phishing vector executed local persistence, setting up automated periodic C2 communication beacons.

## 4. MITRE ATT&CK Mapping
- **T1053.005** (Scheduled Task)
- **T1071.004** (Application Layer Protocol: DNS)

## 5. Closure & Remediation
- Isolated the compromised host.
- Terminated active C2 connections, revoked credentials, and deployed Rule #13 to block future occurrences.
