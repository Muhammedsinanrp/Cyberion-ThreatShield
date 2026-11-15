# Cyberion Defense Labs — Dataset Provenance & Telemetry Evidence Repository

**Document ID:** CDL-DET-V2-PROV  
**Version:** 2.0  
**Classification:** Internal Engineering Deliverable  
**Repositories Referenced:** OTR Mordor Project, EVTX-ATTACK-SAMPLES, Splunk BOTS v2 & v3

---

## 1. Dataset Provenance Summary

In accordance with PRD Section 5 (Reproducibility & Evidence-Based Claims) and Section 9 (Data Sources), this directory stores curated telemetry extracts from public adversarial emulation sessions and attack repositories. Every detection rule, hunt hypothesis, and incident report in this project directly traces to raw telemetry stored within this repository.

### 1.1 Source Mappings

| Dataset ID | Origin & Repository | Scenario Description | Primary Techniques Captured | File Artifact in Repo |
| :--- | :--- | :--- | :--- | :--- |
| **DS-MORD-01** | Open Threat Research (OTR) Forge — Mordor Project | APT29 Day 1 & Day 2 Emulation (`WORKSTATION6.cyberion.local`) | T1059.001 (PowerShell), T1055 (Process Injection), T1003.001 (LSASS Dump), T1071.001 (C2) | `data/sample_telemetry/sysmon_sample_events.json` |
| **DS-EVTX-02** | EVTX-ATTACK-SAMPLES (Florian Roth) | Atomic Execution of LOLBAS & Defense Evasion Artifacts | T1105 (Certutil), T1218.010 (Regsvr32), T1218.011 (Rundll32), T1070.001 (Log Cleared), T1490 (VSSAdmin) | `data/sample_telemetry/sysmon_sample_events.json`, `data/sample_telemetry/win_security_sample_events.json` |
| **DS-BOTS-03** | Splunk Boss of the SOC (BOTS) v2/v3 | Lateral Movement, Service Creation, and Credential Stuffing | T1021.002 (SMB/PsExec), T1543.003 (Service Install), T1558.003 (Kerberoasting), T1110 (Brute Force) | `data/sample_telemetry/win_security_sample_events.json` |
| **DS-ZEEK-04** | Zeek Network Capture Repository / BOTS Enterprise NSM | Multi-hour C2 Beaconing, DNS Query Tunneling, and Exfiltration | T1071.001 (Web C2), T1071.004 (DNS C2), T1001.003 (Jitter Analysis) | `data/sample_telemetry/zeek_conn_dns_sample_events.json` |

---

## 2. Telemetry Environment Specification

The datasets represent a standard corporate Active Directory and Windows Enterprise environment:
- **Domain:** `CYBERION.LOCAL`
- **Domain Controller:** `DC01.cyberion.local` (`10.0.1.10`)
- **Key Enterprise Servers:**
  - `WEBSVR01.cyberion.local` (`10.0.1.25`) — Public-facing web application server running IIS.
  - `SQL01.cyberion.local` (`10.0.1.30`) — Core financial database server hosting MS SQL.
- **Client Endpoints:**
  - `WORKSTATION6.cyberion.local` (`10.0.2.106`) — Finance Department workstation assigned to user `jdoe` (victim host in Incident 001).
  - `DESKTOP-HR2.cyberion.local` (`10.0.2.112`) — Human Resources workstation assigned to user `asmith` (victim host in Incident 002).
- **External Adversary Infrastructure:**
  - `198.51.100.42` — External Cobalt Strike / Empire C2 server (`c2-update.cloud-telemetry.org`).
  - `185.220.101.5` — External payload delivery host (`cdn-edge-pkg.com`).
  - `203.0.113.88` — Tor egress / password spraying source IP.

---

## 3. Telemetry Verification Checksums

To ensure forensic reproducibility, sample event files are maintained in clean JSON formatting with standardized timestamps, event codes, process trees, and network metadata.

