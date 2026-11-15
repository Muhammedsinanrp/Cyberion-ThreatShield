# Cyberion ThreatShield 🛡️
### Managed Security Services | Detection Engineering & Threat Hunting Practice (CDL-DET-V2)

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1-orange.svg)](https://attack.mitre.org/)
[![Sigma Standard](https://img.shields.io/badge/Sigma-v2.0-blue.svg)](https://github.com/SigmaHQ/sigma)
[![Wazuh SIEM](https://img.shields.io/badge/Wazuh-v4.14.10-007EC6.svg)](https://wazuh.com/)
[![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20%7C%20WinSec%20%7C%20Zeek-brightgreen.svg)](#telemetry--lab-environment)
[![pySigma](https://img.shields.io/badge/pySigma-Splunk%20%26%20Sentinel-purple.svg)](https://github.com/SigmaHQ/pySigma)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Executive Overview

**Cyberion ThreatShield** is an advanced detection engineering, threat hunting, and incident response repository produced for **Cyberion Defense Labs**, a Managed Security Service Provider (MSSP) safeguarding enterprise clients across financial services, e-commerce, and healthcare sectors.

This project transitions the SOC from informal, tribal-knowledge alerting to a defensible, audited **Detection-as-Code (DaC)** lifecycle:
- **16+ Production Sigma Detection Rules** mapped strictly to MITRE ATT&CK techniques, including multi-event correlation rules.
- **MITRE ATT&CK Coverage Matrix & Navigator Layer** assessing 24 adversary techniques across 10 distinct tactics.
- **Hypothesis-Driven Threat Hunts** with mathematical beaconing jitter analysis and negative results reporting.
- **Full-Lifecycle Incident Case Reports** tracing intrusions from initial access to root cause analysis, corroboration, and closure.
- **Production Incident Response Playbooks** for rapid containment and eradication under time constraints.
- **Live Lab Verification & Evidence** validated against real telemetry with a live **Wazuh SIEM + Sysmon + pySigma** pipeline.

---

## 🏗️ Architecture & Lab Environment

The detection content and threat hunts in this project were tested and validated across both public adversary emulation datasets (**OTR Mordor**, **EVTX-ATTACK-SAMPLES**, **Splunk BOTS**) and a live simulated enterprise lab environment:

```
+-----------------------------------------------------------------------------------------------+
|                                    CYBERION LAB TOPOLOGY                                      |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|   +------------------------------------+             +------------------------------------+   |
|   |         WAZUH SIEM MANAGER         |             |       WINDOWS 10 WORKSTATION       |   |
|   |           cyberion-ubuntu          |             |          DESKTOP-G67LTP0           |   |
|   |           192.168.23.133           |             |           192.168.23.134           |   |
|   +------------------------------------+             +------------------------------------+   |
|   | • Wazuh Manager v4.14.10           |  TCP 1514   | • Microsoft Windows 10 x64         |   |
|   | • Threat Hunting & Alert Engine    | <=========> | • Microsoft Sysmon (Operational)   |   |
|   | • pySigma Splunk Backend (v2.1.0)  |  (TLS/AES)  | • Windows Security Event Logging   |   |
|   | • Custom Wazuh XML Rule Engine     |             | • Wazuh Agent v4.14.10 (WazuhSvc)  |   |
|   +------------------------------------+             +------------------------------------+   |
|                     ^                                                   ^                     |
|                     +------------------- VMnet Virtual Switch ----------+                     |
+-----------------------------------------------------------------------------------------------+
```

- **SIEM Manager Host:** `cyberion-ubuntu` (`192.168.23.133`) running Wazuh Manager, Elasticsearch/Indexer, and pySigma translation CLI.
- **Monitored Endpoint:** `DESKTOP-G67LTP0` (`192.168.23.134`), running Windows 10 Enterprise, Sysmon v15+, and Wazuh Agent configured for channel-based event log streaming (`Application`, `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`).

---

## 📂 Repository Structure

```
cybireon/
├── README.md                                   # Master Project Documentation & Quickstart
├── .gitignore                                  # Git ignore rules for virtualenvs, logs, and caches
│
├── detections/                                 # Detection Engineering Deliverables
│   ├── rules/                                  # 16+ Production Sigma Detection Rules (YAML)
│   │   ├── sysmon_certutil_download.yml        # T1105 - Certutil URLCache flag download
│   │   ├── sysmon_powershell_download_cradle.yml # T1059.001 - PowerShell download cradle & encoded cmd
│   │   ├── sysmon_lsass_dumping_procdump.yml   # T1003.001 - LSASS dump via ProcDump
│   │   ├── win_security_log_cleared.yml        # T1070.001 - Security event log cleared (Event 1102)
│   │   ├── win_security_suspicious_service_installed.yml # T1543.003 - Service install via PsExec / Temp
│   │   ├── sysmon_msbuild_process_execution.yml# T1127.001 - MSBuild inline task proxy execution
│   │   ├── sysmon_regsvr32_network_activity.yml# T1218.010 - Regsvr32 Squiblydoo scriptlet execution
│   │   ├── sysmon_rundll32_suspicious_extension.yml # T1218.011 - Rundll32 with non-standard extension
│   │   ├── sysmon_wmic_process_creation.yml    # T1047 - WMIC remote process call create
│   │   ├── sysmon_vssadmin_shadow_copy_delete.yml # T1490 - Volume shadow copy deletion
│   │   ├── win_security_kerberoasting_ticket_request.yml # T1558.003 - Kerberoasting RC4 ticket request
│   │   ├── sysmon_suspicious_scheduled_task_creation.yml # T1053.005 - Schtasks persistence
│   │   ├── sysmon_injection_createremotethread.yml # T1055.002 - Cross-process remote thread injection
│   │   ├── correlation_failed_logon_burst_followed_by_success.yml # Correlation: Password spray to valid login
│   │   ├── correlation_recon_enumeration_to_psexec_lateral.yml   # Correlation: Recon to PsExec lateral move
│   │   └── correlation_credential_dump_to_network_beaconing.yml  # Correlation: LSASS dump to external C2
│   ├── translations/                           # Cross-SIEM Query Portability
│   │   ├── splunk_spl_translations.md          # Production Splunk SPL translations
│   │   └── sentinel_kql_translations.md        # Microsoft Sentinel KQL translations
│   └── attack_navigator/                       # MITRE ATT&CK Navigator Layer Export
│       └── cyberion_coverage_layer.json        # Importable Navigator Layer JSON (v4.5 schema)
│
├── rules/                                      # Wazuh SIEM Local Detection Rules & Custom XML
│   └── windows/
│       ├── local_rules.xml                     # Custom Wazuh XML rules (Rule IDs: 100010, 100011, etc.)
│       ├── windows_scheduled_task_created.yml  # Scheduled task detection logic
│       └── windows_security_log_cleared.yml    # Windows security log clearing logic
│
├── docs/                                       # Core Analytical Documentation
│   ├── methodology.md                          # Detection Engineering & Threat Hunting Lifecycle
│   ├── data_dictionary.md                      # Complete Data Dictionary for WinSec, Sysmon, and Zeek
│   └── coverage_matrix.md                      # Detailed ATT&CK Coverage Matrix & Gap Analysis
│
├── evidence/                                   # Real Lab Evidence & Forensic Validation
│   ├── lab_evidence_documentation.md           # 19 Annotated screenshots and verification steps
│   ├── screenshots/                            # Primary forensic screenshots from live lab VM
│   │   ├── SS_105848.png ... SS_161030.png     # Manager setup, agent live connect, Sysmon feeds, alerts
│   │   └── SS_1113_230017.png                  # pySigma Splunk conversion toolchain execution
│   └── wazuh/                                  # Raw Wazuh Alert JSON captures from live lab triggers
│       ├── rule_100011_alert.json              # Live alert: Brute-force correlation (5 failures / 120s)
│       ├── rule_100012_powershell_download_alert.json # Live alert: PowerShell download cradle
│       ├── rule_100013_event_4697.json         # Live alert: Service installation (4697)
│       ├── rule_60228_scheduled_task_alert.json# Live alert: Scheduled task created
│       └── rule_92073_certutil_decode_alert.json # Live alert: Certutil decode/download
│
├── reports/                                    # Validation & Detection Test Reports
│   ├── conversions/
│   │   └── windows_security_sigma_spl.md       # Sigma to Splunk SPL translation report
│   └── detection_tests/                        # End-to-end atomic test execution reports
│       ├── rule_100011_brute_force_test.md
│       ├── rule_100012_powershell_download_test.md
│       ├── rule_100013_service_installation_test.md
│       ├── rule_60228_scheduled_task_test.md
│       └── rule_92073_certutil_decode_test.md
│
├── data/                                       # Datasets & Replay Telemetry
│   ├── datasets_provenance.md                  # Provenance of Mordor, EVTX-ATTACK-SAMPLES, and BOTS
│   └── sample_telemetry/                       # Replayable JSON log telemetry for unit testing
│       ├── sysmon_sample_events.json           # Curated Sysmon events (IDs 1, 3, 8, 10)
│       ├── win_security_sample_events.json     # Curated WinSec events (IDs 1102, 4624, 4625, 4697, 7045)
│       └── zeek_conn_dns_sample_events.json    # Curated Zeek conn/dns/ssl telemetry for beacon hunting
│
├── coverage/
│   └── evtx-sample-inventory.csv               # 250+ EVTX attack samples mapped to technique IDs
│
├── hunts/                                      # Structured Threat Hunt Reports
│   ├── hunt_001_c2_http_beaconing_jitter.md    # Statistical Inter-Arrival Time analysis for C2 beaconing
│   └── hunt_002_bits_jobs_asynchronous_staging.md # BITS abuse hunt targeting coverage gap (T1197)
│
└── incidents/                                  # End-to-End Incident Case Reports
    ├── incident_001_blackcat_precursor_lateral.md # Full incident report: Password spray to lateral movement
    └── incident_002_apt29_c2_credential_theft.md # Full incident report: Ingress staging to LSASS theft
```

---

## 🎯 MITRE ATT&CK Coverage Summary

Our detection engineering matrix evaluates **24 adversary techniques** across **10 distinct tactics**:

| Tactic | Assessed Techniques | Covered | Partially Covered | Gaps (Uncovered) | Coverage % |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Initial Access** | 3 | 1 (`T1078`) | 1 (`T1190`) | 1 (`T1566`) | **33.3%** |
| **Execution** | 2 | 2 (`T1059.001`, `T1047`) | 0 | 0 | **100.0%** |
| **Persistence** | 2 | 2 (`T1053.005`, `T1543.003`) | 0 | 0 | **100.0%** |
| **Privilege Escalation** | 2 | 1 (`T1055.002`) | 1 (`T1068`) | 0 | **50.0%** |
| **Defense Evasion** | 4 | 4 (`T1070.001`, `T1127.001`, `T1218.010`, `T1218.011`) | 0 | 0 | **100.0%** |
| **Credential Access** | 3 | 3 (`T1003.001`, `T1110.003`, `T1558.003`) | 0 | 0 | **100.0%** |
| **Discovery** | 2 | 1 (`T1087`) | 1 (`T1018`) | 0 | **50.0%** |
| **Lateral Movement** | 1 | 1 (`T1021.002`) | 0 | 0 | **100.0%** |
| **Command & Control** | 3 | 2 (`T1105`, `T1071.001`) | 1 (`T1071.004`) | 0 | **66.7%** |
| **Impact** | 1 | 1 (`T1490`) | 0 | 0 | **100.0%** |
| **Exfiltration** | 1 | 0 | 0 | 1 (`T1567`) | **0.0%** |
| **Total** | **24** | **18** | **4** | **2** | **75.0%** |

> 📊 **ATT&CK Navigator Layer:** Import [`detections/attack_navigator/cyberion_coverage_layer.json`](./detections/attack_navigator/cyberion_coverage_layer.json) into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to interactively visualize our covered (green), partially covered (yellow), and gap (red) techniques.

---

## 🔍 Structured Threat Hunts

### Hunt 001: Statistical Inter-Arrival Time Analysis for C2 HTTP/S Beaconing with Jitter
- **Techniques:** `T1071.001` (Web Protocols), `T1001.003` (Data Jitter)
- **Methodology:** Calculated Inter-Arrival Time deltas ($\Delta t = t_i - t_{i-1}$) and Coefficient of Variation ($CV = \sigma / \mu$) across Zeek `conn.log` connection sessions.
- **Outcome:** **CONFIRMED** — Identified persistent HTTPS beaconing on `WORKSTATION6` (`10.0.2.106`) connecting to adversary IP `198.51.100.42` at 60-second intervals with $CV = 0.041$ ($4.1\%$ jitter).
- **Report:** [`hunts/hunt_001_c2_http_beaconing_jitter.md`](./hunts/hunt_001_c2_http_beaconing_jitter.md)

### Hunt 002: Abuse of Background Intelligent Transfer Service (BITS) Jobs
- **Technique:** `T1197` (BITS Jobs) — *Technique deliberately selected as a pre-existing detection gap*.
- **Methodology:** Audited 14 days of `Microsoft-Windows-Bits-Client/Operational` (Event IDs 3, 4, 59) and Sysmon Event ID 1 against 120 endpoints.
- **Outcome:** **RULED OUT** — All observed transfers were verified Microsoft updates (`*.delivery.mp.microsoft.com`). Created and backlogged a new Sigma rule to permanently close this blind spot.
- **Report:** [`hunts/hunt_002_bits_jobs_asynchronous_staging.md`](./hunts/hunt_002_bits_jobs_asynchronous_staging.md)

---

## 🚨 Incident Investigation Highlights

### Incident CDL-IR-2026-001: Ransomware Precursor & Lateral Movement
- **Threat Actor Tradecraft:** FIN7 / BlackCat (ALPHV) affiliate behavior.
- **Incident Summary:** External password spraying from `203.0.113.88` compromised high-privilege account `CYBERION\admin_sec`. Attacker pivoted to database server `SQL01`, installed `PSEXESVC.exe`, attempted shadow copy deletion via `vssadmin.exe delete shadows /all /quiet`, and cleared the Windows Security event log.
- **Classification:** **True Positive (Critical Severity)**.
- **Report:** [`incidents/incident_001_blackcat_precursor_lateral.md`](./incidents/incident_001_blackcat_precursor_lateral.md)

---

## 🛠️ How to Replicate & Use This Content

### 1. Validating Sigma Rules with pySigma
Ensure Python 3.10+ is installed with `sigma-cli` and target backends:

```bash
# Install pySigma and backends
pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto

# Validate Sigma rule syntax
sigma check detections/rules/sysmon_certutil_download.yml

# Convert to Splunk SPL using the Windows Sysmon pipeline
sigma convert -t splunk -p splunk_windows detections/rules/win_security_log_cleared.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t kusto detections/rules/sysmon_lsass_dumping_procdump.yml
```

### 2. Deploying Custom Rules to Wazuh Manager
Copy the custom rules from [`rules/windows/local_rules.xml`](./rules/windows/local_rules.xml) into the Wazuh manager's `/var/ossec/etc/rules/local_rules.xml`:

```bash
# On Wazuh Manager:
sudo cp rules/windows/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t   # Test rule syntax
sudo systemctl restart wazuh-manager     # Apply rules
```

### 3. Replaying Sample Telemetry
The sample telemetry stored in [`data/sample_telemetry/`](./data/sample_telemetry/) can be parsed or ingested directly into your log forwarder, SIEM, or test scripts to verify trigger conditions.

---

## 📜 Deliverables Checklist (PRD CDL-DET-V2 Compliance)

- [x] **Detection Rule Library:** 16+ Sigma rules (YAML) with technique mapping, logic, severity, and false positive notes.
- [x] **Correlation Detections:** 3 multi-event temporal and aggregation correlation rules.
- [x] **MITRE ATT&CK Matrix:** Assessed 24 techniques across 10 tactics; exportable Navigator layer JSON.
- [x] **Data Dictionary:** Exhaustive telemetry schema documentation for Windows Security, Sysmon, and Zeek.
- [x] **Threat Hunting Reports:** 2 structured reports following hypothesis-driven method, including negative results.
- [x] **Incident Case Reports:** Full forensic reconstructions with timeline, root cause, impact, and classification.
- [x] **Cross-Platform SIEM Translations:** Splunk SPL and Microsoft Sentinel KQL queries.
- [x] **Primary Lab Evidence:** 19 real lab screenshots, raw Wazuh alert JSON files, and test reports.

---

## 👤 Author & Engagement Information

- **Organization:** Cyberion Defense Labs
- **Practice:** Detection Engineering & Threat Intelligence Office
- **Project Code:** CDL-DET-V2
- **Version:** 2.0
- **Document Owner:** Manager, Detection Engineering
- **GitHub Repository:** [Muhammedsinanrp/Cyberion-ThreatShield](https://github.com/Muhammedsinanrp/Cyberion-ThreatShield)
