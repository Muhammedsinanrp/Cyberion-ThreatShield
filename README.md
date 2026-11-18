# Cyberion ThreatShield 🛡️

**Detection Engineering · Threat Hunting · Incident Response**  
Project: **CDL-DET-V2**

Cyberion ThreatShield is a hands-on cybersecurity detection and response project. The repository contains Sigma detection content, Wazuh rules, ATT&CK coverage artifacts, threat-hunt notes, incident case studies, response playbooks, telemetry samples, and validation evidence.

> **Project status note:** This README documents files currently present in the repository. A file being present does not by itself mean that its detection has passed syntax validation or end-to-end testing. See the evidence and test reports before treating a rule as verified.

---

## Repository structure

The tree below reflects the current repository paths. It is documentation only; no folders or project files have been moved or deleted.

```text
Cyberion-ThreatShield/
├── README.md
├── .gitignore
├── coverage-matrix.csv
├── cases/
│   ├── incident_case_01_beaconing.md
│   └── incident_case_02_credential_dumping.md
├── coverage/
│   └── evtx-sample-inventory.csv
├── data/
│   ├── datasets_provenance.md
│   └── sample_telemetry/
│       ├── sysmon_sample_events.json
│       ├── win_security_sample_events.json
│       └── zeek_conn_dns_sample_events.json
├── data_dictionary/
│   └── telemetry-data-dictionary.md
├── detections/
│   ├── attack_navigator/
│   │   └── cyberion_coverage_layer.json
│   ├── rules/
│   │   ├── correlation_credential_dump_to_network_beaconing.yml
│   │   ├── correlation_failed_logon_burst_followed_by_success.yml
│   │   ├── correlation_recon_enumeration_to_psexec_lateral.yml
│   │   ├── sysmon_certutil_download.yml
│   │   ├── sysmon_injection_createremotethread.yml
│   │   ├── sysmon_lsass_dumping_procdump.yml
│   │   ├── sysmon_msbuild_process_execution.yml
│   │   ├── sysmon_powershell_download_cradle.yml
│   │   ├── sysmon_regsvr32_network_activity.yml
│   │   ├── sysmon_rundll32_suspicious_extension.yml
│   │   ├── sysmon_suspicious_scheduled_task_creation.yml
│   │   ├── sysmon_vssadmin_shadow_copy_delete.yml
│   │   ├── sysmon_wmic_process_creation.yml
│   │   ├── win_security_kerberoasting_ticket_request.yml
│   │   ├── win_security_log_cleared.yml
│   │   └── win_security_suspicious_service_installed.yml
│   └── translations/
│       ├── sentinel_kql_translations.md
│       └── splunk_spl_translations.md
├── docs/
│   ├── coverage_matrix.md
│   ├── data_dictionary.md
│   └── methodology.md
├── evidence/
│   ├── lab_evidence_documentation.md
│   ├── screenshots/
│   └── wazuh/
│       ├── rule_100011_alert.json
│       ├── rule_100012_powershell_download_alert.json
│       ├── rule_100013_event_4697.json
│       ├── rule_60228_scheduled_task_alert.json
│       ├── rule_92073_certutil_decode_alert.json
│       └── rule_windows_local_account_created_4720.json
├── hunts/
│   ├── hunt_001_c2_http_beaconing_jitter.md
│   ├── hunt_002_bits_jobs_asynchronous_staging.md
│   ├── threat_hunt_01_beaconing.md
│   └── threat_hunt_02_credential_access.md
├── incidents/
│   └── incident_001_blackcat_precursor_lateral.md
├── playbooks/
│   ├── ir_playbook_c2_beaconing.md
│   ├── ir_playbook_credential_compromise.md
│   └── ir_playbook_lateral_movement.md
├── reports/
│   ├── conversions/
│   │   └── windows_security_sigma_spl.md
│   ├── detection_tests/
│   │   ├── rule_100011_brute_force_test.md
│   │   ├── rule_100012_powershell_download_test.md
│   │   ├── rule_100013_service_installation_test.md
│   │   ├── rule_60228_scheduled_task_test.md
│   │   ├── rule_92073_certutil_decode_test.md
│   │   └── rule_windows_local_account_created_test.md
│   ├── executive_summary.md
│   ├── final_presentation.md
│   └── ioc_research_notes.md
└── rules/
    └── windows/
        ├── local_rules.xml
        ├── windows_c2_beaconing_dns_requests.yml
        ├── windows_credential_access_sam_dump.yml
        ├── windows_credential_dumping_lsass.io.yml
        ├── windows_defense_evasion_disable_defender.yml
        ├── windows_discovery_whoami_net.yml
        ├── windows_exfiltration_archive_compression.yml
        ├── windows_lateral_movement_psexec.yml
        ├── windows_local_account_created.yml
        ├── windows_powershell_download_cradle.yml
        ├── windows_process_injection_suspicious_hollow.yml
        ├── windows_remote_desktop_connection_cleared.yml
        ├── windows_scheduled_task_created.yml
        ├── windows_security_log_cleared.yml
        ├── windows_suspicious_scheduled_task_at.yml
        └── windows_suspicious_service_installation.yml
```

---

## Sigma detection library (16 YAML files)

All 16 Sigma YAML files are located in `detections/rules/`.

| # | Rule file | Focus / ATT&CK mapping |
|---:|---|---|
| 1 | `sysmon_certutil_download.yml` | Certutil download activity — T1105 |
| 2 | `sysmon_injection_createremotethread.yml` | Remote thread process injection — T1055.002 |
| 3 | `sysmon_lsass_dumping_procdump.yml` | LSASS memory dumping — T1003.001 |
| 4 | `sysmon_msbuild_process_execution.yml` | MSBuild proxy execution — T1127.001 |
| 5 | `sysmon_powershell_download_cradle.yml` | PowerShell download / execution — T1059.001 |
| 6 | `sysmon_regsvr32_network_activity.yml` | Regsvr32 proxy execution — T1218.010 |
| 7 | `sysmon_rundll32_suspicious_extension.yml` | Rundll32 proxy execution — T1218.011 |
| 8 | `sysmon_suspicious_scheduled_task_creation.yml` | Scheduled task persistence — T1053.005 |
| 9 | `sysmon_vssadmin_shadow_copy_delete.yml` | Shadow copy deletion — T1490 |
| 10 | `sysmon_wmic_process_creation.yml` | WMIC process execution — T1047 |
| 11 | `win_security_kerberoasting_ticket_request.yml` | Kerberoasting — T1558.003 |
| 12 | `win_security_log_cleared.yml` | Security log clearing — T1070.001 |
| 13 | `win_security_suspicious_service_installed.yml` | Windows service installation — T1543.003 |
| 14 | `correlation_credential_dump_to_network_beaconing.yml` | Credential-dumping activity followed by network beaconing (correlation candidate) |
| 15 | `correlation_failed_logon_burst_followed_by_success.yml` | Failed-logon burst followed by successful logon (correlation candidate) |
| 16 | `correlation_recon_enumeration_to_psexec_lateral.yml` | Reconnaissance followed by PsExec lateral movement (correlation candidate) |

The three files prefixed `correlation_` are included as correlation-oriented detection content. Their presence is not a claim that they conform to the formal Sigma correlation specification; validate their schema and semantics before deployment.

### Related Wazuh rules

The separate `rules/windows/` directory contains Wazuh-oriented YAML detections and `local_rules.xml`. These are not included in the 16-file Sigma count above. Keep the distinction clear:

- `detections/rules/` — Sigma detection rules.
- `rules/windows/` — Wazuh-focused rule content and local XML configuration.

## MITRE ATT&CK coverage

Coverage artifacts are maintained in:

- [Coverage matrix CSV](./coverage-matrix.csv)
- [Detailed coverage analysis](./docs/coverage_matrix.md)
- [EVTX sample inventory](./coverage/evtx-sample-inventory.csv)
- [ATT&CK Navigator layer](./detections/attack_navigator/cyberion_coverage_layer.json)

Use these files as the source of truth for technique coverage and gaps. Coverage mapping is not proof that every technique has a tested detection.

## Threat hunting

Hunt documentation is in `hunts/`:

- [Hunt 001 — C2 HTTP beaconing and jitter](./hunts/hunt_001_c2_http_beaconing_jitter.md)
- [Hunt 002 — BITS jobs and asynchronous staging](./hunts/hunt_002_bits_jobs_asynchronous_staging.md)
- [Beaconing hunt notes](./hunts/threat_hunt_01_beaconing.md)
- [Credential-access hunt notes](./hunts/threat_hunt_02_credential_access.md)

## Incident cases and investigations

- `cases/` contains two concise incident case-study files:
  - [Case 01 — Beaconing](./cases/incident_case_01_beaconing.md)
  - [Case 02 — Credential dumping](./cases/incident_case_02_credential_dumping.md)
- `incidents/` contains the detailed investigation:
  - [Incident 001 — BlackCat precursor and lateral movement](./incidents/incident_001_blackcat_precursor_lateral.md)

## Incident response playbooks

The `playbooks/` directory contains three response guides:

- [C2 beaconing response](./playbooks/ir_playbook_c2_beaconing.md)
- [Credential compromise response](./playbooks/ir_playbook_credential_compromise.md)
- [Lateral movement response](./playbooks/ir_playbook_lateral_movement.md)

## Reports, evidence and validation

- `reports/executive_summary.md` — project summary.
- `reports/final_presentation.md` — presentation notes.
- `reports/ioc_research_notes.md` — IOC research notes.
- `reports/conversions/` — Sigma-to-Splunk conversion report.
- `reports/detection_tests/` — individual detection test reports.
- `evidence/lab_evidence_documentation.md` — lab evidence index and verification notes.
- `evidence/screenshots/` — screenshots from the lab.
- `evidence/wazuh/` — captured Wazuh alert JSON.
- `data/` — dataset provenance and sample telemetry.
- `data_dictionary/` and `docs/data_dictionary.md` — telemetry field documentation.

The repository currently contains six detection-test report files and six Wazuh alert JSON files. Each report describes its own test scope and outcome; do not generalize a passing Wazuh test into a claim that all Sigma rules have been validated. Review any stated limitations in the individual reports.

## SIEM translations

- [Splunk SPL translations](./detections/translations/splunk_spl_translations.md)
- [Microsoft Sentinel KQL translations](./detections/translations/sentinel_kql_translations.md)

## Quick start: inspect and validate Sigma content

Use a Python environment with Sigma CLI and the required backend packages installed.

```bash
# Install the CLI and backends
python -m pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto

# Check a Sigma rule
sigma check detections/rules/sysmon_certutil_download.yml

# Convert a rule to Splunk SPL
sigma convert -t splunk -p splunk_windows detections/rules/win_security_log_cleared.yml

# Convert a rule to Microsoft Sentinel KQL
sigma convert -t kusto detections/rules/sysmon_lsass_dumping_procdump.yml
```

Check the installed Sigma CLI/backend versions and pipeline names if a command differs in your environment. Validate every rule individually before operational use.

## Project references

- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://github.com/SigmaHQ/sigma
- Wazuh: https://wazuh.com/
- pySigma: https://github.com/SigmaHQ/pySigma

---

**Project:** CDL-DET-V2  
**Repository:** [Muhammedsinanrp/Cyberion-ThreatShield](https://github.com/Muhammedsinanrp/Cyberion-ThreatShield)
