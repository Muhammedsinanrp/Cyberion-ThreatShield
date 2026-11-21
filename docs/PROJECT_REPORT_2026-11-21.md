# Cyberion ThreatShield v1.0 — Project Report (GitHub Edition)

**Project:** CDL-DET-V2 — Detection Engineering & Threat Hunting  
**Report date:** 2026-11-21  
**Release classification:** STAGED / NOT PRODUCTION APPROVED  
**Evidence status:** One custom detection confirmed live; remaining coverage partly documented or experimental.

## 1. Executive summary

Cyberion ThreatShield is a defensive detection-engineering and threat-hunting portfolio project based on a simulated client security environment. It documents Sigma-format behavioral detection rules, ATT&CK mapping, threat hunts, incident response case studies, written response playbooks, IOC research and Wazuh verification in a lab. This is a research/content-engineering deliverable, **not** an approved production SOC platform.

The strongest verified live result is **six Wazuh alerts** on custom rule **100010**, originating from a Windows TEST endpoint performing `net user` local account discovery. The recorded alerts arrived in three closely paired groups and should not be described as six separate attacks. Built-in PowerShell rule 91816 also confirmed end-to-end EventChannel telemetry.

## 2. Objectives and PRD alignment

The underlying Cyberion Defense Labs PRD (version 2.0) requires 15+ Sigma rules, three correlation detections, 20 mapped ATT&CK techniques, two hunts, two incident investigations, three playbooks, false-positive analysis, data provenance and executive reporting.

Project files meet many **inventory** targets, but presence of YAML, test narratives or diagrams does not automatically establish native detection effectiveness. The [compliance audit](./PRD_COMPLIANCE_AUDIT_2026-11-21.md) identifies the remaining validation gaps.

## 3. Implementation and network architecture

See [VMware TEST lab architecture](./VMWARE_TEST_LAB_ARCHITECTURE_2026-11-21.md).

| System | Role | Primary TEST address | Secondary VMware address |
| --- | --- | --- | --- |
| Ubuntu 22.04.5 / `cyberion-virtual-machine` | TEST Wazuh Manager 4.14.10-1 | `192.168.23.136` on `ens34` | `192.168.157.153` on `ens33` |
| Windows 10 Enterprise Evaluation / `CYBERION-WIN10-LAB` | TEST Wazuh Agent 4.14.10, Sysmon64 | `192.168.23.134` on `Ethernet0` | `192.168.157.151` on `Ethernet1` |

The Windows TEST VM has no default gateway on Ethernet0, and `192.168.157.2` on Ethernet1. The Windows-to-manager Wazuh agent path was verified on the `192.168.23.0/24` TEST network. The separate production manager at `192.168.23.133` was excluded from this exercise.

## 4. Tools and workflows

**Virtualization / systems:** VMware, Ubuntu 22.04.5, Windows 10 Enterprise Evaluation.  
**Telemetry:** Wazuh Manager/Agent 4.14.10, Windows EventChannel, Sysmon, Windows Security logs, PowerShell 4104.  
**Detection engineering:** Sigma YAML, Wazuh XML custom rules, PCRE2 patterns, MITRE ATT&CK Navigator.  
**Analysis and reporting:** Python 3, JSON, log review, Markdown, presentation tools.  
**Networking and evidence:** SSH/SCP, PowerShell, `ifconfig`/`ipconfig`, ZIP integrity verification, SHA-256.

## 5. Detection engineering

The source repository provides Sigma rules for process and PowerShell behaviors, suspicious services and scheduled tasks, account use, security-log clearing, and more. Three correlation candidates are documented. ATT&CK coverage is recorded in matrix and Navigator formats.

The Wazuh custom rule set additionally includes account discovery and experimental Windows event detections. Each rule should be evaluated with the correct telemetry decoder, field mappings, parent-rule chain, representative positive/negative inputs, and a documented false-positive assessment.

## 6. Test method and findings

1. Run Wazuh's native `wazuh-analysisd -t` syntax validation on the isolated TEST Manager.
2. Confirm `<rule_dir>etc/rules</rule_dir>` is configured.
3. Confirm the Windows agent is connected to the isolated TEST manager.
4. Generate benign lab behavior using `net user`; collect Sysmon telemetry on Windows.
5. Retrieve `alerts.json` records with `rule.id == 100010` and `agent.id == 001`; six alerts were present.
6. Confirm PowerShell Event ID 4104 with built-in rule 91816.
7. Document all unverified native custom-rule outcomes as pending rather than successful.

The manager's raw archives were disabled (`logall=no`, `logall_json=no`). Therefore absence of an alert from rule 100127 is not proof the underlying Windows event was never collected. Offline regex matches and generic JSON logtest simulations are **not equivalent** to live Windows EventChannel rule matching.

## 7. Threat hunts, incidents and response playbooks

The project contains written hunt reports, two principal incident case reports, IOC research and three response playbooks. The narratives are useful analytical artifacts, but some asserted incidents and closure labels still require full provenance and independent corroboration against source telemetry. Do not claim that all cases are live intrusions.

The playbooks cover credential misuse, lateral movement and command-and-control response, including investigation, containment, recovery and communication.

## 8. Scope, limitations and next validation

- Complete evidence-based native rule testing is still outstanding for most custom Wazuh rules.
- Validate all Sigma rules and three correlation candidates on real event sequences.
- Verify and, where needed, downgrade ATT&CK matrix coverage claims.
- Link both incident case reports to raw datasets, timestamps, investigation decisions and closure evidence.
- Reproduce at least three documented false-positive tuning passes.
- Review all evidence for internal IPs, usernames, private paths, tokens and dataset redistribution limits before public upload.
- Keep the production manager separate and do not modify it without explicit approval.

## 9. Conclusion

The project demonstrates a functioning **isolated TEST Wazuh monitoring path**, at least one successful custom detector and a broader detection-engineering documentation corpus. It remains a **staged, partially validated prototype**.

## 10. Supporting files

- [Machine, network and tool inventory](./VMWARE_TEST_LAB_ARCHITECTURE_2026-11-21.md)
- [PRD compliance audit](./PRD_COMPLIANCE_AUDIT_2026-11-21.md)
- [PRD compliance matrix](./PRD_COMPLIANCE_MATRIX_2026-11-21.csv)
- [Executive summary](../reports/executive_summary.md)
- [Existing presentation outline](../reports/final_presentation.md)
- [Detection rules](../detections/rules/)
- [Wazuh local rules](../rules/wazuh/local_rules.xml)
- [Incident cases](../cases/)
- [Hunts](../hunts/)
- [Response playbooks](../playbooks/)

**Distribution:** This GitHub Markdown edition intentionally omits raw agent-event exports and unreviewed screenshot attachments. Editable DOCX/PDF project reports and PPTX can be added after separately checking binary file contents for private data.
