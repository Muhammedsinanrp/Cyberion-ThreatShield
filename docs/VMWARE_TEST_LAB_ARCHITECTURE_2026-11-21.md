# VMware Test Lab — Machines, Interfaces and Tools

**Project:** Cyberion ThreatShield v1.0 / CDL-DET-V2  
**Evidence recorded:** 2026-11-21  
**Environment:** VMware-based test lab, not production  
**Status:** STAGED — NOT PRODUCTION APPROVED

## Virtual machines and roles

| VMware display / hostname | OS | Role |
| --- | --- | --- |
| `cyberion-wazuh-lab` / `cyberion-virtual-machine` | Ubuntu 22.04.5 LTS, Wazuh 4.14.10-1 | **TEST** Wazuh Manager, rules, correlation and alerts |
| `Windows 10 x64` / `CYBERION-WIN10-LAB` (Windows hostname `DESKTOP-G67LTP0`) | Windows 10 Enterprise Evaluation | **TEST** endpoint, Wazuh Agent 4.14.10, Sysmon64 and PowerShell telemetry |
| `Ubuntu 64-bit` | Separate Ubuntu VM shown in VMware tab | **Not the identified TEST manager**; do not confuse it with the test environment |
| `192.168.23.133` | Separate Ubuntu Wazuh manager | **PRODUCTION — excluded from tests, no changes authorized** |

A VMware tab title alone is not evidence of a machine's internal hostname, IP or deployment role.

## Observed IPv4 addressing (local TEST only)

| System | Interface | IPv4 | Mask | Default gateway shown |
| --- | --- | --- | --- | --- |
| Ubuntu TEST | `ens34` | `192.168.23.136` | `255.255.255.0` | not shown in `ifconfig` |
| Windows TEST | `Ethernet0` | `192.168.23.134` | `255.255.255.0` | none |
| Ubuntu TEST | `ens33` | `192.168.157.153` | `255.255.255.0` | not shown in `ifconfig` |
| Windows TEST | `Ethernet1` | `192.168.157.151` | `255.255.255.0` | `192.168.157.2` |

**Notes:** `192.168.23.0/24` is the verified host-only TEST telemetry/enrollment path between Windows agent and Ubuntu manager. `192.168.157.0/24` is another VMware-connected network. The connection type and external exposure of the second network have not been independently established. An `ifconfig` printout does not show default routes, so Ubuntu gateway is intentionally not asserted.

## Security telemetry and workflow

```text
Windows 10 TEST (192.168.23.134, Ethernet0)
  |-- Sysmon / Operational event log
  |-- PowerShell / Operational Event ID 4104
  |-- Windows Security events
  +-- Wazuh Agent 4.14.10
          |
          | TEST host-only network 192.168.23.0/24
          v
Ubuntu TEST Wazuh Manager (192.168.23.136, ens34)
  |-- Wazuh rules engine / windows_eventchannel decoder
  |-- custom rules under /var/ossec/etc/rules
  +-- alerts.json evidence
```

## Machines, tools and applications used

- VMware virtual machines for controlled test environments
- Ubuntu 22.04.5 Wazuh TEST Manager and Wazuh analysis engine
- Windows 10 Enterprise Evaluation and Wazuh Agent 4.14.10
- Sysmon64 process telemetry and Windows event logs
- PowerShell Script Block Logging (Event ID 4104)
- Wazuh `wazuh-analysisd -t`, alert JSON and manager logs
- Sigma detection format and MITRE ATT&CK technique mapping
- Python 3 for JSON extraction, reporting and tests
- OpenSSH, SCP, `ifconfig`, `ipconfig` and `sha256sum` for test access and verification

## Confirmed evidence and limitations

- The Windows TEST Agent generated **six live alerts** for custom Wazuh rule **100010** detecting `net user` account discovery. The alerts occurred in three timestamp pairs; they are not six independently proven incidents.
- The built-in rule **91816** generated an alert for genuine Windows PowerShell Event ID 4104 telemetry; this proves the EventChannel pipeline was functional.
- `wazuh-analysisd -t` succeeded and Wazuh's `etc/rules` directory was configured.
- Custom rules **100120** and **100127**, and other custom rule candidates, were **not** proven to trigger end-to-end during the recorded tests.
- No live production Wazuh host was accessed or modified for this validation.
- Raw alerts and extra screenshots are withheld from this document because they may contain personally identifying, internal network or system details.

## Reproduce non-destructive checks (TEST host only)

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo grep -n -A 14 '<ruleset>' /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/agent_control -l
```

No changes to services, firewall, agent enrollment, Defender or production environment are authorized by this document.

**Related:** [PRD compliance audit](./PRD_COMPLIANCE_AUDIT_2026-11-21.md) · [PRD matrix](./PRD_COMPLIANCE_MATRIX_2026-11-21.csv)
