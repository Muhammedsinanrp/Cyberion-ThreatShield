# Cyberion ThreatShield — Telemetry Data Dictionary

## 1. Dataset overview

- Total event records: 4,633
- Unique EVTX files represented: 249
- Unique Event IDs: 95
- Log channels: 12
- ATT&CK tactics represented: 8
- Dataset: EVTX-ATTACK-SAMPLES (public Windows attack telemetry samples)

## 2. Telemetry channels

| Channel | Records | Observed Event IDs |
|---|---:|---|
| Application | 393 | 325, 326, 327, 1040, 1042, 3001, 15281, 15457, 18454, 18456, 33205 |
| Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant | 4 | 17 |
| Microsoft-Windows-Application-Experience/Program-Telemetry | 7 | 500 |
| Microsoft-Windows-Bits-Client/Operational | 11 | 3, 4, 59, 60, 209 |
| Microsoft-Windows-PowerShell/Operational | 6 | 4104, 40961, 40962, 53504 |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational | 61 | 68, 104, 131, 168 |
| Microsoft-Windows-Sysmon/Operational | 2401 | 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23 |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | 228 | 258, 261, 1136, 1149, 1155 |
| Microsoft-Windows-WinRM/Operational | 7 | 91, 169, 193 |
| Microsoft-Windows-Winsock-WS2HELP/Operational | 2 | 1 |
| Security | 1496 | 1102, 4611, 4624, 4625, 4634, 4648, 4656, 4658, 4661, 4662, 4663, 4672, 4673, 4688, 4698, 4699, 4702, 4703, 4719, 4720, 4724, 4732, 4738, 4742, 4765, 4768, 4771, 4776, 4794, 4798, 4799, 4826, 4985, 5136, 5140, 5142, 5145, 5156, 5158 |
| System | 17 | 104, 5805, 7036, 7045, 10016 |

## 3. ATT&CK tactic distribution

| Tactic | Records |
|---|---:|
| Lateral Movement | 1288 |
| Privilege Escalation | 1088 |
| Execution | 533 |
| Command and Control | 432 |
| Defense Evasion | 431 |
| Persistence | 411 |
| Credential Access | 283 |
| Discovery | 167 |

## 4. Important available fields

- `Channel`
- `EventID`
- `EVTX_FileName`
- `EVTX_Tactic`
- `SystemTime`
- `Computer`
- `ProcessName`
- `CommandLine`
- `ParentImage`
- `Image`
- `SourceIp`
- `DestinationIp`
- `SourceAddress`
- `DestAddress`
- `TargetFilename`
- `TargetUserName`
- `SubjectUserName`
- `LogonType`

## 5. Primary telemetry priorities

- Sysmon Operational: process, network, file and registry activity.
- Security: authentication, account management and Windows audit activity.
- Application: application-related events.
- Supporting channels: PowerShell, RDP, WinRM, BITS and System.

## 6. Data limitations

- These are public attack-associated telemetry samples, not production incident logs.
- Event availability depends on the individual sample and its logging configuration.
- A tactic appearing in the dataset does not prove complete ATT&CK technique coverage.
- Detection rules must be tested against relevant event fields and documented evidence.
