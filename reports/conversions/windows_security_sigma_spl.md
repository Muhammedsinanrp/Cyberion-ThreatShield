# Windows Sigma Rules - Splunk SPL Conversion

**Project:** Cyberion ThreatShield
**Backend:** Splunk
**Pipeline:** splunk_windows
**Conversion status:** PASS

## Rule 1: Windows Security Audit Log Cleared

- Event ID: 1102
- ATT&CK: T1685.005
- Status: Converted successfully

    source="WinEventLog:Security" EventCode=1102

## Rule 2: Windows Scheduled Task Created

- Event ID: 4698
- ATT&CK: T1053.005
- Status: Converted successfully

    source="WinEventLog:Security" EventCode=4698

## Limitations

Conversion confirms SPL generation only. Live detection in a Splunk environment has not yet been tested.

## Rule 3: Windows User Account Created

- Event ID: 4720
- ATT&CK: T1136
- Status: Converted successfully

    source="WinEventLog:Security" EventCode=4720
