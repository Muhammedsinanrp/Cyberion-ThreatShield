# Detection Test: Windows Service Installation

## Objective
Verify collection and detection logic for Windows Security Event ID 4697.

## Detection Rule
- Rule ID: 100013
- Description: Cyberion: Windows service installation detected.
- Severity: 7
- ATT&CK: T1543.003 - Windows Service

## Test Environment
- Wazuh Manager: 4.14.10
- Windows Agent: 001 (DESKTOP-G67LTP0)
- Event Channel: Security
- Event ID: 4697
- Test Service: CyberionTestSvc4

## Test Results

| Test | Result |
|---|---|
| Windows generated Event ID 4697 | PASS |
| Event received by Wazuh manager | PASS |
| Raw event archived | PASS |
| Exact archived event matched Rule 100013 using wazuh-logtest | PASS |
| Corresponding live alert found in alerts.json | NOT VERIFIED |

## Evidence
- evidence/wazuh/rule_100013_event_4697.json

## Limitations
The event was received and archived by Wazuh. Replaying the exact archived event through wazuh-logtest matched custom rule 100013 at level 7.

However, no corresponding live alert was found in alerts.json. Therefore, live alert generation is not confirmed. The reason for this difference has not been established.

## Conclusion
Event collection and rule logic replay were successful. Live detection alert generation remains unverified and requires further investigation.
