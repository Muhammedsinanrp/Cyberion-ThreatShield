# Detection Test 8: Windows Scheduled Task Creation

## 1. Objective
Validate Wazuh detection of Windows scheduled-task creation.

## 2. Detection Configuration
- Wazuh Rule ID: 60228 (built-in)
- Severity: Level 4
- Windows Security Event ID: 4698
- ATT&CK Technique: T1053 - Scheduled Task/Job

## 3. Lab Environment
- Wazuh Manager: Ubuntu 22.04
- Wazuh Agent: Windows 10
- Agent ID: 001
- Endpoint: DESKTOP-G67LTP0

## 4. Audit Configuration
Enabled successful auditing for Other Object Access Events using auditpol.
Verified that the setting was Success.

## 5. Test Method
Created a harmless scheduled task named Cyberion-4698-Test.
The task was configured to open Notepad.

## 6. Observed Detection
- Windows Event ID: 4698
- Wazuh Rule ID: 60228
- Severity: Level 4
- Description: A scheduled task was created.
- Account: CyberionAdmin
- Task: \Cyberion-4698-Test
- Agent: DESKTOP-G67LTP0
- ATT&CK: T1053

## 7. Evidence
evidence/wazuh/rule_60228_scheduled_task_alert.json

## 8. Result
PASS - Windows generated Event ID 4698 and Wazuh successfully detected it using built-in rule 60228.

## 9. Limitations
- This test confirms scheduled-task creation detection, not malicious activity.
- Legitimate scheduled tasks may also trigger this rule.
- The built-in rule uses the broader T1053 technique mapping.
- This test does not validate every scheduled-task execution or modification scenario.

## 10. Conclusion
Scheduled-task creation telemetry was successfully audited, forwarded by the Windows agent, and detected by Wazuh.
