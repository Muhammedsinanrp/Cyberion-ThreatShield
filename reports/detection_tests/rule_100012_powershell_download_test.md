# Detection Test 7: PowerShell Download Activity

## 1. Objective
Detect PowerShell process creation commands containing common download-related methods.

## 2. Detection Configuration
- Custom Wazuh Rule ID: 100012
- Severity: Level 8
- Sysmon Event ID: 1 (Process Create)
- Detection field: win.eventdata.commandLine
- ATT&CK Technique: T1105 - Ingress Tool Transfer
- Detection group: cyberion, powershell, download_activity

## 3. Lab Environment
- Wazuh Manager: Ubuntu 22.04
- Wazuh Agent: Windows 10
- Agent ID: 001
- Endpoint: DESKTOP-G67LTP0
- Windows IP: 192.168.23.134
- Ubuntu IP: 192.168.23.133

## 4. Test Method
A harmless text file was hosted on the Ubuntu lab machine using Python HTTP server.

A new PowerShell process executed Invoke-WebRequest to download the file:

Invoke-WebRequest -Uri "http://192.168.23.133:8000/test.txt" -OutFile "$env:TEMP\cyberion-download-test-3.txt"

The downloaded file contents were verified successfully.

## 5. Observed Detection
- Sysmon Event ID: 1
- Wazuh Rule ID: 100012
- Severity: 8
- Description: Cyberion: Suspicious PowerShell download command detected.
- ATT&CK: T1105
- Command: Invoke-WebRequest
- Destination: 192.168.23.133:8000
- Agent: DESKTOP-G67LTP0

## 6. Evidence
evidence/wazuh/rule_100012_powershell_download_alert.json

## 7. Result
PASS - Custom Wazuh rule 100012 successfully detected the controlled PowerShell download command.

## 8. Limitations and False Positives
- The rule detects matching process command lines, not every PowerShell download technique.
- Legitimate administrative downloads may trigger the rule.
- A matching command does not prove that a download succeeded or that the activity is malicious.
- Sysmon Event ID 3 network telemetry was confirmed locally, but a corresponding visible Wazuh alert was not observed.

## 9. Conclusion
The custom detection was validated using a harmless local text-file download in an isolated lab environment.
