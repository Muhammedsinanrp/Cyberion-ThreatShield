# Detection Test: Certutil File Decoding

## 1. Objective
Validate Wazuh detection of certutil.exe being used to decode a file.

## 2. Detection Details

| Field | Result |
|---|---|
| Detection source | Wazuh built-in rule |
| Rule ID | 92073 |
| Description | Powershell executing certutil to decode a file |
| Severity | 6 |
| Windows Event ID | Sysmon Event ID 1 |
| ATT&CK Technique | T1140 |
| ATT&CK Tactic | Defense Evasion |
| Agent | DESKTOP-G67LTP0 |
| Agent ID | 001 |
| Test Result | PASS |

## 3. Test Environment
- Windows 10
- Ubuntu Wazuh manager
- Sysmon 15.22
- Wazuh 4.14.10

## 4. Test Procedure
A harmless local text file was encoded and decoded using certutil.exe.

Commands used:

    "Cyberion ThreatShield detection test" | Set-Content "$env:TEMP\cyberion-test.txt"
    certutil.exe -encode "$env:TEMP\cyberion-test.txt" "$env:TEMP\cyberion-test.b64"
    certutil.exe -decode "$env:TEMP\cyberion-test.b64" "$env:TEMP\cyberion-decoded.txt"
    Get-Content "$env:TEMP\cyberion-decoded.txt"

Decoded output:

    Cyberion ThreatShield detection test

## 5. Detection Evidence
Wazuh generated an alert containing:
- Rule ID: 92073
- Level: 6
- Event ID: 1
- Process: certutil.exe
- Command: certutil.exe -decode
- Parent process: powershell.exe
- ATT&CK: T1140

Evidence file:

    evidence/wazuh/rule_92073_certutil_decode_alert.json

## 6. Result
PASS — Wazuh detected the controlled certutil decode activity using built-in rule 92073.

No custom duplicate rule was created because the existing built-in rule detected the behavior.

## 7. False Positive Considerations
Certutil is a legitimate Windows utility. Administrators and software installers may use it for legitimate encoding and decoding.

Investigate the command line, parent process, user, file paths and surrounding activity before classifying an alert as malicious.

## 8. Safety Notes
The test used a locally created text file. No malicious payload or external download was used.

## 9. Conclusion
The Wazuh built-in certutil detection was successfully validated in the Cyberion ThreatShield lab. The alert and report provide evidence of detection coverage for ATT&CK T1140.
