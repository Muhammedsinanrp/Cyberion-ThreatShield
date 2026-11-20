# Cyberion ThreatShield — PowerShell 4104 Detection Validation

## Detection candidate

- Rule ID: 100123
- Parent Wazuh rule: 91802
- Event source: Microsoft-Windows-PowerShell/Operational
- Target event: PowerShell Script Block Logging, Event ID 4104
- MITRE ATT&CK: T1562.001
- Status: Experimental / Not deployed

## Validation results

| Test case | Expected | Observed |
|---|---|---|
| Set-MpPreference with $true | Match | Pass |
| Set-MpPreference with 1 | Match | Pass |
| Set-MpPreference with $false | No match | Pass |
| Get-MpPreference | No match | Pass |
| Quoted command without trailing space | No match | Pass |
| Write-Output with single-quoted command text | No match | Pass |
| Write-Output with double-quoted command text | No match | Pass |

## Automated tests

- Candidate regression tests: 7 passed
- Full project suite: 22 passed, 1 xfailed
- Wazuh rule parser: Passed
- Live deployment of rule 100123: Not performed

## Known limitations

1. Script-block content does not prove successful execution.
2. The regex does not fully parse PowerShell syntax.
3. Commands preceded by other statements may be missed.
4. Alternate parameter ordering or syntax may be missed.
5. Comments and other command-like text may still generate false positives.
6. Wazuh parser validation does not prove runtime detection accuracy.

## Recommended follow-up

- Test additional harmless command and comment cases.
- Validate matching against representative Wazuh event samples.
- Correlate with Sysmon process telemetry where possible.
- Seek independent Defender configuration-change evidence.
- Avoid claiming successful Defender tampering based only on Event ID 4104.

## Recommended follow-up

- Test additional harmless command and comment cases.
- Validate matching against representative Wazuh event samples.
- Correlate with Sysmon process telemetry where possible.
- Seek independent Defender configuration-change evidence.
- Avoid claiming successful Defender tampering based only on Event ID 4104.
