# Cyberion ThreatShield — Wazuh PCRE2 Runtime Validation

## Objective

Validate the PowerShell Defender-tampering candidate's
regular expression using the Wazuh 4.14.10 rule engine.

## Test environment

- Wazuh Manager: 4.14.10
- Test utility: wazuh-logtest
- Temporary validation rule: 100124
- Decoder: json
- Detection field: win.eventdata.scriptBlockText
- Candidate rule: 100123
- Candidate deployment status: Not deployed

## Runtime test results

| Test case | Expected | Observed | Result |
|---|---|---|---|
| Set-MpPreference with $true | Match | Rule 100124 | Pass |
| Set-MpPreference with 1 | Match | Rule 100124 | Pass |
| Set-MpPreference with $false | No match | No Phase 3 alert | Pass |
| Single-quoted Write-Output | No match | No Phase 3 alert | Pass |
| Double-quoted Write-Output | No match | No Phase 3 alert | Pass |
| Commented command | No match | No Phase 3 alert | Pass |

## Summary

- Total test cases: 6
- Expected outcomes achieved: 6
- Positive matches: 2
- Negative exclusions: 4
- Wazuh parser validation: Passed
- Temporary validation rule removed: Yes
- Production manager restarted: No

## Limitations

The test used temporary standalone rule 100124 with the JSON
decoder and the same PCRE2 expression as candidate rule 100123.

It does not prove that candidate rule 100123 triggers through
the Windows EventChannel parent-rule hierarchy.

PowerShell script-block content alone does not prove successful
command execution or a Microsoft Defender configuration change.

## Next validation milestone

Test candidate rule 100123 using genuine Windows EventChannel
telemetry and verify its complete parent-rule hierarchy.

Correlate suspicious script-block events with process telemetry
and independent Defender configuration evidence.
