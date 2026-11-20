# Cyberion ThreatShield — PowerShell 4104 Integration Validation

## Environment

- Wazuh Manager: 4.14.10
- Windows endpoint: DESKTOP-G67LTP0
- Wazuh agent: 001
- Event source: Microsoft-Windows-PowerShell/Operational
- Event ID: 4104
- Parent rule: 91802
- Temporary validation rule: 100125

## Test

Executed a harmless PowerShell script block containing
a unique CYBERION-4104-INTEGRATION marker.

No Defender configuration changes were performed.

## Result

PASS — Wazuh generated a rule 100125 alert containing
the expected marker from Windows agent 001.

## Cleanup

The temporary validation rule was removed.
Wazuh rule validation passed after removal.
The manager was restarted and returned to active status.

## Scope and limitations

This test validates the Windows EventChannel ingestion path,
parent-rule hierarchy, custom rule evaluation, and alert generation.

It does not establish that experimental candidate rule 100123
detects actual Defender tampering or that a Defender
configuration change occurred.
