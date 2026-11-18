# Windows User Account Created — Detection Test

**Project:** Cyberion ThreatShield  
**Date:** 2026-11-14  
**Rule:** Windows User Account Created  
**Windows Event ID:** 4720  
**ATT&CK mapping:** T1136 — Create Account

## Objective

Validate Windows user-account creation telemetry and confirm that the event reaches Wazuh.

## Test procedure

1. Created a temporary local test account named `CyberionTestUser` using PowerShell.
2. Checked the Windows Security log for Event ID 4720.
3. Checked the Wazuh manager alerts for the matching event.
4. Removed the temporary test account and verified that it no longer existed.

## Results

- Windows Event ID 4720 was generated.
- The event was received by the Wazuh manager.
- Wazuh built-in rule 60109 generated a level 8 alert.
- The alert identified `CyberionTestUser` as the created account.
- Evidence saved to `evidence/wazuh/rule_windows_local_account_created_4720.json`.
- The temporary test account was removed successfully.

## Sigma validation and Splunk conversion

- Sigma rule validation: PASS.
- Splunk SPL conversion using `splunk_windows`: PASS.
- Generated SPL condition: `source="WinEventLog:Security" EventCode=4720`.
- Live Splunk detection: NOT TESTED.
- Custom Sigma rule execution in Wazuh: NOT TESTED.

## ATT&CK mapping note

The project Sigma rule maps this activity to T1136 — Create Account.

Wazuh built-in rule 60109 uses its own mapping, T1098 — Account Manipulation. These are different mappings from different detection sources; this test does not establish that they are interchangeable.

## Limitations

This test confirms Windows event generation, forwarding to Wazuh, and a Wazuh built-in alert. It does not prove that the custom Sigma rule generated the Wazuh alert or that the converted SPL works in a live Splunk deployment.

## Cleanup

The temporary account `CyberionTestUser` was removed. A subsequent `Get-LocalUser` query returned no matching account.
