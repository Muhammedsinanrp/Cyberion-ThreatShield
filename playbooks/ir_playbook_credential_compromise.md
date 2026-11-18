# Incident Response Playbook: Credential Compromise & LSASS Dumping

## 1. Trigger Conditions
- High-severity detection rules triggering on LSASS handle access (`cd-rule-008`) or unauthorized SAM hive reading (`cd-rule-015`).
- Anomalous login patterns or reports of account takeover.

## 2. Investigation Steps
1. Identify the user account and workstation involved from security event logs (Event ID 4624/4688).
2. Review Sysmon Event ID 10 to confirm process interaction with `lsass.exe`.
3. Check active sessions and network connections initiated by the offending user/process.

## 3. Containment Steps
1. Immediately isolate the affected host from the network.
2. Force-terminate malicious processes or tools running from user-writable directories.
3. Revoke active Kerberos tickets and disable the compromised user account temporarily.

## 4. Eradication & Recovery
1. Reset credentials for the affected user and verify no secondary backdoors or scheduled tasks were created.
2. Re-enable the user account only after multi-factor authentication (MFA) and password hygiene are enforced.

## 5. Stakeholder Communications
- Notify the SOC Manager and IT Helpdesk of the account compromise.
- Provide a summary report to business unit leaders outlining the scope and containment status.
