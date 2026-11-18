# Incident Response Playbook: Lateral Movement via Remote Services

## 1. Trigger Conditions
- Detections indicating administrative share access (`cd-rule-010`) or remote service installations (`PSEXESVC`).
- Unexplained internal network authentication spikes.

## 2. Investigation Steps
1. Trace the source IP and target destination host using Windows Security Event logs (Event ID 4697 and 5140).
2. Examine PowerShell execution logs or Sysmon event logs for remote command execution strings.

## 3. Containment Steps
1. Isolate both the source and target endpoints involved in the lateral movement.
2. Block SMB ports (445) internally between untrusted network zones if necessary.

## 4. Eradication & Recovery
1. Remove unauthorized Windows services or scheduled tasks created during the movement phase.
2. Patch underlying vulnerabilities or weak local administrator credentials.

## 5. Stakeholder Communications
- Inform network operations and security leadership about internal propagation vectors.
