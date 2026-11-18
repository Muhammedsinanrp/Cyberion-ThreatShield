# Incident Response Playbook: Command and Control (C2) Beaconing

## 1. Trigger Conditions
- Detections flagging periodic high-frequency DNS requests (`cd-rule-013`) or suspicious outbound TCP connections.
- Threat intelligence alerts on known malicious external IPs.

## 2. Investigation Steps
1. Review firewall, proxy, and Zeek connection logs for recurring temporal patterns and data volume metrics.
2. Identify the internal process responsible for initiating the outbound connection using endpoint telemetry.

## 3. Containment Steps
1. Implement immediate firewall block rules for the external C2 IP and domain.
2. Isolate the affected host to prevent data exfiltration or secondary payload retrieval.

## 4. Eradication & Recovery
1. Clean up malicious binaries, scheduled tasks, or registry run keys responsible for maintaining the beacon.
2. Verify system integrity and monitor network traffic for any fallback C2 channels.

## 5. Stakeholder Communications
- Issue an internal advisory to the threat intelligence and incident response teams regarding the active C2 infrastructure.
