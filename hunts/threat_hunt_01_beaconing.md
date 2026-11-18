# Threat Hunt Report 01: C2 Beaconing Activity

## 1. Hypothesis
Compromised hosts within the internal network are establishing periodic, automated outbound connections (beaconing) to external command and control (C2) servers.

## 2. Methodology & Data Sources
- **Data Source:** Sysmon Network Connect (Event ID 3) and Zeek connection logs.
- **Analysis Approach:** Group outbound destination IPs by connection frequency and regular time intervals (delta between connection timestamps).

## 3. Findings
- Identified recurring outbound connections from IP `192.168.1.50` to external IP `203.0.113.45` every 60 seconds precisely.
- Packet payloads showed consistent small data chunks, characteristic of automated beaconing heartbeats.

## 4. Conclusion & Hand-off
- **Status:** Confirmed
- **Action:** Handed off findings into Incident Case Report 01 for full investigation and created Rule #13 (`windows_c2_beaconing_dns_requests.yml`) to cover recurring signatures.
