# Indicators of Compromise (IOC) Research Notes

## 1. Overview
This document compiles vetted and operationalized Indicators of Compromise (IOCs) identified during threat hunting exercises and incident investigations within the Cyberion Defense Labs engagement.

## 2. Vetted Indicators of Compromise
- **External C2 Infrastructure IP:** `185.220.101.5`
  - *Context:* Observed communicating via periodic TLS-wrapped heartbeat traffic in Incident Case 01 and Threat Hunt 01.
  - *Operationalization:* Blocked at the perimeter firewall and added to active SIEM network threat intelligence feeds.
- **Credential Dumper Binary Hash (SHA-256):** `8a97425f190e87d10e1183234d7d8e24c18b76fa3d20128cbbf8e62d469446f2`
  - *Context:* Associated with customized credential harvesting tool variants executing memory reads against `lsass.exe` in Incident Case 02.
  - *Operationalization:* Enforced via EDR hash blocklists and application control policies.
- **Malicious Domain Indicator:** `update-core-services.internal-sync.net`
  - *Context:* High-frequency DNS query target utilized during C2 channel establishment and payload staging.
  - *Operationalization:* Added to internal DNS sinkhole and proxy blocklists.
