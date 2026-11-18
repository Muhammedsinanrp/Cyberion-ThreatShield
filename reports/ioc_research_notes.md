# Indicators of Compromise (IOC) Research Notes

## 1. Overview
This document compiles the Indicators of Compromise (IOCs) identified during threat hunting exercises and incident investigations within the Cyberion Defense Labs engagement.

## 2. Identified IOCs
- **IP Address (C2 Beacon):** `203.0.113.45`
  - *Context:* Observed communicating via periodic HTTP/DNS heartbeats in Threat Hunt 01 and Incident Case 01.
  - *Operationalization:* Blocked at the perimeter firewall and added to SOC SIEM watchlist feeds.
- **File Hash (Credential Dumper):** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (SHA-256 placeholder)
  - *Context:* Associated with unauthorized LSASS memory access attempts in Incident Case 02.
  - *Operationalization:* Added to endpoint detection and response (EDR) blocking policies and hash blocklists.
- **Domain Name:** `malicious-c2-beacon-domain.local`
  - *Context:* High-frequency DNS query target observed in Rule #13 logic testing.
  - *Operationalization:* Added to internal DNS sinkhole policies.

## 3. Threat Intelligence Alignment
All identified IOCs align with known adversary tactics mapped under MITRE ATT&CK framework techniques (T1071.004 and T1003.001).
