# Threat Hunt Report 02: Unauthorized Credential Harvesting

## 1. Hypothesis
Actors who have gained initial access are actively probing for credential stores and interacting with the LSASS process to dump memory.

## 2. Methodology & Data Sources
- **Data Source:** Sysmon Process Access (Event ID 10) and Windows Security Event Logs.
- **Analysis Approach:** Filter for processes requesting open handle permissions targeting `lsass.exe` and unusual administrative tooling.

## 3. Findings
- Discovered an unauthorized tool execution attempting memory reads against `lsass.exe` from an unprivileged user workspace path (`C:\Users\Public\`).
- Event ID 10 logs confirmed high-privilege handle access (`0x1F3FFF`) matching known credential dumping tool signatures.

## 4. Conclusion & Hand-off
- **Status:** Confirmed
- **Action:** Transitioned findings into Incident Case Report 02 and validated Rule #8 (`windows_credential_dumping_lsass.io.yml`).
