# Cyberion Defense Labs — Detection Engineering & Threat Hunting Methodology

**Document ID:** CDL-DET-V2-METH  
**Version:** 2.0  
**Classification:** Internal Engineering Program Deliverable  
**Document Owner:** Detection Engineering & Threat Intelligence Office  
**Target Environment:** Simulated Client Enterprise (Financial & E-Commerce Infrastructure)

---

## 1. Executive Methodology Overview

Cyberion Defense Labs (CDL) operates as a Managed Security Service Provider (MSSP) delivering round-the-clock Security Operations Center (SOC) monitoring, detection engineering, and proactive threat hunting to enterprise clients across financial services, e-commerce, and healthcare sectors.

Historically, SOC alert logic has suffered from acute operational challenges:
1. **Ad-Hoc Rule Deployment:** Detection rules were written informally in response to isolated incidents without central version control or testing evidence.
2. **Invisible Coverage Gaps:** Absence of standardized mapping against an industry framework (such as MITRE ATT&CK) left severe visibility and coverage blind spots unquantified.
3. **Imprecise Logic & Alert Fatigue:** High-volume log pipelines frequently generated high volumes of false positives, leading to alert desensitization and missed true positives.
4. **Fragmented Investigative Workflows:** Tier-1 and Tier-2 analysts reviewed telemetry reactively without structured playbooks or reproducible threat hunting methodologies.

To address these challenges, this engagement establishes a **Detection-as-Code (DaC)** lifecycle, a defensible library of standardized **Sigma rules**, a structured hypothesis-driven **Threat Hunting framework**, and end-to-end **Incident Response playbooks**.

```
+---------------------------------------------------------------------------------------------------+
|                                CYBERION DETECTION ENGINEERING LIFECYCLE                           |
+---------------------------------------------------------------------------------------------------+
|  1. THREAT MODELING    --> 2. TELEMETRY AUDIT   --> 3. LOGIC AUTHORING   --> 4. LAB VALIDATION    |
|  - MITRE ATT&CK Gap        - Sysmon / WinSec        - Sigma Specification    - Mordor / BOTS      |
|  - Threat Intel / CTI      - Zeek Network Logs      - Correlation Rules      - Test Harness       |
|                            - Data Dictionaries                               - 100% Match Proof   |
+---------------------------------------------------------------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------------------+
|  5. FP TUNING          --> 6. MULTI-BACKEND     --> 7. DEPLOYMENT        --> 8. PROACTIVE HUNT    |
|  - Baseline Profiling      - Splunk SPL             - CI/CD Git Pipeline     - Hypothesis-driven  |
|  - Whitelisting            - Sentinel KQL           - Version Controlled     - Negative Results   |
|  - Trade-off Analysis      - Portable Artifacts     - SOC Production         - Gap Feedback Loop  |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Telemetry and Dataset Provenance

To satisfy the rigorous deliverable standards of the PRD (Section 5 & Section 9), all detection rules, threat hunt hypotheses, and incident investigations are developed and validated against real, publicly documented security datasets rather than synthetic or fabricated strings.

### 2.1 Mordor Project (Open Threat Research Forge)
- **Origin & Maintainers:** Developed by Roberto Rodriguez (@Cyb3rWard0g) and Jose Luis Rodriguez (@Cyb3rPandaH) under the Open Threat Research (OTR) Forge.
- **Nature of Telemetry:** Pre-recorded adversary emulation datasets capturing full-fidelity Windows Event Logs (System, Security) and Microsoft-Windows-Sysmon/Operational telemetry generated during controlled red team executions.
- **Specific Emulation Sessions Utilized:**
  - *Mordor Session APT29 / Cozy Bear Emulation:* Multi-phase evaluation reproducing APT29 tradecraft, including initial access via spearphishing attachments, PowerShell download cradles (`DownloadFile`, `Invoke-WebRequest`), living-off-the-land execution, LSASS memory dumping via custom injection, and persistence through scheduled tasks.
  - *Mordor Session Empire C2 Post-Exploitation:* Emulation of PowerShell Empire agents establishing interactive C2 channels, executing reconnaissance (`net.exe`, `whoami.exe`, `nltest.exe`), privilege escalation, and lateral movement.
- **Format:** High-fidelity JSON lines containing structured XML-parsed Windows Event Log schemas.

### 2.2 EVTX-ATTACK-SAMPLES Repository
- **Origin & Maintainers:** Curated by Florian Roth (Nextron Systems) and the global detection engineering community.
- **Nature of Telemetry:** Granular `.evtx` Windows Event Log captures from isolated test environments where individual, atomic MITRE ATT&CK techniques were executed and captured.
- **Key Techniques Utilized in Engagement:**
  - `T1059.001` (PowerShell Encoded Command & Download Cradle)
  - `T1003.001` (OS Credential Dumping: ProcDump & Mimikatz targeting LSASS)
  - `T1105` (Ingress Tool Transfer via `certutil -urlcache -split -f`)
  - `T1218.010` (Signed Binary Proxy Execution: `regsvr32.exe` / Squiblydoo)
  - `T1218.011` (Signed Binary Proxy Execution: `rundll32.exe`)
  - `T1127.001` (Trusted Developer Utilities: `msbuild.exe` inline compilation)
  - `T1070.001` (Indicator Removal on Host: Security Event Log Cleared - Event ID 1102 & 104)
  - `T1490` (Inhibit System Recovery: `vssadmin delete shadows /all /quiet`)
  - `T1047` (Windows Management Instrumentation: `wmic process call create`)
  - `T1543.003` (Create or Modify System Process: Windows Service Installation - Event ID 7045 & 4697)
  - `T1558.003` (Steal or Forge Kerberos Tickets: Kerberoasting - Event ID 4769 RC4 encryption)

### 2.3 Splunk Boss of the SOC (BOTS) Datasets (v1, v2, v3)
- **Origin & Maintainers:** Splunk Security Research Team.
- **Nature of Telemetry:** Large-scale enterprise telemetry captures encompassing simultaneous host telemetry (Windows Security, Sysmon), network inspection (Zeek/Bro logs, Suricata IDS, DNS server logs, Web proxy logs), and active attack campaigns (ransomware, webshell persistence, Active Directory lateral movement).
- **Target Simulated Environment:**
  - Simulated Client: **Wayne Enterprises / Cyberion Simulated Financial Services (`CYBERION.LOCAL`)**
  - Enterprise Architecture: Active Directory Domain Controller (`DC01.cyberion.local`), Enterprise Web Application Server (`WEBSVR01`), Internal Database Cluster (`SQL01`), End-user Workstations (`WORKSTATION6.cyberion.local`, `DESKTOP-FIN4.cyberion.local`).

### 2.4 Atomic Red Team Telemetry (Red Canary)
- **Usage:** Validation and verification of boundary conditions, command-line variations, and parent-child execution lineages. Used to model both positive hits and realistic administrative false-positive triggers.

---

## 3. Detection Engineering Standards & Lifecycle

### 3.1 The Pyramid of Pain Alignment
Cyberion Defense Labs prioritizes detection content at the upper tiers of David Bianco's *Pyramid of Pain*:
- **Hash Values & IP Addresses (Trivial / Easy):** Operationalized as IOC watchlists and automated perimeter blocks, but *not* relied upon as primary detection rules.
- **Domain Names & Network Artifacts (Simple / Annoying):** Monitored through dynamic DNS logging, high-entropy domain analysis, and SNI inspection.
- **Tools (Challenging):** Targeted through behavioral detection of tool artifacts (e.g., standard execution flags, named pipes, API call traces, service installation signatures).
- **Tactics, Techniques, and Procedures (TTPs) (Tough):** The primary focus of this engagement. All 16+ authored rules target adversary behaviors independent of file hash or network endpoint.

### 3.2 Sigma Rule Authoring Standard
In compliance with Section 8 of the PRD, all detection rules are formatted in the **Sigma Generic Detection Format (v2.0)**:
1. `title`: Concise, actionable name summarizing the behavior detected.
2. `id`: Globally unique identifier formatted as a UUIDv4.
3. `status`: Lifecycle maturity (`experimental`, `test`, `production`).
4. `description`: Exhaustive technical explanation of the attacker behavior and underlying mechanics.
5. `references`: Citations to official MITRE ATT&CK techniques, OTR Mordor datasets, or threat research.
6. `author`: Cyberion Defense Labs — Detection Engineering Practice.
7. `date`: Rule creation and modification dates (ISO 8601).
8. `tags`: Formal taxonomy tags including `attack.<technique_id>` and `attack.<tactic>`.
9. `logsource`: Mapped to actual category/product schemas (`windows`, `sysmon`, `security`, `zeek`).
10. `detection`: Declarative search identifiers, modifiers (`|contains`, `|endswith`, `|re`), and Boolean condition strings.
11. `falsepositives`: Realistic, documented benign enterprise triggers.
12. `level`: Priority rating (`informational`, `low`, `medium`, `high`, `critical`) backed by technical justification.

### 3.3 Rule Verification and Testing Methodology
Every detection rule undergoes a three-stage validation pipeline:
1. **Schema & Syntax Validation:** Verified against the Sigma YAML 2.0 schema, ensuring all required fields, valid data types, and UUID formats exist.
2. **Telemetry Replay & Unit Testing:** Executed against concrete sample event extracts drawn from Mordor and EVTX-ATTACK-SAMPLES. Every rule must trigger on its target malicious telemetry (100% validation requirement).
3. **False Positive & Noise Testing:** Executed against enterprise baseline telemetry (administrative scripts, legitimate developer builds, routine Windows maintenance) to verify that benign activity is correctly excluded.

---

## 4. Threat Hunting Methodology

Threat hunting at Cyberion follows the **Hypothesis-Driven Threat Hunting Framework**:

```
+-------------------+      +-------------------+      +-------------------+      +-------------------+
|  1. INTEL & TTP   | ---> |   2. TESTABLE     | ---> |  3. TELEMETRY     | ---> |  4. EXECUTION &   |
|   ASSESSMENT      |      |    HYPOTHESIS     |      |    EXTRACTION     |      |    ANALYTICS      |
| Review emerging   |      | Define specific   |      | Identify needed   |      | Run hunting logic |
| actor tradecraft  |      | adversary behavior|      | fields & sources  |      | & statistical runs|
+-------------------+      +-------------------+      +-------------------+      +-------------------+
                                                                                           |
                                                                                           v
+-------------------+      +-------------------+      +-------------------+      +-------------------+
| 8. DETECTION GAP  | <--- |  7. INCIDENT      | <--- |   6. OUTCOME      | <--- |   5. FINDINGS &   |
|    FEEDBACK       |      |     HANDOFF       |      | DETERMINATION     |      | NEGATIVE RESULTS  |
| Author new Sigma  |      | Initiate IR for   |      | Confirmed,        |      | Document what was |
| rules for future  |      | verified true     |      | Inconclusive, or  |      | checked and ruled |
| real-time alerting|      | positives         |      | Ruled Out         |      | out               |
+-------------------+      +-------------------+      +-------------------+      +-------------------+
```

Key requirements strictly observed:
- **Negative Results Reporting:** A valid threat hunt must explicitly document what was inspected and ruled out. Ruling out adversary presence is a high-value operational outcome that validates security posture.
- **Coverage Expansion:** As mandated by PRD Section 4.4, at least one hunt targets an ATT&CK technique not currently covered by real-time detection rules, bridging the gap between proactive exploration and permanent detection engineering.

---

## 5. Incident Investigation & Response Methodology

When detections or hunts identify confirmed malicious behavior, the engagement follows the **Cyberion Incident Response Lifecycle** (adapted from NIST SP 800-61 Rev. 2 and SANS IR):

1. **Identification & Triage:** Corroboration of initial trigger across minimum two independent telemetry sources (e.g. host Sysmon + network Zeek).
2. **Timeline Reconstruction:** Chronological mapping of adversary actions with microsecond precision, capturing parent-child process relationships, network sockets, user security identifiers (SIDs), and file system modifications.
3. **Root Cause Analysis (RCA):** Tracing the attack vector backwards to the initial point of entry (e.g. exploitation of exposed service, spearphishing macro execution, credential compromise).
4. **ATT&CK Phase Alignment:** Mapping each chronological event to MITRE ATT&CK Enterprise Matrix techniques.
5. **Impact Assessment:** Evaluating blast radius across Confidentiality, Integrity, Availability, and business continuity.
6. **Closure Classification & Justification:**
   - **True Positive (TP):** Confirmed malicious activity executed by an unauthorized entity or emulated adversary.
   - **Benign Positive (BP):** Legitimate, authorized activity (e.g. penetration testing, internal administrative tool) that matches rule logic as designed.
   - **False Positive (FP):** Erroneous alert triggered by normal system operations due to overly broad detection criteria.
7. **Feedback to Detection Engineering:** Identifying detection gaps and authoring tuning or new rules to prevent recurrence.

