# Cyberion Defense Labs — Microsoft Sentinel KQL Detection Translations

**Document ID:** CDL-DET-V2-KQL  
**Version:** 2.0  
**Target Backend:** Microsoft Sentinel / Azure Monitor  
**Engine:** Kusto Query Language (KQL) / Advanced Security Information Model (ASIM)

---

## 1. Overview & Data Schema Standards

To support client environments utilizing Microsoft Sentinel, Sigma rules are ported to Kusto Query Language (KQL) utilizing native `SecurityEvent` and `DeviceProcessEvents` (Microsoft Defender for Endpoint) schemas.

---

## 2. Translated KQL Queries

### Rule 1: Ingress Tool Transfer Via Certutil URLCache Flag
**Rule ID:** `5b2e1e0a-42c2-4a0b-8d5c-9c7ef2b6e111` | **MITRE ATT&CK:** `T1105`

```kql
SecurityEvent
| where EventID == 4688 or EventID == 1
| where Process has_any (@"\certutil.exe", "CertUtil.exe")
| where CommandLine has_any ("-urlcache", "/urlcache")
| where CommandLine has_any ("-split", "/split", "-f", "/f")
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
```

---

### Rule 2: Suspicious PowerShell Download Cradle Execution
**Rule ID:** `a93b41d0-68e1-4c19-91eb-723a1d95e222` | **MITRE ATT&CK:** `T1059.001`, `T1105`

```kql
SecurityEvent
| where EventID == 4688 or EventID == 1
| where Process has_any (@"\powershell.exe", @"\pwsh.exe", "PowerShell.EXE")
| where CommandLine has_any (
    "Net.WebClient", "DownloadString", "DownloadFile", "Invoke-WebRequest", 
    "Invoke-RestMethod", "curl ", "wget ", "iwr ", "irm ", "Start-BitsTransfer",
    "-enc", "-encodedcommand", "-w hidden", "-ep bypass"
)
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
```

---

### Rule 3: LSASS Process Memory Dumping via ProcDump
**Rule ID:** `d4a89e17-73d6-4442-9988-8123af65e333` | **MITRE ATT&CK:** `T1003.001`

```kql
SecurityEvent
| where EventID == 4688 or EventID == 1
| where Process has_any (@"\procdump.exe", @"\procdump64.exe") or CommandLine has "procdump"
| where CommandLine has_any ("lsass", "lsass.exe")
| where CommandLine has_any ("-ma", "-mm", "-mp")
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
```

---

### Rule 4: Windows Security Event Log Cleared
**Rule ID:** `f71e9842-832a-4f51-b883-29471de8e444` | **MITRE ATT&CK:** `T1070.001`

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, SubjectUserName, SubjectDomainName, SubjectLogonId
```

---

### Rule 5: Suspicious Windows Service Installation
**Rule ID:** `82b45100-36a8-4e1b-8519-75a892b1e555` | **MITRE ATT&CK:** `T1543.003`, `T1021.002`

```kql
SecurityEvent
| where EventID == 7045 or EventID == 4697
| extend ServicePath = coalesce(ImagePath, ServiceFileName)
| where ServicePath has_any (@"\AppData\", @"\Users\Public\", @"\Temp\", @"\Windows\Temp\", "ADMIN$", @"C$\")
    or ServiceName has_any ("PSEXESVC", "winexe", "PAExec")
| project TimeGenerated, Computer, ServiceName, ServicePath, ServiceAccount, SubjectUserName
```

---

### Rule 10: Volume Shadow Copy Deletion via VSSAdmin
**Rule ID:** `41a7c093-9c8e-49b8-a723-95843210eaaa` | **MITRE ATT&CK:** `T1490`

```kql
SecurityEvent
| where EventID == 4688 or EventID == 1
| where Process has_any (@"\vssadmin.exe", "VSSADMIN.EXE")
| where CommandLine has "delete" and CommandLine has "shadows"
| where CommandLine has_any ("/all", "-all", "/quiet", "-quiet")
| project TimeGenerated, Computer, Account, Process, CommandLine
```

---

### Rule 14 (Correlation): Password Spray Burst Followed by Successful Logon
**Rule ID:** `c1894723-5e91-4478-bc02-19283746eeee` | **MITRE ATT&CK:** `T1110.003`, `T1078`

```kql
let timeframe = 5m;
let threshold = 3;
let failed_logons = SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4625 and LogonType == 3
| summarize FailedCount = dcount(TargetUserName), Targets = make_set(TargetUserName) by IpAddress
| where FailedCount >= threshold;
let successful_logons = SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4624 and LogonType == 3
| project SuccessTime = TimeGenerated, IpAddress, SuccessUser = TargetUserName;
failed_logons
| join kind=inner (successful_logons) on IpAddress
| project SuccessTime, IpAddress, SuccessUser, FailedCount, Targets
```
