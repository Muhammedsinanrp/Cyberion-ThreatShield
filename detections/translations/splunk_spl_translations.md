# Cyberion Defense Labs — Splunk SPL Detection Translations

**Document ID:** CDL-DET-V2-SPL  
**Version:** 2.0  
**Target Backend:** Splunk Enterprise / Splunk Cloud  
**Engine:** pySigma Splunk Backend / Cyberion Detection Engineering Standard

---

## 1. Overview & Field Mapping Standards

To ensure cross-platform operational portability across client SIEM environments, Cyberion's Sigma rules are translated to Splunk Search Processing Language (SPL) using standardized Common Information Model (CIM) field mappings:

- `Image` -> `process_path` or `Image`
- `CommandLine` -> `process_exec` or `CommandLine`
- `ParentImage` -> `parent_process_path` or `ParentImage`
- `EventID` -> `EventCode`
- `DestinationIp` -> `dest_ip`

---

## 2. Translated Splunk Queries

### Rule 1: Ingress Tool Transfer Via Certutil URLCache Flag
**Rule ID:** `5b2e1e0a-42c2-4a0b-8d5c-9c7ef2b6e111` | **MITRE ATT&CK:** `T1105`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
    (Image="*\\certutil.exe" OR OriginalFileName="CertUtil.exe")
    (CommandLine="*-urlcache*" OR CommandLine="*/urlcache*")
    (CommandLine="*-split*" OR CommandLine="*/split*" OR CommandLine="*-f*" OR CommandLine="*/f*")
| table _time, host, User, Image, CommandLine, ParentImage, ParentCommandLine, Hashes
```

---

### Rule 2: Suspicious PowerShell Download Cradle Execution
**Rule ID:** `a93b41d0-68e1-4c19-91eb-723a1d95e222` | **MITRE ATT&CK:** `T1059.001`, `T1105`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR OriginalFileName="PowerShell.EXE")
    (
        CommandLine="*Net.WebClient*" OR CommandLine="*DownloadString*" OR 
        CommandLine="*DownloadFile*" OR CommandLine="*Invoke-WebRequest*" OR 
        CommandLine="*Invoke-RestMethod*" OR CommandLine="*curl *" OR 
        CommandLine="*wget *" OR CommandLine="*iwr *" OR CommandLine="*irm *" OR 
        CommandLine="*Start-BitsTransfer*" OR CommandLine="*-enc*" OR 
        CommandLine="*-encodedcommand*" OR CommandLine="*-w hidden*" OR 
        CommandLine="*-ep bypass*"
    )
| table _time, host, User, Image, CommandLine, ParentImage, IntegrityLevel
```

---

### Rule 3: LSASS Process Memory Dumping via ProcDump
**Rule ID:** `d4a89e17-73d6-4442-9988-8123af65e333` | **MITRE ATT&CK:** `T1003.001`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
    (Image="*\\procdump*.exe" OR OriginalFileName="procdump.exe" OR CommandLine="*procdump*")
    (CommandLine="*lsass*" OR CommandLine="*lsass.exe*")
    (CommandLine="*-ma*" OR CommandLine="*-mm*" OR CommandLine="*-mp*")
| table _time, host, User, Image, CommandLine, ParentImage, Hashes
```

---

### Rule 4: Windows Security Event Log Cleared
**Rule ID:** `f71e9842-832a-4f51-b883-29471de8e444` | **MITRE ATT&CK:** `T1070.001`

```spl
index=windows_security sourcetype="WinEventLog:Security" EventCode=1102
| table _time, host, SubjectUserName, SubjectDomainName, SubjectLogonId
```

---

### Rule 5: Suspicious Windows Service Installation - System 7045
**Rule ID:** `6fbf1262-2cd4-4e1d-aad1-d3a3f3f653ec` | **MITRE ATT&CK:** `T1543.003`

```spl
index=windows_system sourcetype="WinEventLog:System" EventCode=7045
(
    ImagePath="*\\AppData\\*" OR
    ImagePath="*\\Users\\Public\\*" OR
    ImagePath="*\\Temp\\*" OR
    ImagePath="*\\Windows\\Temp\\*" OR
    ImagePath="*ADMIN$*" OR
    ImagePath="*C$\\*" OR
    (ServiceName="*PSEXESVC*" AND (ImagePath="*PSEXESVC.exe*" OR ImagePath="*PAExec.exe*")) OR
    (ServiceName="*winexe*" AND (ImagePath="*PSEXESVC.exe*" OR ImagePath="*PAExec.exe*")) OR
    (ServiceName="*PAExec*" AND (ImagePath="*PSEXESVC.exe*" OR ImagePath="*PAExec.exe*"))
)
| table _time, host, ServiceName, ImagePath, ServiceAccount
```
---

### Rule 6: Suspicious Windows Service Installation - Security 4697
**Rule ID:** `82b45100-36a8-4e1b-8519-75a892b1e555` | **MITRE ATT&CK:** `T1543.003`

```spl
index=windows_security sourcetype="WinEventLog:Security" EventCode=4697
(
    ServiceFileName="*\\AppData\\*" OR
    ServiceFileName="*\\Users\\Public\\*" OR
    ServiceFileName="*\\Temp\\*" OR
    ServiceFileName="*\\Windows\\Temp\\*" OR
    ServiceFileName="*ADMIN$*" OR
    ServiceFileName="*C$\\*" OR
    (ServiceName="*PSEXESVC*" AND (ServiceFileName="*PSEXESVC.exe*" OR ServiceFileName="*PAExec.exe*")) OR
    (ServiceName="*winexe*" AND (ServiceFileName="*PSEXESVC.exe*" OR ServiceFileName="*PAExec.exe*")) OR
    (ServiceName="*PAExec*" AND (ServiceFileName="*PSEXESVC.exe*" OR ServiceFileName="*PAExec.exe*"))
)
| table _time, host, ServiceName, ServiceFileName, ServiceAccount, SubjectUserName
```

---

### Rule 10: Volume Shadow Copy Deletion via VSSAdmin
**Rule ID:** `41a7c093-9c8e-49b8-a723-95843210eaaa` | **MITRE ATT&CK:** `T1490`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
    (Image="*\\vssadmin.exe" OR OriginalFileName="VSSADMIN.EXE")
    CommandLine="*delete*" CommandLine="*shadows*"
    (CommandLine="*/all*" OR CommandLine="*-all*" OR CommandLine="*/quiet*" OR CommandLine="*-quiet*")
| table _time, host, User, Image, CommandLine, ParentImage
```

---

### Rule 14 (Correlation): Password Spray Burst Followed by Successful Logon
**Rule ID:** `c1894723-5e91-4478-bc02-19283746eeee` | **MITRE ATT&CK:** `T1110.003`, `T1078`

```spl
index=windows_security sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Logon_Type=3
| eval is_failed=if(EventCode=4625, 1, 0)
| eval is_success=if(EventCode=4624, 1, 0)
| transaction Source_Network_Address maxspan=5m
| where is_failed>=3 AND is_success>=1
| table _time, Source_Network_Address, TargetUserName, is_failed, is_success, duration
```

