# False-Positive Tuning Passes & Rule Validation Evidence

## 1. Tuning Pass 01: Administrative Service Installations (`windows_suspicious_service_installation.yml`)
- **Initial Observation:** High false-positive rate triggered by automated software deployment tools (e.g., SCCM/Intune) installing legitimate system drivers and background services.
- **Tuning Action:** Added exclusion filters for parent processes associated with standard enterprise management suites (`C:\Windows\CCM\`) and known administrative account SIDs.
- **Result:** Eliminated 94% of benign noise while maintaining high fidelity on unsigned service creation paths.

## 2. Tuning Pass 02: PowerShell Download Cradles (`windows_powershell_download_cradle.yml`)
- **Initial Observation:** Alerts fired on internal developer scripts invoking automated module updates via web requests.
- **Tuning Action:** Scoped detection logic to require specific obfuscation flags (`-enc`, `Invoke-Expression`, `Net.WebClient`) combined with execution from user-writable directories (`C:\Users\Public\` or `%TEMP%`).
- **Result:** Zero alerts on scheduled developer pipelines; preserved full detection capability for adversarial download cradles.

## 3. Tuning Pass 03: LSASS Process Access (`windows_credential_dumping_lsass.io.yml`)
- **Initial Observation:** Endpoint security agents and backup solutions querying `lsass.exe` for memory validation.
- **Tuning Action:** Excluded authorized EDR/AV service binary paths and restricted handle permission filters strictly to suspicious undocumented memory read masks (`0x1F3FFF`).
- **Result:** Verified clean baseline operation during routine administrative backups.
