# 🛠️ SysAdmin-PS-Toolkit

> A collection of 20 production-ready PowerShell scripts for Windows system administrators — covering diagnostics, monitoring, security, maintenance, and automation.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Scripts](https://img.shields.io/badge/Scripts-20%20Complete-brightgreen)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Scripts](#scripts)
- [Usage Examples](#usage-examples)
- [Safety & Best Practices](#safety--best-practices)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**SysAdmin-PS-Toolkit** is a complete library of PowerShell scripts designed to streamline common IT administration tasks on Windows environments. Each script is:

- ✅ Self-documented with `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` headers
- ✅ Built with `try/catch` error handling throughout
- ✅ Safe by default — destructive scripts run in **preview/dry-run mode** unless explicitly confirmed
- ✅ Logging-enabled for auditing and troubleshooting
- ✅ Runnable standalone — no external modules or dependencies required

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | Version 5.1 or higher (`$PSVersionTable.PSVersion`) |
| OS | Windows 10 / Windows 11 / Windows Server 2016+ |
| Privileges | Most scripts run as standard user; those requiring **Administrator** are noted below |

---

## Getting Started

**1. Clone the repository**
```powershell
git clone https://github.com/YOUR-USERNAME/SysAdmin-PS-Toolkit.git
cd SysAdmin-PS-Toolkit
```

**2. Allow script execution** *(one-time setup)*
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**3. Run any script**
```powershell
.\01_SystemInventory.ps1
```

**4. Get built-in help for any script**
```powershell
Get-Help .\01_SystemInventory.ps1 -Full
```

---

## Scripts

### 🔍 Diagnostics & Reporting

| # | Script | Description | Admin |
|---|--------|-------------|:-----:|
| 01 | [`01_SystemInventory.ps1`](./01_SystemInventory.ps1) | Full hardware specs, OS version, installed software, and network config in one report | ⚠️ |
| 02 | [`02_DiskSpaceReporter.ps1`](./02_DiskSpaceReporter.ps1) | Drive space overview with visual bars, top N largest files and folders, low-space alerts | ❌ |
| 03 | [`03_NetworkDiagnostics.ps1`](./03_NetworkDiagnostics.ps1) | Connectivity tests, DNS resolution, ping with latency stats, TCP port checks | ❌ |
| 04 | [`04_EventLogAnalyzer.ps1`](./04_EventLogAnalyzer.ps1) | Pulls Error/Critical events from System, Application, and Security logs with source frequency grouping | ⚠️ |
| 05 | [`05_PerformanceMonitor.ps1`](./05_PerformanceMonitor.ps1) | Live sampling of CPU/memory/disk over a configurable window; trend stats and top processes | ❌ |
| 20 | [`20_SystemReportGenerator.ps1`](./20_SystemReportGenerator.ps1) | Master diagnostic report combining OS, hardware, security, updates, processes, software, and event logs | ⚠️ |

### 🔐 Security & Compliance

| # | Script | Description | Admin |
|---|--------|-------------|:-----:|
| 06 | [`06_PasswordResetUtility.ps1`](./06_PasswordResetUtility.ps1) | Interactive menu — change own password with strength validation, unlock accounts, view account status | ⚠️ |
| 13 | [`13_AntivirusStatusChecker.ps1`](./13_AntivirusStatusChecker.ps1) | Defender real-time protection, definition age, threat history, firewall state, and security service health | ⚠️ |
| 14 | [`14_FirewallConfigurator.ps1`](./14_FirewallConfigurator.ps1) | Enable/disable profiles, add/remove rules, block/allow apps, apply hardened baseline, export rules | ✅ |
| 15 | [`15_USBDeviceBlocker.ps1`](./15_USBDeviceBlocker.ps1) | Block, allow, or set read-only for USB storage via registry; logs connection history | ✅ |
| 16 | [`16_PasswordPolicyEnforcer.ps1`](./16_PasswordPolicyEnforcer.ps1) | Audits local password policy against a configurable baseline; optionally applies compliant settings | ✅ |

### 🌐 Connectivity & Configuration

| # | Script | Description | Admin |
|---|--------|-------------|:-----:|
| 07 | [`07_NetworkDriveConnector.ps1`](./07_NetworkDriveConnector.ps1) | Maps org-defined network drives with credential fallback, checks VPN status, tests share reachability | ❌ |
| 17 | [`17_PrinterInstaller.ps1`](./17_PrinterInstaller.ps1) | Install printers from catalog or by IP/UNC path, list/remove printers, set default | ⚠️ |
| 18 | [`18_DeviceDriverUpdater.ps1`](./18_DeviceDriverUpdater.ps1) | Audits driver age and signing status, flags problem devices, queries Windows Update for driver updates | ⚠️ |

### 🧹 Maintenance & Cleanup

| # | Script | Description | Admin |
|---|--------|-------------|:-----:|
| 08 | [`08_ProfileCleanup.ps1`](./08_ProfileCleanup.ps1) | Removes temp files, browser caches, prefetch, old profiles — **preview mode by default** | ⚠️ |
| 19 | [`19_TempFileCleaner.ps1`](./19_TempFileCleaner.ps1) | Deep temp/cache cleanup across all browsers, WU cache, logs, WER, Recycle Bin — **preview by default** | ⚠️ |

### 📦 Software Management

| # | Script | Description | Admin |
|---|--------|-------------|:-----:|
| 09 | [`09_WindowsUpdateChecker.ps1`](./09_WindowsUpdateChecker.ps1) | Lists pending Windows Updates via WUA API with severity, KB number, size; optional download trigger | ⚠️ |
| 10 | [`10_SoftwareInventory.ps1`](./10_SoftwareInventory.ps1) | Full app list from registry (32/64-bit) and AppX, with optional approved-list compliance check + CSV | ❌ |
| 11 | [`11_ApplicationInstaller.ps1`](./11_ApplicationInstaller.ps1) | Deploys approved software via Winget, Chocolatey, or MSI/EXE from a configurable catalog | ✅ |
| 12 | [`12_SoftwareUninstaller.ps1`](./12_SoftwareUninstaller.ps1) | Search and uninstall apps, scan against a blocklist, silent removal mode for policy enforcement | ✅ |

> **Legend:** ✅ = Always required &nbsp; ⚠️ = Recommended / required for some features &nbsp; ❌ = Not required

---

## Usage Examples

```powershell
# Full system inventory with software CSV export
.\01_SystemInventory.ps1 -OutputPath "C:\Reports" -ExportCSV

# Find top 30 largest files on drive D:
.\02_DiskSpaceReporter.ps1 -DriveLetter D -TopN 30

# Custom network diagnostics
.\03_NetworkDiagnostics.ps1 -PingTargets "192.168.1.1","10.0.0.1"

# Analyze last 48h of event logs
.\04_EventLogAnalyzer.ps1 -HoursBack 48 -MaxEvents 1000

# Monitor performance for 2 minutes
.\05_PerformanceMonitor.ps1 -DurationSeconds 120 -IntervalSeconds 10

# Preview what cleanup would remove (safe, no deletion)
.\08_ProfileCleanup.ps1

# Execute the cleanup after reviewing preview
.\08_ProfileCleanup.ps1 -Execute

# Check for updates (flag critical ones)
.\09_WindowsUpdateChecker.ps1

# Software inventory with Store apps and compliance check
.\10_SoftwareInventory.ps1 -IncludeStoreApps -ApprovedListPath "C:\Config\approved.txt"

# Install a specific approved app silently
.\11_ApplicationInstaller.ps1 -SoftwareName "7-Zip"

# Scan and remove blocklisted software
.\12_SoftwareUninstaller.ps1 -BlocklistPath "C:\Config\blocklist.txt"

# Full antivirus health check
.\13_AntivirusStatusChecker.ps1 -AlertThresholdDays 2

# Block all USB storage devices
.\15_USBDeviceBlocker.ps1   # then select option 2

# Audit password policy and apply baseline
.\16_PasswordPolicyEnforcer.ps1 -ApplyBaseline

# Generate a zipped diagnostic report for IT support
.\20_SystemReportGenerator.ps1 -ZipReport -IncludeEventLogs
```

---

## Safety & Best Practices

- **Preview before deleting** — `08_ProfileCleanup.ps1` and `19_TempFileCleaner.ps1` run in dry-run mode until `-Execute` is passed. Always check the preview first.
- **Confirm destructive actions** — Scripts that modify system settings (USB policy, firewall, password policy) prompt for explicit confirmation.
- **Test before deploying broadly** — Validate scripts in a non-production environment first.
- **Least privilege** — Only scripts that genuinely require elevation are marked as needing Administrator.
- **Configure before running** — Several scripts have configurable sections at the top (`$PrinterCatalog`, `$DriveMap`, `$ApprovedSoftware`, `$Baseline`) — edit these to match your org before use.

---

## Logging

Scripts that perform sensitive or impactful actions write audit logs automatically:

| Script | Log File |
|--------|----------|
| `06_PasswordResetUtility.ps1` | `PasswordReset_Audit.log` |
| `07_NetworkDriveConnector.ps1` | `NetworkDrives_Audit.log` |
| `11_ApplicationInstaller.ps1` | `AppInstaller_YYYYMMDD.log` |
| `12_SoftwareUninstaller.ps1` | `Uninstaller_YYYYMMDD.log` |
| `14_FirewallConfigurator.ps1` | `Firewall_YYYYMMDD.log` |
| `15_USBDeviceBlocker.ps1` | `USB_Policy_YYYYMMDD.log` |
| `17_PrinterInstaller.ps1` | `PrinterInstall_YYYYMMDD.log` |

All report-generating scripts save timestamped `.txt` and/or `.csv` files to `%USERPROFILE%\Desktop` by default, or to any path specified with `-OutputPath`.

---

## Contributing

Contributions are welcome. To add or improve a script:

1. Fork the repository
2. Create a branch: `git checkout -b feature/script-name`
3. Follow the existing structure — header comments, error handling, logging
4. Submit a pull request with a clear description

**Script standards:**
- Full comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- `try/catch` for all major operations
- Confirmation prompt before any destructive action
- Preview/dry-run mode for file deletion scripts
- Tested on Windows 10 and Windows 11

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">Made for IT teams who'd rather automate than repeat themselves.</p>