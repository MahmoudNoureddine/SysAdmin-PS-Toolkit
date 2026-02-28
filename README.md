# 🛠️ SysAdmin-PS-Toolkit

> A collection of production-ready PowerShell scripts for Windows system administrators — covering diagnostics, monitoring, security, maintenance, and automation.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Scripts](https://img.shields.io/badge/Scripts-10%20of%2020-orange)

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

**SysAdmin-PS-Toolkit** is a growing library of PowerShell scripts designed to streamline common IT administration tasks on Windows environments. Each script is:

- ✅ Self-documented with `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` headers
- ✅ Built with `try/catch` error handling throughout
- ✅ Safe by default — destructive scripts run in **preview mode** unless explicitly confirmed
- ✅ Logging-enabled for auditing and troubleshooting
- ✅ Runnable standalone — no external dependencies or modules required

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | Version 5.1 or higher (`$PSVersionTable.PSVersion`) |
| OS | Windows 10 / Windows 11 / Windows Server 2016+ |
| Privileges | Most scripts run as standard user; some require **Administrator** (noted per script) |

---

## Getting Started

**1. Clone the repository**
```powershell
git clone https://github.com/YOUR-USERNAME/SysAdmin-PS-Toolkit.git
cd SysAdmin-PS-Toolkit
```

**2. Allow script execution** *(if not already set)*
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**3. Run any script**
```powershell
.\01_SystemInventory.ps1
```

**4. Get help for any script**
```powershell
Get-Help .\01_SystemInventory.ps1 -Full
```

---

## Scripts

### 🔍 Diagnostics & Reporting

| # | Script | Description | Admin Required |
|---|--------|-------------|:--------------:|
| 01 | [`01_SystemInventory.ps1`](./01_SystemInventory.ps1) | Gathers hardware specs, OS version, installed software, and network configuration into a full inventory report | ⚠️ Recommended |
| 02 | [`02_DiskSpaceReporter.ps1`](./02_DiskSpaceReporter.ps1) | Checks available disk space on all drives, identifies the largest files and folders, and flags low-space warnings | ❌ |
| 03 | [`03_NetworkDiagnostics.ps1`](./03_NetworkDiagnostics.ps1) | Tests connectivity, performs DNS resolution checks, ping tests, and verifies full IP configuration | ❌ |
| 04 | [`04_EventLogAnalyzer.ps1`](./04_EventLogAnalyzer.ps1) | Pulls and summarizes Error/Critical events from System, Application, and Security logs | ⚠️ Security log |
| 05 | [`05_PerformanceMonitor.ps1`](./05_PerformanceMonitor.ps1) | Samples CPU, memory, and disk I/O metrics over a configurable period; identifies top resource-consuming processes | ❌ |

### 🔐 Security & User Management

| # | Script | Description | Admin Required |
|---|--------|-------------|:--------------:|
| 06 | [`06_PasswordResetUtility.ps1`](./06_PasswordResetUtility.ps1) | Interactive menu for changing passwords (with strength validation), unlocking accounts, and viewing account status | ⚠️ To unlock others |

### 🌐 Connectivity & Configuration

| # | Script | Description | Admin Required |
|---|--------|-------------|:--------------:|
| 07 | [`07_NetworkDriveConnector.ps1`](./07_NetworkDriveConnector.ps1) | Maps predefined network drives with credential fallback, checks VPN adapter status, and tests share reachability | ❌ |

### 🧹 Maintenance

| # | Script | Description | Admin Required |
|---|--------|-------------|:--------------:|
| 08 | [`08_ProfileCleanup.ps1`](./08_ProfileCleanup.ps1) | Removes temp files, browser caches, prefetch, and Recycle Bin contents. **Runs in preview mode by default** | ⚠️ Full cleanup |

### 📦 Software Management

| # | Script | Description | Admin Required |
|---|--------|-------------|:--------------:|
| 09 | [`09_WindowsUpdateChecker.ps1`](./09_WindowsUpdateChecker.ps1) | Scans for pending Windows Updates using the WUA API, lists severity and KB numbers, optionally triggers downloads | ⚠️ Recommended |
| 10 | [`10_SoftwareInventory.ps1`](./10_SoftwareInventory.ps1) | Lists all installed applications (64-bit, 32-bit, AppX) with versions and publishers; supports approved-list compliance checks | ❌ |

> 🚧 **Scripts 11–20 are in progress** — covering application deployment, antivirus status, firewall config, USB blocking, printer setup, driver updates, and more.

---

## Usage Examples

**Generate a full system inventory and export software to CSV:**
```powershell
.\01_SystemInventory.ps1 -OutputPath "C:\Reports" -ExportCSV
```

**Find the top 30 largest files on the D: drive:**
```powershell
.\02_DiskSpaceReporter.ps1 -DriveLetter D -TopN 30
```

**Run network diagnostics against custom targets:**
```powershell
.\03_NetworkDiagnostics.ps1 -PingTargets "192.168.1.1","10.0.0.1","google.com"
```

**Analyze the last 48 hours of event logs:**
```powershell
.\04_EventLogAnalyzer.ps1 -HoursBack 48 -MaxEvents 1000
```

**Monitor performance for 2 minutes, sampling every 10 seconds:**
```powershell
.\05_PerformanceMonitor.ps1 -DurationSeconds 120 -IntervalSeconds 10
```

**Preview what ProfileCleanup would delete (safe, no files removed):**
```powershell
.\08_ProfileCleanup.ps1
```

**Actually run the cleanup after reviewing the preview:**
```powershell
.\08_ProfileCleanup.ps1 -Execute
```

**Check for updates and flag critical ones:**
```powershell
.\09_WindowsUpdateChecker.ps1
```

**Run software inventory and check against an approved apps list:**
```powershell
.\10_SoftwareInventory.ps1 -IncludeStoreApps -ApprovedListPath "C:\Config\approved_apps.txt"
```

---

## Safety & Best Practices

- **Preview before executing** — Scripts like `08_ProfileCleanup.ps1` default to a dry-run mode. Always review the output before passing `-Execute`.
- **Test in a non-production environment first** — Validate scripts on a test machine before wide deployment.
- **Run with least privilege** — Only elevate to Administrator when a script explicitly requires it.
- **Review the configurable sections** — Scripts like `07_NetworkDriveConnector.ps1` contain a `# CONFIGURE YOUR DRIVES HERE` block that must be updated for your environment.

---

## Logging

Scripts that perform sensitive or destructive actions write audit logs automatically:

| Script | Log File |
|--------|----------|
| `06_PasswordResetUtility.ps1` | `PasswordReset_Audit.log` |
| `07_NetworkDriveConnector.ps1` | `NetworkDrives_Audit.log` |
| `08_ProfileCleanup.ps1` | `ProfileCleanup_<timestamp>.txt` |

All report-generating scripts save timestamped `.txt` and/or `.csv` files to your Desktop by default, or to a path you specify with `-OutputPath`.

---

## Contributing

Contributions are welcome! To add or improve a script:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-script-name`
3. Follow the existing script structure (header comments, error handling, logging)
4. Submit a pull request with a clear description of what the script does

Please ensure all scripts follow these standards:
- Include a full comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- Use `try/catch` for all major operations
- Include a confirmation prompt before any destructive action
- Test on Windows 10 and Windows 11

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Made for IT teams who'd rather automate than repeat themselves.
</p>
