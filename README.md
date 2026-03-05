# 🛠️ SysAdmin-PS-Toolkit

> A collection of 25 production-ready PowerShell scripts for Windows system administrators — covering diagnostics, monitoring, security, maintenance, and automation.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Scripts](https://img.shields.io/badge/Scripts-25%20Complete-brightgreen)

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
.\SystemInventory.ps1
```

**4. Get help for any script**
```powershell
Get-Help .\SystemInventory.ps1 -Full
```

---

## Scripts

### 🔍 Diagnostics & Reporting

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`SystemInventory.ps1`](./SystemInventory.ps1) | Gathers hardware specs, OS version, installed software, and network configuration into a full inventory report | ⚠️ Recommended |
| [`DiskSpaceReporter.ps1`](./DiskSpaceReporter.ps1) | Checks available disk space on all drives, identifies largest files and folders, flags low-space warnings | ❌ |
| [`NetworkDiagnostics.ps1`](./NetworkDiagnostics.ps1) | Tests connectivity, DNS resolution, ping tests, and verifies full IP configuration | ❌ |
| [`EventLogAnalyzer.ps1`](./EventLogAnalyzer.ps1) | Pulls and summarizes Error/Critical events from System, Application, and Security logs | ⚠️ Security log |
| [`PerformanceMonitor.ps1`](./PerformanceMonitor.ps1) | Samples CPU, memory, and disk I/O metrics over a configurable period; identifies top resource-consuming processes | ❌ |
| [`SystemReportGenerator.ps1`](./SystemReportGenerator.ps1) | One-click comprehensive system report combining inventory, disk, events, performance, and software into a single output | ⚠️ Recommended |

### 🔐 Security & User Management

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`PasswordResetUtility.ps1`](./PasswordResetUtility.ps1) | Interactive menu for changing passwords (with strength validation), unlocking accounts, and viewing account status | ⚠️ To manage others |
| [`PasswordPolicyEnforcer.ps1`](./PasswordPolicyEnforcer.ps1) | Audits and enforces local password policy settings — complexity, length, expiry, lockout thresholds | ✅ Always |
| [`USBDeviceBlocker.ps1`](./USBDeviceBlocker.ps1) | Enables or disables USB storage device access via registry and Group Policy. Preview mode by default | ✅ Always |
| [`FirewallConfigurator.ps1`](./FirewallConfigurator.ps1) | Manages Windows Firewall rules — add, remove, enable/disable, and export firewall config | ✅ Always |
| [`AntivirusStatusChecker.ps1`](./AntivirusStatusChecker.ps1) | Reports Windows Defender / AV status, last scan time, definition age, and real-time protection state | ✅ Recommended |
| [`Get-LocalAdminReport.ps1`](./Get-LocalAdminReport.ps1) | Audits local Administrators group membership across remote computers — detects unauthorized local admins | ✅ Always |

### 🌐 Connectivity & Configuration

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`NetworkDriveConnector.ps1`](./NetworkDriveConnector.ps1) | Maps predefined network drives with credential fallback, checks VPN status, and tests share reachability | ❌ |
| [`PrinterInstaller.ps1`](./PrinterInstaller.ps1) | Installs network printers by IP or hostname, sets default printer, and removes stale printer entries | ✅ Always |

### 🧹 Maintenance

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`ProfileCleanup.ps1`](./ProfileCleanup.ps1) | Removes temp files, browser caches, prefetch, and Recycle Bin contents. **Runs in preview mode by default** | ⚠️ Full cleanup |
| [`TempFileCleaner.ps1`](./TempFileCleaner.ps1) | Cleans Windows temp folders, WinSxS backup files, and CBS logs to reclaim disk space | ✅ Always |
| [`DeviceDriverUpdater.ps1`](./DeviceDriverUpdater.ps1) | Scans for outdated or missing drivers using Windows Update and PnP utilities | ✅ Always |
| [`Watch-DiskSpace.ps1`](./Watch-DiskSpace.ps1) | Continuous disk space monitor with configurable warning and critical thresholds — live color-coded dashboard | ❌ |

### 📦 Software Management

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`WindowsUpdateChecker.ps1`](./WindowsUpdateChecker.ps1) | Scans for pending Windows Updates using the WUA API, lists severity and KB numbers, optionally triggers downloads | ⚠️ Recommended |
| [`SoftwareInventory.ps1`](./SoftwareInventory.ps1) | Lists all installed applications (64-bit, 32-bit, AppX) with versions and publishers; supports approved-list compliance checks | ❌ |
| [`ApplicationInstaller.ps1`](./ApplicationInstaller.ps1) | Installs applications silently via Winget or direct installer — supports bulk install from a config list | ✅ Always |
| [`SoftwareUninstaller.ps1`](./SoftwareUninstaller.ps1) | Uninstalls applications by name with confirmation — supports wildcard matching and bulk removal | ✅ Always |

### ⚙️ Remote Administration

| Script | Description | Admin Required |
|--------|-------------|:--------------:|
| [`Invoke-RemoteCommand.ps1`](./Invoke-RemoteCommand.ps1) | Run any PowerShell command or script file on one or multiple remote machines in parallel via WinRM | ✅ Always |
| [`Get-ScheduledTaskReport.ps1`](./Get-ScheduledTaskReport.ps1) | Audits scheduled tasks across local/remote machines — flags non-Microsoft and suspicious tasks | ✅ Always |
| [`New-LocalUserProvision.ps1`](./New-LocalUserProvision.ps1) | Creates and configures local user accounts on remote machines — supports bulk CSV provisioning | ✅ Always |

> **Legend:** ✅ = Always required &nbsp; ⚠️ = Recommended &nbsp; ❌ = Not required

---

## Usage Examples

```powershell
# Full system inventory with CSV export
.\SystemInventory.ps1 -OutputPath "C:\Reports" -ExportCSV

# Find top 30 largest files on D: drive
.\DiskSpaceReporter.ps1 -DriveLetter D -TopN 30

# Run network diagnostics against custom targets
.\NetworkDiagnostics.ps1 -PingTargets "192.168.1.1","10.0.0.1","google.com"

# Analyze last 48 hours of event logs
.\EventLogAnalyzer.ps1 -HoursBack 48 -MaxEvents 1000

# Monitor performance for 2 minutes
.\PerformanceMonitor.ps1 -DurationSeconds 120 -IntervalSeconds 10

# Preview what ProfileCleanup would delete (no files removed)
.\ProfileCleanup.ps1

# Actually run the cleanup
.\ProfileCleanup.ps1 -Execute

# Audit local admins across an OU
.\Get-LocalAdminReport.ps1 -OUPath "OU=Workstations,DC=corp,DC=local" -FlagDomainUsers

# Run a command on multiple remote machines in parallel
.\Invoke-RemoteCommand.ps1 -ComputerName "PC01","PC02","PC03" -Command "Get-Service Spooler"

# Audit scheduled tasks and flag suspicious ones
.\Get-ScheduledTaskReport.ps1 -ComputerName "Server01" -FlagSuspicious -NonMicrosoftOnly

# Live disk space monitor with custom thresholds
.\Watch-DiskSpace.ps1 -ComputerName "FileServer" -WarnPercent 25 -CritPercent 10 -IntervalSec 120

# One-time disk snapshot
.\Watch-DiskSpace.ps1 -Snapshot -OutputPath "C:\Reports"

# Create a local kiosk account on a remote machine
.\New-LocalUserProvision.ps1 -ComputerName "Kiosk01" -Username "kiosk" -FullName "Kiosk Account" -AddToGroup "Users"

# Bulk provision local accounts from CSV
.\New-LocalUserProvision.ps1 -CSVPath "C:\LocalUsers.csv"

# Software inventory with approved apps check
.\SoftwareInventory.ps1 -IncludeStoreApps -ApprovedListPath "C:\Config\approved_apps.txt"
```

---

## Safety & Best Practices

- **Preview before executing** — Scripts like `ProfileCleanup.ps1` and `USBDeviceBlocker.ps1` default to dry-run mode. Always review output before passing `-Execute`.
- **Test in a non-production environment first** — Validate scripts on a test machine before wide deployment.
- **Run with least privilege** — Only elevate to Administrator when a script explicitly requires it.
- **Review configurable sections** — Scripts like `NetworkDriveConnector.ps1` contain a `# CONFIGURE YOUR DRIVES HERE` block that must be updated for your environment.
- **WinRM required for remote scripts** — `Invoke-RemoteCommand.ps1`, `Get-LocalAdminReport.ps1`, `Get-ScheduledTaskReport.ps1`, and `New-LocalUserProvision.ps1` require WinRM enabled on targets (`Enable-PSRemoting`).

---

## Logging

Scripts that perform sensitive or destructive actions write audit logs automatically:

| Script | Log File |
|--------|----------|
| `PasswordResetUtility.ps1` | `PasswordReset_Audit.log` |
| `NetworkDriveConnector.ps1` | `NetworkDrives_Audit.log` |
| `ProfileCleanup.ps1` | `ProfileCleanup_<timestamp>.txt` |
| `Get-LocalAdminReport.ps1` | `LocalAdminReport_<timestamp>.log` |
| `Invoke-RemoteCommand.ps1` | `RemoteCommand_<timestamp>.log` |
| `New-LocalUserProvision.ps1` | `LocalUserProvision_<timestamp>.log` |
| `Watch-DiskSpace.ps1` | `DiskSpaceAlerts_<date>.log` |

All report-generating scripts save timestamped `.txt` and/or `.csv` files to your Desktop by default, or to any path specified with `-OutputPath`.

---

## Contributing

Contributions are welcome! To add or improve a script:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-script-name`
3. Follow the existing script structure (header comments, error handling, logging)
4. Submit a pull request with a clear description of what the script does

Please ensure all scripts follow these standards:
- Full comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- `try/catch` for all major operations
- Confirmation prompt before any destructive action
- Tested on Windows 10 and Windows 11

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Made for IT teams who'd rather automate than repeat themselves.
</p>
