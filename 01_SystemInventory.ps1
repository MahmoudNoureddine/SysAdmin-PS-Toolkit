#Requires -Version 5.1
<#
.SYNOPSIS
    System Inventory Script - Gathers comprehensive system information.

.DESCRIPTION
    Collects hardware specifications, OS details, installed software,
    and network configuration. Outputs a formatted report and optionally
    saves it to a log file.

.PARAMETER OutputPath
    Directory path to save the inventory report. Defaults to the user's Desktop.

.PARAMETER ExportCSV
    If specified, also exports the software list to a separate CSV file.

.EXAMPLE
    .\01_SystemInventory.ps1
    .\01_SystemInventory.ps1 -OutputPath "C:\Reports" -ExportCSV

.NOTES
    Prerequisites : Run with Administrator privileges for full hardware data.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [switch]$ExportCSV
)

# ─── Helper: Section Header ────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    Write-Host "`n$line"  -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "$line"    -ForegroundColor Cyan
}

# Accumulate lines for the report AND echo to console
$report = [System.Collections.Generic.List[string]]::new()
function Add-Line {
    param([string]$Text = "")
    $report.Add($Text)
    Write-Host $Text
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "SystemInventory_$timestamp.txt"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nStarting System Inventory - please wait..." -ForegroundColor Green

    Add-Line "============================================================"
    Add-Line "  SYSTEM INVENTORY REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "  User      : $env:USERNAME"
    Add-Line "============================================================"

    # ── 1. Operating System ────────────────────────────────────────────────────
    Write-Section "OPERATING SYSTEM"
    Add-Line "`n[Operating System]"
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Add-Line "  Name         : $($os.Caption)"
        Add-Line "  Version      : $($os.Version)"
        Add-Line "  Build        : $($os.BuildNumber)"
        Add-Line "  Architecture : $($os.OSArchitecture)"
        Add-Line "  Install Date : $($os.InstallDate)"
        Add-Line "  Last Boot    : $($os.LastBootUpTime)"
        Add-Line "  System Drive : $($os.SystemDrive)"
    } catch {
        Add-Line "  [ERROR] Could not retrieve OS info: $($_.Exception.Message)"
    }

    # ── 2. CPU ─────────────────────────────────────────────────────────────────
    Write-Section "HARDWARE - CPU"
    Add-Line "`n[CPU]"
    try {
        $cpus = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        foreach ($cpu in $cpus) {
            Add-Line "  Name         : $($cpu.Name.Trim())"
            Add-Line "  Cores        : $($cpu.NumberOfCores)"
            Add-Line "  Logical CPUs : $($cpu.NumberOfLogicalProcessors)"
            Add-Line "  Max Speed    : $($cpu.MaxClockSpeed) MHz"
            Add-Line "  Socket       : $($cpu.SocketDesignation)"
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve CPU info: $($_.Exception.Message)"
    }

    # ── 3. Memory ──────────────────────────────────────────────────────────────
    Write-Section "HARDWARE - MEMORY"
    Add-Line "`n[Memory]"
    try {
        $cs      = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $totalGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        Add-Line "  Total RAM : $totalGB GB"

        $sticks = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
        $i = 1
        foreach ($stick in $sticks) {
            $sizeGB = [math]::Round($stick.Capacity / 1GB, 2)
            Add-Line "  Slot $i     : $sizeGB GB  $($stick.Speed) MHz  Mfr: $($stick.Manufacturer)"
            $i++
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve memory info: $($_.Exception.Message)"
    }

    # ── 4. Disks ───────────────────────────────────────────────────────────────
    Write-Section "HARDWARE - DISKS"
    Add-Line "`n[Physical Disk Drives]"
    try {
        $disks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
        foreach ($disk in $disks) {
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)
            Add-Line "  Model      : $($disk.Model)"
            Add-Line "  Size       : $sizeGB GB"
            Add-Line "  Interface  : $($disk.InterfaceType)"
            Add-Line "  Partitions : $($disk.Partitions)"
            Add-Line ""
        }

        Add-Line "[Logical Drives - Free Space]"
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        foreach ($d in $drives) {
            $totalGB = [math]::Round($d.Size / 1GB, 2)
            $freeGB  = [math]::Round($d.FreeSpace / 1GB, 2)
            $pctFree = if ($d.Size -gt 0) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }
            Add-Line "  $($d.DeviceID)  Total: $totalGB GB  Free: $freeGB GB  ($pctFree% free)"
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve disk info: $($_.Exception.Message)"
    }

    # ── 5. Network ─────────────────────────────────────────────────────────────
    Write-Section "NETWORK CONFIGURATION"
    Add-Line "`n[Active Network Adapters]"
    try {
        $nics = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        foreach ($nic in $nics) {
            Add-Line "  Adapter      : $($nic.Description)"
            Add-Line "  MAC Address  : $($nic.MACAddress)"
            Add-Line "  IP Address   : $($nic.IPAddress -join ', ')"
            Add-Line "  Subnet Mask  : $($nic.IPSubnet -join ', ')"
            Add-Line "  Gateway      : $($nic.DefaultIPGateway -join ', ')"
            Add-Line "  DNS Servers  : $($nic.DNSServerSearchOrder -join ', ')"
            Add-Line "  DHCP Enabled : $($nic.DHCPEnabled)"
            Add-Line ""
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve network info: $($_.Exception.Message)"
    }

    # ── 6. Installed Software ──────────────────────────────────────────────────
    Write-Section "INSTALLED SOFTWARE"
    Add-Line "`n[Installed Applications]"
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $software = $regPaths | ForEach-Object {
            Get-ItemProperty $_ -ErrorAction SilentlyContinue
        } | Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName

        foreach ($app in $software) {
            Add-Line ("  {0,-50} {1,-20} {2}" -f $app.DisplayName, $app.DisplayVersion, $app.Publisher)
        }
        Add-Line "`n  Total applications found: $($software.Count)"

        if ($ExportCSV) {
            $csvFile = Join-Path $OutputPath "SoftwareInventory_$timestamp.csv"
            $software | Export-Csv -Path $csvFile -NoTypeInformation
            Write-Host "`n  Software list exported to: $csvFile" -ForegroundColor Green
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve software info: $($_.Exception.Message)"
    }

    # ── Save Report ────────────────────────────────────────────────────────────
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
