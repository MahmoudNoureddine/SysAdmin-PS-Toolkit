#Requires -Version 5.1
<#
.SYNOPSIS
    Device Driver Updater - Scans and updates critical device drivers.

.DESCRIPTION
    Audits installed device drivers and helps keep them current by:
      - Listing all installed drivers with version and date
      - Identifying old or potentially outdated drivers
      - Checking for unsigned drivers (security risk)
      - Updating drivers via Windows Update (if available)
      - Updating via PnPUtil for INF-based drivers
      - Exporting a full driver inventory to CSV

.PARAMETER OutputPath
    Directory for the driver report. Defaults to user's Desktop.

.PARAMETER UpdateViaWindowsUpdate
    If specified, triggers Windows Update to search for driver updates.

.EXAMPLE
    .\18_DeviceDriverUpdater.ps1
    .\18_DeviceDriverUpdater.ps1 -OutputPath "C:\Reports" -UpdateViaWindowsUpdate

.NOTES
    Prerequisites : Administrator rights required for driver updates.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath               = "$env:USERPROFILE\Desktop",
    [switch]$UpdateViaWindowsUpdate,
    [int]$OldDriverThresholdDays      = 365
)

# ─── Admin Check ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`nWARNING: Not running as Administrator. Driver updates will be limited." -ForegroundColor Yellow
}

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "DriverReport_$timestamp.txt"
$csvFile    = Join-Path $OutputPath "DriverInventory_$timestamp.csv"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nDevice Driver Updater" -ForegroundColor Green

    Add-Line "============================================================"
    Add-Line "  DEVICE DRIVER REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "============================================================"

    # ── 1. Problem Devices ─────────────────────────────────────────────────────
    Write-Section "DEVICES WITH PROBLEMS"
    Add-Line "`n[Problem Devices - Errors or Warnings]"
    try {
        $problemDevices = Get-PnpDevice -ErrorAction Stop |
            Where-Object { $_.Status -in "Error", "Unknown", "Degraded" }

        if ($problemDevices) {
            Add-Line ("  {0,-40} {1,-15} {2}" -f "Device", "Class", "Status")
            Add-Line ("  {0,-40} {1,-15} {2}" -f "------", "-----", "------")
            foreach ($d in $problemDevices) {
                $row = "  {0,-40} {1,-15} {2}" -f `
                    ($d.FriendlyName.Substring(0,[math]::Min(39,$d.FriendlyName.Length))), `
                    $d.Class, $d.Status
                Write-Host $row -ForegroundColor Red
                $lines.Add($row)
            }
            Write-Host "`n  $($problemDevices.Count) device(s) have issues - driver update recommended." -ForegroundColor Red
        } else {
            Write-Host "  [OK] No problem devices found." -ForegroundColor Green
            Add-Line "  No problem devices found."
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── 2. Unsigned Drivers ────────────────────────────────────────────────────
    Write-Section "UNSIGNED / UNVERIFIED DRIVERS"
    Add-Line "`n[Checking for Unsigned Drivers]"
    try {
        # Get drivers via Win32_PnPSignedDriver
        $unsignedDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
            Where-Object { $_.IsSigned -eq $false -and $_.DeviceName } |
            Sort-Object DeviceName

        if ($unsignedDrivers) {
            Add-Line ("  {0,-40} {1,-20} {2}" -f "Device", "Driver Version", "Signer")
            foreach ($d in $unsignedDrivers) {
                $row = "  {0,-40} {1,-20} {2}" -f `
                    ($d.DeviceName.Substring(0,[math]::Min(39,$d.DeviceName.Length))), `
                    $d.DriverVersion, "UNSIGNED"
                Write-Host $row -ForegroundColor Yellow
                $lines.Add($row)
            }
            Write-Host "`n  WARNING: $($unsignedDrivers.Count) unsigned driver(s) detected." -ForegroundColor Yellow
        } else {
            Write-Host "  [OK] All drivers appear to be signed." -ForegroundColor Green
            Add-Line "  All drivers are signed."
        }
    } catch {
        Add-Line "  [INFO] Could not enumerate signed driver status: $($_.Exception.Message)"
    }

    # ── 3. Critical Driver Inventory ──────────────────────────────────────────
    Write-Section "CRITICAL DRIVER INVENTORY"
    Add-Line "`n[Key Device Categories]"

    $criticalCategories = @("Net", "Display", "DiskDrive", "Processor", "USB", "AudioEndpoint", "Bluetooth", "System")
    $oldThreshold = (Get-Date).AddDays(-$OldDriverThresholdDays)
    $allDrivers   = [System.Collections.Generic.List[object]]::new()
    $oldDrivers   = [System.Collections.Generic.List[object]]::new()

    try {
        $signedDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
                         Where-Object { $_.DeviceName -and $_.DriverDate }

        foreach ($cat in $criticalCategories) {
            $catDrivers = $signedDrivers | Where-Object { $_.DeviceClass -eq $cat }
            if (-not $catDrivers) { continue }

            Add-Line "`n  [$cat Drivers]"
            Add-Line ("  {0,-40} {1,-15} {2,-12} {3}" -f "Device", "Version", "Date", "Status")
            Add-Line ("  {0,-40} {1,-15} {2,-12} {3}" -f "------", "-------", "----", "------")

            foreach ($d in $catDrivers | Sort-Object DeviceName) {
                $driverDate  = $d.DriverDate
                $ageDays     = if ($driverDate) { [math]::Round(((Get-Date) - $driverDate).TotalDays, 0) } else { 9999 }
                $isOld       = $ageDays -gt $OldDriverThresholdDays
                $status      = if ($isOld) { "OLD ($ageDays days)" } else { "OK" }
                $color       = if ($isOld) { "Yellow" } else { "White" }
                $dateStr     = if ($driverDate) { $driverDate.ToString("yyyy-MM-dd") } else { "Unknown" }

                $row = "  {0,-40} {1,-15} {2,-12} {3}" -f `
                    ($d.DeviceName.Substring(0,[math]::Min(39,$d.DeviceName.Length))), `
                    $d.DriverVersion, $dateStr, $status
                Write-Host $row -ForegroundColor $color
                $lines.Add($row)

                $driverObj = [PSCustomObject]@{
                    Category    = $cat; DeviceName = $d.DeviceName
                    Version     = $d.DriverVersion; Date = $dateStr
                    AgeDays     = $ageDays; Signed = $d.IsSigned; Status = $status
                }
                $allDrivers.Add($driverObj)
                if ($isOld) { $oldDrivers.Add($driverObj) }
            }
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── 4. Old Driver Summary ──────────────────────────────────────────────────
    Write-Section "OLD DRIVER SUMMARY (>$OldDriverThresholdDays days)"
    Add-Line ""
    if ($oldDrivers.Count -gt 0) {
        Write-Host "  $($oldDrivers.Count) driver(s) are older than $OldDriverThresholdDays days:" -ForegroundColor Yellow
        foreach ($d in $oldDrivers | Sort-Object AgeDays -Descending) {
            $row = "  [OLD] $($d.DeviceName)  v$($d.Version)  $($d.Date) ($($d.AgeDays) days)"
            Write-Host $row -ForegroundColor Yellow
            Add-Line $row
        }
    } else {
        Write-Host "  [OK] All drivers are within the $OldDriverThresholdDays-day threshold." -ForegroundColor Green
        Add-Line "  All drivers are current."
    }

    # ── 5. Windows Update Driver Check ────────────────────────────────────────
    if ($UpdateViaWindowsUpdate) {
        Write-Section "WINDOWS UPDATE - DRIVER SEARCH"
        Add-Line "`n[Searching Windows Update for driver updates...]"
        try {
            $updateSession  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $searcher       = $updateSession.CreateUpdateSearcher()
            $searchResult   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
            $driverUpdates  = $searchResult.Updates

            if ($driverUpdates.Count -gt 0) {
                Add-Line "  Found $($driverUpdates.Count) driver update(s) via Windows Update:"
                for ($i = 0; $i -lt $driverUpdates.Count; $i++) {
                    $upd = $driverUpdates.Item($i)
                    $row = "  [AVAILABLE] $($upd.Title)  Size: $([math]::Round($upd.MaxDownloadSize/1MB,1)) MB"
                    Write-Host $row -ForegroundColor Cyan
                    $lines.Add($row)
                }

                $doDownload = Read-Host "`n  Download and queue these driver updates? (Y/N)"
                if ($doDownload -eq 'Y') {
                    $downloader = $updateSession.CreateUpdateDownloader()
                    $collection = New-Object -ComObject Microsoft.Update.UpdateColl
                    for ($i = 0; $i -lt $driverUpdates.Count; $i++) { $collection.Add($driverUpdates.Item($i)) | Out-Null }
                    $downloader.Updates = $collection
                    $result = $downloader.Download()
                    Add-Line "  Download result: $(if($result.ResultCode -eq 2){'Succeeded'}else{"Code: $($result.ResultCode)"})"
                    Write-Host "  Updates downloaded. Install via Windows Update settings." -ForegroundColor Cyan
                }
            } else {
                Write-Host "  [OK] No driver updates found via Windows Update." -ForegroundColor Green
                Add-Line "  No driver updates available via Windows Update."
            }
        } catch {
            Add-Line "  [ERROR] Windows Update driver check failed: $($_.Exception.Message)"
        }
    }

    # ── 6. PnPUtil - List 3rd Party Drivers ────────────────────────────────────
    Write-Section "THIRD-PARTY DRIVER PACKAGES (PnPUtil)"
    Add-Line "`n[Driver Store - Installed Packages]"
    try {
        $pnpOutput = & pnputil /enum-drivers 2>&1 | Out-String
        $lines.Add($pnpOutput)
        Write-Host $pnpOutput -ForegroundColor Gray
    } catch {
        Add-Line "  [INFO] PnPUtil not available or no third-party drivers."
    }

    # ── Export CSV ─────────────────────────────────────────────────────────────
    if ($allDrivers.Count -gt 0) {
        $allDrivers | Export-Csv -Path $csvFile -NoTypeInformation
        Add-Line "`n  Full driver inventory exported to: $csvFile"
        Write-Host "  [OK] CSV exported: $csvFile" -ForegroundColor Green
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
