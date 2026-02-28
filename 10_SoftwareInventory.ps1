#Requires -Version 5.1
<#
.SYNOPSIS
    Software Inventory - Lists all installed applications with full details.

.DESCRIPTION
    Queries multiple sources to compile a comprehensive application inventory:
      - 64-bit registry hive
      - 32-bit registry hive (WOW6432Node)
      - Windows Store / AppX packages
      - Optional: checks against an approved software list and flags violations

    Exports results to a CSV and a formatted text report.

.PARAMETER OutputPath
    Directory to save reports. Defaults to user's Desktop.

.PARAMETER ApprovedListPath
    Optional path to a text file containing one approved application name per line.
    When provided, unapproved applications are highlighted.

.PARAMETER IncludeStoreApps
    If specified, includes Windows Store (AppX) applications.

.EXAMPLE
    .\10_SoftwareInventory.ps1
    .\10_SoftwareInventory.ps1 -IncludeStoreApps -ApprovedListPath "C:\Config\approved_apps.txt"

.NOTES
    Prerequisites : No special privileges required for current-user view.
                    Run as Administrator for full system-wide inventory.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath        = "$env:USERPROFILE\Desktop",
    [string]$ApprovedListPath  = "",
    [switch]$IncludeStoreApps
)

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
$reportFile = Join-Path $OutputPath "SoftwareInventory_$timestamp.txt"
$csvFile    = Join-Path $OutputPath "SoftwareInventory_$timestamp.csv"

# Load approved list if provided
$approvedApps = @()
if ($ApprovedListPath -and (Test-Path $ApprovedListPath)) {
    $approvedApps = Get-Content $ApprovedListPath | Where-Object { $_ -match '\S' }
    Write-Host "  Loaded $($approvedApps.Count) approved applications from: $ApprovedListPath" -ForegroundColor Gray
}

# ─── Collect from Registry ─────────────────────────────────────────────────────
function Get-RegistrySoftware {
    $regPaths = @(
        # 64-bit applications
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*";           Arch = "64-bit" },
        # 32-bit applications on 64-bit OS
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Arch = "32-bit" },
        # Per-user installations
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*";           Arch = "User"   }
    )

    $apps = foreach ($source in $regPaths) {
        Get-ItemProperty -Path $source.Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "^\s*$" } |
            ForEach-Object {
                [PSCustomObject]@{
                    Source        = "Registry ($($source.Arch))"
                    Name          = $_.DisplayName.Trim()
                    Version       = if ($_.DisplayVersion) { $_.DisplayVersion } else { "N/A" }
                    Publisher     = if ($_.Publisher)      { $_.Publisher.Trim() } else { "Unknown" }
                    InstallDate   = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                    Size_MB       = if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize / 1024, 1) } else { 0 }
                    UninstallCmd  = $_.UninstallString
                }
            }
    }
    # Deduplicate by Name + Version
    return $apps | Sort-Object Name, Version | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nSoftware Inventory Tool" -ForegroundColor Green
    Write-Host "Collecting installed applications..." -ForegroundColor Gray

    Add-Line "============================================================"
    Add-Line "  SOFTWARE INVENTORY REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "  User      : $env:USERNAME"
    Add-Line "============================================================"

    # ── Traditional Installed Applications ────────────────────────────────────
    Write-Section "INSTALLED APPLICATIONS (Registry)"
    $software = Get-RegistrySoftware

    Add-Line "`n  Found $($software.Count) applications.`n"
    Add-Line ("  {0,-50} {1,-20} {2,-30} {3,-10}" -f "Application", "Version", "Publisher", "Size(MB)")
    Add-Line ("  {0,-50} {1,-20} {2,-30} {3,-10}" -f "-----------", "-------", "---------", "--------")

    $unapproved = [System.Collections.Generic.List[object]]::new()

    foreach ($app in $software | Sort-Object Name) {
        $isApproved = $true
        if ($approvedApps.Count -gt 0) {
            $isApproved = $approvedApps | Where-Object { $app.Name -like "*$_*" }
        }

        $row = "  {0,-50} {1,-20} {2,-30} {3,-10}" -f `
            ($app.Name.Substring(0, [math]::Min(49, $app.Name.Length))), `
            ($app.Version.Substring(0, [math]::Min(19, $app.Version.Length))), `
            ($app.Publisher.Substring(0, [math]::Min(29, $app.Publisher.Length))), `
            $app.Size_MB

        if (-not $isApproved) {
            Write-Host $row -ForegroundColor Yellow
            $unapproved.Add($app)
        } else {
            Write-Host $row
        }
        $lines.Add($row)
    }

    # ── Windows Store Applications ─────────────────────────────────────────────
    if ($IncludeStoreApps) {
        Write-Section "WINDOWS STORE / APPX APPLICATIONS"
        Add-Line "`n[AppX Packages]"
        try {
            $appxApps = Get-AppxPackage -AllUsers -ErrorAction Stop |
                        Where-Object { $_.IsFramework -eq $false } |
                        Select-Object Name, Version, Publisher, PackageUserInformation |
                        Sort-Object Name

            Add-Line "  Found $($appxApps.Count) Store applications.`n"
            Add-Line ("  {0,-50} {1,-20} {2}" -f "Package Name", "Version", "Publisher")
            Add-Line ("  {0,-50} {1,-20} {2}" -f "------------", "-------", "---------")

            foreach ($a in $appxApps) {
                $row = "  {0,-50} {1,-20} {2}" -f `
                    ($a.Name.Substring(0, [math]::Min(49, $a.Name.Length))), `
                    ($a.Version.Substring(0, [math]::Min(19, $a.Version.Length))), `
                    ($a.Publisher.Substring(0, [math]::Min(40, $a.Publisher.Length)))
                Add-Line $row
            }

            # Add AppX to master list for CSV export
            $appxForCsv = $appxApps | ForEach-Object {
                [PSCustomObject]@{
                    Source        = "Windows Store"
                    Name          = $_.Name
                    Version       = $_.Version
                    Publisher     = $_.Publisher
                    InstallDate   = "N/A"
                    InstallLocation = "N/A"
                    Size_MB       = 0
                    UninstallCmd  = "N/A"
                }
            }
            $software = @($software) + @($appxForCsv)

        } catch {
            Add-Line "  [ERROR] Could not retrieve Store apps: $($_.Exception.Message)"
        }
    }

    # ── Unapproved Applications Summary ────────────────────────────────────────
    if ($approvedApps.Count -gt 0 -and $unapproved.Count -gt 0) {
        Write-Section "UNAPPROVED APPLICATIONS (Policy Violations)"
        Add-Line "`n  The following applications are NOT on the approved software list:"
        foreach ($app in $unapproved) {
            Add-Line "  [UNAPPROVED] $($app.Name)  v$($app.Version)  by $($app.Publisher)"
        }
        Write-Host "`n  $($unapproved.Count) unapproved application(s) detected - review required." -ForegroundColor Red
    }

    # ── Statistics ─────────────────────────────────────────────────────────────
    Write-Section "STATISTICS"
    $totalSizeMB = ($software | Measure-Object -Property Size_MB -Sum).Sum
    Add-Line "`n  Total applications   : $($software.Count)"
    Add-Line "  Total install size   : $([math]::Round($totalSizeMB / 1024, 2)) GB (estimated)"
    if ($approvedApps.Count -gt 0) {
        Add-Line "  Unapproved apps      : $($unapproved.Count)"
    }

    # ── CSV Export ─────────────────────────────────────────────────────────────
    $software | Export-Csv -Path $csvFile -NoTypeInformation
    Add-Line "`n  CSV data exported to : $csvFile"

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Text report : $reportFile" -ForegroundColor Green
    Write-Host "[OK] CSV export  : $csvFile"      -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
