#Requires -Version 5.1
<#
.SYNOPSIS
    Disk Space Reporter - Identifies disk usage, large files, and folders.

.DESCRIPTION
    Checks free/used space on all local drives. Finds the largest files
    and folders on a chosen drive, and flags drives below a warning threshold.

.PARAMETER DriveLetter
    Drive letter to scan for large files/folders (e.g. "C"). Defaults to system drive.

.PARAMETER TopN
    How many largest files/folders to list. Default is 20.

.PARAMETER WarningThresholdGB
    Drives with less than this many GB free will be flagged. Default is 10 GB.

.PARAMETER OutputPath
    Directory to save the report. Defaults to the user's Desktop.

.EXAMPLE
    .\02_DiskSpaceReporter.ps1
    .\02_DiskSpaceReporter.ps1 -DriveLetter D -TopN 30 -WarningThresholdGB 5

.NOTES
    Prerequisites : Administrator rights recommended for full folder access.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$DriveLetter      = $env:SystemDrive.TrimEnd(':'),
    [int]$TopN                = 20,
    [double]$WarningThresholdGB = 10,
    [string]$OutputPath       = "$env:USERPROFILE\Desktop"
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Format-Size {
    param([long]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1TB } { return "{0:N2} TB" -f ($_ / 1TB) }
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default        { return "$_ B" }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line {
    param([string]$Text = "")
    $lines.Add($Text)
    Write-Host $Text
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "DiskReport_$timestamp.txt"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nDisk Space Reporter starting..." -ForegroundColor Green

    Add-Line "============================================================"
    Add-Line "  DISK SPACE REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "============================================================"

    # ── All Local Drives Overview ──────────────────────────────────────────────
    Write-Section "ALL LOCAL DRIVE SUMMARY"
    Add-Line "`n[Drive Overview]"
    try {
        $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        foreach ($d in $drives) {
            $totalGB = [math]::Round($d.Size / 1GB, 2)
            $freeGB  = [math]::Round($d.FreeSpace / 1GB, 2)
            $usedGB  = [math]::Round(($d.Size - $d.FreeSpace) / 1GB, 2)
            $pctUsed = if ($d.Size -gt 0) { [math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 1) } else { 0 }

            # Visual bar (20 chars wide)
            $filled = [math]::Round($pctUsed / 5)
            $bar    = ("[" + ("#" * $filled) + ("-" * (20 - $filled)) + "]")

            $status = if ($freeGB -lt $WarningThresholdGB) { "WARNING - LOW DISK SPACE" } else { "OK" }
            $color  = if ($status -like "WARNING*") { "Red" } else { "Green" }

            Add-Line "  Drive $($d.DeviceID)  $bar  $usedGB GB used / $totalGB GB total  Free: $freeGB GB  [$status]"
            if ($status -like "WARNING*") {
                Write-Host "  *** Drive $($d.DeviceID) is LOW on space! Only $freeGB GB remaining. ***" -ForegroundColor Red
            }
        }
    } catch {
        Add-Line "  [ERROR] Could not query drives: $($_.Exception.Message)"
    }

    # ── Top Large Files ────────────────────────────────────────────────────────
    Write-Section "TOP $TopN LARGEST FILES ON ${DriveLetter}:\"
    Add-Line "`n[Scanning for largest files on ${DriveLetter}:\ - this may take a moment...]"
    try {
        $scanRoot = "${DriveLetter}:\"
        if (-not (Test-Path $scanRoot)) { throw "Drive ${DriveLetter}: not found." }

        $largeFiles = Get-ChildItem -Path $scanRoot -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object Length -Descending |
            Select-Object -First $TopN

        Add-Line "`n  Rank  Size          Last Modified        Path"
        Add-Line "  ----  ------------  -------------------  ----"
        $rank = 1
        foreach ($f in $largeFiles) {
            $size    = Format-Size $f.Length
            $modified = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            Add-Line ("  {0,-5} {1,-13} {2,-21} {3}" -f $rank, $size, $modified, $f.FullName)
            $rank++
        }
    } catch {
        Add-Line "  [ERROR] Could not scan files: $($_.Exception.Message)"
    }

    # ── Top Large Folders ──────────────────────────────────────────────────────
    Write-Section "TOP $TopN LARGEST FOLDERS ON ${DriveLetter}:\"
    Add-Line "`n[Calculating folder sizes - please wait...]"
    try {
        $scanRoot = "${DriveLetter}:\"
        $folders  = Get-ChildItem -Path $scanRoot -Directory -ErrorAction SilentlyContinue

        $folderSizes = foreach ($folder in $folders) {
            $size = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            [PSCustomObject]@{ Path = $folder.FullName; Size = $size }
        }

        $topFolders = $folderSizes | Sort-Object Size -Descending | Select-Object -First $TopN

        Add-Line "`n  Rank  Size          Path"
        Add-Line "  ----  ------------  ----"
        $rank = 1
        foreach ($f in $topFolders) {
            Add-Line ("  {0,-5} {1,-13} {2}" -f $rank, (Format-Size $f.Size), $f.Path)
            $rank++
        }
    } catch {
        Add-Line "  [ERROR] Could not calculate folder sizes: $($_.Exception.Message)"
    }

    # ── Save Report ────────────────────────────────────────────────────────────
    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
