#Requires -Version 5.1
<#
.SYNOPSIS
    Profile Cleanup Script - Removes temporary files and old profile data.

.DESCRIPTION
    Safely cleans up disk space by removing:
      - Windows Temp folders (%TEMP% and C:\Windows\Temp)
      - Browser caches (Chrome, Edge, Firefox)
      - Windows prefetch files (admin required)
      - Thumbnail cache
      - Old user profiles (optional, with confirmation)
      - Recycle Bin contents

    Runs in preview mode by default (shows what WOULD be deleted).
    Use -Execute to actually perform deletions.

.PARAMETER Execute
    Switch to actually delete files. Without this, runs in preview/dry-run mode.

.PARAMETER CleanOldProfiles
    Also attempt to remove user profiles not accessed in more than 90 days.

.PARAMETER ProfileAgeDays
    Age threshold in days for old profile cleanup. Default: 90.

.PARAMETER OutputPath
    Where to save the cleanup report. Defaults to user's Desktop.

.EXAMPLE
    .\08_ProfileCleanup.ps1                          # Preview mode (safe)
    .\08_ProfileCleanup.ps1 -Execute                 # Actually delete files
    .\08_ProfileCleanup.ps1 -Execute -CleanOldProfiles

.NOTES
    Prerequisites : Administrator rights needed for Windows Temp and Prefetch.
    ALWAYS run in preview mode first to see what will be removed.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$CleanOldProfiles,
    [int]$ProfileAgeDays   = 90,
    [string]$OutputPath    = "$env:USERPROFILE\Desktop"
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }

$totalFreed    = 0
$totalPreviewed = 0

# ─── Clean a Folder ────────────────────────────────────────────────────────────
function Invoke-FolderClean {
    param(
        [string]$FolderPath,
        [string]$Label,
        [int]$OlderThanDays = 0    # 0 = clean everything
    )
    if (-not (Test-Path $FolderPath)) {
        Add-Line "  [SKIP] $Label - Path not found: $FolderPath"
        return
    }

    $cutoff = if ($OlderThanDays -gt 0) { (Get-Date).AddDays(-$OlderThanDays) } else { (Get-Date).AddYears(10) }

    try {
        $items = Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer -and ($OlderThanDays -eq 0 -or $_.LastWriteTime -lt $cutoff) }

        $size  = ($items | Measure-Object -Property Length -Sum).Sum
        $count = $items.Count
        if ($null -eq $size) { $size = 0 }

        if ($Execute) {
            $deleted = 0; $errors = 0
            foreach ($item in $items) {
                try {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    $deleted++
                } catch {
                    $errors++
                }
            }
            # Remove empty directories
            Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer } |
                Sort-Object FullName -Descending |
                ForEach-Object { try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {} }

            Add-Line "  [CLEANED] $Label : $deleted files removed ($(Format-Size $size) freed)  errors: $errors"
            $script:totalFreed += $size
        } else {
            Add-Line "  [PREVIEW] $Label : $count files would be removed ($(Format-Size $size))"
            $script:totalPreviewed += $size
        }
    } catch {
        Add-Line "  [ERROR]  $Label : $($_.Exception.Message)"
    }
}

# ─── Main ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "ProfileCleanup_$timestamp.txt"

try {
    $mode = if ($Execute) { "EXECUTE MODE - FILES WILL BE DELETED" } else { "PREVIEW MODE - No files will be deleted (run with -Execute to delete)" }
    Write-Host "`nProfile Cleanup Script" -ForegroundColor Green
    Write-Host $mode -ForegroundColor $(if ($Execute) { "Red" } else { "Yellow" })

    # Safety confirmation for Execute mode
    if ($Execute) {
        Write-Host "`nWARNING: This will permanently delete files. This cannot be undone." -ForegroundColor Red
        $confirm = Read-Host "Type YES to confirm and continue"
        if ($confirm -ne "YES") {
            Write-Host "Aborted by user." -ForegroundColor Yellow
            exit 0
        }
    }

    Add-Line "============================================================"
    Add-Line "  PROFILE CLEANUP REPORT  [$mode]"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME  User: $env:USERNAME"
    Add-Line "============================================================"

    # ── User Temp Folder ───────────────────────────────────────────────────────
    Write-Section "USER TEMP FOLDER"
    Invoke-FolderClean -FolderPath $env:TEMP -Label "User Temp (%TEMP%)"

    # ── Windows Temp Folder ────────────────────────────────────────────────────
    Write-Section "WINDOWS TEMP FOLDER"
    Invoke-FolderClean -FolderPath "C:\Windows\Temp" -Label "Windows Temp"

    # ── Thumbnail Cache ────────────────────────────────────────────────────────
    Write-Section "THUMBNAIL CACHE"
    $thumbPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    Invoke-FolderClean -FolderPath $thumbPath -Label "Thumbnail Cache (thumbcache_*.db)"

    # ── Browser Caches ─────────────────────────────────────────────────────────
    Write-Section "BROWSER CACHES"

    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    Invoke-FolderClean -FolderPath $chromePath -Label "Google Chrome Cache"

    $edgePath   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    Invoke-FolderClean -FolderPath $edgePath -Label "Microsoft Edge Cache"

    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfiles) {
        Get-ChildItem $firefoxProfiles -Directory | ForEach-Object {
            $ffCache = Join-Path $_.FullName "cache2"
            Invoke-FolderClean -FolderPath $ffCache -Label "Firefox Cache ($($_.Name))"
        }
    }

    # ── Prefetch (Admin required) ──────────────────────────────────────────────
    Write-Section "PREFETCH FILES"
    Invoke-FolderClean -FolderPath "C:\Windows\Prefetch" -Label "Prefetch Files" -OlderThanDays 30

    # ── Windows Update Cache ───────────────────────────────────────────────────
    Write-Section "WINDOWS UPDATE DOWNLOAD CACHE"
    Invoke-FolderClean -FolderPath "C:\Windows\SoftwareDistribution\Download" -Label "Windows Update Downloads"

    # ── Recycle Bin ────────────────────────────────────────────────────────────
    Write-Section "RECYCLE BIN"
    try {
        if ($Execute) {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Add-Line "  [CLEANED] Recycle Bin emptied."
        } else {
            $shell = New-Object -ComObject Shell.Application
            $bin   = $shell.Namespace(0xA)  # 0xA = Recycle Bin
            $items = $bin.Items()
            Add-Line "  [PREVIEW] Recycle Bin contains $($items.Count) items."
        }
    } catch {
        Add-Line "  [ERROR] Recycle Bin: $($_.Exception.Message)"
    }

    # ── Old User Profiles ──────────────────────────────────────────────────────
    if ($CleanOldProfiles) {
        Write-Section "OLD USER PROFILES (unused > $ProfileAgeDays days)"
        Add-Line ""
        try {
            $cutoff  = (Get-Date).AddDays(-$ProfileAgeDays)
            $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                        Where-Object {
                            -not $_.Special -and
                            $_.LastUseTime -and
                            $_.LastUseTime -lt $cutoff -and
                            $_.LocalPath -notlike "*$env:SystemDrive\Users\Default*"
                        }

            if ($profiles.Count -eq 0) {
                Add-Line "  No old profiles found (all active within $ProfileAgeDays days)."
            } else {
                foreach ($p in $profiles) {
                    Add-Line "  Profile : $($p.LocalPath)  Last Used: $($p.LastUseTime)"
                    if ($Execute) {
                        Write-Host "  Remove this profile? (Y/N)" -ForegroundColor Yellow
                        $ans = Read-Host "  Confirm removal of $($p.LocalPath)"
                        if ($ans -eq 'Y') {
                            try {
                                $p | Remove-CimInstance -ErrorAction Stop
                                Add-Line "  [REMOVED] $($p.LocalPath)"
                            } catch {
                                Add-Line "  [ERROR]   Could not remove: $($_.Exception.Message)"
                            }
                        } else {
                            Add-Line "  [SKIPPED] $($p.LocalPath)"
                        }
                    }
                }
            }
        } catch {
            Add-Line "  [ERROR] Profile scan failed: $($_.Exception.Message)"
        }
    }

    # ── Summary ────────────────────────────────────────────────────────────────
    Write-Section "SUMMARY"
    if ($Execute) {
        Add-Line "  Total space freed : $(Format-Size $totalFreed)"
    } else {
        Add-Line "  Potential space to free : $(Format-Size $totalPreviewed)"
        Add-Line "  Re-run with -Execute to actually delete these files."
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
