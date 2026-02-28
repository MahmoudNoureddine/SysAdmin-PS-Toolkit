#Requires -Version 5.1
<#
.SYNOPSIS
    Temporary File Cleaner - Removes temp files, cache, and Recycle Bin contents.

.DESCRIPTION
    A thorough disk cleanup utility that targets:
      - User and system temp folders
      - Windows Update download cache
      - Browser caches (Chrome, Edge, Firefox, IE)
      - Windows prefetch files
      - Thumbnail cache
      - Windows Installer patch cache (optional)
      - Windows log files older than threshold
      - Recycle Bin
      - Windows Error Reporting files

    Runs in PREVIEW MODE by default. Use -Execute to perform actual deletion.
    Reports space freed before and after.

.PARAMETER Execute
    Performs actual file deletion. Without this, shows only what would be removed.

.PARAMETER OlderThanDays
    Only delete files older than this many days. Default: 0 (all files).

.PARAMETER OutputPath
    Directory for the cleanup report. Defaults to user's Desktop.

.EXAMPLE
    .\19_TempFileCleaner.ps1                    # Preview mode
    .\19_TempFileCleaner.ps1 -Execute           # Actually clean
    .\19_TempFileCleaner.ps1 -Execute -OlderThanDays 30

.NOTES
    Prerequisites : Administrator rights needed for system-level folders.
    ALWAYS review preview output before running with -Execute.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [int]$OlderThanDays     = 0,
    [string]$OutputPath     = "$env:USERPROFILE\Desktop"
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

$lines        = [System.Collections.Generic.List[string]]::new()
$totalFreed   = [long]0
$totalFound   = [long]0
$cleanSummary = [System.Collections.Generic.List[object]]::new()

function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }

# ─── Core Clean Function ───────────────────────────────────────────────────────
function Invoke-Clean {
    param(
        [string]$Path,
        [string]$Label,
        [string[]]$Extensions    = @("*"),
        [string[]]$ExcludeNames  = @(),
        [int]$OlderThanDays      = 0
    )

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        $row = [PSCustomObject]@{ Label = $Label; Found = "N/A"; Freed = "N/A"; Files = 0; Status = "Path not found" }
        $cleanSummary.Add($row)
        Write-Host ("  {0,-45} {1}" -f $Label, "SKIPPED - Path not found") -ForegroundColor DarkGray
        Add-Line  ("  {0,-45} SKIPPED - Path not found" -f $Label)
        return
    }

    try {
        $cutoff = if ($OlderThanDays -gt 0) { (Get-Date).AddDays(-$OlderThanDays) } else { (Get-Date).AddYears(100) }

        # Build file list
        $files = foreach ($ext in $Extensions) {
            Get-ChildItem -Path $Path -Filter $ext -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object {
                    ($OlderThanDays -eq 0 -or $_.LastWriteTime -lt $cutoff) -and
                    ($_.Name -notin $ExcludeNames)
                }
        }

        $count   = ($files | Measure-Object).Count
        $size    = ($files | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $size) { $size = 0 }
        $script:totalFound += $size

        if ($Execute) {
            $deleted = 0; $errors = 0
            foreach ($f in $files) {
                try { Remove-Item $f.FullName -Force -ErrorAction Stop; $deleted++ }
                catch { $errors++ }
            }
            # Clean empty dirs
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer } | Sort-Object FullName -Descending |
                ForEach-Object { try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {} }

            $script:totalFreed += $size
            $status = "CLEANED ($deleted files, $errors errors)"
            $color  = if ($errors -gt 0) { "Yellow" } else { "Green" }
        } else {
            $status = "PREVIEW ($count files, $(Format-Size $size))"
            $color  = "Cyan"
        }

        $row = [PSCustomObject]@{ Label = $Label; Found = Format-Size $size; Files = $count; Status = $status }
        $cleanSummary.Add($row)
        Write-Host ("  {0,-45} {1}" -f $Label, $status) -ForegroundColor $color
        Add-Line  ("  {0,-45} {1}" -f $Label, $status)

    } catch {
        $row = [PSCustomObject]@{ Label = $Label; Found = "ERROR"; Files = 0; Status = $_.Exception.Message }
        $cleanSummary.Add($row)
        Write-Host ("  {0,-45} ERROR: {1}" -f $Label, $_.Exception.Message) -ForegroundColor Red
        Add-Line  ("  {0,-45} ERROR: {1}" -f $Label, $_.Exception.Message)
    }
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "TempClean_$timestamp.txt"

# ─── Disk Space Before ─────────────────────────────────────────────────────────
function Get-DiskFreeSpace {
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
    if ($drive) { return $drive.FreeSpace } else { return 0 }
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    $mode = if ($Execute) { "EXECUTE MODE - Files will be DELETED" } else { "PREVIEW MODE - No files will be deleted" }
    Write-Host "`nTemp File Cleaner" -ForegroundColor Green
    Write-Host $mode -ForegroundColor $(if ($Execute) { "Red" } else { "Yellow" })

    # Confirmation gate for execute mode
    if ($Execute) {
        Write-Host "`nWARNING: This will permanently delete files. Review preview first." -ForegroundColor Red
        $confirm = Read-Host "Type YES to proceed with file deletion"
        if ($confirm -ne "YES") { Write-Host "Aborted." -ForegroundColor Yellow; exit 0 }
    }

    $diskBefore = Get-DiskFreeSpace

    Add-Line "============================================================"
    Add-Line "  TEMP FILE CLEANER REPORT  [$mode]"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME  User: $env:USERNAME"
    Add-Line "  Age Filter: $(if($OlderThanDays -gt 0){"Files older than $OlderThanDays days"}else{"All files"})"
    Add-Line "============================================================"

    Write-Section "TEMP FOLDERS"
    Add-Line ""
    Invoke-Clean -Path $env:TEMP                                   -Label "User Temp (%TEMP%)"            -OlderThanDays $OlderThanDays
    Invoke-Clean -Path "$env:LOCALAPPDATA\Temp"                    -Label "Local AppData Temp"            -OlderThanDays $OlderThanDays
    Invoke-Clean -Path "C:\Windows\Temp"                           -Label "Windows System Temp"           -OlderThanDays $OlderThanDays

    Write-Section "BROWSER CACHES"
    Add-Line ""
    # Chrome
    Invoke-Clean -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"       -Label "Chrome Cache"
    Invoke-Clean -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache"  -Label "Chrome Code Cache"
    Invoke-Clean -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache"    -Label "Chrome GPU Cache"

    # Edge
    Invoke-Clean -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"      -Label "Edge Cache"
    Invoke-Clean -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache" -Label "Edge Code Cache"

    # Firefox
    $ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Invoke-Clean -Path (Join-Path $_.FullName "cache2") -Label "Firefox Cache ($($_.Name.Substring(0,[math]::Min(12,$_.Name.Length))))"
            Invoke-Clean -Path (Join-Path $_.FullName "thumbnails") -Label "Firefox Thumbnails"
        }
    }

    # IE / Legacy Edge
    Invoke-Clean -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" -Label "IE / Legacy Edge Cache"
    Invoke-Clean -Path "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"  -Label "WebCache Database"

    Write-Section "WINDOWS SYSTEM CACHES"
    Add-Line ""
    Invoke-Clean -Path "C:\Windows\Prefetch"                                   -Label "Prefetch Files"        -OlderThanDays 30
    Invoke-Clean -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"          -Label "Thumbnail Cache"
    Invoke-Clean -Path "C:\Windows\SoftwareDistribution\Download"              -Label "WU Download Cache"
    Invoke-Clean -Path "$env:LOCALAPPDATA\CrashDumps"                         -Label "Crash Dump Files"
    Invoke-Clean -Path "C:\ProgramData\Microsoft\Windows\WER\ReportArchive"    -Label "Windows Error Reports (Archive)"
    Invoke-Clean -Path "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"      -Label "Windows Error Reports (Queue)"

    Write-Section "LOG FILES"
    Add-Line ""
    Invoke-Clean -Path "C:\Windows\Logs"         -Label "Windows Logs"         -Extensions "*.log","*.etl" -OlderThanDays 30
    Invoke-Clean -Path "C:\Windows\System32\winevt\Logs" -Label "Event Log Archive" -Extensions "*.evtx"  -OlderThanDays 90

    Write-Section "RECYCLE BIN"
    Add-Line ""
    try {
        if ($Execute) {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Host ("  {0,-45} {1}" -f "Recycle Bin", "EMPTIED") -ForegroundColor Green
            Add-Line  ("  {0,-45} EMPTIED" -f "Recycle Bin")
        } else {
            $shell = New-Object -ComObject Shell.Application
            $count = $shell.Namespace(0xA).Items().Count
            Write-Host ("  {0,-45} {1}" -f "Recycle Bin", "PREVIEW: $count item(s)") -ForegroundColor Cyan
            Add-Line  ("  {0,-45} PREVIEW: $count item(s)" -f "Recycle Bin")
        }
    } catch {
        Add-Line "  [ERROR] Recycle Bin: $($_.Exception.Message)"
    }

    # ── Summary ────────────────────────────────────────────────────────────────
    Write-Section "SUMMARY"
    $diskAfter = Get-DiskFreeSpace

    if ($Execute) {
        $actualFreed = $diskAfter - $diskBefore
        Add-Line "`n  Space freed (measured) : $(Format-Size $actualFreed)"
        Add-Line   "  Space freed (tracked)  : $(Format-Size $totalFreed)"
        Add-Line   "  Disk free before       : $(Format-Size $diskBefore)"
        Add-Line   "  Disk free after        : $(Format-Size $diskAfter)"
    } else {
        Add-Line "`n  Potential space to free : $(Format-Size $totalFound)"
        Add-Line   "  Run with -Execute to perform actual cleanup."
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
