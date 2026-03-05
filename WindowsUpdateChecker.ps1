#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Update Checker - Scans for and reports available Windows Updates.

.DESCRIPTION
    Uses the Windows Update API to:
      - Check for available updates (without installing them)
      - List pending updates with severity, size, and KB number
      - Report the date of the last successful update
      - Optionally trigger update downloads
      - Flag critical/security updates separately

.PARAMETER OutputPath
    Directory to save the report. Defaults to user's Desktop.

.PARAMETER Download
    If specified, initiates download of available updates (does NOT install).

.EXAMPLE
    .\09_WindowsUpdateChecker.ps1
    .\09_WindowsUpdateChecker.ps1 -OutputPath "C:\Reports"

.NOTES
    Prerequisites : Run with Administrator rights for full functionality.
                    Script uses COM objects (Windows Update Agent API).
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [switch]$Download
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
    return "{0:N2} KB" -f ($Bytes / 1KB)
}

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "WindowsUpdates_$timestamp.txt"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nWindows Update Checker" -ForegroundColor Green
    Write-Host "Initializing Windows Update Agent - this may take a moment..." -ForegroundColor Gray

    Add-Line "============================================================"
    Add-Line "  WINDOWS UPDATE REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "============================================================"

    # ── Last Update History ────────────────────────────────────────────────────
    Write-Section "LAST INSTALLED UPDATES"
    Add-Line "`n[Recently Installed Updates]"
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher      = $updateSession.CreateUpdateSearcher()
        $totalInstalled = $searcher.GetTotalHistoryCount()

        if ($totalInstalled -gt 0) {
            $history = $searcher.QueryHistory(0, [math]::Min(10, $totalInstalled))
            Add-Line ("  {0,-25} {1,-12} {2}" -f "Date", "Result", "Update")
            Add-Line ("  {0,-25} {1,-12} {2}" -f "----", "------", "------")
            for ($i = 0; $i -lt $history.Count; $i++) {
                $item   = $history.Item($i)
                $result = switch ($item.ResultCode) {
                    1 { "In Progress" }; 2 { "Succeeded" }; 3 { "Succeeded w/Err" }
                    4 { "Failed" }; 5 { "Aborted" }; default { "Unknown" }
                }
                $color = if ($result -eq "Succeeded") { "Green" } elseif ($result -eq "Failed") { "Red" } else { "Yellow" }
                $row   = "  {0,-25} {1,-12} {2}" -f $item.Date.ToString("yyyy-MM-dd HH:mm"), $result, ($item.Title -replace ".{100}$", "...")
                Write-Host $row -ForegroundColor $color
                $lines.Add($row)
            }
        } else {
            Add-Line "  No update history found."
        }
    } catch {
        Add-Line "  [ERROR] Could not retrieve update history: $($_.Exception.Message)"
    }

    # ── Pending Updates Search ─────────────────────────────────────────────────
    Write-Section "SEARCHING FOR AVAILABLE UPDATES"
    Add-Line "`n[Scanning for pending updates - please wait...]"
    Write-Host "  This may take 1-5 minutes depending on system state..." -ForegroundColor Gray

    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Search for updates that are not installed and not hidden
        $searchResult   = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        $updates        = $searchResult.Updates

        $totalCount     = $updates.Count
        Add-Line "`n  Found $totalCount pending update(s)."

        if ($totalCount -eq 0) {
            Write-Host "`n  [OK] System is up to date!" -ForegroundColor Green
            Add-Line "  System is up to date."
        } else {
            $criticalCount = 0
            $totalSizeBytes = 0

            Add-Line "`n[Pending Updates]"
            Add-Line ("  {0,-5} {1,-12} {2,-10} {3,-10} {4}" -f "#", "Severity", "Size", "KB", "Title")
            Add-Line ("  {0,-5} {1,-12} {2,-10} {3,-10} {4}" -f "-", "--------", "----", "--", "-----")

            # Collect updates for optional download
            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

            for ($i = 0; $i -lt $updates.Count; $i++) {
                $upd      = $updates.Item($i)
                $severity = if ($upd.MsrcSeverity) { $upd.MsrcSeverity } else { "Unspecified" }
                $sizeBytes = $upd.MaxDownloadSize
                $totalSizeBytes += $sizeBytes
                $sizeStr  = Format-Size $sizeBytes

                # Extract KB number if present
                $kb = ""
                if ($upd.KBArticleIDs.Count -gt 0) {
                    $kb = "KB" + $upd.KBArticleIDs.Item(0)
                }

                $color = switch ($severity) {
                    "Critical"  { $criticalCount++; "Red"    }
                    "Important" { "Yellow" }
                    "Moderate"  { "Cyan"   }
                    default     { "White"  }
                }

                $title = if ($upd.Title.Length -gt 60) { $upd.Title.Substring(0, 57) + "..." } else { $upd.Title }
                $row   = "  {0,-5} {1,-12} {2,-10} {3,-10} {4}" -f ($i+1), $severity, $sizeStr, $kb, $title
                Write-Host $row -ForegroundColor $color
                $lines.Add($row)

                if ($Download) { $updatesToDownload.Add($upd) | Out-Null }
            }

            Add-Line "`n  Summary:"
            Add-Line "    Total updates   : $totalCount"
            Add-Line "    Critical updates: $criticalCount"
            Add-Line "    Total download  : $(Format-Size $totalSizeBytes)"

            if ($criticalCount -gt 0) {
                Write-Host "`n  *** CRITICAL UPDATES AVAILABLE - Apply as soon as possible! ***" -ForegroundColor Red
            }

            # ── Optional Download ──────────────────────────────────────────────
            if ($Download -and $updatesToDownload.Count -gt 0) {
                Write-Host "`n  Initiating download of $($updatesToDownload.Count) updates..." -ForegroundColor Yellow
                Add-Line "`n[Downloading Updates]"
                try {
                    $downloader           = $updateSession.CreateUpdateDownloader()
                    $downloader.Updates   = $updatesToDownload
                    $downloadResult       = $downloader.Download()
                    $dlStatus = switch ($downloadResult.ResultCode) {
                        2 { "Download Succeeded" }; 4 { "Download Failed" }; default { "Unknown ($($downloadResult.ResultCode))" }
                    }
                    Add-Line "  Download result: $dlStatus"
                    Write-Host "  Download complete: $dlStatus" -ForegroundColor $(if ($downloadResult.ResultCode -eq 2) {"Green"} else {"Red"})
                    Write-Host "  Updates are ready to install via Windows Update settings." -ForegroundColor Cyan
                } catch {
                    Add-Line "  [ERROR] Download failed: $($_.Exception.Message)"
                }
            } elseif ($Download -eq $false -and $totalCount -gt 0) {
                Write-Host "`n  Tip: Run with -Download to initiate downloading the updates." -ForegroundColor Gray
            }
        }

    } catch {
        Add-Line "  [ERROR] Update scan failed: $($_.Exception.Message)"
        Write-Host "  Note: Some errors are normal if Windows Update service is busy." -ForegroundColor Yellow
    }

    # ── Windows Update Service Status ─────────────────────────────────────────
    Write-Section "WINDOWS UPDATE SERVICE STATUS"
    Add-Line "`n[Service Status]"
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService) {
        Add-Line "  Windows Update Service: $($wuService.Status)"
        $color = if ($wuService.Status -eq "Running") { "Green" } else { "Yellow" }
        Write-Host "  Windows Update Service: $($wuService.Status)" -ForegroundColor $color
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
