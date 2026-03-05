#Requires -Version 5.1
<#
.SYNOPSIS
    Event Log Analyzer - Pulls and summarizes Windows Event Logs.

.DESCRIPTION
    Retrieves recent Error and Critical events from System, Application, and
    Security event logs. Groups events by source, highlights recurring issues,
    and exports a structured report for IT troubleshooting.

.PARAMETER LogNames
    Which event logs to query. Default: System, Application, Security.

.PARAMETER HoursBack
    How many hours of history to analyze. Default: 24.

.PARAMETER MaxEvents
    Maximum events to retrieve per log. Default: 500.

.PARAMETER OutputPath
    Directory to save the report. Defaults to the user's Desktop.

.EXAMPLE
    .\04_EventLogAnalyzer.ps1
    .\04_EventLogAnalyzer.ps1 -HoursBack 48 -MaxEvents 1000

.NOTES
    Prerequisites : Administrator rights required for Security log access.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string[]]$LogNames   = @("System", "Application", "Security"),
    [int]$HoursBack       = 24,
    [int]$MaxEvents       = 500,
    [string]$OutputPath   = "$env:USERPROFILE\Desktop"
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
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
$reportFile = Join-Path $OutputPath "EventLogAnalysis_$timestamp.txt"
$startTime  = (Get-Date).AddHours(-$HoursBack)

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nEvent Log Analyzer" -ForegroundColor Green
    Write-Host "Analyzing logs from the last $HoursBack hours (since $($startTime.ToString('yyyy-MM-dd HH:mm')))..." -ForegroundColor Gray

    Add-Line "============================================================"
    Add-Line "  EVENT LOG ANALYSIS REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "  Timeframe : Last $HoursBack hours (since $($startTime.ToString('yyyy-MM-dd HH:mm')))"
    Add-Line "============================================================"

    $allErrors = [System.Collections.Generic.List[object]]::new()

    foreach ($logName in $LogNames) {
        Write-Section "LOG: $logName"
        Add-Line "`n[Event Log: $logName]"

        try {
            # Level 1 = Critical, Level 2 = Error, Level 3 = Warning
            $filterXml = @"
<QueryList>
  <Query Id="0" Path="$logName">
    <Select Path="$logName">
      *[System[
        (Level=1 or Level=2)
        and TimeCreated[@SystemTime &gt;= '$($startTime.ToUniversalTime().ToString("o"))']
      ]]
    </Select>
  </Query>
</QueryList>
"@
            $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $MaxEvents -ErrorAction Stop |
                      Sort-Object TimeCreated -Descending

            Add-Line "  Events found : $($events.Count)  (Errors and Criticals in last $HoursBack hrs)"
            Add-Line ""

            # Group by source to find recurring problems
            $grouped = $events | Group-Object ProviderName | Sort-Object Count -Descending
            Add-Line "  [Top Event Sources by Frequency]"
            Add-Line ("  {0,-40} {1}" -f "Source", "Count")
            Add-Line ("  {0,-40} {1}" -f "------", "-----")
            foreach ($g in $grouped | Select-Object -First 15) {
                $levelInd = if (($g.Group | Where-Object { $_.Level -eq 1 }).Count -gt 0) { " [CRITICAL]" } else { "" }
                Add-Line ("  {0,-40} {1}{2}" -f $g.Name, $g.Count, $levelInd)
            }

            # Show recent individual events
            Add-Line "`n  [Most Recent 20 Events]"
            Add-Line ("  {0,-20} {1,-10} {2,-6} {3,-30} {4}" -f "Time", "Level", "ID", "Source", "Message")
            Add-Line ("  {0,-20} {1,-10} {2,-6} {3,-30} {4}" -f "----", "-----", "--", "------", "-------")

            foreach ($ev in $events | Select-Object -First 20) {
                $lvlText = switch ($ev.Level) {
                    1 { "CRITICAL" }
                    2 { "ERROR"    }
                    3 { "WARNING"  }
                    default { "INFO" }
                }
                $msg = ($ev.Message -replace "`n"," " -replace "`r"," ").Substring(0, [math]::Min(60, $ev.Message.Length))
                $line = "  {0,-20} {1,-10} {2,-6} {3,-30} {4}" -f `
                    $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), `
                    $lvlText, $ev.Id, $ev.ProviderName.Substring(0,[math]::Min(29,$ev.ProviderName.Length)), $msg
                Add-Line $line

                # Accumulate for cross-log summary
                $allErrors.Add([PSCustomObject]@{
                    Log     = $logName
                    Time    = $ev.TimeCreated
                    Level   = $lvlText
                    ID      = $ev.Id
                    Source  = $ev.ProviderName
                    Message = $ev.Message -replace "`n"," "
                })
            }

        } catch [System.Exception] {
            if ($_.Exception.Message -like "*No events*" -or $_.Exception.Message -like "*not found*") {
                Add-Line "  No matching events found in this log."
            } else {
                Add-Line "  [ERROR] Could not read $logName log: $($_.Exception.Message)"
                Write-Host "  Note: Security log may require Administrator rights." -ForegroundColor Yellow
            }
        }
    }

    # ── Cross-Log Summary ──────────────────────────────────────────────────────
    Write-Section "OVERALL SUMMARY"
    Add-Line "`n[Summary]"
    Add-Line "  Total errors/criticals across all logs: $($allErrors.Count)"

    $critCount = ($allErrors | Where-Object { $_.Level -eq "CRITICAL" }).Count
    $errCount  = ($allErrors | Where-Object { $_.Level -eq "ERROR"    }).Count
    Add-Line "  Critical events : $critCount"
    Add-Line "  Error events    : $errCount"

    if ($critCount -gt 0) {
        Write-Host "`n  WARNING: Critical events detected! Review the report carefully." -ForegroundColor Red
    } elseif ($errCount -gt 10) {
        Write-Host "`n  NOTICE: High error count. Consider further investigation." -ForegroundColor Yellow
    } else {
        Write-Host "`n  System appears relatively stable within the analysis window." -ForegroundColor Green
    }

    # Export raw CSV for deeper analysis
    if ($allErrors.Count -gt 0) {
        $csvFile = Join-Path $OutputPath "EventLog_Raw_$timestamp.csv"
        $allErrors | Export-Csv -Path $csvFile -NoTypeInformation
        Write-Host "  Raw data exported to: $csvFile" -ForegroundColor Gray
        Add-Line "  Raw CSV exported to: $csvFile"
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
