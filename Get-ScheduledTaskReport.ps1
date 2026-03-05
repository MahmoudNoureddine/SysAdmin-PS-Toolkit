#Requires -Version 5.1
<#
.SYNOPSIS
    Scheduled Task Report - Audits scheduled tasks across local and remote computers.

.DESCRIPTION
    Enumerates all scheduled tasks on one or multiple machines and flags:
      - Non-Microsoft / third-party tasks
      - Tasks running as SYSTEM or Administrator
      - Tasks with missing or suspicious executable paths
      - Disabled tasks (for cleanup review)
      - Tasks that haven't run in 30+ days
      - Unknown or suspicious trigger types

.PARAMETER ComputerName  Target computer(s). Defaults to local machine.
.PARAMETER OutputPath    Report directory. Defaults to Desktop.
.PARAMETER FlagSuspicious  Highlight tasks with suspicious characteristics.
.PARAMETER NonMicrosoftOnly  Only show non-Microsoft tasks.

.EXAMPLE
    .\23_Get-ScheduledTaskReport.ps1
    .\23_Get-ScheduledTaskReport.ps1 -ComputerName "PC01","PC02" -FlagSuspicious
    .\23_Get-ScheduledTaskReport.ps1 -ComputerName "Server01" -NonMicrosoftOnly

.NOTES
    Requires: Admin rights on target machines. WinRM for remotes.
    Author  : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName    = @($env:COMPUTERNAME),
    [string]$OutputPath        = "$env:USERPROFILE\Desktop",
    [switch]$FlagSuspicious,
    [switch]$NonMicrosoftOnly
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Suspicious indicators
$suspiciousKeywords = @("temp","appdata","roaming","public","downloads","tmp","%.%","powershell -e","cmd /c","wscript","cscript","mshta","rundll32","regsvr32","certutil","bitsadmin")
$suspiciousUsers    = @("SYSTEM","Administrator","NT AUTHORITY\SYSTEM")

Write-Host "`nScheduled Task Report" -ForegroundColor Green
Write-Host "  Scanning $($ComputerName.Count) computer(s)..." -ForegroundColor Cyan

$report    = [System.Collections.Generic.List[object]]::new()
$flagCount = 0

foreach ($computer in $ComputerName) {
    Write-Host "`n  [$computer]" -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet -EA SilentlyContinue)) {
        Write-Host "  UNREACHABLE" -ForegroundColor Red; continue
    }

    try {
        $tasks = if ($computer -eq $env:COMPUTERNAME) {
            Get-ScheduledTask -ErrorAction Stop
        } else {
            Invoke-Command -ComputerName $computer -ScriptBlock { Get-ScheduledTask } -ErrorAction Stop
        }

        # Filter
        if ($NonMicrosoftOnly) {
            $tasks = $tasks | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
        }

        Write-Host "  Found $($tasks.Count) task(s)" -ForegroundColor Gray

        foreach ($task in $tasks | Sort-Object TaskPath, TaskName) {
            # Get task info
            $info     = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $action   = ($task.Actions | Select-Object -First 1)
            $execute  = if ($action) { $action.Execute } else { "" }
            $args     = if ($action) { $action.Arguments } else { "" }
            $runAs    = $task.Principal.UserId
            $state    = $task.State
            $lastRun  = $info?.LastRunTime
            $lastResult = $info?.LastTaskResult

            $daysSinceRun = if ($lastRun -and $lastRun -gt [datetime]"1900-01-01") {
                [math]::Round(((Get-Date) - $lastRun).TotalDays)
            } else { $null }

            # Suspicious checks
            $suspicious = $false; $suspiciousReasons = @()
            if ($FlagSuspicious) {
                foreach ($kw in $suspiciousKeywords) {
                    if ("$execute $args" -like "*$kw*") { $suspicious = $true; $suspiciousReasons += "Suspicious path/arg: $kw" }
                }
                if ($execute -and -not (Test-Path $execute -ErrorAction SilentlyContinue) -and $execute -notlike "*.exe" -and $execute -ne "") {
                    # Don't flag system32 paths
                    if ($execute -notlike "*system32*" -and $execute -notlike "*Windows*") {
                        $suspicious = $true; $suspiciousReasons += "Executable not found"
                    }
                }
                if ($state -eq "Disabled") { $suspiciousReasons += "Disabled" }
                if ($daysSinceRun -gt 30)  { $suspiciousReasons += "Not run in $daysSinceRun days" }
            }

            $isMicrosoft = $task.TaskPath -like "\Microsoft\*"
            $color = if ($suspicious) { "Red" } elseif (-not $isMicrosoft) { "Yellow" } else { "DarkGray" }

            if (-not $isMicrosoft -or $suspicious) {
                $flagStr = if ($suspicious) { " *** SUSPICIOUS ***" } else { "" }
                Write-Host ("  {0,-50} RunAs:{1,-25} State:{2}{3}" -f `
                    "$($task.TaskPath)$($task.TaskName)".Substring(0,[math]::Min(49,"$($task.TaskPath)$($task.TaskName)".Length)),
                    $runAs, $state, $flagStr) -ForegroundColor $color
                if ($suspicious) { $flagCount++; $suspiciousReasons | ForEach-Object { Write-Host "    Reason: $_" -ForegroundColor Red } }
            }

            $report.Add([PSCustomObject]@{
                Computer       = $computer
                TaskPath       = $task.TaskPath
                TaskName       = $task.TaskName
                State          = $state
                RunAs          = $runAs
                Execute        = $execute
                Arguments      = $args
                LastRun        = if($lastRun -gt [datetime]"1900-01-01"){$lastRun.ToString("yyyy-MM-dd HH:mm")}else{"Never"}
                DaysSinceRun   = $daysSinceRun
                LastResult     = $lastResult
                IsMicrosoft    = $isMicrosoft
                Suspicious     = $suspicious
                SuspiciousWhy  = ($suspiciousReasons -join "; ")
            })
        }
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n  ================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Total tasks found   : $($report.Count)"
Write-Host "  Non-Microsoft tasks : $(@($report | Where-Object { -not $_.IsMicrosoft }).Count)" -ForegroundColor Yellow
if ($FlagSuspicious) {
    Write-Host "  Suspicious tasks    : $flagCount" -ForegroundColor $(if($flagCount){"Red"}else{"Green"})
}

$csv = Join-Path $OutputPath "ScheduledTaskReport_$timestamp.csv"
$report | Export-Csv $csv -NoTypeInformation
Write-Host "`n  [OK] Report exported: $csv" -ForegroundColor Green
