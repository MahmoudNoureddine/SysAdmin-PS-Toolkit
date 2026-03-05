#Requires -Version 5.1
<#
.SYNOPSIS
    Disk Space Monitor - Continuously monitors disk space with threshold alerting.

.DESCRIPTION
    Monitors free disk space on local or remote machines at a configurable interval.
    Alerts when drives drop below defined thresholds:
      - WARNING threshold (default: 20% free)
      - CRITICAL threshold (default: 10% free)
    Features:
      - Live dashboard with color-coded status
      - Configurable polling interval
      - Logs all threshold breach events
      - Optional email alert (requires SMTP config)
      - Snapshot mode (run once and exit)

.PARAMETER ComputerName  Target computer(s). Defaults to local machine.
.PARAMETER WarnPercent   Warning threshold % free. Default: 20.
.PARAMETER CritPercent   Critical threshold % free. Default: 10.
.PARAMETER IntervalSec   Polling interval in seconds. Default: 60.
.PARAMETER Snapshot      Run once and exit (no loop).
.PARAMETER OutputPath    Log directory. Defaults to Desktop.

.EXAMPLE
    .\24_Watch-DiskSpace.ps1
    .\24_Watch-DiskSpace.ps1 -ComputerName "Server01","Server02" -WarnPercent 25 -CritPercent 15
    .\24_Watch-DiskSpace.ps1 -ComputerName "FileServer" -IntervalSec 300
    .\24_Watch-DiskSpace.ps1 -Snapshot -OutputPath "C:\Reports"

.NOTES
    Press Ctrl+C to stop monitoring.
    Author  : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$WarnPercent       = 20,
    [int]$CritPercent       = 10,
    [int]$IntervalSec       = 60,
    [switch]$Snapshot,
    [string]$OutputPath     = "$env:USERPROFILE\Desktop"
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "DiskSpaceAlerts_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
}

function Get-DiskStatus {
    param([string[]]$Computers)
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($computer in $Computers) {
        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet -EA SilentlyContinue)) {
            $results.Add([PSCustomObject]@{ Computer=$computer; Drive="N/A"; Label="N/A"; TotalGB=0; FreeGB=0; UsedGB=0; FreePercent=0; Status="UNREACHABLE" })
            continue
        }
        try {
            $disks = Get-WmiObject Win32_LogicalDisk -ComputerName $computer -Filter "DriveType=3" -EA Stop
            foreach ($disk in $disks) {
                $totalGB   = [math]::Round($disk.Size / 1GB, 1)
                $freeGB    = [math]::Round($disk.FreeSpace / 1GB, 1)
                $usedGB    = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 1)
                $freePct   = if ($disk.Size -gt 0) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) } else { 0 }
                $status    = if ($freePct -le $CritPercent) { "CRITICAL" } elseif ($freePct -le $WarnPercent) { "WARNING" } else { "OK" }
                $results.Add([PSCustomObject]@{ Computer=$computer; Drive=$disk.DeviceID; Label=$disk.VolumeName; TotalGB=$totalGB; FreeGB=$freeGB; UsedGB=$usedGB; FreePercent=$freePct; Status=$status })
            }
        } catch {
            $results.Add([PSCustomObject]@{ Computer=$computer; Drive="ERROR"; Label=$_.Exception.Message; TotalGB=0; FreeGB=0; UsedGB=0; FreePercent=0; Status="ERROR" })
        }
    }
    return $results
}

function Draw-Dashboard {
    param($DiskData, [int]$Iteration)
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   DISK SPACE MONITOR  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  Poll #$Iteration" -ForegroundColor Yellow
    Write-Host "   WARN: <$WarnPercent% free  |  CRITICAL: <$CritPercent% free  |  Interval: ${IntervalSec}s" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("   {0,-20} {1,-6} {2,-12} {3,-8} {4,-8} {5,-8} {6,-10} {7}" -f "Computer","Drive","Label","Total","Used","Free","Free%","Status")
    Write-Host ("   {0,-20} {1,-6} {2,-12} {3,-8} {4,-8} {5,-8} {6,-10} {7}" -f "--------","-----","-----","-----","----","----","------","------")

    foreach ($d in $DiskData) {
        $color = switch ($d.Status) {
            "CRITICAL"    { "Red" }
            "WARNING"     { "Yellow" }
            "UNREACHABLE" { "DarkGray" }
            "ERROR"       { "Red" }
            default       { "Green" }
        }

        # Bar graph (20 chars)
        $bar = ""
        if ($d.Status -notin @("UNREACHABLE","ERROR","N/A")) {
            $filled = [math]::Round((1 - ($d.FreePercent/100)) * 20)
            $bar = "[" + ("█" * $filled) + ("░" * (20 - $filled)) + "]"
        }

        Write-Host ("   {0,-20} {1,-6} {2,-12} {3,-7}G {4,-7}G {5,-7}G {6,-9}% {7} {8}" -f `
            $d.Computer, $d.Drive, $d.Label, $d.TotalGB, $d.UsedGB, $d.FreeGB, $d.FreePercent, $d.Status, $bar) -ForegroundColor $color

        # Log alerts
        if ($d.Status -in @("WARNING","CRITICAL")) {
            Write-Log "$($d.Status): $($d.Computer) $($d.Drive) - $($d.FreePercent)% free ($($d.FreeGB)GB of $($d.TotalGB)GB)" $d.Status
        }
    }

    # Alert summary
    $crits = @($DiskData | Where-Object { $_.Status -eq "CRITICAL" })
    $warns = @($DiskData | Where-Object { $_.Status -eq "WARNING" })
    Write-Host ""
    if ($crits.Count -gt 0) { Write-Host "   *** $($crits.Count) CRITICAL drive(s) require immediate attention! ***" -ForegroundColor Red }
    if ($warns.Count -gt 0) { Write-Host "   *** $($warns.Count) WARNING drive(s) approaching threshold ***" -ForegroundColor Yellow }
    if ($crits.Count -eq 0 -and $warns.Count -eq 0) { Write-Host "   All drives OK" -ForegroundColor Green }

    if (-not $Snapshot) { Write-Host "`n   Press Ctrl+C to stop | Next refresh in ${IntervalSec}s" -ForegroundColor Gray }
}

# Main loop
$iteration = 1
if ($Snapshot) {
    $data = Get-DiskStatus -Computers $ComputerName
    Draw-Dashboard -DiskData $data -Iteration $iteration
    $csv = Join-Path $OutputPath "DiskSnapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $data | Export-Csv $csv -NoTypeInformation
    Write-Host "`n   [OK] Snapshot exported: $csv" -ForegroundColor Green
} else {
    Write-Host "Starting disk space monitor... (Ctrl+C to stop)" -ForegroundColor Green
    while ($true) {
        $data = Get-DiskStatus -Computers $ComputerName
        Draw-Dashboard -DiskData $data -Iteration $iteration
        $iteration++
        Start-Sleep -Seconds $IntervalSec
    }
}
