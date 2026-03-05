#Requires -Version 5.1
<#
.SYNOPSIS
    Performance Monitor - Captures CPU, memory, and disk usage metrics.

.DESCRIPTION
    Samples system performance counters over a configurable duration and
    interval. Identifies top CPU- and memory-consuming processes, checks
    disk I/O, and saves a summary report with trend data.

.PARAMETER DurationSeconds
    Total time to monitor in seconds. Default: 60.

.PARAMETER IntervalSeconds
    How often to sample metrics. Default: 5.

.PARAMETER TopProcessCount
    Number of top processes to display. Default: 10.

.PARAMETER OutputPath
    Directory to save the report. Defaults to the user's Desktop.

.EXAMPLE
    .\05_PerformanceMonitor.ps1
    .\05_PerformanceMonitor.ps1 -DurationSeconds 120 -IntervalSeconds 10

.NOTES
    Prerequisites : No special privileges needed for basic metrics.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [int]$DurationSeconds  = 60,
    [int]$IntervalSeconds  = 5,
    [int]$TopProcessCount  = 10,
    [string]$OutputPath    = "$env:USERPROFILE\Desktop"
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

function Get-ColorForValue {
    param([double]$Value, [double]$WarnAt = 75, [double]$CritAt = 90)
    if ($Value -ge $CritAt) { return "Red" }
    if ($Value -ge $WarnAt) { return "Yellow" }
    return "Green"
}

function Draw-Bar {
    param([double]$Percent, [int]$Width = 30)
    $filled = [math]::Round($Percent / 100 * $Width)
    $bar    = "[" + ("=" * $filled) + (" " * ($Width - $filled)) + "]"
    return $bar
}

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line {
    param([string]$Text = "")
    $lines.Add($Text)
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "PerformanceReport_$timestamp.txt"

# Storage for trend data
$cpuSamples  = [System.Collections.Generic.List[double]]::new()
$memSamples  = [System.Collections.Generic.List[double]]::new()
$diskSamples = [System.Collections.Generic.List[double]]::new()

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nPerformance Monitor" -ForegroundColor Green
    Write-Host "Monitoring for $DurationSeconds seconds, sampling every $IntervalSeconds seconds..." -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop early.`n" -ForegroundColor Gray

    Add-Line "============================================================"
    Add-Line "  PERFORMANCE MONITOR REPORT"
    Add-Line "  Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer   : $env:COMPUTERNAME"
    Add-Line "  Duration   : $DurationSeconds sec  (sample every $IntervalSeconds sec)"
    Add-Line "============================================================"

    $endTime     = (Get-Date).AddSeconds($DurationSeconds)
    $sampleCount = 0

    # ── Sampling Loop ──────────────────────────────────────────────────────────
    Write-Section "LIVE SAMPLING"
    Write-Host ("  {0,-20} {1,-10} {2,-10} {3,-10}" -f "Time", "CPU %", "Mem %", "Disk %")
    Write-Host ("  {0,-20} {1,-10} {2,-10} {3,-10}" -f "----", "-----", "-----", "------")

    while ((Get-Date) -lt $endTime) {
        $sampleCount++

        # CPU usage (average across all cores)
        $cpu = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        if ($null -eq $cpu) { $cpu = 0 }

        # Memory usage
        $os      = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMB = $os.TotalVisibleMemorySize / 1KB
        $freeMB  = $os.FreePhysicalMemory / 1KB
        $usedPct = [math]::Round((($totalMB - $freeMB) / $totalMB) * 100, 1)

        # Disk I/O (percentage using performance counter)
        try {
            $diskPct = [math]::Round((Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue, 1)
            if ($diskPct -gt 100) { $diskPct = 100 }
        } catch {
            $diskPct = 0
        }

        $cpuSamples.Add($cpu)
        $memSamples.Add($usedPct)
        $diskSamples.Add($diskPct)

        $timeStr = (Get-Date).ToString("HH:mm:ss")
        $row     = "  {0,-20} {1,-10} {2,-10} {3,-10}" -f $timeStr, "$cpu%", "$usedPct%", "$diskPct%"
        Write-Host $row -ForegroundColor $(Get-ColorForValue $cpu)
        Add-Line $row

        Start-Sleep -Seconds $IntervalSeconds
    }

    # ── Statistics Summary ─────────────────────────────────────────────────────
    Write-Section "STATISTICS SUMMARY"

    function Get-Stats {
        param([System.Collections.Generic.List[double]]$Values, [string]$Label)
        if ($Values.Count -eq 0) { return }
        $avg = [math]::Round(($Values | Measure-Object -Average).Average, 1)
        $max = [math]::Round(($Values | Measure-Object -Maximum).Maximum, 1)
        $min = [math]::Round(($Values | Measure-Object -Minimum).Minimum, 1)
        $bar = Draw-Bar -Percent $avg

        $color = Get-ColorForValue $avg
        Write-Host "  $Label" -ForegroundColor White
        Write-Host "    $bar $avg% avg  (min: $min%  max: $max%)" -ForegroundColor $color
        Add-Line "  $Label : avg=$avg%  min=$min%  max=$max%"
    }

    Get-Stats -Values $cpuSamples  -Label "CPU Usage "
    Get-Stats -Values $memSamples  -Label "Memory Use"
    Get-Stats -Values $diskSamples -Label "Disk I/O  "

    # ── Current Memory Detail ──────────────────────────────────────────────────
    Write-Section "MEMORY DETAIL"
    Add-Line "`n[Memory]"
    try {
        $os      = Get-CimInstance Win32_OperatingSystem
        $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedGB  = [math]::Round($totalGB - $freeGB, 2)

        Write-Host "  Total : $totalGB GB  Used: $usedGB GB  Free: $freeGB GB"
        Add-Line "  Total : $totalGB GB  Used: $usedGB GB  Free: $freeGB GB"

        # Page file
        $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
        if ($pf) {
            Write-Host "  Page File: $($pf.AllocatedBaseSize) MB allocated, $($pf.CurrentUsage) MB in use"
            Add-Line "  Page File: $($pf.AllocatedBaseSize) MB allocated, $($pf.CurrentUsage) MB in use"
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── Top CPU Processes ──────────────────────────────────────────────────────
    Write-Section "TOP $TopProcessCount PROCESSES - CPU"
    Add-Line "`n[Top CPU Consumers]"
    try {
        $topCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First $TopProcessCount
        Add-Line ("  {0,-35} {1,-12} {2,-12} {3}" -f "Process", "CPU (s)", "Memory (MB)", "PID")
        Add-Line ("  {0,-35} {1,-12} {2,-12} {3}" -f "-------", "-------", "-----------", "---")
        foreach ($p in $topCpu) {
            $memMB = [math]::Round($p.WorkingSet / 1MB, 1)
            $cpuS  = [math]::Round($p.CPU, 1)
            $line  = "  {0,-35} {1,-12} {2,-12} {3}" -f $p.Name, $cpuS, $memMB, $p.Id
            Write-Host $line; Add-Line $line
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── Top Memory Processes ───────────────────────────────────────────────────
    Write-Section "TOP $TopProcessCount PROCESSES - MEMORY"
    Add-Line "`n[Top Memory Consumers]"
    try {
        $topMem = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First $TopProcessCount
        Add-Line ("  {0,-35} {1,-15} {2}" -f "Process", "Working Set MB", "PID")
        Add-Line ("  {0,-35} {1,-15} {2}" -f "-------", "--------------", "---")
        foreach ($p in $topMem) {
            $memMB = [math]::Round($p.WorkingSet / 1MB, 1)
            $line  = "  {0,-35} {1,-15} {2}" -f $p.Name, $memMB, $p.Id
            Write-Host $line; Add-Line $line
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
