#Requires -Version 5.1
<#
.SYNOPSIS
    System Report Generator - Creates a comprehensive diagnostic report for IT support.

.DESCRIPTION
    Consolidates all key system information into a single, shareable report:
      - System overview (OS, hardware, uptime)
      - Network configuration and connectivity
      - Disk usage and health
      - Running services and processes
      - Recent error events
      - Installed software summary
      - Security posture (Defender, Firewall)
      - Performance snapshot
      - Startup programs
      - Scheduled tasks
      - Hotfix / patch history

    The report is saved as a formatted .txt file and optionally zipped for easy sharing.

.PARAMETER OutputPath
    Directory to save the report. Defaults to user's Desktop.

.PARAMETER ZipReport
    If specified, compresses the report into a .zip file.

.PARAMETER IncludeEventLogs
    Includes recent error event logs in the report (may slow generation).

.EXAMPLE
    .\20_SystemReportGenerator.ps1
    .\20_SystemReportGenerator.ps1 -ZipReport -OutputPath "C:\Reports"
    .\20_SystemReportGenerator.ps1 -IncludeEventLogs

.NOTES
    Prerequisites : Some sections require Administrator rights.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath       = "$env:USERPROFILE\Desktop",
    [switch]$ZipReport,
    [switch]$IncludeEventLogs
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n  >> $Title" -ForegroundColor Yellow
    $script:progress++
    Write-Progress -Activity "Generating System Report" -Status $Title -PercentComplete (($script:progress / $script:totalSections) * 100)
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    return "{0:N2} KB" -f ($Bytes / 1KB)
}

$lines = [System.Collections.Generic.List[string]]::new()
function Out-Section { param([string]$Title); $lines.Add("`n" + ("=" * 65)); $lines.Add("  $Title"); $lines.Add("=" * 65) }
function Out-Line    { param([string]$T = ""); $lines.Add($T) }

$script:progress     = 0
$script:totalSections = 16

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "SystemReport_${env:COMPUTERNAME}_$timestamp.txt"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nSystem Report Generator" -ForegroundColor Green
    Write-Host "Collecting system information - please wait..." -ForegroundColor Gray

    Out-Line "================================================================="
    Out-Line "  COMPREHENSIVE SYSTEM DIAGNOSTIC REPORT"
    Out-Line "  Computer   : $env:COMPUTERNAME"
    Out-Line "  User       : $env:USERNAME  ($env:USERDOMAIN)"
    Out-Line "  Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Out-Line "  PowerShell : $($PSVersionTable.PSVersion)"
    Out-Line "================================================================="

    # ── 1. Operating System ────────────────────────────────────────────────────
    Write-Section "Operating System"
    Out-Section "1. OPERATING SYSTEM"
    try {
        $os   = Get-CimInstance Win32_OperatingSystem
        $cs   = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $uptime = (Get-Date) - $os.LastBootUpTime

        Out-Line "  OS Name         : $($os.Caption)"
        Out-Line "  Version         : $($os.Version)  Build: $($os.BuildNumber)"
        Out-Line "  Architecture    : $($os.OSArchitecture)"
        Out-Line "  Install Date    : $($os.InstallDate.ToString('yyyy-MM-dd'))"
        Out-Line "  Last Boot       : $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Out-Line "  Uptime          : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        Out-Line "  Computer Model  : $($cs.Manufacturer) $($cs.Model)"
        Out-Line "  Domain/Workgroup: $(if($cs.PartOfDomain){"Domain: $($cs.Domain)"}else{"Workgroup: $($cs.Workgroup)"})"
        Out-Line "  BIOS Version    : $($bios.SMBIOSBIOSVersion)  Released: $($bios.ReleaseDate.ToString('yyyy-MM-dd'))"
        Out-Line "  Serial Number   : $($bios.SerialNumber)"
        Out-Line "  TimeZone        : $((Get-TimeZone).DisplayName)"
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 2. CPU ─────────────────────────────────────────────────────────────────
    Write-Section "CPU"
    Out-Section "2. PROCESSOR"
    try {
        $cpus = Get-CimInstance Win32_Processor
        foreach ($cpu in $cpus) {
            Out-Line "  Name            : $($cpu.Name.Trim())"
            Out-Line "  Cores / Threads : $($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)"
            Out-Line "  Speed           : $($cpu.MaxClockSpeed) MHz"
            Out-Line "  Current Load    : $($cpu.LoadPercentage)%"
            Out-Line "  Socket          : $($cpu.SocketDesignation)"
        }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 3. Memory ──────────────────────────────────────────────────────────────
    Write-Section "Memory"
    Out-Section "3. MEMORY"
    try {
        $os   = Get-CimInstance Win32_OperatingSystem
        $totalGB  = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB   = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedGB   = [math]::Round($totalGB - $freeGB, 2)
        $usedPct  = [math]::Round(($usedGB / $totalGB) * 100, 1)

        Out-Line "  Total RAM       : $totalGB GB"
        Out-Line "  Used            : $usedGB GB  ($usedPct%)"
        Out-Line "  Available       : $freeGB GB"

        $sticks = Get-CimInstance Win32_PhysicalMemory
        $i = 1
        foreach ($s in $sticks) {
            Out-Line "  Slot $i          : $([math]::Round($s.Capacity/1GB,1)) GB  $($s.Speed) MHz  $($s.Manufacturer)"
            $i++
        }

        $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
        if ($pf) { Out-Line "  Page File       : $($pf.CurrentUsage) MB used / $($pf.AllocatedBaseSize) MB allocated" }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 4. Disks ───────────────────────────────────────────────────────────────
    Write-Section "Disks"
    Out-Section "4. DISK STORAGE"
    try {
        $disks = Get-CimInstance Win32_DiskDrive
        foreach ($d in $disks) {
            Out-Line "  Disk            : $($d.Model)  $([math]::Round($d.Size/1GB,1)) GB  Interface: $($d.InterfaceType)"
        }
        Out-Line ""
        $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        Out-Line ("  {0,-5} {1,-12} {1,-12} {2,-12} {3}" -f "Drive", "Total", "Used", "Free", "Used%")
        foreach ($drv in $drives) {
            $tot  = [math]::Round($drv.Size/1GB,1)
            $free = [math]::Round($drv.FreeSpace/1GB,1)
            $used = [math]::Round($tot - $free, 1)
            $pct  = if ($drv.Size -gt 0) { [math]::Round(($used/$tot)*100,1) } else { 0 }
            $warn = if ($pct -gt 85) { "  *** LOW ***" } else { "" }
            Out-Line ("  {0,-5} {1,-12} {2,-12} {3,-12} {4}%{5}" -f $drv.DeviceID, "${tot}GB", "${used}GB", "${free}GB", $pct, $warn)
        }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 5. Network ─────────────────────────────────────────────────────────────
    Write-Section "Network"
    Out-Section "5. NETWORK CONFIGURATION"
    try {
        $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($n in $nics) {
            Out-Line "  Adapter         : $($n.Description)"
            Out-Line "  MAC             : $($n.MACAddress)"
            Out-Line "  IP Address      : $($n.IPAddress -join ', ')"
            Out-Line "  Subnet          : $($n.IPSubnet -join ', ')"
            Out-Line "  Gateway         : $($n.DefaultIPGateway -join ', ')"
            Out-Line "  DNS             : $($n.DNSServerSearchOrder -join ', ')"
            Out-Line "  DHCP            : $($n.DHCPEnabled)"
            Out-Line ""
        }
        # Quick connectivity test
        $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction SilentlyContinue
        Out-Line "  Internet Test   : $(if($ping){"REACHABLE  ($(${ping}[0].ResponseTime)ms)"}else{"UNREACHABLE"})"
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 6. Security ────────────────────────────────────────────────────────────
    Write-Section "Security"
    Out-Section "6. SECURITY STATUS"
    try {
        # Defender
        $def = Get-MpComputerStatus -ErrorAction Stop
        Out-Line "  Defender RTP    : $($def.RealTimeProtectionEnabled)"
        Out-Line "  AV Enabled      : $($def.AntivirusEnabled)"
        Out-Line "  Sig Version     : $($def.AntivirusSignatureVersion)"
        $sigAge = [math]::Round(((Get-Date) - $def.AntivirusSignatureLastUpdated).TotalDays, 1)
        Out-Line "  Sig Age (days)  : $sigAge $(if($sigAge -gt 3){"*** OLD ***"}else{"(current)"})"
        Out-Line "  Last Quick Scan : $($def.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm'))"
        Out-Line "  Tamper Protect  : $($def.IsTamperProtected)"
    } catch { Out-Line "  [INFO] Windows Defender status unavailable." }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $fw) {
            Out-Line "  Firewall ($($p.Name)) : $(if($p.Enabled){"ENABLED"}else{"DISABLED ***"})"
        }
    } catch { Out-Line "  [INFO] Firewall status unavailable." }

    # Last 5 security events
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{ LogName="Security"; Level=2; StartTime=(Get-Date).AddDays(-1) } `
                     -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($secEvents) {
            Out-Line "`n  Recent Security Errors (last 24h):"
            foreach ($e in $secEvents) {
                Out-Line "    $($e.TimeCreated.ToString('HH:mm')) ID:$($e.Id) $($e.Message.Substring(0,[math]::Min(80,$e.Message.Length)) -replace "`n"," ")"
            }
        } else { Out-Line "  No security errors in last 24h." }
    } catch {}

    # ── 7. Windows Updates ─────────────────────────────────────────────────────
    Write-Section "Windows Updates"
    Out-Section "7. WINDOWS UPDATE STATUS"
    try {
        # Last 10 installed updates
        $sess    = New-Object -ComObject Microsoft.Update.Session
        $total   = $sess.CreateUpdateSearcher().GetTotalHistoryCount()
        if ($total -gt 0) {
            $history = $sess.CreateUpdateSearcher().QueryHistory(0, [math]::Min(10, $total))
            Out-Line "  Last 10 Installed Updates:"
            for ($i = 0; $i -lt $history.Count; $i++) {
                $h = $history.Item($i)
                $res = switch($h.ResultCode){2{"OK"};4{"FAIL"};default{"?$($h.ResultCode)"}}
                Out-Line ("  [{0}] {1,-12} {2}" -f $res, $h.Date.ToString("yyyy-MM-dd"), $h.Title.Substring(0,[math]::Min(70,$h.Title.Length)))
            }
        }
    } catch { Out-Line "  [INFO] Update history unavailable." }

    try {
        # Pending updates
        $pending = $sess.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
        Out-Line "`n  Pending Updates : $($pending.Updates.Count)"
        if ($pending.Updates.Count -gt 0) { Out-Line "  *** UPDATES AVAILABLE - System not fully patched ***" }
    } catch {}

    # ── 8. Hotfixes ────────────────────────────────────────────────────────────
    Write-Section "Hotfixes"
    Out-Section "8. INSTALLED HOTFIXES (Last 20)"
    try {
        $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
        Out-Line ("  {0,-15} {1,-12} {2}" -f "HotFixID", "Date", "Description")
        foreach ($h in $hf) {
            Out-Line ("  {0,-15} {1,-12} {2}" -f $h.HotFixID, $h.InstalledOn, $h.Description)
        }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 9. Running Processes ───────────────────────────────────────────────────
    Write-Section "Processes"
    Out-Section "9. TOP 20 PROCESSES BY MEMORY"
    try {
        $procs = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 20
        Out-Line ("  {0,-35} {1,-12} {2,-12} {3}" -f "Name", "Memory MB", "CPU (s)", "PID")
        foreach ($p in $procs) {
            Out-Line ("  {0,-35} {1,-12} {2,-12} {3}" -f $p.Name, [math]::Round($p.WorkingSet/1MB,1), [math]::Round($p.CPU,1), $p.Id)
        }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 10. Services ───────────────────────────────────────────────────────────
    Write-Section "Services"
    Out-Section "10. STOPPED AUTO-START SERVICES (Potential Issues)"
    try {
        $stoppedAuto = Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }
        if ($stoppedAuto) {
            foreach ($s in $stoppedAuto) {
                Out-Line "  [STOPPED] $($s.DisplayName) ($($s.Name))"
            }
            Out-Line "`n  Total stopped auto services: $($stoppedAuto.Count)"
        } else {
            Out-Line "  All Automatic services are running."
        }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 11. Startup Programs ───────────────────────────────────────────────────
    Write-Section "Startup Programs"
    Out-Section "11. STARTUP PROGRAMS"
    try {
        $startupPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($path in $startupPaths) {
            $hive = ($path -split "\\")[0]
            if (Test-Path $path) {
                $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
                $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    Out-Line "  [$hive] $($_.Name) = $($_.Value)"
                }
            }
        }

        # Startup folder
        $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        $startupItems  = Get-ChildItem $startupFolder -ErrorAction SilentlyContinue
        foreach ($item in $startupItems) { Out-Line "  [Folder] $($item.Name)" }
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 12. Scheduled Tasks ────────────────────────────────────────────────────
    Write-Section "Scheduled Tasks"
    Out-Section "12. ACTIVE SCHEDULED TASKS (Non-Microsoft)"
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
                 Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notlike "\Microsoft\*" } |
                 Select-Object -First 25
        Out-Line ("  {0,-40} {1,-15} {2}" -f "Task Name", "State", "Path")
        foreach ($t in $tasks) {
            Out-Line ("  {0,-40} {1,-15} {2}" -f $t.TaskName.Substring(0,[math]::Min(39,$t.TaskName.Length)), $t.State, $t.TaskPath)
        }
        Out-Line "`n  Total non-Microsoft ready tasks: $($tasks.Count)"
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 13. Installed Software Summary ────────────────────────────────────────
    Write-Section "Software"
    Out-Section "13. INSTALLED SOFTWARE (Top 30 by Name)"
    try {
        $apps = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        ) | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
            Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object -First 30

        Out-Line ("  {0,-45} {1,-20} {2}" -f "Application", "Version", "Publisher")
        foreach ($a in $apps) {
            Out-Line ("  {0,-45} {1,-20} {2}" -f `
                ($a.DisplayName.Substring(0,[math]::Min(44,$a.DisplayName.Length))), `
                $a.DisplayVersion, $a.Publisher)
        }
        Out-Line "`n  (Showing 30 of total installed applications)"
    } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }

    # ── 14. Event Log Summary (Optional) ──────────────────────────────────────
    if ($IncludeEventLogs) {
        Write-Section "Event Logs"
        Out-Section "14. RECENT ERROR EVENTS (Last 24 Hours)"
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName=@("System","Application"); Level=@(1,2); StartTime=(Get-Date).AddHours(-24) } `
                      -MaxEvents 30 -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
            if ($events) {
                Out-Line ("  {0,-20} {1,-10} {2,-6} {3,-30} {4}" -f "Time", "Level", "ID", "Source", "Message")
                foreach ($e in $events) {
                    $lvl = if ($e.Level -eq 1) { "CRITICAL" } else { "ERROR" }
                    $msg = ($e.Message -replace "`n"," ").Substring(0,[math]::Min(50,$e.Message.Length))
                    Out-Line ("  {0,-20} {1,-10} {2,-6} {3,-30} {4}" -f $e.TimeCreated.ToString("yyyy-MM-dd HH:mm"), $lvl, $e.Id, $e.ProviderName.Substring(0,[math]::Min(29,$e.ProviderName.Length)), $msg)
                }
            } else {
                Out-Line "  No error/critical events in the last 24 hours."
            }
        } catch { Out-Line "  [ERROR] $($_.Exception.Message)" }
    } else {
        Out-Section "14. EVENT LOGS"
        Out-Line "  (Skipped. Run with -IncludeEventLogs to include.)"
    }

    # ── 15. Environment Variables ─────────────────────────────────────────────
    Write-Section "Environment"
    Out-Section "15. KEY ENVIRONMENT VARIABLES"
    @("COMPUTERNAME","USERNAME","USERDOMAIN","SystemRoot","ProgramFiles","TEMP","Path") | ForEach-Object {
        Out-Line ("  {0,-20} = {1}" -f $_, [System.Environment]::GetEnvironmentVariable($_))
    }

    # ── 16. Report Footer ─────────────────────────────────────────────────────
    Write-Section "Finalizing"
    Out-Section "16. REPORT SUMMARY"
    Out-Line "  Report generated at  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Out-Line "  Computer             : $env:COMPUTERNAME"
    Out-Line "  Report file          : $reportFile"
    Out-Line "  To share: attach this .txt file to your IT support ticket."
    Out-Line ""
    Out-Line "================================================================="
    Out-Line "  END OF REPORT"
    Out-Line "================================================================="

    Write-Progress -Activity "Generating System Report" -Completed

    # ── Save Report ────────────────────────────────────────────────────────────
    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved: $reportFile" -ForegroundColor Green

    # ── Optional Zip ──────────────────────────────────────────────────────────
    if ($ZipReport) {
        $zipFile = $reportFile -replace "\.txt$", ".zip"
        try {
            Compress-Archive -Path $reportFile -DestinationPath $zipFile -Force
            Write-Host "[OK] Zipped report : $zipFile" -ForegroundColor Green
            Remove-Item $reportFile -Force  # Keep only the zip
        } catch {
            Write-Host "[WARN] Could not create zip: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "`nShare this report with your IT support team for diagnostics." -ForegroundColor Cyan

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
