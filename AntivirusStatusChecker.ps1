#Requires -Version 5.1
<#
.SYNOPSIS
    Antivirus & Defender Status Checker - Verifies security software health.

.DESCRIPTION
    Comprehensive security posture check that verifies:
      - Windows Defender status, real-time protection, and definition age
      - Third-party antivirus products registered with Windows Security Center
      - Windows Firewall state
      - Last scan date and results
      - Threat history and active threats
      - Security-related Windows services

    Generates a report and raises alerts for any issues found.

.PARAMETER OutputPath
    Directory to save the report. Defaults to user's Desktop.

.PARAMETER AlertThresholdDays
    Flag if virus definitions are older than this many days. Default: 3.

.EXAMPLE
    .\13_AntivirusStatusChecker.ps1
    .\13_AntivirusStatusChecker.ps1 -AlertThresholdDays 2 -OutputPath "C:\Reports"

.NOTES
    Prerequisites : WMI/CIM access; some checks require Administrator rights.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath          = "$env:USERPROFILE\Desktop",
    [int]$AlertThresholdDays     = 3
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}
function Write-OK   { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-Fail { param([string]$m) Write-Host "  [FAIL] $m" -ForegroundColor Red    }
function Write-Warn { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }

$lines  = [System.Collections.Generic.List[string]]::new()
$alerts = [System.Collections.Generic.List[string]]::new()

function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }
function Add-Alert {
    param([string]$T)
    $alerts.Add($T)
    Write-Host "  *** ALERT: $T ***" -ForegroundColor Red
    $lines.Add("  *** ALERT: $T ***")
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "AVStatus_$timestamp.txt"

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nAntivirus & Security Status Checker" -ForegroundColor Green

    Add-Line "============================================================"
    Add-Line "  ANTIVIRUS & SECURITY STATUS REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME  User: $env:USERNAME"
    Add-Line "============================================================"

    # ── 1. Windows Defender Status ─────────────────────────────────────────────
    Write-Section "WINDOWS DEFENDER STATUS"
    Add-Line "`n[Windows Defender]"
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        # Real-time protection
        if ($mpStatus.RealTimeProtectionEnabled) {
            Write-OK "Real-Time Protection: ENABLED"
            Add-Line "  Real-Time Protection : ENABLED"
        } else {
            Write-Fail "Real-Time Protection: DISABLED"
            Add-Alert "Windows Defender Real-Time Protection is DISABLED"
        }

        # Antispyware enabled
        $avEnabled = $mpStatus.AntivirusEnabled
        if ($avEnabled) {
            Write-OK "Antivirus Engine: ENABLED"
            Add-Line "  Antivirus Engine     : ENABLED"
        } else {
            Write-Fail "Antivirus Engine: DISABLED"
            Add-Alert "Windows Defender Antivirus is DISABLED"
        }

        # Definition age
        $sigDate     = $mpStatus.AntivirusSignatureLastUpdated
        $sigAgeDays  = [math]::Round(((Get-Date) - $sigDate).TotalDays, 1)
        $sigVersion  = $mpStatus.AntivirusSignatureVersion
        Add-Line "  Signature Version    : $sigVersion"
        Add-Line "  Signature Date       : $($sigDate.ToString('yyyy-MM-dd HH:mm'))"
        Add-Line "  Signature Age        : $sigAgeDays days"

        if ($sigAgeDays -gt $AlertThresholdDays) {
            Write-Warn "Virus definitions are $sigAgeDays days old (threshold: $AlertThresholdDays days)"
            Add-Alert "Virus definitions are $sigAgeDays days old - update required"
        } else {
            Write-OK "Virus definitions are current ($sigAgeDays days old)"
        }

        # Last scan
        $lastScan    = $mpStatus.QuickScanEndTime
        $lastFull    = $mpStatus.FullScanEndTime
        Add-Line "  Last Quick Scan      : $($lastScan.ToString('yyyy-MM-dd HH:mm'))"
        Add-Line "  Last Full Scan       : $($lastFull.ToString('yyyy-MM-dd HH:mm'))"

        $quickAgeDays = [math]::Round(((Get-Date) - $lastScan).TotalDays, 1)
        if ($quickAgeDays -gt 7) {
            Write-Warn "Last Quick Scan was $quickAgeDays days ago"
            Add-Alert "No Quick Scan performed in $quickAgeDays days"
        } else {
            Write-OK "Recent scan detected ($quickAgeDays days ago)"
        }

        # Active threats
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            Write-Fail "ACTIVE THREATS DETECTED: $($threats.Count)"
            Add-Alert "$($threats.Count) active threat(s) detected by Windows Defender"
            foreach ($t in $threats) {
                Add-Line "  [THREAT] $($t.ThreatName)  Severity: $($t.SeverityID)  Status: $($t.ThreatStatusID)"
            }
        } else {
            Write-OK "No active threats detected"
            Add-Line "  Active Threats       : None"
        }

        # Tamper protection
        Add-Line "  Tamper Protection    : $($mpStatus.IsTamperProtected)"
        if (-not $mpStatus.IsTamperProtected) {
            Write-Warn "Tamper Protection is disabled"
            Add-Alert "Windows Defender Tamper Protection is disabled"
        }

        # Behavior monitoring
        Add-Line "  Behavior Monitoring  : $($mpStatus.BehaviorMonitorEnabled)"
        Add-Line "  Network Inspection   : $($mpStatus.NISEnabled)"
        Add-Line "  Cloud Protection     : $($mpStatus.MAPSReporting)"

    } catch {
        Add-Line "  [ERROR] Could not retrieve Defender status: $($_.Exception.Message)"
        Write-Warn "Could not query Windows Defender (may not be installed)"
    }

    # ── 2. Third-Party Antivirus (Security Center) ─────────────────────────────
    Write-Section "REGISTERED SECURITY PRODUCTS"
    Add-Line "`n[Windows Security Center - Registered AV Products]"
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop

        if ($avProducts) {
            foreach ($av in $avProducts) {
                # productState is a hex-encoded field
                $state    = $av.productState
                $isEnabled = ($state -band 0x1000) -gt 0
                $isUpdated = ($state -band 0x0010) -eq 0

                $statusColor = if ($isEnabled -and $isUpdated) { "Green" } else { "Red" }
                Write-Host "  Product   : $($av.displayName)" -ForegroundColor $statusColor
                Write-Host "  Enabled   : $isEnabled  |  Definitions Current: $isUpdated"
                Add-Line "  Product   : $($av.displayName)"
                Add-Line "  Enabled   : $isEnabled  |  Definitions Current: $isUpdated"

                if (-not $isEnabled) { Add-Alert "$($av.displayName) is not active/enabled" }
                if (-not $isUpdated) { Add-Alert "$($av.displayName) definitions are OUT OF DATE" }
                Add-Line ""
            }
        } else {
            Add-Line "  No AV products registered in Security Center."
            Write-Warn "No third-party AV products registered with Windows Security Center."
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── 3. Windows Firewall ────────────────────────────────────────────────────
    Write-Section "WINDOWS FIREWALL"
    Add-Line "`n[Firewall Status]"
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $state = if ($p.Enabled) { "ENABLED" } else { "DISABLED" }
            $color = if ($p.Enabled) { "Green" } else { "Red" }
            Write-Host "  $($p.Name) Profile : $state" -ForegroundColor $color
            Add-Line "  $($p.Name) Profile : $state"
            if (-not $p.Enabled) { Add-Alert "Firewall DISABLED for $($p.Name) profile" }
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── 4. Security Services ───────────────────────────────────────────────────
    Write-Section "SECURITY-RELATED SERVICES"
    Add-Line "`n[Service Status]"
    $secServices = @(
        @{ Name = "WinDefend";     Label = "Windows Defender Antivirus"    },
        @{ Name = "SecurityHealthService"; Label = "Windows Security Service" },
        @{ Name = "MpsSvc";        Label = "Windows Firewall"              },
        @{ Name = "wscsvc";        Label = "Security Center"               },
        @{ Name = "WdNisSvc";      Label = "Defender Network Inspection"   }
    )
    foreach ($svc in $secServices) {
        try {
            $s     = Get-Service -Name $svc.Name -ErrorAction Stop
            $color = if ($s.Status -eq "Running") { "Green" } else { "Yellow" }
            Write-Host ("  {0,-40} {1}" -f $svc.Label, $s.Status) -ForegroundColor $color
            Add-Line  ("  {0,-40} {1}" -f $svc.Label, $s.Status)
            if ($s.Status -ne "Running") { Add-Alert "$($svc.Label) service is not running" }
        } catch {
            Write-Host ("  {0,-40} {1}" -f $svc.Label, "NOT FOUND") -ForegroundColor Gray
            Add-Line  ("  {0,-40} NOT FOUND" -f $svc.Label)
        }
    }

    # ── 5. Threat Detection History ────────────────────────────────────────────
    Write-Section "RECENT THREAT DETECTION HISTORY"
    Add-Line "`n[Last 10 Detected Threats]"
    try {
        $history = Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
        if ($history) {
            Add-Line ("  {0,-22} {1,-40} {2}" -f "Detected", "Threat", "Action")
            Add-Line ("  {0,-22} {1,-40} {2}" -f "--------", "------", "------")
            foreach ($h in $history) {
                $row = "  {0,-22} {1,-40} {2}" -f $h.InitialDetectionTime.ToString("yyyy-MM-dd HH:mm"), ($h.ThreatName -replace ".{40}$","..."), $h.ActionSuccess
                Add-Line $row
            }
        } else {
            Write-OK "No threat detections in history."
            Add-Line "  No threat detections recorded."
        }
    } catch {
        Add-Line "  [INFO] Threat history not available."
    }

    # ── 6. Summary & Alerts ────────────────────────────────────────────────────
    Write-Section "SECURITY SUMMARY"
    Add-Line ""
    if ($alerts.Count -eq 0) {
        Write-OK "All security checks passed. System appears healthy."
        Add-Line "  Overall Status: HEALTHY - All checks passed."
    } else {
        Write-Fail "$($alerts.Count) security issue(s) require attention:"
        Add-Line "  Overall Status: ACTION REQUIRED - $($alerts.Count) issue(s) found."
        Add-Line ""
        foreach ($a in $alerts) { Add-Line "  - $a" }
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
