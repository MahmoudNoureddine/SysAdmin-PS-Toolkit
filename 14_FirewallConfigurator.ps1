#Requires -Version 5.1
<#
.SYNOPSIS
    Firewall Configurator - Enables and configures Windows Defender Firewall.

.DESCRIPTION
    Provides a menu-driven interface to:
      - View current firewall status for all profiles
      - Enable/disable firewall for specific profiles
      - Add, remove, and list custom inbound/outbound rules
      - Apply a hardened baseline rule set
      - Export current rules to a CSV backup
      - Block or allow specific applications through the firewall

.PARAMETER OutputPath
    Directory for logs and exports. Defaults to user's Desktop.

.EXAMPLE
    .\14_FirewallConfigurator.ps1
    .\14_FirewallConfigurator.ps1 -OutputPath "C:\Logs"

.NOTES
    Prerequisites : Administrator rights REQUIRED for all firewall changes.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Admin Check ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[ERROR] This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "  Right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "Firewall_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Show Firewall Status ──────────────────────────────────────────────────────
function Show-FirewallStatus {
    Write-Host "`n--- FIREWALL PROFILE STATUS ---" -ForegroundColor Yellow
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $stateColor = if ($p.Enabled) { "Green" } else { "Red" }
            $state = if ($p.Enabled) { "ENABLED" } else { "DISABLED" }
            Write-Host ""
            Write-Host "  Profile          : $($p.Name)" -ForegroundColor Cyan
            Write-Host "  State            : $state"     -ForegroundColor $stateColor
            Write-Host "  Default Inbound  : $($p.DefaultInboundAction)"
            Write-Host "  Default Outbound : $($p.DefaultOutboundAction)"
            Write-Host "  Log Allowed      : $($p.LogAllowed)"
            Write-Host "  Log Blocked      : $($p.LogBlocked)"
            Write-Host "  Log Path         : $($p.LogFileName)"
        }

        # Total rule count
        $totalRules = (Get-NetFirewallRule | Measure-Object).Count
        $enabledRules = (Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
        Write-Host "`n  Total Rules: $totalRules  |  Enabled: $enabledRules"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Enable/Disable Profiles ───────────────────────────────────────────────────
function Set-FirewallProfile {
    Write-Host "`n--- ENABLE / DISABLE FIREWALL PROFILES ---" -ForegroundColor Yellow
    Write-Host "  [1] Enable  ALL profiles"
    Write-Host "  [2] Disable ALL profiles (NOT recommended)"
    Write-Host "  [3] Enable  specific profile"
    Write-Host "  [4] Disable specific profile"
    Write-Host "  [B] Back"

    $c = Read-Host "`n  Select"
    switch ($c.ToUpper()) {
        '1' {
            Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
            Write-Log "Enabled ALL firewall profiles" "OK"
            Write-Host "  [OK] All profiles enabled." -ForegroundColor Green
        }
        '2' {
            $confirm = Read-Host "  WARNING: Disabling firewall exposes the system. Type CONFIRM to proceed"
            if ($confirm -eq "CONFIRM") {
                Set-NetFirewallProfile -All -Enabled False
                Write-Log "DISABLED ALL firewall profiles - SECURITY RISK" "WARN"
                Write-Host "  [WARN] All profiles disabled." -ForegroundColor Red
            } else {
                Write-Host "  Cancelled." -ForegroundColor Gray
            }
        }
        '3' {
            $prof = Read-Host "  Profile name (Domain/Private/Public)"
            Set-NetFirewallProfile -Name $prof -Enabled True -ErrorAction Stop
            Write-Log "Enabled firewall profile: $prof" "OK"
            Write-Host "  [OK] Profile '$prof' enabled." -ForegroundColor Green
        }
        '4' {
            $prof = Read-Host "  Profile name (Domain/Private/Public)"
            $confirm = Read-Host "  Disable '$prof' firewall? (Y/N)"
            if ($confirm -eq 'Y') {
                Set-NetFirewallProfile -Name $prof -Enabled False
                Write-Log "Disabled firewall profile: $prof" "WARN"
            }
        }
        'B' { return }
    }
}

# ─── List Firewall Rules ───────────────────────────────────────────────────────
function Show-FirewallRules {
    Write-Host "`n  Filter: [1] All  [2] Enabled only  [3] Inbound  [4] Outbound  [5] Custom (non-Windows)"
    $f = Read-Host "  Choose filter"

    $rules = Get-NetFirewallRule -ErrorAction Stop
    $rules = switch ($f) {
        '2' { $rules | Where-Object { $_.Enabled -eq $true } }
        '3' { $rules | Where-Object { $_.Direction -eq "Inbound" } }
        '4' { $rules | Where-Object { $_.Direction -eq "Outbound" } }
        '5' { $rules | Where-Object { $_.Group -notlike "@*" -and $_.Group -ne "Windows*" } }
        default { $rules }
    }

    Write-Host "`n  Showing $($rules.Count) rules:`n" -ForegroundColor Cyan
    Write-Host ("  {0,-40} {1,-10} {2,-10} {3,-10} {4}" -f "Rule Name", "Direction", "Action", "Enabled", "Profile")
    Write-Host ("  {0,-40} {1,-10} {2,-10} {3,-10} {4}" -f "---------", "---------", "------", "-------", "-------")

    foreach ($r in $rules | Sort-Object DisplayName | Select-Object -First 50) {
        $color = switch ($r.Action) { "Allow" { "White" } "Block" { "Red" } default { "Gray" } }
        Write-Host ("  {0,-40} {1,-10} {2,-10} {3,-10} {4}" -f `
            ($r.DisplayName.Substring(0,[math]::Min(39,$r.DisplayName.Length))), `
            $r.Direction, $r.Action, $r.Enabled, $r.Profile) -ForegroundColor $color
    }
    if ($rules.Count -gt 50) { Write-Host "  ... and $($rules.Count - 50) more. Export CSV for full list." -ForegroundColor Gray }
}

# ─── Add a Custom Rule ─────────────────────────────────────────────────────────
function Add-CustomRule {
    Write-Host "`n--- ADD FIREWALL RULE ---" -ForegroundColor Yellow

    $name      = Read-Host "  Rule name (e.g., 'Allow HTTP')"
    $direction = Read-Host "  Direction (Inbound/Outbound)"
    $action    = Read-Host "  Action (Allow/Block)"
    $protocol  = Read-Host "  Protocol (TCP/UDP/Any)"
    $port      = Read-Host "  Local Port (e.g., 80 or 80,443 or Any)"
    $profile   = Read-Host "  Profile (Domain/Private/Public/Any)"
    $desc      = Read-Host "  Description (optional)"

    $params = @{
        DisplayName = $name
        Direction   = $direction
        Action      = $action
        Protocol    = $protocol
        Profile     = $profile
        Enabled     = "True"
    }
    if ($port -and $port -ne "Any") { $params["LocalPort"] = $port }
    if ($desc) { $params["Description"] = $desc }

    try {
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        Write-Log "Added firewall rule: '$name' $direction $action $protocol:$port ($profile)" "OK"
        Write-Host "`n  [OK] Rule '$name' added successfully." -ForegroundColor Green
    } catch {
        Write-Log "Failed to add rule '$name': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Remove a Rule ─────────────────────────────────────────────────────────────
function Remove-CustomRule {
    Write-Host "`n--- REMOVE FIREWALL RULE ---" -ForegroundColor Yellow
    $name = Read-Host "  Enter the exact rule display name to remove"

    $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if (-not $rule) {
        Write-Host "  Rule '$name' not found." -ForegroundColor Yellow
        return
    }

    Write-Host "  Found: $($rule.DisplayName)  Direction: $($rule.Direction)  Action: $($rule.Action)" -ForegroundColor Cyan
    $confirm = Read-Host "  Remove this rule? (Y/N)"
    if ($confirm -eq 'Y') {
        try {
            Remove-NetFirewallRule -DisplayName $name -ErrorAction Stop
            Write-Log "Removed firewall rule: $name" "OK"
            Write-Host "  [OK] Rule removed." -ForegroundColor Green
        } catch {
            Write-Log "Failed to remove rule '$name': $($_.Exception.Message)" "ERROR"
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ─── Block / Allow Application ────────────────────────────────────────────────
function Set-AppFirewallRule {
    param([string]$Action)  # "Allow" or "Block"
    Write-Host "`n--- $Action APPLICATION ---" -ForegroundColor Yellow
    $appPath = Read-Host "  Enter full path to the application EXE"

    if (-not (Test-Path $appPath)) {
        Write-Host "  [ERROR] File not found: $appPath" -ForegroundColor Red
        return
    }

    $appName = [System.IO.Path]::GetFileNameWithoutExtension($appPath)
    $ruleName = "$Action $appName (Custom)"

    try {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound  -Action $Action -Program $appPath -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "$ruleName Outbound" -Direction Outbound -Action $Action -Program $appPath -Enabled True | Out-Null
        Write-Log "$Action rule applied to: $appPath" "OK"
        Write-Host "  [OK] $Action rules created for '$appName'." -ForegroundColor Green
    } catch {
        Write-Log "Failed to apply $Action rule: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Apply Hardened Baseline ───────────────────────────────────────────────────
function Invoke-HardenedBaseline {
    Write-Host "`n--- APPLY HARDENED FIREWALL BASELINE ---" -ForegroundColor Yellow
    Write-Host "  This will:" -ForegroundColor White
    Write-Host "    - Enable firewall on ALL profiles"
    Write-Host "    - Set default inbound action to BLOCK"
    Write-Host "    - Set default outbound action to ALLOW"
    Write-Host "    - Enable logging for blocked connections"
    Write-Host ""
    $confirm = Read-Host "  Apply hardened baseline? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; return }

    try {
        # Enable all profiles with block-inbound default
        Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -LogBlocked True -LogAllowed False -NotifyOnListen True

        Write-Log "Applied hardened firewall baseline" "OK"
        Write-Host "`n  [OK] Hardened baseline applied." -ForegroundColor Green
        Write-Host "  Firewall enabled on all profiles with default BLOCK inbound." -ForegroundColor Green
    } catch {
        Write-Log "Failed to apply baseline: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Export Rules to CSV ───────────────────────────────────────────────────────
function Export-FirewallRules {
    $csvFile = Join-Path $OutputPath "FirewallRules_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    try {
        Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled, Profile, Description |
            Export-Csv -Path $csvFile -NoTypeInformation
        Write-Log "Exported firewall rules to: $csvFile" "OK"
        Write-Host "  [OK] Exported to: $csvFile" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   FIREWALL CONFIGURATOR"                                       -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME (Administrator) on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Show firewall status"              -ForegroundColor White
    Write-Host "  [2] Enable / Disable profiles"         -ForegroundColor White
    Write-Host "  [3] List firewall rules"               -ForegroundColor White
    Write-Host "  [4] Add a custom rule"                 -ForegroundColor White
    Write-Host "  [5] Remove a rule"                     -ForegroundColor White
    Write-Host "  [6] Allow an application"              -ForegroundColor White
    Write-Host "  [7] Block an application"              -ForegroundColor White
    Write-Host "  [8] Apply hardened baseline"           -ForegroundColor Yellow
    Write-Host "  [9] Export rules to CSV"               -ForegroundColor White
    Write-Host "  [Q] Quit"                              -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "Firewall Configurator started by $env:USERNAME"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Show-FirewallStatus;                   Read-Host "`nPress Enter" }
            '2' { Set-FirewallProfile;                   Read-Host "`nPress Enter" }
            '3' { Show-FirewallRules;                    Read-Host "`nPress Enter" }
            '4' { Add-CustomRule;                        Read-Host "`nPress Enter" }
            '5' { Remove-CustomRule;                     Read-Host "`nPress Enter" }
            '6' { Set-AppFirewallRule -Action "Allow";   Read-Host "`nPress Enter" }
            '7' { Set-AppFirewallRule -Action "Block";   Read-Host "`nPress Enter" }
            '8' { Invoke-HardenedBaseline;               Read-Host "`nPress Enter" }
            '9' { Export-FirewallRules;                  Read-Host "`nPress Enter" }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "  Invalid selection." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}
Write-Log "Firewall Configurator exited"
