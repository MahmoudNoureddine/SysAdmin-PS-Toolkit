#Requires -Version 5.1
<#
.SYNOPSIS
    Password Policy Enforcer - Audits and configures password policy settings.

.DESCRIPTION
    Audits the local Windows password policy and compares it against a
    configurable baseline. Can also apply the baseline policy if desired.
    Features:
      - View current local password policy
      - Compare against organizational baseline
      - Apply compliant password policy settings
      - Audit all local accounts for compliance (password age, expiry)
      - Generate a compliance report

.PARAMETER OutputPath
    Directory for the compliance report. Defaults to user's Desktop.

.PARAMETER ApplyBaseline
    If specified, applies the defined baseline policy after auditing.

.EXAMPLE
    .\16_PasswordPolicyEnforcer.ps1
    .\16_PasswordPolicyEnforcer.ps1 -ApplyBaseline

.NOTES
    Prerequisites : Administrator rights required.
    In domain environments, domain GPO will override local policy.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath   = "$env:USERPROFILE\Desktop",
    [switch]$ApplyBaseline
)

# ─── ORGANIZATIONAL BASELINE ──────────────────────────────────────────────────
# Adjust these values to match your organization's security policy.
$Baseline = @{
    MinPasswordLength    = 12          # Minimum password characters
    MaxPasswordAge       = 90          # Days before password expires
    MinPasswordAge       = 1           # Days before password can be changed
    PasswordHistoryCount = 10          # Previous passwords remembered
    LockoutThreshold     = 5           # Failed attempts before lockout
    LockoutDuration      = 30          # Minutes account stays locked
    LockoutObservation   = 30          # Minutes to reset lockout counter
    ComplexityEnabled    = $true       # Require uppercase, lowercase, digits, symbols
}

# ─── Admin Check ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[ERROR] Administrator rights required." -ForegroundColor Red
    exit 1
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "PasswordPolicy_$timestamp.txt"

$lines      = [System.Collections.Generic.List[string]]::new()
$violations = [System.Collections.Generic.List[string]]::new()

function Add-Line { param([string]$T = ""); $lines.Add($T); Write-Host $T }
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

function Check-Setting {
    param([string]$Label, $Current, $Required, [string]$Operator = "ge")
    $pass = switch ($Operator) {
        "ge"  { $Current -ge $Required }
        "le"  { $Current -le $Required }
        "eq"  { $Current -eq $Required }
        "gt"  { $Current -gt $Required }
        default { $Current -ge $Required }
    }
    $status = if ($pass) { "[PASS]" } else { "[FAIL]" }
    $color  = if ($pass) { "Green"  } else { "Red"   }
    $row    = "  $status  {0,-35} Current: {1,-10}  Required: {2}" -f $Label, $Current, $Required
    Write-Host $row -ForegroundColor $color
    Add-Line $row
    if (-not $pass) {
        $violations.Add("$Label : current=$Current, required=$Required")
    }
    return $pass
}

# ─── Read Current Policy via net accounts ─────────────────────────────────────
function Get-LocalPasswordPolicy {
    $raw = & net accounts 2>&1 | Out-String
    $policy = @{}

    if ($raw -match "Maximum password age \(days\):\s+(\d+|Unlimited)") {
        $policy.MaxPasswordAge = if ($Matches[1] -eq "Unlimited") { 0 } else { [int]$Matches[1] }
    }
    if ($raw -match "Minimum password age \(days\):\s+(\d+)") {
        $policy.MinPasswordAge = [int]$Matches[1]
    }
    if ($raw -match "Minimum password length:\s+(\d+)") {
        $policy.MinPasswordLength = [int]$Matches[1]
    }
    if ($raw -match "Password history length:\s+(\d+|None)") {
        $policy.PasswordHistoryCount = if ($Matches[1] -eq "None") { 0 } else { [int]$Matches[1] }
    }
    if ($raw -match "Lockout threshold:\s+(\d+|Never)") {
        $policy.LockoutThreshold = if ($Matches[1] -eq "Never") { 0 } else { [int]$Matches[1] }
    }
    if ($raw -match "Lockout duration \(minutes\):\s+(\d+)") {
        $policy.LockoutDuration = [int]$Matches[1]
    }
    if ($raw -match "Lockout observation window \(minutes\):\s+(\d+)") {
        $policy.LockoutObservation = [int]$Matches[1]
    }

    # Complexity via secedit
    $secFile = [System.IO.Path]::GetTempFileName()
    & secedit /export /cfg $secFile /quiet 2>&1 | Out-Null
    if (Test-Path $secFile) {
        $secContent = Get-Content $secFile -Raw
        $policy.ComplexityEnabled = $secContent -match "PasswordComplexity\s*=\s*1"
        Remove-Item $secFile -Force -ErrorAction SilentlyContinue
    }
    return $policy
}

# ─── Apply Baseline Policy ─────────────────────────────────────────────────────
function Apply-BaselinePolicy {
    Write-Section "APPLYING BASELINE POLICY"
    $confirm = Read-Host "`n  Apply password policy baseline? This changes local security settings. (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; return }

    try {
        # Apply via net accounts
        & net accounts /maxpwage:$($Baseline.MaxPasswordAge)   2>&1 | Out-Null
        & net accounts /minpwage:$($Baseline.MinPasswordAge)   2>&1 | Out-Null
        & net accounts /minpwlen:$($Baseline.MinPasswordLength) 2>&1 | Out-Null
        & net accounts /uniquepw:$($Baseline.PasswordHistoryCount) 2>&1 | Out-Null
        & net accounts /lockoutthreshold:$($Baseline.LockoutThreshold) 2>&1 | Out-Null
        & net accounts /lockoutduration:$($Baseline.LockoutDuration) 2>&1 | Out-Null
        & net accounts /lockoutwindow:$($Baseline.LockoutObservation) 2>&1 | Out-Null

        # Apply complexity via secedit
        $secFile = [System.IO.Path]::GetTempFileName() -replace "\.tmp$", ".inf"
        $secContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordComplexity = $(if($Baseline.ComplexityEnabled){1}else{0})
"@
        $secContent | Out-File -FilePath $secFile -Encoding Unicode
        & secedit /configure /db secedit.sdb /cfg $secFile /quiet 2>&1 | Out-Null
        Remove-Item $secFile -Force -ErrorAction SilentlyContinue

        Write-Host "`n  [OK] Baseline policy applied." -ForegroundColor Green
        Add-Line "  [OK] Baseline password policy applied at $(Get-Date -Format 'HH:mm:ss')"
    } catch {
        Write-Host "  [ERROR] Failed to apply policy: $($_.Exception.Message)" -ForegroundColor Red
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }
}

# ─── Audit Local Accounts ─────────────────────────────────────────────────────
function Get-AccountCompliance {
    Write-Section "LOCAL ACCOUNT AUDIT"
    Add-Line "`n[Account Password Compliance]"
    Add-Line ("  {0,-25} {1,-10} {2,-10} {3,-20} {4,-20} {5}" -f "Username","Enabled","PwdExpire","Last Changed","Expires","Status")
    Add-Line ("  {0,-25} {1,-10} {2,-10} {3,-20} {4,-20} {5}" -f "--------","-------","----------","-----------","-------","------")

    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled }
        foreach ($u in $users) {
            $lastSet  = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" }
            $expires  = if ($u.PasswordExpires) { $u.PasswordExpires.ToString("yyyy-MM-dd") } else { "Never" }
            $neverExp = $u.PasswordNeverExpires

            $issues = @()
            if ($neverExp) { $issues += "Password never expires" }
            if ($u.PasswordLastSet -and ((Get-Date) - $u.PasswordLastSet).Days -gt $Baseline.MaxPasswordAge) {
                $issues += "Password overdue for change"
            }

            $status = if ($issues.Count -eq 0) { "OK" } else { $issues -join "; " }
            $color  = if ($issues.Count -eq 0) { "White" } else { "Yellow" }

            $row = "  {0,-25} {1,-10} {2,-10} {3,-20} {4,-20} {5}" -f `
                $u.Name, $u.Enabled, (-not $neverExp), $lastSet, $expires, $status
            Write-Host $row -ForegroundColor $color
            Add-Line $row

            if ($issues.Count -gt 0) {
                foreach ($issue in $issues) { $violations.Add("Account '$($u.Name)': $issue") }
            }
        }
    } catch {
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nPassword Policy Enforcer" -ForegroundColor Green

    Add-Line "============================================================"
    Add-Line "  PASSWORD POLICY COMPLIANCE REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME  User: $env:USERNAME"
    Add-Line "============================================================"

    # ── Read Current Policy ────────────────────────────────────────────────────
    Write-Section "CURRENT POLICY vs. BASELINE"
    Add-Line "`n[Password Policy Audit]"
    Write-Host "`n  Reading current policy..." -ForegroundColor Gray

    $current = Get-LocalPasswordPolicy

    Add-Line ""
    Check-Setting "Min Password Length"     $current.MinPasswordLength    $Baseline.MinPasswordLength    "ge"
    Check-Setting "Max Password Age (days)" $current.MaxPasswordAge       $Baseline.MaxPasswordAge       "le"
    Check-Setting "Min Password Age (days)" $current.MinPasswordAge       $Baseline.MinPasswordAge       "ge"
    Check-Setting "Password History Count"  $current.PasswordHistoryCount $Baseline.PasswordHistoryCount "ge"
    Check-Setting "Lockout Threshold"       $current.LockoutThreshold     $Baseline.LockoutThreshold     "le"
    Check-Setting "Lockout Duration (min)"  $current.LockoutDuration      $Baseline.LockoutDuration      "ge"
    Check-Setting "Lockout Window (min)"    $current.LockoutObservation   $Baseline.LockoutObservation   "ge"

    # Complexity check
    $complexOk = $current.ComplexityEnabled -eq $Baseline.ComplexityEnabled
    $cRow = "  $(if($complexOk){'[PASS]'}else{'[FAIL]'})  {0,-35} Current: {1,-10}  Required: {2}" -f "Password Complexity", $current.ComplexityEnabled, $Baseline.ComplexityEnabled
    Write-Host $cRow -ForegroundColor $(if($complexOk){"Green"}else{"Red"})
    Add-Line $cRow
    if (-not $complexOk) { $violations.Add("Password Complexity: current=$($current.ComplexityEnabled), required=$($Baseline.ComplexityEnabled)") }

    # ── Account Audit ──────────────────────────────────────────────────────────
    Get-AccountCompliance

    # ── Apply Baseline ─────────────────────────────────────────────────────────
    if ($ApplyBaseline -and $violations.Count -gt 0) {
        Apply-BaselinePolicy
    } elseif ($violations.Count -gt 0 -and -not $ApplyBaseline) {
        Write-Host "`n  Tip: Run with -ApplyBaseline to automatically fix these settings." -ForegroundColor Gray
    }

    # ── Summary ────────────────────────────────────────────────────────────────
    Write-Section "COMPLIANCE SUMMARY"
    if ($violations.Count -eq 0) {
        Write-Host "`n  [COMPLIANT] All password policy settings meet the baseline." -ForegroundColor Green
        Add-Line "  Status: COMPLIANT - All checks passed."
    } else {
        Write-Host "`n  [NON-COMPLIANT] $($violations.Count) violation(s) found:" -ForegroundColor Red
        Add-Line "  Status: NON-COMPLIANT - $($violations.Count) violation(s)."
        foreach ($v in $violations) { Add-Line "    - $v"; Write-Host "    - $v" -ForegroundColor Yellow }
    }

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
