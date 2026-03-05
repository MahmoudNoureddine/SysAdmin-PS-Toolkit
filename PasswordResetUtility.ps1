#Requires -Version 5.1
<#
.SYNOPSIS
    Password Reset Utility - Self-service password change and account unlock.

.DESCRIPTION
    Provides a menu-driven interface allowing users to:
      1. Change their own Windows account password
      2. Unlock a locked local account (requires admin rights)
      3. Check the current status of a local account

    All actions are logged for auditing purposes.

.PARAMETER LogPath
    Path to the audit log file. Defaults to the user's Desktop.

.EXAMPLE
    .\06_PasswordResetUtility.ps1
    .\06_PasswordResetUtility.ps1 -LogPath "C:\Logs"

.NOTES
    Prerequisites : Standard users can change own passwords.
                    Administrator rights required to unlock other accounts.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath "PasswordReset_Audit.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [User:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry
    Write-Host $entry -ForegroundColor $(switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "Gray" } })
}

# ─── Menu Display ──────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   PASSWORD RESET UTILITY"                                     -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Change MY password (current user)"                       -ForegroundColor White
    Write-Host "  [2] Unlock a local account     (Admin required)"             -ForegroundColor White
    Write-Host "  [3] Check account status"                                    -ForegroundColor White
    Write-Host "  [4] List all local accounts"                                 -ForegroundColor White
    Write-Host "  [Q] Quit"                                                    -ForegroundColor Gray
    Write-Host ""
}

# ─── Password Strength Checker ─────────────────────────────────────────────────
function Test-PasswordStrength {
    param([SecureString]$SecurePass)
    $bstr  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    $issues = @()
    if ($plain.Length -lt 8)                       { $issues += "At least 8 characters required" }
    if ($plain -notmatch '[A-Z]')                  { $issues += "Must contain an uppercase letter" }
    if ($plain -notmatch '[a-z]')                  { $issues += "Must contain a lowercase letter" }
    if ($plain -notmatch '[0-9]')                  { $issues += "Must contain a number" }
    if ($plain -notmatch '[!@#\$%^&*()_+\-=\[\]]') { $issues += "Must contain a special character" }
    return $issues
}

# ─── Change Own Password ───────────────────────────────────────────────────────
function Invoke-ChangeOwnPassword {
    Write-Host "`n--- CHANGE YOUR PASSWORD ---" -ForegroundColor Yellow
    Write-Host "This will change the password for account: $env:USERNAME" -ForegroundColor White
    Write-Host ""

    # Collect current password
    $current = Read-Host "Enter your CURRENT password" -AsSecureString

    # Collect and confirm new password
    $new1    = Read-Host "Enter your NEW password" -AsSecureString
    $new2    = Read-Host "Confirm your NEW password" -AsSecureString

    # Compare new passwords (must convert to plain for comparison)
    function Get-Plain { param([SecureString]$ss)
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        $p    = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        return $p
    }
    $p1 = Get-Plain $new1
    $p2 = Get-Plain $new2

    if ($p1 -ne $p2) {
        Write-Host "`n[ERROR] New passwords do not match. Aborting." -ForegroundColor Red
        Write-Log "Password change FAILED for $env:USERNAME - passwords did not match" "WARN"
        return
    }

    # Check strength
    $strengthIssues = Test-PasswordStrength -SecurePass $new1
    if ($strengthIssues.Count -gt 0) {
        Write-Host "`n[ERROR] Password does not meet requirements:" -ForegroundColor Red
        $strengthIssues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Log "Password change FAILED for $env:USERNAME - strength requirements not met" "WARN"
        return
    }

    # Attempt the change via ADSI (works for local accounts)
    try {
        $account = [ADSI]"WinNT://$env:COMPUTERNAME/$env:USERNAME,user"
        $account.ChangePassword((Get-Plain $current), $p1)
        $account.SetInfo()
        Write-Host "`n[OK] Password changed successfully!" -ForegroundColor Green
        Write-Log "Password changed successfully for $env:USERNAME"
    } catch {
        Write-Host "`n[ERROR] Password change failed: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        Write-Log "Password change FAILED for $env:USERNAME - $($_.Exception.InnerException.Message)" "ERROR"
    }

    # Clear sensitive strings from memory
    Clear-Variable p1, p2 -ErrorAction SilentlyContinue
}

# ─── Unlock Account ────────────────────────────────────────────────────────────
function Invoke-UnlockAccount {
    Write-Host "`n--- UNLOCK A LOCAL ACCOUNT ---" -ForegroundColor Yellow
    Write-Host "Note: Administrator rights required." -ForegroundColor Gray

    $target = Read-Host "`nEnter the username to unlock"
    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "[ERROR] No username entered." -ForegroundColor Red
        return
    }

    try {
        $user = Get-LocalUser -Name $target -ErrorAction Stop

        if (-not $user.Enabled) {
            Write-Host "`n  Account '$target' is DISABLED (not locked). Enable it instead?" -ForegroundColor Yellow
            $choice = Read-Host "  Enable account? (Y/N)"
            if ($choice -eq 'Y') {
                Enable-LocalUser -Name $target
                Write-Host "  [OK] Account '$target' has been enabled." -ForegroundColor Green
                Write-Log "Account ENABLED: $target"
            }
        } else {
            # Reset lockout by using net user (direct ADSI is more reliable for lockouts)
            $account = [ADSI]"WinNT://$env:COMPUTERNAME/$target,user"
            $account.IsAccountLocked = $false
            $account.SetInfo()
            Write-Host "`n  [OK] Account '$target' has been unlocked." -ForegroundColor Green
            Write-Log "Account UNLOCKED: $target"
        }
    } catch {
        Write-Host "`n  [ERROR] Could not unlock '$target': $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Failed to unlock account $target - $($_.Exception.Message)" "ERROR"
    }
}

# ─── Check Account Status ──────────────────────────────────────────────────────
function Invoke-CheckAccountStatus {
    Write-Host "`n--- CHECK ACCOUNT STATUS ---" -ForegroundColor Yellow
    $target = Read-Host "Enter username to check (leave blank for your own account)"
    if ([string]::IsNullOrWhiteSpace($target)) { $target = $env:USERNAME }

    try {
        $user = Get-LocalUser -Name $target -ErrorAction Stop
        Write-Host ""
        Write-Host "  Account    : $($user.Name)"         -ForegroundColor White
        Write-Host "  Full Name  : $($user.FullName)"     -ForegroundColor White
        Write-Host "  Enabled    : $($user.Enabled)"      -ForegroundColor $(if ($user.Enabled) {"Green"} else {"Red"})
        Write-Host "  Last Logon : $($user.LastLogon)"    -ForegroundColor White
        Write-Host "  Pwd Expires: $($user.PasswordExpires)" -ForegroundColor White
        Write-Host "  Pwd Changed: $($user.PasswordLastSet)" -ForegroundColor White
        Write-Log "Account status checked: $target"
    } catch {
        Write-Host "  [ERROR] User '$target' not found: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── List All Local Accounts ───────────────────────────────────────────────────
function Invoke-ListAccounts {
    Write-Host "`n--- LOCAL ACCOUNTS ---" -ForegroundColor Yellow
    try {
        $users = Get-LocalUser | Sort-Object Name
        Write-Host ""
        Write-Host ("  {0,-25} {1,-10} {2,-20} {3}" -f "Username", "Enabled", "Last Logon", "Desc")
        Write-Host ("  {0,-25} {1,-10} {2,-20} {3}" -f "--------", "-------", "----------", "----")
        foreach ($u in $users) {
            $color = if ($u.Enabled) { "White" } else { "DarkGray" }
            Write-Host ("  {0,-25} {1,-10} {2,-20} {3}" -f $u.Name, $u.Enabled, $u.LastLogon, $u.Description) -ForegroundColor $color
        }
        Write-Log "Local accounts listed"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "Password Reset Utility started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select an option"
        switch ($choice.ToUpper()) {
            '1' { Invoke-ChangeOwnPassword;   Read-Host "`nPress Enter to return to menu" }
            '2' { Invoke-UnlockAccount;        Read-Host "`nPress Enter to return to menu" }
            '3' { Invoke-CheckAccountStatus;   Read-Host "`nPress Enter to return to menu" }
            '4' { Invoke-ListAccounts;         Read-Host "`nPress Enter to return to menu" }
            'Q' { Write-Host "`nExiting. Goodbye." -ForegroundColor Gray; break }
            default { Write-Host "`nInvalid option. Please choose 1-4 or Q." -ForegroundColor Yellow }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "ERROR"
    exit 1
}
Write-Log "Password Reset Utility exited"
