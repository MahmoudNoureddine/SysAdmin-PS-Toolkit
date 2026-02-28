#Requires -Version 5.1
<#
.SYNOPSIS
    Software Uninstaller - Removes deprecated or unauthorized applications.

.DESCRIPTION
    Scans installed applications and provides a safe, menu-driven interface to:
      - Search for and uninstall specific applications
      - Scan against a blocklist of unauthorized software
      - Bulk-remove all blocklisted applications (with confirmation)
      - Use silent uninstall strings from the registry for clean removal

.PARAMETER OutputPath
    Directory for logs. Defaults to user's Desktop.

.PARAMETER BlocklistPath
    Optional path to a text file with one app name per line to auto-flag.

.PARAMETER SilentMode
    If specified with -BlocklistPath, removes blocklisted apps without prompting.

.EXAMPLE
    .\12_SoftwareUninstaller.ps1
    .\12_SoftwareUninstaller.ps1 -BlocklistPath "C:\Config\blocklist.txt"

.NOTES
    Prerequisites : Administrator rights required for most uninstallations.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath    = "$env:USERPROFILE\Desktop",
    [string]$BlocklistPath = "",
    [switch]$SilentMode
)

# ─── DEFAULT BLOCKLIST ─────────────────────────────────────────────────────────
# Add software names (partial match) that are unauthorized in your organization.
$DefaultBlocklist = @(
    "Candy Crush",
    "TikTok",
    "uTorrent",
    "BitTorrent",
    "LimeWire",
    "Spotify",     # Remove if Spotify is approved in your org
    "Discord"      # Remove if Discord is approved in your org
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile  = Join-Path $OutputPath "Uninstaller_$(Get-Date -Format 'yyyyMMdd').log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Get All Installed Apps from Registry ─────────────────────────────────────
function Get-InstalledApps {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = foreach ($path in $regPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.UninstallString } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.DisplayName.Trim()
                    Version        = if ($_.DisplayVersion) { $_.DisplayVersion } else { "N/A" }
                    Publisher      = if ($_.Publisher) { $_.Publisher.Trim() } else { "Unknown" }
                    UninstallCmd   = $_.UninstallString
                    QuietUninstall = $_.QuietUninstallString
                    InstallDate    = $_.InstallDate
                }
            }
    }
    return $apps | Sort-Object Name | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }
}

# ─── Perform Uninstall ─────────────────────────────────────────────────────────
function Invoke-Uninstall {
    param([PSCustomObject]$App)

    Write-Host "`n  Uninstalling: $($App.Name) v$($App.Version)" -ForegroundColor Yellow
    Write-Log "Attempting uninstall: $($App.Name) v$($App.Version)"

    # Prefer quiet uninstall string if available
    $cmd = if ($App.QuietUninstall) { $App.QuietUninstall } else { $App.UninstallCmd }

    if (-not $cmd) {
        Write-Log "No uninstall command found for '$($App.Name)'" "ERROR"
        return $false
    }

    try {
        # Handle MSI-based uninstalls
        if ($cmd -match "MsiExec|msiexec") {
            # Extract product code
            if ($cmd -match "\{[A-F0-9\-]+\}" -or $cmd -match "\{[a-f0-9\-]+\}") {
                $productCode = $Matches[0]
                Write-Log "MSI uninstall - product code: $productCode"
                $proc = Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru
            } else {
                # Run as-is with quiet flags appended
                $proc = Start-Process "msiexec.exe" -ArgumentList ($cmd -replace "msiexec.exe","").Trim() + " /qn /norestart" -Wait -PassThru
            }
        } else {
            # EXE-based uninstall — try to add silent flags
            $silentArgs = @("/S", "/silent", "/quiet", "/uninstall")
            $alreadySilent = $silentArgs | Where-Object { $cmd -match $_ }

            if (-not $alreadySilent) {
                # Try appending /S for silent
                if ($cmd -match '"(.+?)"(.*)') {
                    $exe  = $Matches[1]
                    $args = $Matches[2].Trim() + " /S"
                    $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
                } else {
                    $proc = Start-Process -FilePath $cmd -ArgumentList "/S" -Wait -PassThru
                }
            } else {
                if ($cmd -match '"(.+?)"\s*(.*)') {
                    $proc = Start-Process -FilePath $Matches[1] -ArgumentList $Matches[2] -Wait -PassThru
                } else {
                    $proc = Start-Process -FilePath $cmd -Wait -PassThru
                }
            }
        }

        # 0 = success, 3010 = success but reboot needed, 1605 = not installed
        if ($proc.ExitCode -in 0, 3010, 1605) {
            Write-Log "Successfully uninstalled: $($App.Name) (ExitCode: $($proc.ExitCode))" "OK"
            if ($proc.ExitCode -eq 3010) { Write-Host "  NOTE: Reboot required to complete removal." -ForegroundColor Yellow }
            return $true
        } else {
            Write-Log "Uninstall may have failed. ExitCode: $($proc.ExitCode)" "WARN"
            return $false
        }
    } catch {
        Write-Log "Exception during uninstall: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ─── Search and Select App ────────────────────────────────────────────────────
function Invoke-SearchUninstall {
    param([PSCustomObject[]]$Apps)

    $query = Read-Host "`n  Enter app name to search (partial match OK)"
    if ([string]::IsNullOrWhiteSpace($query)) { return }

    $matches = $Apps | Where-Object { $_.Name -like "*$query*" }

    if (-not $matches) {
        Write-Host "  No applications found matching '$query'." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  Found $($matches.Count) match(es):" -ForegroundColor Cyan
    $i = 1
    foreach ($m in $matches) {
        Write-Host ("  [{0}] {1,-50} v{2,-15} {3}" -f $i, $m.Name, $m.Version, $m.Publisher)
        $i++
    }

    $sel = Read-Host "`n  Enter number to uninstall (or Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($sel)) { return }

    $idx = [int]$sel - 1
    if ($idx -ge 0 -and $idx -lt $matches.Count) {
        $app = @($matches)[$idx]
        $confirm = Read-Host "  Confirm uninstall '$($app.Name)'? (Y/N)"
        if ($confirm -eq 'Y') {
            Invoke-Uninstall -App $app
        } else {
            Write-Host "  Cancelled." -ForegroundColor Gray
        }
    } else {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
    }
}

# ─── Blocklist Scan ────────────────────────────────────────────────────────────
function Invoke-BlocklistScan {
    param([PSCustomObject[]]$Apps, [string[]]$Blocklist)

    Write-Host "`n  Scanning against blocklist ($($Blocklist.Count) entries)..." -ForegroundColor Cyan
    $flagged = foreach ($entry in $Blocklist) {
        $Apps | Where-Object { $_.Name -like "*$entry*" }
    }

    if (-not $flagged) {
        Write-Host "`n  [OK] No blocklisted applications found." -ForegroundColor Green
        Write-Log "Blocklist scan: no violations found."
        return
    }

    Write-Host "`n  Found $($flagged.Count) BLOCKLISTED application(s):" -ForegroundColor Red
    foreach ($app in $flagged) {
        Write-Host "  [BLOCKED] $($app.Name) v$($app.Version)  Publisher: $($app.Publisher)" -ForegroundColor Red
        Write-Log "Blocklisted app detected: $($app.Name) v$($app.Version)" "WARN"
    }

    if ($SilentMode) {
        Write-Log "Silent mode active - removing all blocklisted apps automatically."
        foreach ($app in $flagged) { Invoke-Uninstall -App $app }
    } else {
        $confirm = Read-Host "`n  Remove ALL blocklisted apps? (Y/N)"
        if ($confirm -eq 'Y') {
            $ok = 0; $fail = 0
            foreach ($app in $flagged) {
                $result = Invoke-Uninstall -App $app
                if ($result) { $ok++ } else { $fail++ }
            }
            Write-Host "`n  Removal complete: $ok removed, $fail failed." -ForegroundColor $(if($fail -eq 0){"Green"}else{"Yellow"})
        }
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   SOFTWARE UNINSTALLER"                                        -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Search and uninstall a specific application"  -ForegroundColor White
    Write-Host "  [2] Scan and remove BLOCKLISTED applications"     -ForegroundColor White
    Write-Host "  [3] List all installed applications"              -ForegroundColor White
    Write-Host "  [Q] Quit"                                         -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`nWARNING: Not running as Administrator. Uninstalls may fail." -ForegroundColor Yellow
}

# Load blocklist
$blocklist = $DefaultBlocklist
if ($BlocklistPath -and (Test-Path $BlocklistPath)) {
    $blocklist = Get-Content $BlocklistPath | Where-Object { $_ -match '\S' }
    Write-Log "Loaded blocklist from file: $BlocklistPath ($($blocklist.Count) entries)"
}

Write-Log "Software Uninstaller started by $env:USERNAME"

try {
    Write-Host "`nLoading installed applications..." -ForegroundColor Gray
    $apps = Get-InstalledApps
    Write-Host "  Found $($apps.Count) installed applications." -ForegroundColor Gray

    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Invoke-SearchUninstall -Apps $apps; $apps = Get-InstalledApps; Read-Host "`nPress Enter to continue" }
            '2' { Invoke-BlocklistScan  -Apps $apps -Blocklist $blocklist; $apps = Get-InstalledApps; Read-Host "`nPress Enter to continue" }
            '3' {
                Write-Host "`n  Installed Applications ($($apps.Count) total):" -ForegroundColor Cyan
                $apps | Format-Table Name, Version, Publisher -AutoSize | Out-Host
                Read-Host "Press Enter to continue"
            }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "  Invalid selection." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Software Uninstaller exited"
