#Requires -Version 5.1
<#
.SYNOPSIS
    Application Installer - Deploys approved software to the local machine.

.DESCRIPTION
    Provides a menu-driven interface to install pre-approved applications.
    Supports multiple installation methods:
      - Direct EXE/MSI silent install
      - Winget (Windows Package Manager)
      - Chocolatey (if installed)

    All installations are logged for auditing. The approved software catalog
    is defined in the $ApprovedSoftware hashtable — edit it to match your org.

.PARAMETER OutputPath
    Directory for the installation log. Defaults to user's Desktop.

.PARAMETER SoftwareName
    Optional: name of a specific app to install non-interactively.

.EXAMPLE
    .\11_ApplicationInstaller.ps1
    .\11_ApplicationInstaller.ps1 -SoftwareName "7-Zip"

.NOTES
    Prerequisites : Administrator rights required for system-wide installs.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath    = "$env:USERPROFILE\Desktop",
    [string]$SoftwareName  = ""
)

# ─── APPROVED SOFTWARE CATALOG ────────────────────────────────────────────────
# Edit this hashtable to define your organization's approved applications.
# Methods: "winget", "choco", "msi", "exe"
$ApprovedSoftware = [ordered]@{
    "7-Zip"              = @{ Method = "winget"; ID = "7zip.7zip";                    Description = "File archiver"              }
    "Notepad++"          = @{ Method = "winget"; ID = "Notepad++.Notepad++";          Description = "Text/code editor"           }
    "Google Chrome"      = @{ Method = "winget"; ID = "Google.Chrome";               Description = "Web browser"                }
    "Mozilla Firefox"    = @{ Method = "winget"; ID = "Mozilla.Firefox";             Description = "Web browser"                }
    "VLC Media Player"   = @{ Method = "winget"; ID = "VideoLAN.VLC";               Description = "Media player"               }
    "Visual Studio Code" = @{ Method = "winget"; ID = "Microsoft.VisualStudioCode";  Description = "Code editor"                }
    "Git"                = @{ Method = "winget"; ID = "Git.Git";                     Description = "Version control system"     }
    "Adobe Acrobat Reader"= @{ Method = "winget"; ID = "Adobe.Acrobat.Reader.64-bit"; Description = "PDF reader"               }
    "Zoom"               = @{ Method = "winget"; ID = "Zoom.Zoom";                   Description = "Video conferencing"         }
    "Teams"              = @{ Method = "winget"; ID = "Microsoft.Teams";             Description = "Microsoft Teams"            }
    "WinRAR"             = @{ Method = "winget"; ID = "RARLab.WinRAR";              Description = "Archive manager"            }
    "PuTTY"              = @{ Method = "winget"; ID = "PuTTY.PuTTY";               Description = "SSH/Telnet client"          }
    "WinSCP"             = @{ Method = "winget"; ID = "WinSCP.WinSCP";             Description = "SFTP/FTP client"            }
    "Greenshot"          = @{ Method = "winget"; ID = "Greenshot.Greenshot";        Description = "Screenshot tool"            }
    "Wireshark"          = @{ Method = "winget"; ID = "WiresharkFoundation.Wireshark"; Description = "Network analyzer"       }
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AppInstaller_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Check if Winget is available ─────────────────────────────────────────────
function Test-Winget {
    try {
        $null = & winget --version 2>&1
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

# ─── Check if Chocolatey is available ─────────────────────────────────────────
function Test-Choco {
    try {
        $null = & choco --version 2>&1
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

# ─── Install via Winget ────────────────────────────────────────────────────────
function Install-ViaWinget {
    param([string]$Name, [string]$ID)
    Write-Log "Installing '$Name' via winget (ID: $ID)..."
    try {
        $result = & winget install --id $ID --silent --accept-package-agreements --accept-source-agreements 2>&1
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
            # -1978335189 = already installed
            Write-Log "Successfully installed: $Name" "OK"
            return $true
        } else {
            Write-Log "Winget install failed for '$Name'. Exit code: $LASTEXITCODE" "ERROR"
            Write-Log "Output: $($result | Out-String)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception installing '$Name': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ─── Install via Chocolatey ────────────────────────────────────────────────────
function Install-ViaChoco {
    param([string]$Name, [string]$ID)
    Write-Log "Installing '$Name' via Chocolatey (package: $ID)..."
    try {
        $result = & choco install $ID -y --no-progress 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully installed: $Name" "OK"
            return $true
        } else {
            Write-Log "Chocolatey install failed for '$Name'. Exit: $LASTEXITCODE" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ─── Install via MSI/EXE ──────────────────────────────────────────────────────
function Install-ViaFile {
    param([string]$Name, [string]$InstallerPath, [string]$Args)
    if (-not (Test-Path $InstallerPath)) {
        Write-Log "Installer not found: $InstallerPath" "ERROR"
        return $false
    }
    Write-Log "Installing '$Name' from: $InstallerPath"
    try {
        $ext = [System.IO.Path]::GetExtension($InstallerPath).ToLower()
        if ($ext -eq ".msi") {
            $proc = Start-Process msiexec.exe -ArgumentList "/i `"$InstallerPath`" /qn $Args" -Wait -PassThru
        } else {
            $proc = Start-Process $InstallerPath -ArgumentList $Args -Wait -PassThru
        }
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-Log "Successfully installed: $Name (ExitCode: $($proc.ExitCode))" "OK"
            if ($proc.ExitCode -eq 3010) { Write-Log "Reboot required to complete installation." "WARN" }
            return $true
        } else {
            Write-Log "Install failed. ExitCode: $($proc.ExitCode)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ─── Install a Single App ──────────────────────────────────────────────────────
function Invoke-InstallApp {
    param([string]$Name, [hashtable]$App)
    Write-Host "`n  Installing: $Name" -ForegroundColor Cyan
    Write-Host "  $($App.Description)" -ForegroundColor Gray

    switch ($App.Method) {
        "winget" {
            if (-not (Test-Winget)) {
                Write-Log "Winget not available. Install Windows Package Manager first." "ERROR"
                return $false
            }
            return Install-ViaWinget -Name $Name -ID $App.ID
        }
        "choco" {
            if (-not (Test-Choco)) {
                Write-Log "Chocolatey not installed. Visit https://chocolatey.org/install" "ERROR"
                return $false
            }
            return Install-ViaChoco -Name $Name -ID $App.ID
        }
        "msi" { return Install-ViaFile -Name $Name -InstallerPath $App.Path -Args "/qn" }
        "exe" { return Install-ViaFile -Name $Name -InstallerPath $App.Path -Args $App.Args }
        default {
            Write-Log "Unknown install method: $($App.Method)" "ERROR"
            return $false
        }
    }
}

# ─── Display Menu ──────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   APPLICATION INSTALLER - Approved Software Catalog"         -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan

    $wingetOk = Test-Winget
    $chocoOk  = Test-Choco
    Write-Host "`n  Package Managers: Winget $(if($wingetOk){'[OK]'}else{'[NOT FOUND]'})  Choco $(if($chocoOk){'[OK]'}else{'[NOT FOUND]'})" -ForegroundColor $(if($wingetOk){"Green"}else{"Yellow"})
    Write-Host ""

    $i = 1
    foreach ($name in $ApprovedSoftware.Keys) {
        $app = $ApprovedSoftware[$name]
        Write-Host ("  [{0,2}] {1,-25} {2}" -f $i, $name, $app.Description) -ForegroundColor White
        $i++
    }
    Write-Host ""
    Write-Host "  [A] Install ALL approved software"  -ForegroundColor Yellow
    Write-Host "  [Q] Quit"                            -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "Application Installer started by $env:USERNAME"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n  WARNING: Not running as Administrator. Some installs may fail." -ForegroundColor Yellow
    Write-Log "Running without Administrator privileges." "WARN"
}

# Non-interactive mode: install specific app by name
if ($SoftwareName) {
    if ($ApprovedSoftware.ContainsKey($SoftwareName)) {
        Invoke-InstallApp -Name $SoftwareName -App $ApprovedSoftware[$SoftwareName]
    } else {
        Write-Host "  '$SoftwareName' is not in the approved software catalog." -ForegroundColor Red
        Write-Log "Requested app not in catalog: $SoftwareName" "WARN"
    }
    exit 0
}

# Interactive mode
try {
    $keys = @($ApprovedSoftware.Keys)
    do {
        Show-Menu
        $choice = Read-Host "Select option"

        if ($choice.ToUpper() -eq 'Q') { break }

        if ($choice.ToUpper() -eq 'A') {
            Write-Host "`n  Installing all approved software. This may take a while..." -ForegroundColor Yellow
            $confirm = Read-Host "  Confirm install ALL? (Y/N)"
            if ($confirm -eq 'Y') {
                $ok = 0; $fail = 0
                foreach ($name in $ApprovedSoftware.Keys) {
                    $result = Invoke-InstallApp -Name $name -App $ApprovedSoftware[$name]
                    if ($result) { $ok++ } else { $fail++ }
                }
                Write-Host "`n  Done. $ok installed, $fail failed." -ForegroundColor $(if($fail -eq 0){"Green"}else{"Yellow"})
                Write-Log "Install All: $ok succeeded, $fail failed"
            }
            Read-Host "`nPress Enter to continue"
            continue
        }

        # Numeric selection
        $idx = [int]$choice - 1
        if ($idx -ge 0 -and $idx -lt $keys.Count) {
            $name = $keys[$idx]
            Invoke-InstallApp -Name $name -App $ApprovedSoftware[$name]
            Read-Host "`nPress Enter to continue"
        } else {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }

    } while ($true)

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Application Installer exited"
