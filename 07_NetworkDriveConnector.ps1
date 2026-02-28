#Requires -Version 5.1
<#
.SYNOPSIS
    Network Drive Connector - Maps network shares and manages VPN connections.

.DESCRIPTION
    Provides a menu-driven tool to:
      1. Map predefined network drives (configure the $DriveMap hashtable below)
      2. Disconnect mapped drives
      3. List currently mapped drives
      4. Reconnect all defined drives at once
      5. Test VPN/connection status

    Edit the $DriveMap section to match your organization's shares.

.PARAMETER LogPath
    Directory for the connection log. Defaults to user's Desktop.

.EXAMPLE
    .\07_NetworkDriveConnector.ps1
    .\07_NetworkDriveConnector.ps1 -LogPath "C:\Logs"

.NOTES
    Prerequisites : Network access to the target shares is required.
                    Domain credentials may be needed for remote shares.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:USERPROFILE\Desktop"
)

# ─── CONFIGURE YOUR NETWORK DRIVES HERE ───────────────────────────────────────
# Format: DriveLabel = @{ Letter = "X:"; Path = "\\server\share"; Description = "..." }
$DriveMap = @{
    "Company Files"    = @{ Letter = "Z:"; Path = "\\fileserver\company";    Description = "Main company file share"  }
    "Department Share" = @{ Letter = "Y:"; Path = "\\fileserver\department"; Description = "Department shared folder" }
    "IT Tools"         = @{ Letter = "X:"; Path = "\\fileserver\ittools";    Description = "IT department tools"      }
    "Backups"          = @{ Letter = "W:"; Path = "\\nas\backups";           Description = "Network backup storage"   }
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath "NetworkDrives_Audit.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
}

function Write-Status {
    param([string]$Msg, [string]$Type = "info")
    $color = switch ($Type) { "ok" { "Green" } "error" { "Red" } "warn" { "Yellow" } default { "White" } }
    Write-Host "  $Msg" -ForegroundColor $color
}

# ─── Map a Single Drive ────────────────────────────────────────────────────────
function Connect-NetworkDrive {
    param([string]$Label, [hashtable]$Drive)
    $letter = $Drive.Letter
    $path   = $Drive.Path

    Write-Host "`n  Connecting '$Label' ($letter => $path)..." -ForegroundColor Gray

    # Remove existing mapping if present
    if (Get-PSDrive -Name $letter.TrimEnd(':') -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name $letter.TrimEnd(':') -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }

    # Test if path is reachable before mapping
    if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
        Write-Status "[UNREACHABLE] $path - check network/VPN connection" "error"
        Write-Log "Drive map FAILED (unreachable): $label - $letter => $path" "ERROR"
        return $false
    }

    try {
        # Use net use for persistent mapping (survives logoff)
        $result = net use $letter $path /persistent:yes 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "[OK] Mapped $letter => $path" "ok"
            Write-Log "Drive mapped: $label - $letter => $path"
            return $true
        } else {
            # Try with credentials if net use failed
            Write-Status "[WARN] Could not auto-map. Trying with credentials..." "warn"
            $cred   = Get-Credential -Message "Enter credentials for $path"
            $result = net use $letter $path /user:$($cred.UserName) $($cred.GetNetworkCredential().Password) /persistent:yes 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "[OK] Mapped $letter => $path (with credentials)" "ok"
                Write-Log "Drive mapped with credentials: $label - $letter"
                return $true
            } else {
                Write-Status "[FAIL] Could not map drive: $result" "error"
                Write-Log "Drive map FAILED: $label - $result" "ERROR"
                return $false
            }
        }
    } catch {
        Write-Status "[ERROR] $($_.Exception.Message)" "error"
        Write-Log "Drive map EXCEPTION: $label - $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ─── Disconnect a Drive ────────────────────────────────────────────────────────
function Disconnect-NetworkDrive {
    Write-Host "`n--- DISCONNECT A DRIVE ---" -ForegroundColor Yellow
    $letter = Read-Host "Enter drive letter to disconnect (e.g. Z)"
    $letter = $letter.ToUpper().TrimEnd(':') + ":"

    try {
        $result = net use $letter /delete /yes 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "[OK] Drive $letter disconnected." "ok"
            Write-Log "Drive disconnected: $letter"
        } else {
            Write-Status "[WARN] $result" "warn"
        }
    } catch {
        Write-Status "[ERROR] $($_.Exception.Message)" "error"
    }
}

# ─── List Current Mappings ─────────────────────────────────────────────────────
function Show-MappedDrives {
    Write-Host "`n--- CURRENTLY MAPPED DRIVES ---" -ForegroundColor Yellow
    Write-Host ""

    try {
        $mapped = Get-CimInstance -ClassName Win32_MappedLogicalDisk -ErrorAction Stop
        if ($mapped) {
            Write-Host ("  {0,-6} {1,-40} {2,-15} {3}" -f "Drive", "Remote Path", "Free GB", "Status")
            Write-Host ("  {0,-6} {1,-40} {2,-15} {3}" -f "-----", "-----------", "-------", "------")
            foreach ($m in $mapped) {
                $freeGB = if ($m.FreeSpace) { [math]::Round($m.FreeSpace / 1GB, 1) } else { "N/A" }
                Write-Host ("  {0,-6} {1,-40} {2,-15} {3}" -f $m.Name, $m.ProviderName, $freeGB, "Connected") -ForegroundColor Green
            }
        } else {
            Write-Status "No network drives currently mapped." "warn"
        }
    } catch {
        Write-Status "[ERROR] $($_.Exception.Message)" "error"
    }

    # Also show any pending/defined but unconnected drives
    Write-Host "`n  Defined drives in configuration:"
    foreach ($label in $DriveMap.Keys) {
        $d  = $DriveMap[$label]
        $ok = Test-Path $d.Letter -ErrorAction SilentlyContinue
        $status = if ($ok) { "[Connected]" } else { "[Not mapped]" }
        $color  = if ($ok) { "Green" } else { "DarkGray" }
        Write-Host ("  {0,-6} {1,-40} {2}" -f $d.Letter, $d.Path, $status) -ForegroundColor $color
    }
}

# ─── Connect All Defined Drives ────────────────────────────────────────────────
function Connect-AllDrives {
    Write-Host "`n--- CONNECT ALL DEFINED DRIVES ---" -ForegroundColor Yellow
    $ok = 0; $fail = 0
    foreach ($label in $DriveMap.Keys) {
        $result = Connect-NetworkDrive -Label $label -Drive $DriveMap[$label]
        if ($result) { $ok++ } else { $fail++ }
    }
    Write-Host "`n  Results: $ok connected, $fail failed." -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Yellow"})
    Write-Log "Connect All: $ok succeeded, $fail failed"
}

# ─── VPN / Connectivity Status ────────────────────────────────────────────────
function Show-ConnectivityStatus {
    Write-Host "`n--- VPN / CONNECTIVITY STATUS ---" -ForegroundColor Yellow
    Write-Host ""

    # Show VPN-like adapters (TAP / WAN Miniport)
    $vpnAdapters = Get-NetAdapter | Where-Object {
        $_.InterfaceDescription -match "TAP|VPN|WAN Miniport|PPTP|L2TP|OpenVPN|Cisco|Palo Alto"
    }
    if ($vpnAdapters) {
        Write-Host "  VPN Adapters detected:"
        foreach ($a in $vpnAdapters) {
            $color = if ($a.Status -eq "Up") { "Green" } else { "Gray" }
            Write-Host "    $($a.Name) - $($a.InterfaceDescription)  Status: $($a.Status)" -ForegroundColor $color
        }
    } else {
        Write-Status "No VPN adapters detected." "warn"
    }

    # Test basic internet connectivity
    Write-Host "`n  Internet Connectivity Test:"
    $test = Test-Connection -ComputerName "8.8.8.8" -Count 2 -ErrorAction SilentlyContinue
    if ($test) {
        Write-Status "Internet reachable (8.8.8.8)  avg $([math]::Round(($test | Measure-Object ResponseTime -Average).Average))ms" "ok"
    } else {
        Write-Status "Cannot reach internet (8.8.8.8)." "error"
    }

    # Test reachability of defined file servers
    Write-Host "`n  Defined Share Reachability:"
    $servers = $DriveMap.Values.Path | ForEach-Object { ($_ -split "\\")[2] } | Select-Object -Unique
    foreach ($server in $servers) {
        if ($server) {
            $reachable = Test-Connection -ComputerName $server -Count 1 -ErrorAction SilentlyContinue
            if ($reachable) {
                Write-Status "$server - Reachable" "ok"
            } else {
                Write-Status "$server - UNREACHABLE (VPN may be needed)" "error"
            }
        }
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   NETWORK DRIVE CONNECTOR"                                     -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Connect ALL defined network drives"  -ForegroundColor White
    Write-Host "  [2] Connect a specific drive"            -ForegroundColor White
    Write-Host "  [3] Disconnect a drive"                  -ForegroundColor White
    Write-Host "  [4] Show mapped drives"                  -ForegroundColor White
    Write-Host "  [5] Check VPN / connectivity status"     -ForegroundColor White
    Write-Host "  [Q] Quit"                                -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "Network Drive Connector started by $env:USERNAME"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select an option"
        switch ($choice.ToUpper()) {
            '1' { Connect-AllDrives; Read-Host "`nPress Enter to continue" }
            '2' {
                Write-Host "`nAvailable drives to connect:"
                $i = 1; $keys = $DriveMap.Keys | Sort-Object
                $keys | ForEach-Object { Write-Host "  [$i] $_ ($($DriveMap[$_].Letter) => $($DriveMap[$_].Path))"; $i++ }
                $sel = Read-Host "Enter number"
                $key = $keys | Select-Object -Index ([int]$sel - 1)
                if ($key) { Connect-NetworkDrive -Label $key -Drive $DriveMap[$key] }
                Read-Host "`nPress Enter to continue"
            }
            '3' { Disconnect-NetworkDrive;        Read-Host "`nPress Enter to continue" }
            '4' { Show-MappedDrives;              Read-Host "`nPress Enter to continue" }
            '5' { Show-ConnectivityStatus;        Read-Host "`nPress Enter to continue" }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "ERROR"
    exit 1
}
Write-Log "Network Drive Connector exited"
