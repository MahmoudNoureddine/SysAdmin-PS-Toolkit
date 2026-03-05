#Requires -Version 5.1
<#
.SYNOPSIS
    USB Device Blocker - Restricts and logs removable media access.

.DESCRIPTION
    Manages removable media (USB drives) access via Windows registry and
    device policies. Features include:
      - Block all removable storage devices
      - Allow removable storage devices
      - Check current USB access policy
      - View USB device connection history from Event Log
      - Log all USB device connection events

    Changes take effect immediately (no reboot required in most cases).

.PARAMETER OutputPath
    Directory for logs and reports. Defaults to user's Desktop.

.EXAMPLE
    .\15_USBDeviceBlocker.ps1
    .\15_USBDeviceBlocker.ps1 -OutputPath "C:\Logs"

.NOTES
    Prerequisites : Administrator rights REQUIRED.
    Group Policy may override registry settings in domain environments.
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
    Write-Host "`n[ERROR] Administrator rights required." -ForegroundColor Red
    exit 1
}

# ─── Registry Keys for USB Policy ─────────────────────────────────────────────
$StoragePolicyKey = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
$RemovableDenyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
$RemovableDenySubKey = "$RemovableDenyKey\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"  # Removable Disk GUID

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "USB_Policy_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [User:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Get Current Policy ────────────────────────────────────────────────────────
function Get-USBPolicy {
    Write-Host "`n--- CURRENT USB POLICY STATUS ---" -ForegroundColor Yellow
    Write-Host ""

    # Method 1: USBSTOR service start type
    # 3 = Manual (USB allowed), 4 = Disabled (USB storage blocked)
    try {
        $usbstor = Get-ItemProperty -Path $StoragePolicyKey -Name "Start" -ErrorAction Stop
        $startType = $usbstor.Start
        $statusMsg = switch ($startType) {
            3 { "ALLOWED  (USBSTOR service: Manual)" }
            4 { "BLOCKED  (USBSTOR service: Disabled)" }
            default { "UNKNOWN  (Start value: $startType)" }
        }
        $color = if ($startType -eq 3) { "Green" } else { "Red" }
        Write-Host "  USBSTOR Driver : $statusMsg" -ForegroundColor $color
    } catch {
        Write-Host "  USBSTOR Driver : Could not read registry" -ForegroundColor Yellow
    }

    # Method 2: Group Policy removable storage
    $gpBlocked = $false
    if (Test-Path $RemovableDenySubKey) {
        $deny = Get-ItemProperty -Path $RemovableDenySubKey -ErrorAction SilentlyContinue
        if ($deny.Deny_Write -eq 1 -or $deny.Deny_Read -eq 1 -or $deny.Deny_Execute -eq 1) {
            $gpBlocked = $true
        }
    }
    Write-Host "  GP Storage Block: $(if($gpBlocked){'ACTIVE - Removable storage restricted'}else{'Not configured'})" -ForegroundColor $(if($gpBlocked){"Red"}else{"Green"})

    # Currently connected USB devices
    Write-Host "`n  Currently Connected Removable Devices:"
    try {
        $usb = Get-PnpDevice -Class "DiskDrive" -Status "OK" -ErrorAction SilentlyContinue |
               Where-Object { $_.InstanceId -like "USBSTOR*" }
        if ($usb) {
            foreach ($d in $usb) {
                Write-Host "    [CONNECTED] $($d.FriendlyName)" -ForegroundColor Yellow
                Write-Log "USB device currently connected: $($d.FriendlyName)"
            }
        } else {
            Write-Host "    No USB storage devices currently connected." -ForegroundColor Gray
        }
    } catch {
        Write-Host "    Could not enumerate USB devices." -ForegroundColor Gray
    }
}

# ─── Block USB Storage ─────────────────────────────────────────────────────────
function Block-USBStorage {
    Write-Host "`n--- BLOCK USB STORAGE DEVICES ---" -ForegroundColor Red
    Write-Host "  This will prevent users from using USB storage drives."
    Write-Host "  Other USB devices (keyboard, mouse) will still work."
    Write-Host ""
    $confirm = Read-Host "  Confirm BLOCK USB storage? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; return }

    try {
        # Disable USBSTOR driver start
        Set-ItemProperty -Path $StoragePolicyKey -Name "Start" -Value 4 -Type DWord -ErrorAction Stop

        # Also set Group Policy deny via registry
        if (-not (Test-Path $RemovableDenyKey)) {
            New-Item -Path $RemovableDenyKey -Force | Out-Null
        }
        if (-not (Test-Path $RemovableDenySubKey)) {
            New-Item -Path $RemovableDenySubKey -Force | Out-Null
        }
        Set-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Write"   -Value 1 -Type DWord
        Set-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Read"    -Value 1 -Type DWord
        Set-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Execute" -Value 1 -Type DWord

        Write-Log "USB storage BLOCKED" "OK"
        Write-Host "`n  [OK] USB storage devices are now BLOCKED." -ForegroundColor Green
        Write-Host "  Changes take effect for newly connected devices immediately." -ForegroundColor Gray
        Write-Host "  Existing connections may require a system restart to enforce." -ForegroundColor Gray
    } catch {
        Write-Log "Failed to block USB storage: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Allow USB Storage ─────────────────────────────────────────────────────────
function Allow-USBStorage {
    Write-Host "`n--- ALLOW USB STORAGE DEVICES ---" -ForegroundColor Green
    $confirm = Read-Host "  Confirm ALLOW USB storage? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; return }

    try {
        # Re-enable USBSTOR driver
        Set-ItemProperty -Path $StoragePolicyKey -Name "Start" -Value 3 -Type DWord -ErrorAction Stop

        # Remove GP deny keys
        if (Test-Path $RemovableDenySubKey) {
            Remove-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Write"   -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Read"    -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Execute" -ErrorAction SilentlyContinue
        }

        Write-Log "USB storage ALLOWED" "OK"
        Write-Host "`n  [OK] USB storage devices are now ALLOWED." -ForegroundColor Green
    } catch {
        Write-Log "Failed to allow USB storage: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Read-Only Mode ────────────────────────────────────────────────────────────
function Set-USBReadOnly {
    Write-Host "`n--- SET USB STORAGE TO READ-ONLY ---" -ForegroundColor Yellow
    Write-Host "  Users can read from USB drives but cannot write to them."
    $confirm = Read-Host "  Apply read-only policy? (Y/N)"
    if ($confirm -ne 'Y') { return }

    try {
        # Allow reads, deny writes
        if (-not (Test-Path $RemovableDenySubKey)) {
            New-Item -Path $RemovableDenySubKey -Force | Out-Null
        }
        Set-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Write"   -Value 1 -Type DWord
        Remove-ItemProperty -Path $RemovableDenySubKey -Name "Deny_Read" -ErrorAction SilentlyContinue

        # Ensure USBSTOR is enabled (for reads)
        Set-ItemProperty -Path $StoragePolicyKey -Name "Start" -Value 3 -Type DWord

        Write-Log "USB storage set to READ-ONLY" "OK"
        Write-Host "`n  [OK] USB storage is now READ-ONLY." -ForegroundColor Green
    } catch {
        Write-Log "Failed to set read-only: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── USB Connection History ────────────────────────────────────────────────────
function Get-USBHistory {
    Write-Host "`n--- USB DEVICE CONNECTION HISTORY ---" -ForegroundColor Yellow

    # From registry (all devices ever connected)
    Write-Host "`n  [Historical USB Devices - Ever Connected]"
    try {
        $usbKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbKey) {
            $devices = Get-ChildItem $usbKey -ErrorAction SilentlyContinue
            $count = 0
            foreach ($device in $devices) {
                $friendly = $device.PSChildName -replace "_\d+$",""
                $instances = Get-ChildItem $device.PSPath -ErrorAction SilentlyContinue
                foreach ($inst in $instances) {
                    $props = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                    $name  = if ($props.FriendlyName) { $props.FriendlyName } else { $friendly }
                    Write-Host ("  {0,-50} SerialNumber: {1}" -f $name, $inst.PSChildName)
                    $count++
                }
            }
            Write-Host "`n  Total historical devices: $count"
        } else {
            Write-Host "  No USB storage history found in registry."
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }

    # From Event Log (recent connections)
    Write-Host "`n  [Recent USB Events from System Event Log (last 7 days)]"
    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            StartTime = $startTime
            Id        = @(20001, 20003)   # PnP device install/removal events
        } -ErrorAction SilentlyContinue | Select-Object -First 20

        if ($events) {
            foreach ($e in $events) {
                $type  = if ($e.Id -eq 20001) { "CONNECTED" } else { "REMOVED" }
                $color = if ($e.Id -eq 20001) { "Yellow" } else { "Gray" }
                Write-Host "  [$type] $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))  $($e.Message -replace "`n"," " | Select-Object -First 1)" -ForegroundColor $color
            }
        } else {
            Write-Host "  No USB plug/unplug events found in last 7 days."
        }
    } catch {
        Write-Host "  [INFO] Could not retrieve event log data." -ForegroundColor Gray
    }

    # Export history to CSV
    $csvFile = Join-Path $OutputPath "USB_History_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    try {
        $usbKey  = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        $history = if (Test-Path $usbKey) {
            Get-ChildItem $usbKey -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Property -contains "FriendlyName" } |
                ForEach-Object {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    [PSCustomObject]@{ DeviceName = $p.FriendlyName; SerialNumber = $_.PSChildName; RegistryPath = $_.PSPath }
                }
        }
        if ($history) {
            $history | Export-Csv -Path $csvFile -NoTypeInformation
            Write-Host "`n  History exported to: $csvFile" -ForegroundColor Gray
            Write-Log "USB history exported to: $csvFile"
        }
    } catch {}
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   USB DEVICE BLOCKER & MONITOR"                               -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME (Administrator) on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Show current USB policy status"    -ForegroundColor White
    Write-Host "  [2] BLOCK all USB storage devices"     -ForegroundColor Red
    Write-Host "  [3] ALLOW all USB storage devices"     -ForegroundColor Green
    Write-Host "  [4] Set USB storage to READ-ONLY"      -ForegroundColor Yellow
    Write-Host "  [5] View USB device history"           -ForegroundColor White
    Write-Host "  [Q] Quit"                              -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "USB Device Blocker started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Get-USBPolicy;     Read-Host "`nPress Enter" }
            '2' { Block-USBStorage;  Read-Host "`nPress Enter" }
            '3' { Allow-USBStorage;  Read-Host "`nPress Enter" }
            '4' { Set-USBReadOnly;   Read-Host "`nPress Enter" }
            '5' { Get-USBHistory;    Read-Host "`nPress Enter" }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}
Write-Log "USB Device Blocker exited"
