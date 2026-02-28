#Requires -Version 5.1
<#
.SYNOPSIS
    Printer Installer - Adds network printers to the user's computer.

.DESCRIPTION
    Provides a menu-driven interface to:
      - Install printers from a predefined network printer catalog
      - Add printers by UNC path or IP address manually
      - List and remove installed printers
      - Set a default printer
      - Test print a page

    Edit the $PrinterCatalog hashtable below to define your org's printers.

.PARAMETER OutputPath
    Directory for logs. Defaults to user's Desktop.

.EXAMPLE
    .\17_PrinterInstaller.ps1
    .\17_PrinterInstaller.ps1 -OutputPath "C:\Logs"

.NOTES
    Prerequisites : Administrator rights needed for system-wide printer install.
                    Standard users can install network printers in their profile.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── PRINTER CATALOG ──────────────────────────────────────────────────────────
# Edit this to match your organization's print environment.
$PrinterCatalog = [ordered]@{
    "Finance Printer (2nd Floor)"   = @{ Path = "\\printserver\Finance_2F";    Driver = "HP Universal Printing PCL 6"; Location = "2nd Floor Finance" }
    "Reception Color Printer"       = @{ Path = "\\printserver\Reception_CLR"; Driver = "HP Universal Printing PCL 6"; Location = "Ground Floor Reception" }
    "IT Department Laser"           = @{ Path = "\\printserver\IT_Laser";      Driver = "HP Universal Printing PCL 6"; Location = "1st Floor IT" }
    "Warehouse Label Printer"       = @{ Path = "\\printserver\WH_Labels";     Driver = "Zebra ZPL";                  Location = "Warehouse" }
    "Executive Suite Printer"       = @{ Path = "\\printserver\Exec_Suite";    Driver = "HP Universal Printing PCL 6"; Location = "3rd Floor Exec" }
    "HR Department Printer"         = @{ Path = "\\printserver\HR_Dept";       Driver = "HP Universal Printing PCL 6"; Location = "2nd Floor HR" }
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "PrinterInstall_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Install Printer by UNC Path ──────────────────────────────────────────────
function Install-NetworkPrinter {
    param([string]$PrinterPath, [string]$PrinterName = "", [string]$Driver = "")

    Write-Host "`n  Connecting to: $PrinterPath" -ForegroundColor Gray

    # Test if print server is reachable
    $server = ($PrinterPath -split "\\")[2]
    if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Log "Print server unreachable: $server" "ERROR"
        Write-Host "  [ERROR] Print server '$server' is not reachable. Check network/VPN." -ForegroundColor Red
        return $false
    }

    try {
        # Use Add-Printer for modern Windows (preferred)
        if (Get-Command Add-PrinterConnection -ErrorAction SilentlyContinue) {
            Add-PrinterConnection -ConnectionName $PrinterPath -ErrorAction Stop
        } else {
            # Fallback: rundll32 method
            & rundll32 printui.dll,PrintUIEntry /in /n $PrinterPath 2>&1
        }

        $displayName = if ($PrinterName) { $PrinterName } else { $PrinterPath.Split("\")[-1] }
        Write-Log "Printer installed: $displayName ($PrinterPath)" "OK"
        Write-Host "  [OK] Printer '$displayName' installed successfully." -ForegroundColor Green
        return $true
    } catch {
        # If modern cmdlet fails, try WScript.Network COM method
        try {
            $network = New-Object -ComObject WScript.Network
            $network.AddWindowsPrinterConnection($PrinterPath)
            Write-Log "Printer installed via WScript: $PrinterPath" "OK"
            Write-Host "  [OK] Printer connected via WScript method." -ForegroundColor Green
            return $true
        } catch {
            Write-Log "Failed to install printer '$PrinterPath': $($_.Exception.Message)" "ERROR"
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

# ─── Install by IP Address ─────────────────────────────────────────────────────
function Install-IPPrinter {
    Write-Host "`n--- ADD PRINTER BY IP ADDRESS ---" -ForegroundColor Yellow
    $ip     = Read-Host "  Enter printer IP address"
    $name   = Read-Host "  Enter a friendly name for this printer"
    $driver = Read-Host "  Enter driver name (leave blank for 'Generic / Text Only')"
    if (-not $driver) { $driver = "Generic / Text Only" }

    try {
        # Create TCP/IP port
        $portName = "IP_$ip"
        $existingPort = Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue
        if (-not $existingPort) {
            Add-PrinterPort -Name $portName -PrinterHostAddress $ip -ErrorAction Stop
            Write-Log "Created printer port: $portName for $ip"
        }

        # Add printer
        $existingPrinter = Get-Printer -Name $name -ErrorAction SilentlyContinue
        if ($existingPrinter) {
            Write-Host "  Printer '$name' already exists." -ForegroundColor Yellow
        } else {
            Add-Printer -Name $name -DriverName $driver -PortName $portName -ErrorAction Stop
            Write-Log "IP printer added: $name at $ip using driver '$driver'" "OK"
            Write-Host "  [OK] Printer '$name' ($ip) added." -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to add IP printer: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Note: Driver '$driver' may not be installed. Check Printer Drivers." -ForegroundColor Yellow
    }
}

# ─── List Installed Printers ──────────────────────────────────────────────────
function Show-InstalledPrinters {
    Write-Host "`n--- INSTALLED PRINTERS ---" -ForegroundColor Yellow
    try {
        $printers = Get-Printer -ErrorAction Stop | Sort-Object Name
        if ($printers.Count -eq 0) {
            Write-Host "  No printers installed." -ForegroundColor Gray
            return
        }
        Write-Host ""
        Write-Host ("  {0,-45} {1,-10} {2,-10} {3}" -f "Printer Name", "Type", "Status", "Default")
        Write-Host ("  {0,-45} {1,-10} {2,-10} {3}" -f "------------", "----", "------", "-------")
        foreach ($p in $printers) {
            $isDefault = if ($p.Default) { "*** DEFAULT ***" } else { "" }
            $color     = if ($p.Default) { "Yellow" } elseif ($p.PrinterStatus -eq "Normal") { "White" } else { "Gray" }
            Write-Host ("  {0,-45} {1,-10} {2,-10} {3}" -f `
                ($p.Name.Substring(0,[math]::Min(44,$p.Name.Length))), $p.Type, $p.PrinterStatus, $isDefault) -ForegroundColor $color
        }
        Write-Host "`n  Total: $($printers.Count) printer(s) installed."
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Remove Printer ────────────────────────────────────────────────────────────
function Remove-SelectedPrinter {
    Write-Host "`n--- REMOVE A PRINTER ---" -ForegroundColor Yellow
    try {
        $printers = Get-Printer -ErrorAction Stop | Where-Object { $_.Type -eq "Connection" -or $_.Type -eq "Local" }
        $i = 1
        foreach ($p in $printers) {
            Write-Host ("  [{0}] {1}" -f $i, $p.Name)
            $i++
        }
        $sel = Read-Host "`n  Enter number to remove (or Enter to cancel)"
        if ([string]::IsNullOrWhiteSpace($sel)) { return }
        $idx = [int]$sel - 1
        $printer = @($printers)[$idx]
        if (-not $printer) { Write-Host "  Invalid selection." -ForegroundColor Yellow; return }

        $confirm = Read-Host "  Remove '$($printer.Name)'? (Y/N)"
        if ($confirm -eq 'Y') {
            Remove-Printer -Name $printer.Name -ErrorAction Stop
            Write-Log "Removed printer: $($printer.Name)" "OK"
            Write-Host "  [OK] Printer '$($printer.Name)' removed." -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to remove printer: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Set Default Printer ───────────────────────────────────────────────────────
function Set-DefaultPrinterMenu {
    Write-Host "`n--- SET DEFAULT PRINTER ---" -ForegroundColor Yellow
    try {
        $printers = Get-Printer -ErrorAction Stop
        $i = 1
        foreach ($p in $printers) {
            $mark = if ($p.Default) { " [CURRENT DEFAULT]" } else { "" }
            Write-Host ("  [{0}] {1}{2}" -f $i, $p.Name, $mark)
            $i++
        }
        $sel = Read-Host "`n  Select default printer number"
        if ([string]::IsNullOrWhiteSpace($sel)) { return }
        $idx = [int]$sel - 1
        $printer = @($printers)[$idx]
        if (-not $printer) { Write-Host "  Invalid selection." -ForegroundColor Yellow; return }

        (New-Object -ComObject WScript.Network).SetDefaultPrinter($printer.Name)
        Write-Log "Default printer set to: $($printer.Name)" "OK"
        Write-Host "  [OK] Default printer set to '$($printer.Name)'." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   PRINTER INSTALLER"                                          -ForegroundColor Yellow
    Write-Host "   Running as: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Install from org printer catalog"   -ForegroundColor White
    Write-Host "  [2] Add printer by IP address"          -ForegroundColor White
    Write-Host "  [3] Add printer by UNC path manually"   -ForegroundColor White
    Write-Host "  [4] Show installed printers"            -ForegroundColor White
    Write-Host "  [5] Remove a printer"                   -ForegroundColor White
    Write-Host "  [6] Set default printer"                -ForegroundColor White
    Write-Host "  [Q] Quit"                               -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "Printer Installer started by $env:USERNAME"
try {
    $keys = @($PrinterCatalog.Keys)
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host "`n  Available Network Printers:" -ForegroundColor Cyan
                $i = 1
                foreach ($name in $PrinterCatalog.Keys) {
                    $p = $PrinterCatalog[$name]
                    Write-Host ("  [{0,2}] {1,-40} Location: {2}" -f $i, $name, $p.Location)
                    $i++
                }
                Write-Host "  [A] Install ALL printers"
                $sel = Read-Host "`n  Select"
                if ($sel.ToUpper() -eq 'A') {
                    foreach ($name in $PrinterCatalog.Keys) {
                        Install-NetworkPrinter -PrinterPath $PrinterCatalog[$name].Path -PrinterName $name
                    }
                } else {
                    $idx = [int]$sel - 1
                    if ($idx -ge 0 -and $idx -lt $keys.Count) {
                        $name = $keys[$idx]
                        Install-NetworkPrinter -PrinterPath $PrinterCatalog[$name].Path -PrinterName $name
                    }
                }
                Read-Host "`nPress Enter"
            }
            '2' { Install-IPPrinter;         Read-Host "`nPress Enter" }
            '3' {
                $unc = Read-Host "  Enter UNC path (e.g. \\server\printer)"
                Install-NetworkPrinter -PrinterPath $unc
                Read-Host "`nPress Enter"
            }
            '4' { Show-InstalledPrinters;    Read-Host "`nPress Enter" }
            '5' { Remove-SelectedPrinter;    Read-Host "`nPress Enter" }
            '6' { Set-DefaultPrinterMenu;    Read-Host "`nPress Enter" }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}
Write-Log "Printer Installer exited"
