#Requires -Version 5.1
<#
.SYNOPSIS
    Remote Command Runner - Execute PowerShell commands on one or multiple remote machines.

.DESCRIPTION
    Runs a PowerShell script block or command string on remote computers using
    WinRM (Invoke-Command). Supports:
      - Single command on one or many machines
      - Load a .ps1 script file and run it remotely
      - Parallel execution (ThrottleLimit configurable)
      - Per-machine result capture and error handling
      - Full output and error log per run
      - Optional credential prompt

.PARAMETER ComputerName  Target computer(s). Required.
.PARAMETER Command       PowerShell command string to execute remotely.
.PARAMETER ScriptFile    Path to a .ps1 file to run on remote machines.
.PARAMETER ThrottleLimit Max concurrent connections. Default: 10.
.PARAMETER Credential    PSCredential for remote auth (optional, prompts if not set).
.PARAMETER OutputPath    Report directory. Defaults to Desktop.

.EXAMPLE
    .\22_Invoke-RemoteCommand.ps1 -ComputerName "PC01","PC02" -Command "Get-Service Spooler"
    .\22_Invoke-RemoteCommand.ps1 -ComputerName "PC01" -ScriptFile "C:\Scripts\fix.ps1"
    .\22_Invoke-RemoteCommand.ps1 -ComputerName (Get-Content servers.txt) -Command "Restart-Service Spooler" -ThrottleLimit 5

.NOTES
    Requires: WinRM enabled on target machines (Enable-PSRemoting).
    Author  : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [string]$Command      = "",
    [string]$ScriptFile   = "",
    [int]$ThrottleLimit   = 10,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath   = "$env:USERPROFILE\Desktop"
)

if (-not $Command -and -not $ScriptFile) { throw "Provide either -Command or -ScriptFile." }
if ($ScriptFile -and -not (Test-Path $ScriptFile)) { throw "Script file not found: $ScriptFile" }
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $OutputPath "RemoteCommand_$timestamp.log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L) { "ERROR"{"Red"} "OK"{"Green"} "WARN"{"Yellow"} default{"Gray"} })
}

# Build script block
$scriptBlock = if ($ScriptFile) {
    Write-Host "  Loading script: $ScriptFile" -ForegroundColor Gray
    [scriptblock]::Create((Get-Content $ScriptFile -Raw))
} else {
    [scriptblock]::Create($Command)
}

Write-Host "`nRemote Command Execution" -ForegroundColor Green
Write-Host "  Targets    : $($ComputerName.Count) computer(s)"
Write-Host "  Command    : $(if($ScriptFile){"[Script] $ScriptFile"}else{$Command})"
Write-Host "  Throttle   : $ThrottleLimit concurrent`n"

$confirm = Read-Host "  Execute on $($ComputerName.Count) machine(s)? (Y/N)"
if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; exit 0 }

# Invoke
$invokeParams = @{
    ComputerName  = $ComputerName
    ScriptBlock   = $scriptBlock
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = "SilentlyContinue"
}
if ($Credential) { $invokeParams["Credential"] = $Credential }

Write-Host "`n  Running..." -ForegroundColor Gray
$startTime = Get-Date

$results = Invoke-Command @invokeParams -ErrorVariable remoteErrors 2>&1

$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

# Display results per machine
$report = [System.Collections.Generic.List[object]]::new()
$successCount = 0; $errorCount = 0

Write-Host "`n  Results:" -ForegroundColor Cyan
Write-Host ("  {0,-25} {1,-10} {2}" -f "Computer","Status","Output")
Write-Host ("  {0,-25} {1,-10} {2}" -f "--------","------","------")

foreach ($r in $results) {
    $output = if ($r -is [string]) { $r } else { $r | Out-String -Width 120 }
    $output = $output.Trim() -replace "`r`n","; "
    if ($output.Length -gt 80) { $output = $output.Substring(0,77) + "..." }
    Write-Host ("  {0,-25} {1,-10} {2}" -f $r.PSComputerName, "OK", $output) -ForegroundColor Green
    Write-Log "OK: $($r.PSComputerName) | $output" "OK"
    $report.Add([PSCustomObject]@{ Computer=$r.PSComputerName; Status="OK"; Output=$r | Out-String; Error="" })
    $successCount++
}

# Capture errors
foreach ($err in $remoteErrors) {
    $comp = $err.TargetObject
    Write-Host ("  {0,-25} {1,-10} {2}" -f $comp, "ERROR", $err.Exception.Message) -ForegroundColor Red
    Write-Log "ERROR: $comp | $($err.Exception.Message)" "ERROR"
    $report.Add([PSCustomObject]@{ Computer=$comp; Status="ERROR"; Output=""; Error=$err.Exception.Message })
    $errorCount++
}

# Summary
Write-Host "`n  ================================================" -ForegroundColor Cyan
Write-Host "  EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Elapsed   : ${elapsed}s"
Write-Host "  Succeeded : $successCount" -ForegroundColor Green
Write-Host "  Failed    : $errorCount"   -ForegroundColor $(if($errorCount){"Red"}else{"White"})

$csv = Join-Path $OutputPath "RemoteCommand_$timestamp.csv"
$report | Export-Csv $csv -NoTypeInformation
Write-Host "  [OK] Results exported: $csv" -ForegroundColor Green
Write-Host "  [OK] Log saved: $logFile"    -ForegroundColor Green
