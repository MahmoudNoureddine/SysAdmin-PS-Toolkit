#Requires -Version 5.1
<#
.SYNOPSIS
    Local User Provisioning - Creates and configures local user accounts on remote machines.

.DESCRIPTION
    Creates local user accounts on one or multiple remote computers:
      - Set username, full name, description, and password
      - Optionally add to local Administrators or other local groups
      - Set password never expires / user must change password options
      - Bulk provision from CSV file
      - Full audit log of all account creations
      - Confirmation required before any changes

.PARAMETER ComputerName  Target computer(s). Required unless using CSV.
.PARAMETER Username      Local username to create. Required unless using CSV.
.PARAMETER FullName      Display name for the account.
.PARAMETER Description   Account description.
.PARAMETER Password      SecureString password. Will prompt if not provided.
.PARAMETER AddToGroup    Local group to add the user to (e.g. "Administrators", "Remote Desktop Users").
.PARAMETER PasswordNeverExpires  Set password to never expire.
.PARAMETER CSVPath       CSV file for bulk provisioning (columns: ComputerName,Username,FullName,Description,Group).
.PARAMETER OutputPath    Log directory. Defaults to Desktop.

.EXAMPLE
    .\25_New-LocalUserProvision.ps1 -ComputerName "Kiosk01" -Username "kiosk" -FullName "Kiosk Account" -AddToGroup "Users"
    .\25_New-LocalUserProvision.ps1 -ComputerName "Server01","Server02" -Username "svc_backup" -AddToGroup "Administrators" -PasswordNeverExpires
    .\25_New-LocalUserProvision.ps1 -CSVPath "C:\LocalUsers.csv"

.NOTES
    CSV format: ComputerName,Username,FullName,Description,Group
    Requires: Local admin rights on target machines.
    Author  : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName       = @(),
    [string]$Username             = "",
    [string]$FullName             = "",
    [string]$Description          = "Provisioned by IT Admin",
    [System.Security.SecureString]$Password,
    [string]$AddToGroup           = "",
    [switch]$PasswordNeverExpires,
    [string]$CSVPath              = "",
    [string]$OutputPath           = "$env:USERPROFILE\Desktop"
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $OutputPath "LocalUserProvision_$timestamp.log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] [Op:$env:USERNAME] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L) { "ERROR"{"Red"} "OK"{"Green"} "WARN"{"Yellow"} default{"Gray"} })
}

function New-RemoteLocalUser {
    param(
        [string]$Computer,
        [string]$User,
        [string]$Name,
        [string]$Desc,
        [System.Security.SecureString]$Pwd,
        [string]$Group,
        [bool]$PwdNeverExpires
    )

    Write-Host "`n  Creating '$User' on [$Computer]..." -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -EA SilentlyContinue)) {
        Write-Log "UNREACHABLE: $Computer" "ERROR"; return $false
    }

    try {
        $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd)
        )

        # Check if user already exists
        $existing = Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($u); Get-LocalUser -Name $u -ErrorAction SilentlyContinue
        } -ArgumentList $User -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Log "SKIPPED: $User on $Computer — user already exists" "WARN"
            return $false
        }

        # Create user
        Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($u, $fn, $desc, $pwd, $group, $pwdNeverExp)
            $secPwd = ConvertTo-SecureString $pwd -AsPlainText -Force
            $params = @{ Name=$u; Password=$secPwd; FullName=$fn; Description=$desc; AccountNeverExpires=$true; ErrorAction="Stop" }
            if ($pwdNeverExp) { $params["PasswordNeverExpires"] = $true } else { $params["UserMustChangePasswordAtNextLogon"] = $false }
            New-LocalUser @params | Out-Null
            if ($group) { Add-LocalGroupMember -Group $group -Member $u -ErrorAction Stop }
        } -ArgumentList $User, $Name, $Desc, $plainPwd, $Group, $PwdNeverExpires -ErrorAction Stop

        $groupStr = if ($Group) { " | Group: $Group" } else { "" }
        Write-Log "CREATED: $User on $Computer | FullName: $Name$groupStr" "OK"
        Write-Host "  [OK] Created: $User on $Computer" -ForegroundColor Green
        return $true

    } catch {
        Write-Log "FAILED: $User on $Computer - $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

Write-Host "`nLocal User Provisioning" -ForegroundColor Green

# Build provisioning list
$provisionList = [System.Collections.Generic.List[object]]::new()

if ($CSVPath) {
    if (-not (Test-Path $CSVPath)) { throw "CSV not found: $CSVPath" }
    $csv = Import-Csv $CSVPath -ErrorAction Stop
    foreach ($row in $csv) {
        $provisionList.Add(@{ Computer=$row.ComputerName; User=$row.Username; FullName=$row.FullName; Desc=$row.Description; Group=$row.Group })
    }
    Write-Host "  Loaded $($provisionList.Count) account(s) from CSV" -ForegroundColor Cyan
} else {
    if (-not $ComputerName -or -not $Username) { throw "Provide -ComputerName and -Username, or use -CSVPath." }
    foreach ($c in $ComputerName) {
        $provisionList.Add(@{ Computer=$c; User=$Username; FullName=$FullName; Desc=$Description; Group=$AddToGroup })
    }
}

# Prompt for password if not provided
if (-not $Password) {
    Write-Host "`n  Enter password for the new account(s):" -ForegroundColor Yellow
    $Password = Read-Host "  Password" -AsSecureString
    $confirm  = Read-Host "  Confirm password" -AsSecureString
    $p1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $p2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
    if ($p1 -ne $p2) { throw "Passwords do not match." }
}

# Preview
Write-Host "`n  Accounts to create:" -ForegroundColor Cyan
$provisionList | ForEach-Object { Write-Host ("  Computer: {0,-20} User: {1,-15} Group: {2}" -f $_["Computer"], $_["User"], $_["Group"]) }

$confirm = Read-Host "`n  Create $($provisionList.Count) local account(s)? (Y/N)"
if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; exit 0 }

# Execute
$ok = 0; $fail = 0; $results = [System.Collections.Generic.List[object]]::new()
foreach ($item in $provisionList) {
    $success = New-RemoteLocalUser -Computer $item["Computer"] -User $item["User"] -Name $item["FullName"] `
        -Desc $item["Desc"] -Pwd $Password -Group $item["Group"] -PwdNeverExpires $PasswordNeverExpires.IsPresent
    if ($success) { $ok++ } else { $fail++ }
    $results.Add([PSCustomObject]@{ Computer=$item["Computer"]; Username=$item["User"]; Group=$item["Group"]; Status=if($success){"Created"}else{"Failed/Skipped"} })
}

# Summary
Write-Host "`n  ================================================" -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
Write-Host "  PROVISIONING COMPLETE: $ok created, $fail failed/skipped" -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
Write-Host "  ================================================" -ForegroundColor $(if($fail){"Yellow"}else{"Green"})

$resultCsv = Join-Path $OutputPath "LocalUserProvision_Results_$timestamp.csv"
$results | Export-Csv $resultCsv -NoTypeInformation
Write-Host "  Results : $resultCsv" -ForegroundColor Gray
Write-Host "  Log     : $logFile"   -ForegroundColor Gray
