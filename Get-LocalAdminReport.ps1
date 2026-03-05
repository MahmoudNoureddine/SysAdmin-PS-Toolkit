#Requires -Version 5.1
<#
.SYNOPSIS
    Local Admin Report - Audits local Administrators group membership across computers.

.DESCRIPTION
    Connects to one or multiple remote computers and enumerates all members of the
    local Administrators group. Helps detect:
      - Unauthorized local admin accounts
      - Domain accounts with unexpected local admin rights
      - Stale or unrecognized local accounts with elevated privileges
      - Computers where too many users have local admin access

.PARAMETER ComputerName  One or more computer names. Defaults to local machine.
.PARAMETER OUPath        OU distinguished name to pull all computers from AD.
.PARAMETER OutputPath    Report directory. Defaults to Desktop.
.PARAMETER FlagDomainUsers  Flag any domain user accounts (not groups) found in local admins.

.EXAMPLE
    .\21_Get-LocalAdminReport.ps1
    .\21_Get-LocalAdminReport.ps1 -ComputerName "PC01","PC02","PC03"
    .\21_Get-LocalAdminReport.ps1 -OUPath "OU=Workstations,DC=corp,DC=local"
    .\21_Get-LocalAdminReport.ps1 -OUPath "OU=Workstations,DC=corp,DC=local" -FlagDomainUsers

.NOTES
    Requires: Remote Registry / WinRM enabled on target machines.
    Run as Domain Admin or with local admin rights on targets.
    Author  : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName   = @($env:COMPUTERNAME),
    [string]$OUPath           = "",
    [string]$OutputPath       = "$env:USERPROFILE\Desktop",
    [switch]$FlagDomainUsers
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $OutputPath "LocalAdminReport_$timestamp.log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} })
}

# Pull computers from AD OU if specified
if ($OUPath) {
    try {
        Write-Host "  Pulling computers from OU: $OUPath" -ForegroundColor Gray
        $ComputerName = (Get-ADComputer -Filter * -SearchBase $OUPath -ErrorAction Stop).Name
        Write-Host "  Found $($ComputerName.Count) computer(s) in OU" -ForegroundColor Cyan
    } catch {
        Write-Host "  [ERROR] Failed to query AD: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nLocal Admin Report" -ForegroundColor Green
Write-Host "  Scanning $($ComputerName.Count) computer(s)...`n" -ForegroundColor Cyan

$report      = [System.Collections.Generic.List[object]]::new()
$reachable   = 0
$unreachable = 0
$flagged     = [System.Collections.Generic.List[object]]::new()

foreach ($computer in $ComputerName) {
    Write-Host "  [$computer]" -ForegroundColor Cyan -NoNewline

    # Ping check
    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Host " UNREACHABLE" -ForegroundColor Red
        Write-Log "UNREACHABLE: $computer" "WARN"
        $report.Add([PSCustomObject]@{ Computer=$computer; Member="N/A"; MemberType="N/A"; Domain="N/A"; Status="Unreachable"; Flagged=$false })
        $unreachable++
        continue
    }

    try {
        # Get local admins via ADSI
        $admins = ([ADSI]"WinNT://$computer/Administrators,group").Invoke("Members") |
            ForEach-Object {
                $member = [ADSI]$_
                [PSCustomObject]@{
                    Name   = $member.Name[0]
                    Path   = $member.Path
                    Class  = $member.Class[0]
                }
            }

        Write-Host " $($admins.Count) member(s)" -ForegroundColor $(if ($admins.Count -gt 3) { "Yellow" } else { "Green" })

        foreach ($admin in $admins) {
            # Parse domain from WinNT path: WinNT://DOMAIN/Username
            $parts  = $admin.Path -replace "WinNT://","" -split "/"
            $domain = if ($parts.Count -ge 2) { $parts[0] } else { "LOCAL" }
            $isDomainUser = ($domain -ne $computer -and $admin.Class -eq "User")

            $flag = $FlagDomainUsers -and $isDomainUser

            if ($flag) {
                Write-Host ("    *** FLAGGED: {0}\{1} (Domain User with local admin)" -f $domain, $admin.Name) -ForegroundColor Red
                $flagged.Add([PSCustomObject]@{ Computer=$computer; Account="$domain\$($admin.Name)" })
            } else {
                Write-Host ("    - {0,-25} Type:{1,-10} Domain:{2}" -f $admin.Name, $admin.Class, $domain)
            }

            $report.Add([PSCustomObject]@{
                Computer    = $computer
                Member      = $admin.Name
                MemberType  = $admin.Class
                Domain      = $domain
                IsDomainUser = $isDomainUser
                Status      = "OK"
                Flagged     = $flag
            })
        }

        Write-Log "Scanned: $computer | $($admins.Count) admin member(s)" "OK"
        $reachable++

    } catch {
        Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "ERROR on $computer : $($_.Exception.Message)" "ERROR"
        $report.Add([PSCustomObject]@{ Computer=$computer; Member="ERROR"; MemberType="N/A"; Domain="N/A"; Status=$_.Exception.Message; Flagged=$false })
        $unreachable++
    }
}

# Summary
Write-Host "`n  ================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Computers scanned : $($ComputerName.Count)"
Write-Host "  Reachable         : $reachable" -ForegroundColor Green
Write-Host "  Unreachable       : $unreachable" -ForegroundColor $(if($unreachable){"Red"}else{"White"})
Write-Host "  Total admin entries: $($report.Count)"

if ($flagged.Count -gt 0) {
    Write-Host "`n  *** $($flagged.Count) FLAGGED: Domain users with local admin rights ***" -ForegroundColor Red
    $flagged | ForEach-Object { Write-Host "    - $($_.Computer): $($_.Account)" -ForegroundColor Red }
}

# Computers with unusually high admin count
$highAdmin = $report | Where-Object { $_.Status -eq "OK" } | Group-Object Computer | Where-Object { $_.Count -gt 3 }
if ($highAdmin) {
    Write-Host "`n  Computers with more than 3 local admins:" -ForegroundColor Yellow
    $highAdmin | ForEach-Object { Write-Host "    - $($_.Name): $($_.Count) members" -ForegroundColor Yellow }
}

$csv = Join-Path $OutputPath "LocalAdminReport_$timestamp.csv"
$report | Export-Csv $csv -NoTypeInformation
Write-Host "`n  [OK] Report exported: $csv" -ForegroundColor Green
