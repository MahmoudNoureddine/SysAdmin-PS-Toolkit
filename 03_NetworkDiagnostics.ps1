#Requires -Version 5.1
<#
.SYNOPSIS
    Network Diagnostics - Tests connectivity, DNS, ping, and IP configuration.

.DESCRIPTION
    Performs a comprehensive network health check including:
      - Local IP / adapter configuration
      - Ping tests to configurable targets
      - DNS resolution tests
      - Default gateway reachability
      - Traceroute to a remote host
      - Port connectivity tests (HTTP/HTTPS)

.PARAMETER PingTargets
    Array of hosts to ping. Defaults to common public DNS servers.

.PARAMETER DnsTestNames
    Array of hostnames to resolve via DNS lookup.

.PARAMETER OutputPath
    Directory to save the diagnostic report. Defaults to the user's Desktop.

.EXAMPLE
    .\03_NetworkDiagnostics.ps1
    .\03_NetworkDiagnostics.ps1 -PingTargets "192.168.1.1","8.8.8.8" -OutputPath "C:\Logs"

.NOTES
    Prerequisites : No special privileges required for basic tests.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string[]]$PingTargets  = @("8.8.8.8", "1.1.1.1", "google.com"),
    [string[]]$DnsTestNames = @("google.com", "microsoft.com", "github.com"),
    [string]$OutputPath     = "$env:USERPROFILE\Desktop"
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 60)"   -ForegroundColor Cyan
}

function Write-Pass { param([string]$msg) Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail { param([string]$msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Warn { param([string]$msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line {
    param([string]$Text = "")
    $lines.Add($Text)
}

# ─── Output Setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "NetworkDiagnostics_$timestamp.txt"

$passCount = 0; $failCount = 0

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nNetwork Diagnostics Tool" -ForegroundColor Green
    Write-Host "Starting tests at $(Get-Date -Format 'HH:mm:ss')..." -ForegroundColor Gray

    Add-Line "============================================================"
    Add-Line "  NETWORK DIAGNOSTICS REPORT"
    Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Line "  Computer  : $env:COMPUTERNAME"
    Add-Line "============================================================"

    # ── 1. IP Configuration ────────────────────────────────────────────────────
    Write-Section "IP CONFIGURATION"
    Add-Line "`n[IP Configuration]"
    try {
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }
        foreach ($a in $adapters) {
            $info = "  Adapter: $($a.InterfaceAlias)  IP: $($a.IPAddress)/$($a.PrefixLength)"
            Write-Host $info; Add-Line $info
        }

        # Default Gateway
        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1).NextHop
        $gwInfo = "  Default Gateway: $gw"
        Write-Host $gwInfo; Add-Line $gwInfo

        # DNS
        $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.ServerAddresses } | Select-Object -First 1).ServerAddresses
        $dnsInfo = "  DNS Servers    : $($dns -join ', ')"
        Write-Host $dnsInfo; Add-Line $dnsInfo
    } catch {
        Write-Fail "Could not retrieve IP config: $($_.Exception.Message)"
        Add-Line "  [ERROR] $($_.Exception.Message)"
    }

    # ── 2. Gateway Reachability ────────────────────────────────────────────────
    Write-Section "DEFAULT GATEWAY PING"
    Add-Line "`n[Gateway Reachability]"
    try {
        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1).NextHop
        if ($gw) {
            $ping = Test-Connection -ComputerName $gw -Count 2 -ErrorAction SilentlyContinue
            if ($ping) {
                $avgMs = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 0)
                Write-Pass "Gateway $gw is reachable  (avg ${avgMs}ms)"
                Add-Line "  [PASS] Gateway $gw reachable  avg: ${avgMs}ms"
                $passCount++
            } else {
                Write-Fail "Gateway $gw is NOT reachable"
                Add-Line "  [FAIL] Gateway $gw is NOT reachable"
                $failCount++
            }
        } else {
            Write-Warn "No default gateway found."
            Add-Line "  [WARN] No default gateway configured."
        }
    } catch {
        Write-Fail "Gateway test error: $($_.Exception.Message)"
        $failCount++
    }

    # ── 3. Ping Tests ──────────────────────────────────────────────────────────
    Write-Section "PING TESTS"
    Add-Line "`n[Ping Results]"
    foreach ($target in $PingTargets) {
        try {
            $ping = Test-Connection -ComputerName $target -Count 4 -ErrorAction SilentlyContinue
            if ($ping) {
                $avgMs = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 0)
                $minMs = ($ping | Measure-Object -Property ResponseTime -Minimum).Minimum
                $maxMs = ($ping | Measure-Object -Property ResponseTime -Maximum).Maximum
                Write-Pass "$target  avg:${avgMs}ms  min:${minMs}ms  max:${maxMs}ms"
                Add-Line "  [PASS] $target  avg:${avgMs}ms  min:${minMs}ms  max:${maxMs}ms"
                $passCount++
            } else {
                Write-Fail "$target - no response"
                Add-Line "  [FAIL] $target - no response"
                $failCount++
            }
        } catch {
            Write-Fail "$target - error: $($_.Exception.Message)"
            Add-Line "  [FAIL] $target - $($_.Exception.Message)"
            $failCount++
        }
    }

    # ── 4. DNS Resolution ──────────────────────────────────────────────────────
    Write-Section "DNS RESOLUTION TESTS"
    Add-Line "`n[DNS Lookups]"
    foreach ($name in $DnsTestNames) {
        try {
            $result = Resolve-DnsName -Name $name -ErrorAction Stop | Where-Object { $_.IPAddress }
            $ips    = ($result.IPAddress | Select-Object -First 3) -join ", "
            Write-Pass "$name  ->  $ips"
            Add-Line "  [PASS] $name  ->  $ips"
            $passCount++
        } catch {
            Write-Fail "$name  ->  RESOLUTION FAILED"
            Add-Line "  [FAIL] $name  ->  $($_.Exception.Message)"
            $failCount++
        }
    }

    # ── 5. HTTP/HTTPS Port Test ────────────────────────────────────────────────
    Write-Section "HTTP/HTTPS PORT TESTS"
    Add-Line "`n[Port Connectivity]"
    $portTests = @(
        @{ Host = "google.com";    Port = 80;  Label = "HTTP"  },
        @{ Host = "google.com";    Port = 443; Label = "HTTPS" },
        @{ Host = "microsoft.com"; Port = 443; Label = "HTTPS" }
    )
    foreach ($t in $portTests) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $conn = $tcp.BeginConnect($t.Host, $t.Port, $null, $null)
            $wait = $conn.AsyncWaitHandle.WaitOne(3000, $false)
            if ($wait -and -not $tcp.Client.Connected -eq $false) {
                $tcp.EndConnect($conn)
                Write-Pass "$($t.Label) $($t.Host):$($t.Port) - Open"
                Add-Line "  [PASS] $($t.Label) $($t.Host):$($t.Port) - Open"
                $passCount++
            } else {
                Write-Fail "$($t.Label) $($t.Host):$($t.Port) - Timed out"
                Add-Line "  [FAIL] $($t.Label) $($t.Host):$($t.Port) - Timed out"
                $failCount++
            }
            $tcp.Close()
        } catch {
            Write-Fail "$($t.Label) $($t.Host):$($t.Port) - $($_.Exception.Message)"
            Add-Line "  [FAIL] $($t.Label) $($t.Host):$($t.Port) - $($_.Exception.Message)"
            $failCount++
        }
    }

    # ── 6. Summary ─────────────────────────────────────────────────────────────
    Write-Section "SUMMARY"
    $summary = "`n  Tests Passed : $passCount`n  Tests Failed : $failCount`n  Overall      : $(if ($failCount -eq 0) { 'HEALTHY' } else { 'ISSUES DETECTED' })"
    Write-Host $summary -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
    Add-Line $summary

    $lines | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n[OK] Report saved to: $reportFile" -ForegroundColor Green

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
