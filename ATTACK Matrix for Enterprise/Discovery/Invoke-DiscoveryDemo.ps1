<#
.SYNOPSIS
    Educational Purple Team demo - Discovery techniques (Phase 2)

.DESCRIPTION
    Safely demonstrates common MITRE ATT&CK Discovery techniques using only
    benign enumeration. Designed for isolated lab environments
    (SANS SEC504 Windows 10 Enterprise + Sysmon).

    Techniques covered:
    - T1082  System Information Discovery
    - T1057  Process Discovery
    - T1087  Account Discovery
    - T1016  System Network Configuration Discovery
    - T1083  File and Directory Discovery

    This script is intentionally noisy so that corresponding defensive
    hunting scripts can detect the activity via Sysmon Event ID 1 and
    PowerShell Script Block Logging (Event ID 4104).

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Development assisted by xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    Requires        : PowerShell 5.1+, local admin not required for most actions
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.EXAMPLE
    .\Invoke-DiscoveryDemo.ps1
#>

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 2 : DISCOVERY DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script performs only benign system enumeration.
  It creates marker files under C:\Users\Public\PurpleTeam-Phase2

  Do NOT run this on any system you do not own or lack
  explicit written permission to test.
========================================================================

"@
Write-Host $banner -ForegroundColor Cyan

$confirm = Read-Host "Type YES to continue in a lab environment"
if ($confirm -ne "YES") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ---------------------------------------------------------------------------
# Setup staging location (used later by Collection / Exfiltration demos)
# ---------------------------------------------------------------------------
$stagingRoot  = Join-Path $PSScriptRoot "PurpleTeam-Phase2"
$discoveryDir = Join-Path $stagingRoot "Discovery"
$reportFile   = Join-Path $discoveryDir "Discovery-Report.txt"
$markerFile   = Join-Path $discoveryDir "DiscoveryDemo-Marker.txt"

if (-not (Test-Path $discoveryDir)) {
    New-Item -ItemType Directory -Path $discoveryDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report = @()
$report += "=== Purple Team Phase 2 - Discovery Demo ==="
$report += "Timestamp : $timestamp"
$report += "User      : $env:USERNAME"
$report += "Host      : $env:COMPUTERNAME"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Staging directory : $discoveryDir" -ForegroundColor Green
Write-Host "[*] Report will be written to : $reportFile" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 1. System Information Discovery (T1082)
# ---------------------------------------------------------------------------
Write-Host "[+] T1082 - System Information Discovery" -ForegroundColor Yellow
Write-Host "    Running systeminfo.exe (first 25 lines)..." -ForegroundColor Gray

$sysInfo = systeminfo 2>$null | Select-Object -First 25
$sysInfo | ForEach-Object { Write-Host "    $_" }
$report += "=== T1082 System Information Discovery ==="
$report += $sysInfo
$report += ""

# PowerShell equivalent (appears in Script Block Logging)
$compInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer, CsProcessors, CsTotalPhysicalMemory
$report += "Get-ComputerInfo summary:"
$report += ($compInfo | Format-List | Out-String)
$report += ""

# ---------------------------------------------------------------------------
# 2. Process Discovery (T1057)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1057 - Process Discovery" -ForegroundColor Yellow
Write-Host "    Running tasklist.exe /FO LIST (sample)..." -ForegroundColor Gray

# Native binary (Sysmon Event ID 1)
$taskSample = tasklist /FO LIST 2>$null | Select-Object -First 40
$taskSample | ForEach-Object { Write-Host "    $_" }

$report += "=== T1057 Process Discovery (tasklist sample) ==="
$report += $taskSample
$report += ""

# PowerShell
$procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, WorkingSet
$report += "Top 10 processes by CPU (Get-Process):"
$report += ($procs | Format-Table -AutoSize | Out-String)
$report += ""

# ---------------------------------------------------------------------------
# 3. Account Discovery (T1087)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1087 - Account Discovery" -ForegroundColor Yellow
Write-Host "    whoami /all + local users..." -ForegroundColor Gray

# whoami.exe (classic)
$whoami = whoami /all 2>$null
$whoami | ForEach-Object { Write-Host "    $_" }

$report += "=== T1087 Account Discovery ==="
$report += $whoami
$report += ""

# Local users via PowerShell
try {
    $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon
    $report += "Get-LocalUser:"
    $report += ($localUsers | Format-Table -AutoSize | Out-String)
} catch {
    $report += "Get-LocalUser not available or access denied."
}
$report += ""

# ---------------------------------------------------------------------------
# 4. System Network Configuration Discovery (T1016)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1016 - System Network Configuration Discovery" -ForegroundColor Yellow
Write-Host "    ipconfig /all (sample)..." -ForegroundColor Gray

$ipconfig = ipconfig /all 2>$null | Select-Object -First 35
$ipconfig | ForEach-Object { Write-Host "    $_" }

$report += "=== T1016 Network Configuration Discovery ==="
$report += $ipconfig
$report += ""

# PowerShell
try {
    $netConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer
    $report += "Get-NetIPConfiguration:"
    $report += ($netConfig | Format-List | Out-String)
} catch {
    $report += "Get-NetIPConfiguration failed (module may not be available)."
}
$report += ""

# ---------------------------------------------------------------------------
# 5. File and Directory Discovery (T1083)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1083 - File and Directory Discovery" -ForegroundColor Yellow
Write-Host "    Searching common locations for interesting file types (list only)..." -ForegroundColor Gray

$searchPaths = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "C:\Users\Public"
)

$interestingExtensions = @("*.txt", "*.docx", "*.xlsx", "*.pdf", "*.config", "*.xml", "*.csv", "*.ps1")

$foundFiles = @()
foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        foreach ($ext in $interestingExtensions) {
            $matches = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Depth 2 |
                       Select-Object -First 5 FullName, Length, LastWriteTime
            if ($matches) {
                $foundFiles += $matches
            }
        }
    }
}

if ($foundFiles.Count -gt 0) {
    $foundFiles | ForEach-Object {
        Write-Host ("    {0}  ({1:N0} bytes)" -f $_.FullName, $_.Length)
    }
    $report += "=== T1083 File and Directory Discovery (sample) ==="
    $report += ($foundFiles | Format-Table -AutoSize | Out-String)
} else {
    Write-Host "    No matching files found in searched locations (this is fine)." -ForegroundColor Gray
    $report += "=== T1083 File and Directory Discovery ==="
    $report += "No matching files found in the limited search paths."
}
$report += ""

# ---------------------------------------------------------------------------
# Write report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 2 - Discovery Demo Marker
-------------------------------------------
Executed   : $timestamp
User       : $env:USERNAME
Computer   : $env:COMPUTERNAME
Techniques : T1082, T1057, T1087, T1016, T1083
Report     : $reportFile

This file is intentionally created so defensive scripts and later
Collection / Exfiltration demos have a clear artifact to work with.
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Discovery complete." -ForegroundColor Green
Write-Host "    Report  : $reportFile" -ForegroundColor Cyan
Write-Host "    Marker  : $markerFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] These artifacts will be useful for the Collection phase next." -ForegroundColor Green
Write-Host "[*] Remember to clean up C:\Users\Public\PurpleTeam-Phase2 when finished." -ForegroundColor Yellow
Write-Host ""
