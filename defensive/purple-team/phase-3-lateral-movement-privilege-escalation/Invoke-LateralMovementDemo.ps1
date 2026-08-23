<#
.SYNOPSIS
    Educational Purple Team demo - Lateral Movement via WinRM (Phase 3)

.DESCRIPTION
    Safely demonstrates MITRE ATT&CK Lateral Movement using PowerShell Remoting
    (WinRM). Designed for the SANS SEC504 lab with Windows 10 + Slingshot on the
    same internal network.

    Technique:
    - T1021.006  Remote Services: Windows Remote Management

    The script runs benign remote commands only (whoami, hostname, write a marker
    file on the target). No credential theft, no persistence, no destructive actions.

    Typical lab layout:
    - Windows SEC504 VM : 10.10.0.1  (target / detection focus, Sysmon)
    - Slingshot         : 10.10.75.1 (optional alternate source host)

    You can run this script:
    A) From the Windows VM targeting itself (localhost / 10.10.0.1) to prove WinRM
       and generate local telemetry, or
    B) From any host that can reach the target over WinRM with valid lab credentials.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Development assisted by xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise + Slingshot
    Requires        : PowerShell 5.1+; WinRM enabled on target; lab credentials
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.PARAMETER TargetHost
    Computer name or IP of the WinRM target. Default: 10.10.0.1

.PARAMETER UseCurrentCredentials
    Try current session credentials instead of prompting (works well for localhost).

.EXAMPLE
    .\Invoke-LateralMovementDemo.ps1

.EXAMPLE
    .\Invoke-LateralMovementDemo.ps1 -TargetHost 10.10.0.1

.EXAMPLE
    .\Invoke-LateralMovementDemo.ps1 -TargetHost localhost -UseCurrentCredentials
#>

param(
    [string]$TargetHost = "10.10.0.1",
    [switch]$UseCurrentCredentials
)

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 3 : LATERAL MOVEMENT DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script uses WinRM (PowerShell Remoting) to run ONLY benign
  commands on the target (whoami, hostname, write a marker file).

  No credential dumping. No persistence. No destructive actions.

  Target (default): 10.10.0.1 (SEC504 Windows VM)
  Ensure WinRM is enabled and you have permission to test.

  Do NOT run this against systems you do not own or lack
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
# Setup local staging (on the machine running this script)
# ---------------------------------------------------------------------------
$stagingRoot = Join-Path $PSScriptRoot "PurpleTeam-Phase3"
$lmDir       = Join-Path $stagingRoot "LateralMovement"
$reportFile  = Join-Path $lmDir "LateralMovement-Report.txt"
$markerFile  = Join-Path $lmDir "LateralMovementDemo-Marker.txt"

foreach ($dir in @($stagingRoot, $lmDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report = @()
$report += "=== Purple Team Phase 3 - Lateral Movement Demo ==="
$report += "Timestamp  : $timestamp"
$report += "Operator   : $env:USERNAME@$env:COMPUTERNAME"
$report += "TargetHost : $TargetHost"
$report += "Technique  : T1021.006 Windows Remote Management"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Local staging : $lmDir" -ForegroundColor Green
Write-Host "[*] Target host   : $TargetHost" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Connectivity check
# ---------------------------------------------------------------------------
Write-Host "[+] Checking WinRM reachability to $TargetHost ..." -ForegroundColor Yellow

try {
    $wsman = Test-WSMan -ComputerName $TargetHost -ErrorAction Stop
    Write-Host "    [+] Test-WSMan succeeded" -ForegroundColor Green
    $report += "Test-WSMan : SUCCESS"
}
catch {
    Write-Host "    [!] Test-WSMan failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "        On the target, run: winrm quickconfig -Force" -ForegroundColor Yellow
    $report += "Test-WSMan : FAILED - $($_.Exception.Message)"
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host ""
    Write-Host "[!] Aborting - WinRM not reachable." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Credential handling
# ---------------------------------------------------------------------------
$cred = $null
$invokeParams = @{
    ComputerName = $TargetHost
    ErrorAction  = 'Stop'
}

$isLocal = ($TargetHost -eq 'localhost' -or $TargetHost -eq '127.0.0.1' -or
            $TargetHost -eq $env:COMPUTERNAME -or $TargetHost -eq '10.10.0.1')

if ($UseCurrentCredentials -or $isLocal) {
    Write-Host "[*] Using current session credentials" -ForegroundColor Gray
    $report += "Credentials : current session"
}
else {
    Write-Host "[*] Prompting for lab credentials for $TargetHost" -ForegroundColor Gray
    $cred = Get-Credential -Message "Lab credentials for WinRM to $TargetHost"
    $invokeParams['Credential'] = $cred
    $report += "Credentials : prompted (lab account)"
}

# ---------------------------------------------------------------------------
# 3. T1021.006 - Remote benign commands via WinRM
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1021.006 - Windows Remote Management (benign commands)" -ForegroundColor Yellow

$remoteScript = {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $user = whoami
    $hostName = $env:COMPUTERNAME
    $markerDir = 'C:\Users\Public\PurpleTeam-Phase3-LM'
    if (-not (Test-Path $markerDir)) {
        New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
    }
    $remoteMarker = Join-Path $markerDir 'LM-Remote-Marker.txt'
    @(
        'Purple Team Phase 3 - Lateral Movement Remote Marker'
        "Executed  : $ts"
        "User      : $user"
        "Host      : $hostName"
        'Source    : WinRM / PowerShell Remoting (T1021.006)'
        'This file was created by Invoke-LateralMovementDemo.ps1'
    ) | Out-File -FilePath $remoteMarker -Encoding UTF8

    [PSCustomObject]@{
        Timestamp    = $ts
        User         = $user
        Hostname     = $hostName
        RemoteMarker = $remoteMarker
        Whoami       = (whoami /all | Select-Object -First 8) -join ' | '
    }
}

try {
    Write-Host "    Running remote whoami / hostname / marker write on $TargetHost ..." -ForegroundColor Gray
    $result = Invoke-Command @invokeParams -ScriptBlock $remoteScript

    Write-Host "    [+] Remote execution succeeded" -ForegroundColor Green
    Write-Host "        Remote user     : $($result.User)" -ForegroundColor Gray
    Write-Host "        Remote hostname : $($result.Hostname)" -ForegroundColor Gray
    Write-Host "        Remote marker   : $($result.RemoteMarker)" -ForegroundColor Gray

    $report += "Remote execution : SUCCESS"
    $report += "Remote user      : $($result.User)"
    $report += "Remote hostname  : $($result.Hostname)"
    $report += "Remote marker    : $($result.RemoteMarker)"
    $report += "Whoami (excerpt) : $($result.Whoami)"
    $report += ""
}
catch {
    Write-Host "    [!] Invoke-Command failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "        Check WinRM config, firewall, and credentials." -ForegroundColor Yellow
    $report += "Remote execution : FAILED - $($_.Exception.Message)"
    $report += ""
}

# ---------------------------------------------------------------------------
# 4. Local report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 3 - Lateral Movement Demo Marker
--------------------------------------------------
Executed   : $timestamp
Operator   : $env:USERNAME@$env:COMPUTERNAME
TargetHost : $TargetHost
Technique  : T1021.006 Windows Remote Management
Report     : $reportFile

Remote marker (on target):
  C:\Users\Public\PurpleTeam-Phase3-LM\LM-Remote-Marker.txt

Cleanup on target:
  Remove-Item -Recurse -Force C:\Users\Public\PurpleTeam-Phase3-LM

Cleanup on operator host:
  Remove-Item -Recurse -Force '$stagingRoot'
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Lateral Movement demo complete." -ForegroundColor Green
Write-Host "    Local report  : $reportFile" -ForegroundColor Cyan
Write-Host "    Local marker  : $markerFile" -ForegroundColor Cyan
Write-Host "    Remote marker : C:\Users\Public\PurpleTeam-Phase3-LM\LM-Remote-Marker.txt" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Defenders (on the Windows target) should look for:" -ForegroundColor Green
Write-Host "    - Sysmon EID 1: wsmprovhost.exe / powershell.exe in remoting context" -ForegroundColor Gray
Write-Host "    - Microsoft-Windows-WinRM / Operational and PowerShell logs" -ForegroundColor Gray
Write-Host "    - Network logon (type 3) related to WinRM" -ForegroundColor Gray
Write-Host "    - FileCreate under C:\Users\Public\PurpleTeam-Phase3-LM\" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] To run the same pattern from Slingshot (if pwsh is available):" -ForegroundColor Yellow
Write-Host "    pwsh -Command \"Invoke-Command -ComputerName 10.10.0.1 -ScriptBlock { whoami; hostname }\"" -ForegroundColor Yellow
Write-Host ""
