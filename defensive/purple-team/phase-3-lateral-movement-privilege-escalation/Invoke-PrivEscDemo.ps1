<#
.SYNOPSIS
    Educational Purple Team demo - Privilege Escalation techniques (Phase 3)

.DESCRIPTION
    Safely demonstrates common MITRE ATT&CK Privilege Escalation patterns using
    only benign actions. Designed for isolated lab environments
    (SANS SEC504 Windows 10 Enterprise + Sysmon).

    Techniques covered:
    - T1053.005  Scheduled Task/Job: Scheduled Task (RunLevel Highest)
    - T1548      Abuse Elevation Control Mechanism (context / pattern)
    - Supporting enumeration of current integrity level and privileges

    The script creates a benign scheduled task configured to run with the
    highest privileges available to the user, executes it once to write a
    marker file, then leaves clear artifacts for defensive hunting.

    No exploits, no UAC bypass binaries, no real privilege abuse beyond
    standard administrative scheduled-task behavior.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Development assisted by xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    Requires        : PowerShell 5.1+; Administrator recommended for full demo
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.EXAMPLE
    .\Invoke-PrivEscDemo.ps1
#>

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 3 : PRIVILEGE ESCALATION DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script demonstrates elevation patterns using only benign
  scheduled-task behavior. No exploits or UAC bypasses are used.

  Artifacts are created in a PurpleTeam-Phase3 folder
  next to this script.

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
# Setup staging location
# ---------------------------------------------------------------------------
$stagingRoot = Join-Path $PSScriptRoot "PurpleTeam-Phase3"
$privEscDir  = Join-Path $stagingRoot "PrivEsc"
$reportFile  = Join-Path $privEscDir "PrivEsc-Report.txt"
$markerFile  = Join-Path $privEscDir "PrivEscDemo-Marker.txt"
$taskMarker  = Join-Path $privEscDir "ElevatedTask-Marker.txt"

foreach ($dir in @($stagingRoot, $privEscDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$taskName  = "PurpleTeam-Phase3-PrivEscDemo"
$report = @()
$report += "=== Purple Team Phase 3 - Privilege Escalation Demo ==="
$report += "Timestamp : $timestamp"
$report += "User      : $env:USERNAME"
$report += "Host      : $env:COMPUTERNAME"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Staging directory : $privEscDir" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Current privilege / integrity context (enumeration)
# ---------------------------------------------------------------------------
Write-Host "[+] Enumerating current privilege context..." -ForegroundColor Yellow

$whoamiAll = whoami /all 2>$null
$whoamiPriv = whoami /priv 2>$null
$whoamiGroups = whoami /groups 2>$null

Write-Host "    User    : $(whoami)" -ForegroundColor Gray
Write-Host "    Integrity / groups (sample):" -ForegroundColor Gray
$whoamiGroups | Select-Object -First 12 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }

$report += "=== Current Context ==="
$report += "whoami     : $(whoami)"
$report += ""
$report += "whoami /groups (excerpt):"
$report += ($whoamiGroups | Select-Object -First 20)
$report += ""
$report += "whoami /priv (excerpt):"
$report += ($whoamiPriv | Select-Object -First 25)
$report += ""

# Integrity level via whoami groups (High Mandatory Level = elevated)
$isElevated = $false
if ($whoamiGroups -match "High Mandatory Level") {
    $isElevated = $true
    Write-Host "    [+] Current process appears ELEVATED (High Mandatory Level)" -ForegroundColor Green
} else {
    Write-Host "    [*] Current process does not show High Mandatory Level" -ForegroundColor Yellow
    Write-Host "        (Run PowerShell as Administrator for the full scheduled-task demo)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 2. T1053.005 - Scheduled Task with highest privileges
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1053.005 - Scheduled Task (RunLevel Highest)" -ForegroundColor Yellow
Write-Host "    Creating benign scheduled task: $taskName" -ForegroundColor Gray

# Remove any previous instance of this lab task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Write a small helper script the scheduled task will run (avoids nested-quoting issues)
$helperScript = Join-Path $privEscDir "ElevatedTask-Helper.ps1"
$helperContent = @"
# Purple Team Phase 3 - benign elevated task helper
# Created by Invoke-PrivEscDemo.ps1 - safe to delete
`$t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
`$u = whoami
`$i = (whoami /groups | Select-String 'Mandatory Label' | ForEach-Object { `$_.Line })
@(
    'Purple Team Phase 3 - Elevated Task Marker'
    "Executed: `$t"
    "User: `$u"
    "Integrity: `$i"
    'This task was created by Invoke-PrivEscDemo.ps1'
) | Out-File -FilePath '$taskMarker' -Encoding UTF8
"@
$helperContent | Out-File -FilePath $helperScript -Encoding ASCII

try {
    $actionArgs = "-NoProfile -WindowStyle Hidden -File `"$helperScript`""
    $action     = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $actionArgs
    $trigger    = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(10)
    $principal  = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $settings   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $taskName `
                           -Action $action `
                           -Trigger $trigger `
                           -Principal $principal `
                           -Settings $settings `
                           -Description "Purple Team Phase 3 lab demo - benign privilege escalation pattern (T1053.005). Safe to delete." `
                           -Force | Out-Null

    Write-Host "    [+] Scheduled task registered with RunLevel Highest" -ForegroundColor Green
    Write-Host "    [+] Helper script : $helperScript" -ForegroundColor Gray

    # Start it once now
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Start-Sleep -Seconds 3

    if (Test-Path $taskMarker) {
        Write-Host "    [+] Elevated task ran and wrote marker: $taskMarker" -ForegroundColor Green
    } else {
        Write-Host "    [*] Task started; marker may appear shortly (check $taskMarker)" -ForegroundColor Yellow
    }

    $report += "=== T1053.005 Scheduled Task ==="
    $report += "Task name    : $taskName"
    $report += "RunLevel     : Highest"
    $report += "Helper script: $helperScript"
    $report += "Marker file  : $taskMarker"
    $report += "Status       : Registered and started once"
    $report += ""
}
catch {
    Write-Host "    [!] Failed to create/start scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "        Ensure you are running an elevated PowerShell session." -ForegroundColor Yellow
    $report += "=== T1053.005 Scheduled Task ==="
    $report += "FAILED: $($_.Exception.Message)"
    $report += ""
}

# ---------------------------------------------------------------------------
# 3. Show the task for defender visibility
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] Listing lab scheduled task (defender-visible artifact)..." -ForegroundColor Yellow
try {
    $taskInfo = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop |
                Select-Object TaskName, State, @{N='RunLevel';E={ $_.Principal.RunLevel }}
    $taskInfo | Format-List | Out-String | Write-Host -ForegroundColor Gray
    $report += "=== Task Info ==="
    $report += ($taskInfo | Format-List | Out-String)
}
catch {
    Write-Host "    [*] Could not query task details." -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Write report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 3 - Privilege Escalation Demo Marker
------------------------------------------------------
Executed   : $timestamp
User       : $env:USERNAME
Computer   : $env:COMPUTERNAME
Techniques : T1053.005 (Scheduled Task, RunLevel Highest), T1548 (elevation context)
Task Name  : $taskName
Report     : $reportFile
Task Marker: $taskMarker

Cleanup:
  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false
  Remove-Item -Recurse -Force '$stagingRoot'
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Privilege Escalation demo complete." -ForegroundColor Green
Write-Host "    Report      : $reportFile" -ForegroundColor Cyan
Write-Host "    Marker      : $markerFile" -ForegroundColor Cyan
Write-Host "    Task marker : $taskMarker" -ForegroundColor Cyan
Write-Host "    Task name   : $taskName" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Defenders should look for:" -ForegroundColor Green
Write-Host "    - Sysmon EID 1: powershell.exe spawned by taskeng.exe / svchost (Task Scheduler)" -ForegroundColor Gray
Write-Host "    - Security / TaskScheduler operational logs for task creation" -ForegroundColor Gray
Write-Host "    - Scheduled task with RunLevel Highest and suspicious action" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Cleanup when finished:" -ForegroundColor Yellow
Write-Host "    Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor Yellow
Write-Host "    Remove-Item -Recurse -Force '$stagingRoot'" -ForegroundColor Yellow
Write-Host ""
