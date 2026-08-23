<#
.SYNOPSIS
    Purple Team Phase 3 defensive hunter - Privilege Escalation and Lateral Movement.

.DESCRIPTION
    Hunts for indicators from the Phase 3 offensive demos using Sysmon telemetry.

    Focus areas:
    - Privilege Escalation (T1053.005):
        Sysmon Event ID 1 for powershell.exe parented by Task Scheduler
        (svchost.exe / taskeng.exe), and activity related to the lab task name.
    - Lateral Movement (T1021.006):
        Sysmon Event ID 1 for wsmprovhost.exe / remoting-related powershell.exe,
        and FileCreate under the lab remote marker path.

    Designed for the SANS SEC504 Windows 10 lab with Sysmon installed.
    Requires Administrator rights to read the Sysmon Operational log.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Developed with assistance from xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    MITRE ATT&CK    : T1053.005, T1548, T1021.006
    Requires        : Administrator + Sysmon
    Ethical Use     : AUTHORIZED LAB / DEFENSIVE USE ONLY

.EXAMPLE
    .\Detect-PrivEscAndLateral.ps1

.EXAMPLE
    .\Detect-PrivEscAndLateral.ps1 -TimeWindowMinutes 180
#>

param(
    [int]$TimeWindowMinutes = 90,
    [string]$OutputPath = ".\Phase3-HuntReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
)

function Write-HuntLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "ALERT"   { Write-Host $line -ForegroundColor Red }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "FOUND"   { Write-Host $line -ForegroundColor Green }
        default   { Write-Host $line }
    }
}

function Get-SysmonEvents {
    param(
        [int]$EventId,
        [datetime]$StartTime,
        [int]$MaxEvents = 500
    )
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = $EventId
            StartTime = $StartTime
        } -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        return @()
    }
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  PURPLE TEAM PHASE 3 - DEFENSIVE HUNT" -ForegroundColor Cyan
Write-Host "  Privilege Escalation / Lateral Movement" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
Write-HuntLog "Time window : last $TimeWindowMinutes minutes (since $($startTime.ToString('yyyy-MM-dd HH:mm:ss')))"
Write-HuntLog "Output CSV  : $OutputPath"
Write-Host ""

$findings = @()

# ===========================================================================
# 1. PRIVILEGE ESCALATION - Scheduled Task elevation (Sysmon EID 1)
# ===========================================================================
Write-HuntLog "=== PRIVILEGE ESCALATION (Sysmon EID 1) ===" -Level "INFO"

$eid1 = Get-SysmonEvents -EventId 1 -StartTime $startTime -MaxEvents 400

if ($eid1.Count -eq 0) {
    Write-HuntLog "No Sysmon Event ID 1 events found in the time window." -Level "WARNING"
}
else {
    Write-HuntLog "Retrieved $($eid1.Count) Process Create events. Scanning for PrivEsc patterns..."

    foreach ($evt in $eid1) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $image       = if ($msg -match 'Image:\s*(.+)') { $matches[1].Trim() } else { '' }
        $parentImage = if ($msg -match 'ParentImage:\s*(.+)') { $matches[1].Trim() } else { '' }
        $commandLine = if ($msg -match 'CommandLine:\s*(.+)') { $matches[1].Trim() } else { '' }
        $user        = if ($msg -match 'User:\s*(.+)') { $matches[1].Trim() } else { '' }

        $isPrivEsc = $false
        $technique = ''
        $notes     = ''

        # Task Scheduler spawning PowerShell (classic T1053.005 elevation path)
        if ($image -match 'powershell\.exe' -and $parentImage -match 'svchost\.exe|taskeng\.exe') {
            $isPrivEsc = $true
            $technique = 'T1053.005 Scheduled Task (elevated context)'
            $notes     = 'powershell.exe parented by Task Scheduler host'
        }
        # Lab helper / task name in command line
        elseif ($commandLine -match 'ElevatedTask-Helper|PurpleTeam-Phase3-PrivEscDemo') {
            $isPrivEsc = $true
            $technique = 'T1053.005 Scheduled Task lab artifact'
            $notes     = 'Phase 3 PrivEsc helper or task name in CommandLine'
        }
        # whoami from elevated helper context (supporting signal)
        elseif ($image -match 'whoami\.exe' -and $parentImage -match 'powershell\.exe' -and
                $commandLine -match 'whoami') {
            # Only flag if recent PrivEsc activity context - keep as low-noise supporting
            # Skip generic whoami to reduce noise; main signal is powershell<-svchost
        }

        if ($isPrivEsc) {
            $findings += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                Tactic      = 'PrivilegeEscalation'
                Technique   = $technique
                EventId     = 1
                Image       = $image
                ParentImage = $parentImage
                CommandLine = $commandLine
                User        = $user
                TargetFile  = ''
                Notes       = $notes
            }
            Write-HuntLog ("FOUND  {0}  |  {1}  |  Parent: {2}" -f $evt.TimeCreated.ToString('HH:mm:ss'), $technique, $parentImage) -Level "FOUND"
        }
    }
}

Write-Host ""

# ===========================================================================
# 2. LATERAL MOVEMENT - WinRM / remoting (Sysmon EID 1 + EID 11)
# ===========================================================================
Write-HuntLog "=== LATERAL MOVEMENT (Sysmon EID 1 / EID 11) ===" -Level "INFO"

# Process creates related to WinRM host process
if ($eid1.Count -gt 0) {
    foreach ($evt in $eid1) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $image       = if ($msg -match 'Image:\s*(.+)') { $matches[1].Trim() } else { '' }
        $parentImage = if ($msg -match 'ParentImage:\s*(.+)') { $matches[1].Trim() } else { '' }
        $commandLine = if ($msg -match 'CommandLine:\s*(.+)') { $matches[1].Trim() } else { '' }
        $user        = if ($msg -match 'User:\s*(.+)') { $matches[1].Trim() } else { '' }

        $isLM = $false
        $technique = ''
        $notes = ''

        if ($image -match 'wsmprovhost\.exe') {
            $isLM = $true
            $technique = 'T1021.006 WinRM (wsmprovhost)'
            $notes = 'Windows Remote Management host process'
        }
        elseif ($image -match 'powershell\.exe' -and $commandLine -match 'PurpleTeam-Phase3-LM|LM-Remote-Marker') {
            $isLM = $true
            $technique = 'T1021.006 WinRM remote payload'
            $notes = 'PowerShell related to LM remote marker path'
        }

        if ($isLM) {
            $findings += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                Tactic      = 'LateralMovement'
                Technique   = $technique
                EventId     = 1
                Image       = $image
                ParentImage = $parentImage
                CommandLine = $commandLine
                User        = $user
                TargetFile  = ''
                Notes       = $notes
            }
            Write-HuntLog ("FOUND  {0}  |  {1}  |  {2}" -f $evt.TimeCreated.ToString('HH:mm:ss'), $technique, $image) -Level "FOUND"
        }
    }
}

# FileCreate for remote marker path
$eid11 = Get-SysmonEvents -EventId 11 -StartTime $startTime -MaxEvents 300

if ($eid11.Count -eq 0) {
    Write-HuntLog "No Sysmon Event ID 11 events in window (or FileCreate filtered by config)." -Level "WARNING"
}
else {
    Write-HuntLog "Retrieved $($eid11.Count) FileCreate events. Scanning for LM marker paths..."

    foreach ($evt in $eid11) {
        $msg = $evt.Message
        if (-not $msg) { continue }
        if ($msg -notmatch 'PurpleTeam-Phase3-LM|LM-Remote-Marker') { continue }

        $targetFile = if ($msg -match 'TargetFilename:\s*(.+)') { $matches[1].Trim() } else { 'n/a' }
        $image      = if ($msg -match 'Image:\s*(.+)') { $matches[1].Trim() } else { 'n/a' }
        $user       = if ($msg -match 'User:\s*(.+)') { $matches[1].Trim() } else { 'n/a' }

        $findings += [PSCustomObject]@{
            Timestamp   = $evt.TimeCreated
            Tactic      = 'LateralMovement'
            Technique   = 'T1021.006 WinRM remote marker write'
            EventId     = 11
            Image       = $image
            ParentImage = ''
            CommandLine = ''
            User        = $user
            TargetFile  = $targetFile
            Notes       = 'FileCreate under LM staging path'
        }
        Write-HuntLog ("FOUND  {0}  |  T1021.006 marker  |  {1}" -f $evt.TimeCreated.ToString('HH:mm:ss'), $targetFile) -Level "FOUND"
    }
}

Write-Host ""

# ===========================================================================
# 3. Summary + export
# ===========================================================================
Write-HuntLog "=== SUMMARY ===" -Level "INFO"

if ($findings.Count -eq 0) {
    Write-HuntLog "No Phase 3 related activity detected in the time window." -Level "WARNING"
    Write-HuntLog "Re-run the offensive demos, then re-run this hunter (as Administrator)." -Level "INFO"
}
else {
    $byTactic = $findings | Group-Object Tactic
    foreach ($g in $byTactic) {
        Write-HuntLog ("{0,-20} : {1} finding(s)" -f $g.Name, $g.Count) -Level "FOUND"
    }

    Write-Host ""
    Write-Host "Detailed findings:" -ForegroundColor Cyan
    $findings |
        Sort-Object Timestamp |
        Format-Table Timestamp, Tactic, Technique, EventId, Image, ParentImage, TargetFile -AutoSize -Wrap

    try {
        $findings | Sort-Object Timestamp | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-HuntLog "Results exported to: $OutputPath" -Level "INFO"
    }
    catch {
        Write-HuntLog "Failed to write CSV: $($_.Exception.Message)" -Level "WARNING"
    }
}

Write-Host ""
Write-HuntLog "Hunt complete." -Level "INFO"
Write-Host ""
Write-Host "Notes:" -ForegroundColor Yellow
Write-Host "  - PrivEsc strong signal: powershell.exe parented by svchost.exe/taskeng.exe" -ForegroundColor Yellow
Write-Host "  - LM strong signal: wsmprovhost.exe and/or marker under PurpleTeam-Phase3-LM" -ForegroundColor Yellow
Write-Host "  - FileCreate (EID 11) may be filtered by lab Sysmon config" -ForegroundColor Yellow
Write-Host ""
