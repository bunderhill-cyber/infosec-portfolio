<#
.SYNOPSIS
    Purple Team Phase 4 defensive hunter - Command and Control and Impact.

.DESCRIPTION
    Hunts for indicators from the Phase 4 offensive demos using Sysmon telemetry.

    Focus areas:
    - Command and Control (T1071.001):
        Sysmon Event ID 3 for connections to the lab listener
        (default 10.10.75.1:8080), and Event ID 1 for the beacon script.
    - Impact / Data Encrypted (T1486):
        Event ID 1 for Invoke-ImpactDemo.ps1 and Event ID 11 for
        *.purplelocked / READ_ME_PURPLETEAM.txt under the sandbox.
    - Inhibit System Recovery (T1490) - enumeration pattern:
        Event ID 1 for vssadmin.exe / wbadmin.exe / bcdedit.exe
        with list/enum command lines (not delete / disable).

    Designed for the SANS SEC504 Windows 10 lab with Sysmon installed.
    Requires Administrator rights to read the Sysmon Operational log.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Developed with assistance from xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise + Slingshot
    MITRE ATT&CK    : T1071.001, T1486, T1490
    Requires        : Administrator + Sysmon
    Ethical Use     : AUTHORIZED LAB / DEFENSIVE USE ONLY

.EXAMPLE
    .\Detect-C2AndImpact.ps1

.EXAMPLE
    .\Detect-C2AndImpact.ps1 -TimeWindowMinutes 180

.EXAMPLE
    .\Detect-C2AndImpact.ps1 -ListenerHost 10.10.75.1 -ListenerPort 8080
#>

param(
    [int]$TimeWindowMinutes = 180,
    [string]$ListenerHost = "10.10.75.1",
    [int]$ListenerPort = 8080,
    [string]$OutputPath = ".\Phase4-HuntReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
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
        [int]$MaxEvents = 800
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

function Get-SysmonField {
    param([string]$Message, [string]$Field)
    if ($Message -match "$Field`:\s*(.+)") { return $matches[1].Trim() }
    return ''
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  PURPLE TEAM PHASE 4 - DEFENSIVE HUNT" -ForegroundColor Cyan
Write-Host "  Command and Control / Impact" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
Write-HuntLog "Time window : last $TimeWindowMinutes minutes (since $($startTime.ToString('yyyy-MM-dd HH:mm:ss')))"
Write-HuntLog "C2 target   : ${ListenerHost}:$ListenerPort"
Write-HuntLog "Output CSV  : $OutputPath"
Write-Host ""

$findings = @()

# ===========================================================================
# 1. COMMAND AND CONTROL - HTTP beacon (Sysmon EID 3 + EID 1)
# ===========================================================================
Write-HuntLog "=== COMMAND AND CONTROL (Sysmon EID 3 / EID 1) ===" -Level "INFO"

$eid3 = Get-SysmonEvents -EventId 3 -StartTime $startTime -MaxEvents 800

if ($eid3.Count -eq 0) {
    Write-HuntLog "No Sysmon Event ID 3 (NetworkConnect) events in the window (or EID 3 not logged)." -Level "WARNING"
}
else {
    Write-HuntLog "Retrieved $($eid3.Count) NetworkConnect events. Scanning for lab C2..."

    foreach ($evt in $eid3) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $image     = Get-SysmonField $msg 'Image'
        $user      = Get-SysmonField $msg 'User'
        $destIp    = Get-SysmonField $msg 'DestinationIp'
        $destPort  = Get-SysmonField $msg 'DestinationPort'
        $srcIp     = Get-SysmonField $msg 'SourceIp'
        $protocol  = Get-SysmonField $msg 'Protocol'

        $destHostField = Get-SysmonField $msg 'DestinationHostname'
        $matchesListenerIp   = ($destIp -eq $ListenerHost)
        $matchesListenerPort = ($destPort -eq [string]$ListenerPort)
        $matchesHostName     = ($destHostField -match [regex]::Escape($ListenerHost))

        if (($matchesListenerIp -or $matchesHostName) -and $matchesListenerPort) {
            $findings += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                Tactic      = 'CommandAndControl'
                Technique   = 'T1071.001 HTTP beacon (NetworkConnect)'
                EventId     = 3
                Image       = $image
                ParentImage = ''
                CommandLine = ''
                User        = $user
                TargetFile  = ''
                Notes       = "src=$srcIp dest=${destIp}:$destPort proto=$protocol"
            }
            Write-HuntLog ("FOUND  {0}  |  T1071.001 EID3  |  {1} -> {2}:{3}" -f $evt.TimeCreated.ToString('HH:mm:ss'), $image, $destIp, $destPort) -Level "FOUND"
        }
    }
}

$eid1 = Get-SysmonEvents -EventId 1 -StartTime $startTime -MaxEvents 800

if ($eid1.Count -eq 0) {
    Write-HuntLog "No Sysmon Event ID 1 events found in the time window." -Level "WARNING"
}
else {
    Write-HuntLog "Retrieved $($eid1.Count) Process Create events. Scanning C2 / Impact patterns..."

    foreach ($evt in $eid1) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $image       = Get-SysmonField $msg 'Image'
        $parentImage = Get-SysmonField $msg 'ParentImage'
        $commandLine = Get-SysmonField $msg 'CommandLine'
        $user        = Get-SysmonField $msg 'User'

        $isC2 = $false
        $technique = ''
        $notes = ''

        if ($commandLine -match 'Invoke-C2BeaconDemo|C2BeaconDemo|PurpleTeam-Phase4\\C2') {
            $isC2 = $true
            $technique = 'T1071.001 HTTP beacon script'
            $notes = 'Phase 4 C2 demo script in CommandLine'
        }
        elseif ($image -match 'powershell\.exe' -and $commandLine -match [regex]::Escape($ListenerHost) -and $commandLine -match "$ListenerPort") {
            $isC2 = $true
            $technique = 'T1071.001 HTTP beacon (listener in CommandLine)'
            $notes = "PowerShell referencing ${ListenerHost}:$ListenerPort"
        }

        if ($isC2) {
            $findings += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                Tactic      = 'CommandAndControl'
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

Write-Host ""

# ===========================================================================
# 2. IMPACT - T1486 sandbox encryption + T1490 recovery enum
# ===========================================================================
Write-HuntLog "=== IMPACT (Sysmon EID 1 / EID 11) ===" -Level "INFO"

if ($eid1.Count -gt 0) {
    foreach ($evt in $eid1) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $image       = Get-SysmonField $msg 'Image'
        $parentImage = Get-SysmonField $msg 'ParentImage'
        $commandLine = Get-SysmonField $msg 'CommandLine'
        $user        = Get-SysmonField $msg 'User'

        $isImpact = $false
        $technique = ''
        $notes = ''

        if ($commandLine -match 'Invoke-ImpactDemo|ImpactSandbox|READ_ME_PURPLETEAM|purplelocked') {
            $isImpact = $true
            $technique = 'T1486 Data Encrypted for Impact (lab script)'
            $notes = 'Phase 4 Impact demo script or sandbox artifact in CommandLine'
        }
        elseif ($image -match 'vssadmin\.exe' -and $commandLine -match 'list\s+shadows|list\s+volumes') {
            $isImpact = $true
            $technique = 'T1490 Inhibit Recovery (vssadmin list only)'
            $notes = 'Enumeration of shadow copies / volumes — not delete'
        }
        elseif ($image -match 'wbadmin\.exe' -and $commandLine -match 'get\s+versions') {
            $isImpact = $true
            $technique = 'T1490 Inhibit Recovery (wbadmin get versions)'
            $notes = 'Backup version enumeration — not catalog delete'
        }
        elseif ($image -match 'bcdedit\.exe' -and $commandLine -match '/enum') {
            $isImpact = $true
            $technique = 'T1490 Inhibit Recovery (bcdedit /enum)'
            $notes = 'Boot configuration enumeration — not disable recovery'
        }

        if ($isImpact) {
            $tactic = if ($technique -match 'T1486') { 'Impact-Encrypt' } else { 'Impact-InhibitRecovery' }
            $findings += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                Tactic      = $tactic
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

$eid11 = Get-SysmonEvents -EventId 11 -StartTime $startTime -MaxEvents 500

if ($eid11.Count -eq 0) {
    Write-HuntLog "No Sysmon Event ID 11 events in window (or FileCreate filtered by config)." -Level "WARNING"
}
else {
    Write-HuntLog "Retrieved $($eid11.Count) FileCreate events. Scanning Impact sandbox paths..."

    foreach ($evt in $eid11) {
        $msg = $evt.Message
        if (-not $msg) { continue }

        $targetFile = Get-SysmonField $msg 'TargetFilename'
        $image      = Get-SysmonField $msg 'Image'
        $user       = Get-SysmonField $msg 'User'

        if ($targetFile -notmatch 'ImpactSandbox|purplelocked|READ_ME_PURPLETEAM|ImpactDemo-Marker|RecoveryEnum\.txt|Impact-Report\.txt') {
            continue
        }

        $findings += [PSCustomObject]@{
            Timestamp   = $evt.TimeCreated
            Tactic      = 'Impact-Encrypt'
            Technique   = 'T1486 sandbox FileCreate'
            EventId     = 11
            Image       = $image
            ParentImage = ''
            CommandLine = ''
            User        = $user
            TargetFile  = $targetFile
            Notes       = 'FileCreate under Phase 4 Impact paths'
        }
        Write-HuntLog ("FOUND  {0}  |  T1486 FileCreate  |  {1}" -f $evt.TimeCreated.ToString('HH:mm:ss'), $targetFile) -Level "FOUND"
    }
}

Write-Host ""

# ===========================================================================
# 3. Summary + export
# ===========================================================================
Write-HuntLog "=== SUMMARY ===" -Level "INFO"

if ($findings.Count -eq 0) {
    Write-HuntLog "No Phase 4 related activity detected in the time window." -Level "WARNING"
    Write-HuntLog "Re-run the offensive demos, then re-run this hunter (as Administrator)." -Level "INFO"
}
else {
    $byTactic = $findings | Group-Object Tactic
    foreach ($g in $byTactic) {
        Write-HuntLog ("{0,-24} : {1} finding(s)" -f $g.Name, $g.Count) -Level "FOUND"
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
Write-Host "  - C2 strong signal: Sysmon EID 3 to ${ListenerHost}:$ListenerPort" -ForegroundColor Yellow
Write-Host "  - Impact strong signal: vssadmin/wbadmin/bcdedit list|enum + *.purplelocked FileCreate" -ForegroundColor Yellow
Write-Host "  - FileCreate (EID 11) and NetworkConnect (EID 3) may be filtered by lab Sysmon config" -ForegroundColor Yellow
Write-Host "  - T1490 detections here are enumeration patterns, not destructive recovery-wipe" -ForegroundColor Yellow
Write-Host ""
