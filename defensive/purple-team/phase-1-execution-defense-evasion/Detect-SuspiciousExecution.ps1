<#
.SYNOPSIS
    Detects suspicious execution and defense-evasion activity related to LOLBins and AMSI bypass attempts.

.DESCRIPTION
    Hunts for common indicators of Living-Off-the-Land binary abuse and AMSI bypass techniques.
    Uses Sysmon (preferred) and Windows PowerShell / Security logs.
    Designed as the defensive counterpart to Invoke-LolbinDemo.ps1 and Invoke-AmsiBypassDemo.ps1.

.NOTES
    Author: B. Underhill
    Version: 1.0
    MITRE ATT&CK:
        T1059  - Command and Scripting Interpreter
        T1218  - System Binary Proxy Execution
        T1047  - Windows Management Instrumentation
        T1562.001 - Impair Defenses: Disable or Modify Tools (AMSI)
    Requires: Administrator or appropriate log access. Sysmon strongly recommended.
    Lab / authorized use only.

.EXAMPLE
    .\Detect-SuspiciousExecution.ps1
    .\Detect-SuspiciousExecution.ps1 -TimeWindowMinutes 60 -VerboseOutput
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [int]$TimeWindowMinutes = 60,
    [string]$OutputPath = ".\SuspiciousExecution_$(Get-Date -Format 'yyyyMMdd_HHmm').csv",
    [switch]$VerboseOutput
)

function Write-ScriptLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    $LogMessage | Out-File -FilePath ".\Detect-SuspiciousExecution.log" -Append -Encoding UTF8
}

Write-ScriptLog "Starting suspicious execution hunt. Looking back $TimeWindowMinutes minutes."

$startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
$findings = @()

try {
    # ============================================
    # 1. Sysmon Process Creation (Event ID 1) - Preferred
    # ============================================
    $sysmonLog = "Microsoft-Windows-Sysmon/Operational"
    if (Get-WinEvent -ListLog $sysmonLog -ErrorAction SilentlyContinue) {
        Write-ScriptLog "Sysmon log found. Querying process creation events..." -Level "DEBUG"

        $filter = "*[System[EventID=1 and TimeCreated[@SystemTime >= '$($startTime.ToUniversalTime().ToString('o'))']]]"
        $events = Get-WinEvent -LogName $sysmonLog -FilterXPath $filter -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            try {
                $xml = [xml]$event.ToXml()
                $data = $xml.Event.EventData.Data

                $image         = ($data | Where-Object { $_.Name -eq 'Image' }).'#text'
                $commandLine   = ($data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
                $parentImage   = ($data | Where-Object { $_.Name -eq 'ParentImage' }).'#text'
                $user          = ($data | Where-Object { $_.Name -eq 'User' }).'#text'
                $processId     = ($data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'

                $reason = @()

                # LOLBin checks
                if ($image -match '\\mshta\.exe$')                          { $reason += "mshta.exe execution" }
                if ($image -match '\\rundll32\.exe$')                       { $reason += "rundll32.exe execution" }
                if ($image -match '\\regsvr32\.exe$')                       { $reason += "regsvr32.exe execution" }
                if ($image -match '\\wmic\.exe$')                           { $reason += "wmic.exe execution" }
                if ($image -match '\\msiexec\.exe$' -and $commandLine -match '/q') { $reason += "msiexec quiet install pattern" }

                # Encoded / suspicious PowerShell
                if ($commandLine -match '-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}' -or 
                    $commandLine -match '-e\s+[A-Za-z0-9+/=]{20,}') {
                    $reason += "Encoded PowerShell command"
                }

                # Suspicious parent-child or javascript/mshta patterns
                if ($commandLine -match 'javascript:' -or $commandLine -match 'vbscript:') {
                    $reason += "Scriptlet / javascript protocol in command line"
                }
                if ($commandLine -match 'scrobj\.dll' -or $commandLine -match '\.sct') {
                    $reason += "Possible regsvr32 SCT / scrobj pattern"
                }

                # AMSI-related suspicious patterns (heuristic)
                if ($commandLine -match 'AmsiUtils' -or $commandLine -match 'amsi\.dll' -or 
                    $commandLine -match 'AmsiScanBuffer' -or $commandLine -match 'amsiInitFailed') {
                    $reason += "Possible AMSI bypass / tampering indicator"
                }

                if ($reason.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Timestamp    = $event.TimeCreated
                        Technique    = ($reason -join " | ")
                        Image        = $image
                        CommandLine  = $commandLine
                        ParentImage  = $parentImage
                        User         = $user
                        ProcessId    = $processId
                        Source       = "Sysmon Event ID 1"
                    }
                }
            }
            catch {
                # Skip malformed events
            }
        }
    }
    else {
        Write-ScriptLog "Sysmon log not found. Falling back to other sources." -Level "WARNING"
    }

    # ============================================
    # 2. PowerShell Script Block Logging (Event ID 4104)
    # ============================================
    $psLog = "Microsoft-Windows-PowerShell/Operational"
    if (Get-WinEvent -ListLog $psLog -ErrorAction SilentlyContinue) {
        Write-ScriptLog "Checking PowerShell Script Block logging (4104)..." -Level "DEBUG"

        $filterPS = "*[System[EventID=4104 and TimeCreated[@SystemTime >= '$($startTime.ToUniversalTime().ToString('o'))']]]"
        $psEvents = Get-WinEvent -LogName $psLog -FilterXPath $filterPS -ErrorAction SilentlyContinue

        foreach ($event in $psEvents) {
            try {
                $msg = $event.Message
                $reason = @()

                if ($msg -match 'AmsiUtils' -or $msg -match 'AmsiScanBuffer' -or $msg -match 'amsiInitFailed') {
                    $reason += "AMSI bypass pattern in script block"
                }
                if ($msg -match '-enc(odedcommand)?' -or $msg -match 'FromBase64String') {
                    $reason += "Encoded / Base64 content in script block"
                }
                if ($msg -match 'mshta' -or $msg -match 'rundll32' -or $msg -match 'regsvr32') {
                    $reason += "LOLBin reference inside PowerShell script block"
                }

                if ($reason.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Timestamp    = $event.TimeCreated
                        Technique    = ($reason -join " | ")
                        Image        = "powershell.exe (ScriptBlock)"
                        CommandLine  = ($msg -replace "`r|`n", " ").Substring(0, [Math]::Min(300, $msg.Length))
                        ParentImage  = "N/A"
                        User         = "N/A"
                        ProcessId    = "N/A"
                        Source       = "PowerShell Event ID 4104"
                    }
                }
            }
            catch { }
        }
    }

    # ============================================
    # Output
    # ============================================
    if ($findings.Count -gt 0) {
        $findings = $findings | Sort-Object Timestamp -Descending
        $findings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

        Write-ScriptLog "ALERT: $($findings.Count) suspicious execution event(s) detected!" -Level "WARNING"
        Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Yellow

        if ($VerboseOutput) {
            $findings | Format-Table Timestamp, Technique, Image, User -AutoSize
        }
        else {
            $findings | Select-Object Timestamp, Technique, Image, User | Format-Table -AutoSize
        }
    }
    else {
        Write-ScriptLog "No suspicious execution activity detected in the time window." -Level "INFO"
        Write-Host "No suspicious execution activity detected." -ForegroundColor Green
    }
}
catch {
    Write-ScriptLog "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Error $_.Exception.Message
}
finally {
    Write-ScriptLog "Suspicious execution hunt completed."
}