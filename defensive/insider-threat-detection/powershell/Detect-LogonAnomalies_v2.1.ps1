<# 
.SYNOPSIS
    Detects anomalous Windows logon activity for insider threat hunting.

.DESCRIPTION
    Analyzes Windows Security Event Logs to identify suspicious logon patterns, including:
    - Off-hours logons
    - Logons from unusual workstations
    - Spikes in failed logon attempts

    Designed for financial services and regulated environments where abuse of valid accounts is a high risk.

.NOTES
    Author: B. Underhill
    Development assisted by: xAI Grok
    Version: 2.1
    MITRE ATT&CK: T1078 Valid Accounts, T1110 Brute Force
    Requires: Administrator or Event Log Readers rights
    Tested in: SANS SEC504 Windows 10 lab environment

    Ethical Disclaimer: For authorized educational and defensive security testing only.
    Unauthorized use is prohibited.
#>

param(
    [datetime]$StartTime = (Get-Date).AddHours(-4),
    [datetime]$EndTime = (Get-Date),
    [int]$BusinessStartHour = 7,
    [int]$BusinessEndHour = 19,
    [string[]]$AllowedWorkstationPatterns = @("DESKTOP-", "WORKSTATION-", "SEC504", "STUDENT"),
    [switch]$VerboseOutput
)

# Full logging function
function Write-ScriptLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    $LogMessage | Out-File -FilePath ".\Detect-LogonAnomalies.log" -Append -Encoding UTF8
}

Write-ScriptLog "Starting improved anomalous logon detection..."

try {
    $filter = "*[System[(EventID=4624 or EventID=4625 or EventID=4648) and TimeCreated[@SystemTime>='$($StartTime.ToUniversalTime().ToString('o'))']]]"
    $events = Get-WinEvent -LogName "Security" -FilterXPath $filter -ErrorAction Stop

    $anomalies = @()
    $logonStats = @{}

    foreach ($event in $events) {
        $time = $event.TimeCreated
        $hour = $time.Hour
        $user = $event.Properties[5].Value
        $workstation = $event.Properties[11].Value
        $ip = $event.Properties[18].Value
        $eventId = $event.Id

        if ($user -match "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS)") { continue }

        if (-not $logonStats.ContainsKey($user)) {
            $logonStats[$user] = @{Total=0; OffHours=0; Failed=0}
        }
        $logonStats[$user].Total++
        if ($eventId -eq 4625) { $logonStats[$user].Failed++ }

        $isOffHours = ($hour -lt $BusinessStartHour) -or ($hour -ge $BusinessEndHour)
        if ($isOffHours) { $logonStats[$user].OffHours++ }

        $isUnusual = $true
        foreach ($p in $AllowedWorkstationPatterns) {
            if ($workstation -like "*$p*") { $isUnusual = $false; break }
        }

        if ($isOffHours -or $isUnusual -or ($eventId -eq 4625 -and $logonStats[$user].Failed -ge 3)) {
            $reason = if ($isOffHours) { "Off-hours logon" }
                      elseif ($isUnusual) { "Unusual workstation" }
                      else { "Failed logon spike" }

            $anomalies += [PSCustomObject]@{
                Timestamp                = $time
                User                     = $user
                EventID                  = $eventId
                Workstation              = $workstation
                IPAddress                = $ip
                IsOffHours               = $isOffHours
                IsUnusualWorkstation     = $isUnusual
                Reason                   = $reason
            }
        }
    }

    if ($anomalies.Count -gt 0) {
        $reportPath = ".\LogonAnomalyReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $anomalies | Export-Csv -Path $reportPath -NoTypeInformation
        Write-Host "ALERT: $($anomalies.Count) anomalies detected!" -ForegroundColor Yellow
        Write-Host "Report saved: $reportPath" -ForegroundColor Yellow
    } else {
        Write-Host "No anomalies detected." -ForegroundColor Green
    }

    # Summary report
    $logonStats.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            User          = $_.Key
            TotalLogons   = $_.Value.Total
            OffHours      = $_.Value.OffHours
            FailedLogons  = $_.Value.Failed
        }
    } | Export-Csv -Path ".\LogonSummary_$(Get-Date -Format 'yyyyMMdd_HHmm').csv" -NoTypeInformation

} catch {
    Write-ScriptLog "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Error $_.Exception.Message
}

Write-ScriptLog "Detection run completed."
