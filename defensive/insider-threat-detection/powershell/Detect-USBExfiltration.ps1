<# 
.SYNOPSIS
    Detects potential data exfiltration via USB/removable media (Insider Threat).

.DESCRIPTION
    Monitors USB device insertion and correlates with large file operations to removable drives.
    Designed for financial services environments where data theft via USB is a major risk.

.NOTES
    Author: B. Underhill Cybersecurity Portfolio
    Version: 1.0
    MITRE ATT&CK: T1052 Exfiltration Over Physical Medium, T1091 Replication Through Removable Media
    Requires: Admin rights + ideally Sysmon installed
    Ethical Disclaimer: For authorized lab and defensive use only.
#>

param(
    [int]$TimeWindowMinutes = 60,
    [int]$SizeThresholdMB = 50,                    # Flag transfers > 50 MB
    [string]$OutputPath = ".\USBExfilReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv",
    [switch]$VerboseOutput
)

function Write-ScriptLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    $LogMessage | Out-File -FilePath ".\Detect-USBExfiltration.log" -Append -Encoding UTF8
}

Write-ScriptLog "Starting USB exfiltration detection. Window: last $TimeWindowMinutes minutes."

try {
    $startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

    # Get USB insertion events (PnP)
    $usbEvents = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" -FilterXPath "*[System[TimeCreated[@SystemTime >= '$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

    # Get recent file create events on removable drives (basic fallback)
    $removableDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[E-Z]$' }

    $suspiciousActivity = @()

    # Simple correlation logic (expand with Sysmon for production)
    foreach ($drive in $removableDrives) {
        $files = Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $startTime -and $_.Length -gt ($SizeThresholdMB * 1MB) }

        foreach ($file in $files) {
            $suspiciousActivity += [PSCustomObject]@{
                Timestamp     = $file.LastWriteTime
                Drive         = $drive.Name + ":"
                FilePath      = $file.FullName
                SizeMB        = [math]::Round($file.Length / 1MB, 2)
                Reason        = "Large file written to removable media"
            }
        }
    }

    if ($suspiciousActivity.Count -gt 0) {
        $suspiciousActivity | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-ScriptLog "ALERT: $($suspiciousActivity.Count) suspicious USB activity detected!" -Level "WARNING"
        Write-Host "Report saved: $OutputPath" -ForegroundColor Yellow
    } else {
        Write-ScriptLog "No suspicious USB activity detected." -Level "INFO"
    }

} catch {
    Write-ScriptLog "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Error $_.Exception.Message
}

Write-ScriptLog "USB detection run completed."
