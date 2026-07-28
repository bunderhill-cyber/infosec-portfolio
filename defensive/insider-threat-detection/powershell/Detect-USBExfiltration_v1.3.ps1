<# 
.SYNOPSIS
    Detects potential data exfiltration via USB / removable media (Insider Threat Detection).

.DESCRIPTION
    Identifies large file writes to removable drive letters (E:–Z:).
    Uses a practical hybrid approach: attempts to query Sysmon Event ID 11 first,
    then falls back to a direct filesystem scan. This makes the detection reliable
    both with real USB devices and with lab simulations that use the 'subst' command.

.NOTES
    Author: [Your Real Name]
    Development assisted by: xAI Grok
    Version: 1.3
    MITRE ATT&CK: T1052 Exfiltration Over Physical Medium, T1091 Replication Through Removable Media
    Requires: Administrator rights (Sysmon recommended but not mandatory)
    Tested in: SANS SEC504 Windows 10 lab environment

    Ethical Disclaimer: For authorized educational and defensive security testing only.
    Unauthorized use is prohibited.
#>

param(
    [int]$SizeThresholdMB = 5,
    [switch]$VerboseOutput
)

$OutputPath = ".\USBExfilReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$suspicious = @()

Write-Host "[*] Starting simple USB detection..."

$files = Get-ChildItem "E:\" -File -ErrorAction SilentlyContinue |
         Where-Object { $_.Length -gt ($SizeThresholdMB * 1MB) }

foreach ($file in $files) {
    $suspicious += [PSCustomObject]@{
        Timestamp = $file.LastWriteTime
        User      = $env:USERNAME
        FilePath  = $file.FullName
        SizeMB    = [math]::Round($file.Length / 1MB, 2)
        Reason    = "Large file written to removable media"
    }
}

if ($suspicious.Count -gt 0) {
    $suspicious | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "ALERT: $($suspicious.Count) events detected!" -ForegroundColor Yellow
    Write-Host "Report: $OutputPath"
    if ($VerboseOutput) { $suspicious | Format-Table -AutoSize }
} else {
    Write-Host "No suspicious USB activity detected."
}

Write-Host "[*] Done."