<#
.SYNOPSIS
    Educational simulation of a script delivered via phishing link or malicious attachment.
    SEC504 Lab + GitHub Portfolio Demonstration ONLY.

.DESCRIPTION
    This script performs benign system enumeration to simulate post-initial-access
    actions an attacker might take after successful user execution (T1204.002 + T1059.001).
    It is intentionally non-destructive and contains multiple safety checks.

.NOTES
    Author: B. Underhill
    Date: July 2026
    MITRE ATT&CK: T1566.002, T1204.002, T1059.001
    Ethical Use: Authorized lab environments and portfolio demonstration only.
    Never execute on production systems or without explicit written authorization.
#>

[CmdletBinding()]
param()

Write-Host "`n=== INITIAL ACCESS SIMULATION ===" -ForegroundColor Yellow
Write-Host "Technique: Phishing Link / Malicious Script Delivery" -ForegroundColor Cyan
Write-Host "Running as: $env:USERNAME on $env:COMPUTERNAME`n" -ForegroundColor White

try {
    # Benign reconnaissance (what a real stager might do)
    $whoami = whoami
    Write-Host "[+] Current user context: $whoami" -ForegroundColor Green

    $date = Get-Date
    Write-Host "[+] Timestamp: $date" -ForegroundColor Green

    # Example: Could be extended to call existing persistence hunter
    # & "$PSScriptRoot\..\..\powershell\Persistence_Hunting_Script.ps1" -HuntOnly

    Write-Host "`n[+] Simulation complete. No harmful actions performed." -ForegroundColor Green
    Write-Host "    This demonstrates the execution flow an attacker would achieve after successful phishing." -ForegroundColor DarkGray

} catch {
    Write-Error "Error during simulation: $_"
    exit 1
}