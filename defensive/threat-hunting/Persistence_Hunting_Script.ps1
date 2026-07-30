# ================================================
#   PERSISTENCE HUNTING SCRIPT - Windows PCs
#   SEC504 Style - Threat Hunting
# ================================================

<#
.SYNOPSIS
    Persistence Hunting Script for Windows PCs (Threat Hunting)

.DESCRIPTION
    Scans common persistence mechanisms: Startup programs, Scheduled Tasks,
    Registry Run keys, Browser extensions, and WMI subscriptions.
    Designed for authorized threat hunting on home/owned systems.

.DISCLAIMER
    For educational and authorized use only. Do not run on systems you do
    do not own or have explicit permission to inspect.
#>
$ReportFolder = "$HOME\Documents\PersistenceHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null
Set-Location $ReportFolder

Write-Host "=== Persistence Hunt Started ===" -ForegroundColor Green
Write-Host "Report folder: $ReportFolder`n" -ForegroundColor Cyan

# 1. Startup Programs
Write-Host "`n[1] Startup Programs" -ForegroundColor Cyan
Get-CimInstance Win32_StartupCommand | 
    Select-Object Name, Command, Location, User | 
    Export-Csv "$ReportFolder\Startup-Programs.csv" -NoTypeInformation
Get-CimInstance Win32_StartupCommand | Out-GridView -Title "Startup Programs"

# 2. Scheduled Tasks (Enabled only)
Write-Host "`n[2] Scheduled Tasks" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object State -ne "Disabled" | 
    Select-Object TaskName, TaskPath, State, Author, LastRunTime | 
    Export-Csv "$ReportFolder\Scheduled-Tasks.csv" -NoTypeInformation
Get-ScheduledTask | Where-Object State -ne "Disabled" | Out-GridView -Title "Enabled Scheduled Tasks"

# 3. Registry Run Keys
Write-Host "`n[3] Registry Run Keys" -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-GridView -Title "HKLM Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-GridView -Title "HKCU Run"

# 4. Browser Extensions
Write-Host "`n[4] Browser Extensions" -ForegroundColor Cyan

# Brave
Get-ChildItem "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions" -ErrorAction SilentlyContinue | 
    Select-Object Name, LastWriteTime | Out-GridView -Title "Brave Extensions"

# Edge
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" -ErrorAction SilentlyContinue | 
    Select-Object Name, LastWriteTime | Out-GridView -Title "Edge Extensions"

# 5. WMI Persistence Check
Write-Host "`n[5] WMI Persistence Check" -ForegroundColor Cyan
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Out-GridView -Title "WMI Event Filters"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | 
    Select-Object Name, __CLASS, CommandLineTemplate, ScriptText | Out-GridView -Title "WMI Event Consumers"

Write-Host "`nHunt completed! Report saved to: $ReportFolder" -ForegroundColor Green