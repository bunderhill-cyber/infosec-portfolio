<#
.SYNOPSIS
    Educational Purple Team demo - Exfiltration techniques (Phase 2)

.DESCRIPTION
    Safely demonstrates common MITRE ATT&CK Exfiltration techniques using only
    local, lab-controlled actions. Designed for isolated lab environments
    (SANS SEC504 Windows 10 Enterprise + Sysmon).

    Techniques covered (simulated / lab-only):
    - T1041   Exfiltration Over C2 Channel (simulated local transfer)
    - T1020   Automated Exfiltration
    - T1560.001 Archive Collected Data (re-uses Collection archive)

    IMPORTANT: This script performs NO real external network transfer.
    All "exfiltration" is simulated by copying the Collection archive into
    a clearly marked local Exfiltration folder and writing a transfer log.
    This keeps the demo safe while still generating realistic artifacts
    and Sysmon FileCreate / Process Create telemetry.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Development assisted by xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    Requires        : PowerShell 5.1+
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.EXAMPLE
    .\Invoke-ExfiltrationDemo.ps1
#>

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 2 : EXFILTRATION DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script simulates exfiltration using ONLY local file operations.
  No data leaves the machine. No real external network transfer occurs.

  Artifacts are created in a PurpleTeam-Phase2 folder
  next to this script.

  Do NOT run this on any system you do not own or lack
  explicit written permission to test.
========================================================================

"@
Write-Host $banner -ForegroundColor Cyan

$confirm = Read-Host "Type YES to continue in a lab environment"
if ($confirm -ne "YES") {
    Write-Host "[!] Aborted by user." -ForegroundColor Yellow
    exit
}

# ---------------------------------------------------------------------------
# Setup staging locations (shared with Discovery / Collection demos)
# ---------------------------------------------------------------------------
$stagingRoot     = Join-Path $PSScriptRoot "PurpleTeam-Phase2"
$collectionDir   = Join-Path $stagingRoot "Collection"
$archiveDir      = Join-Path $collectionDir "Archive"
$exfilDir        = Join-Path $stagingRoot "Exfiltration"
$exfilDropDir    = Join-Path $exfilDir "Drop"
$reportFile      = Join-Path $exfilDir "Exfiltration-Report.txt"
$markerFile      = Join-Path $exfilDir "ExfiltrationDemo-Marker.txt"
$transferLogFile = Join-Path $exfilDir "Transfer-Log.txt"

foreach ($dir in @($stagingRoot, $exfilDir, $exfilDropDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report = @()
$report += "=== Purple Team Phase 2 - Exfiltration Demo ==="
$report += "Timestamp : $timestamp"
$report += "User      : $env:USERNAME"
$report += "Host      : $env:COMPUTERNAME"
$report += "---------------------------------------------"
$report += ""
$report += "NOTE: All exfiltration in this demo is SIMULATED and local only."
$report += "No data is sent outside the lab virtual machine."
$report += ""

Write-Host ""
Write-Host "[*] Staging root      : $stagingRoot" -ForegroundColor Green
Write-Host "[*] Collection archive: $archiveDir" -ForegroundColor Green
Write-Host "[*] Exfiltration dir  : $exfilDir" -ForegroundColor Green
Write-Host "[*] Drop location     : $exfilDropDir" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Locate the Collection archive (or fall back to staged files)
# ---------------------------------------------------------------------------
Write-Host "[+] Locating collected data to exfiltrate..." -ForegroundColor Yellow

$archiveToExfil = $null
if (Test-Path $archiveDir) {
    $archives = Get-ChildItem -Path $archiveDir -Filter "CollectedData_*.zip" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
    if ($archives) {
        $archiveToExfil = $archives[0]
        Write-Host ("    Found archive: {0}  ({1:N0} bytes)" -f $archiveToExfil.Name, $archiveToExfil.Length) -ForegroundColor Green
    }
}

if (-not $archiveToExfil) {
    # Fallback: look for any staged files in Collection
    Write-Host "    [!] No CollectedData_*.zip found. Looking for staged files..." -ForegroundColor DarkYellow
    $stagedFiles = Get-ChildItem -Path $collectionDir -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notlike "Collection-*" -and $_.Name -notlike "CollectionDemo-*" }
    if ($stagedFiles) {
        Write-Host ("    Found {0} staged file(s). Will package them for exfil simulation." -f $stagedFiles.Count) -ForegroundColor Green
    }
    else {
        Write-Host "    [!] No Collection artifacts found." -ForegroundColor Red
        Write-Host "        Run Invoke-CollectionDemo.ps1 first, then re-run this script." -ForegroundColor Yellow
        Write-Host ""
        exit
    }
}

# ---------------------------------------------------------------------------
# 2. Simulated Exfiltration (T1041 / T1020) - local copy only
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1041 / T1020 - Simulated Exfiltration (local only)" -ForegroundColor Yellow
Write-Host "    Copying archive/staged data to Exfiltration drop location..." -ForegroundColor Gray

$exfilTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$transferEntries = @()

if ($archiveToExfil) {
    $destName = "EXFIL_{0}_{1}" -f $exfilTimestamp, $archiveToExfil.Name
    $destPath = Join-Path $exfilDropDir $destName

    try {
        Copy-Item -Path $archiveToExfil.FullName -Destination $destPath -Force -ErrorAction Stop
        $copiedSize = (Get-Item $destPath).Length
        Write-Host ("    [exfil] {0}  ->  {1}" -f $archiveToExfil.Name, $destName) -ForegroundColor Green
        Write-Host ("            Size: {0:N0} bytes" -f $copiedSize) -ForegroundColor Gray

        $transferEntries += [PSCustomObject]@{
            Time       = $timestamp
            Source     = $archiveToExfil.FullName
            Destination= $destPath
            SizeBytes  = $copiedSize
            Method     = "Local copy (simulated C2 drop)"
            Technique  = "T1041 / T1020"
        }
    }
    catch {
        Write-Host ("    [!] Failed to copy archive: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}
else {
    # Package staged files on the fly
    $tempZipName = "EXFIL_{0}_StagedFiles.zip" -f $exfilTimestamp
    $tempZipPath = Join-Path $exfilDropDir $tempZipName
    try {
        Compress-Archive -Path $stagedFiles.FullName -DestinationPath $tempZipPath -Force
        $copiedSize = (Get-Item $tempZipPath).Length
        Write-Host ("    [exfil] Created and staged {0}  ({1:N0} bytes)" -f $tempZipName, $copiedSize) -ForegroundColor Green

        $transferEntries += [PSCustomObject]@{
            Time       = $timestamp
            Source     = "Collection staged files"
            Destination= $tempZipPath
            SizeBytes  = $copiedSize
            Method     = "Local archive + copy (simulated C2 drop)"
            Technique  = "T1041 / T1020 / T1560.001"
        }
    }
    catch {
        Write-Host ("    [!] Failed to create exfil package: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

$report += "=== Simulated Exfiltration Actions ==="
if ($transferEntries.Count -gt 0) {
    $report += ($transferEntries | Format-List | Out-String)
}
else {
    $report += "No files were successfully staged for exfiltration."
}
$report += ""

# ---------------------------------------------------------------------------
# 3. Write transfer log (useful for defensive hunting later)
# ---------------------------------------------------------------------------
$logLines = @()
$logLines += "Purple Team Phase 2 - Simulated Exfiltration Transfer Log"
$logLines += "Generated : $timestamp"
$logLines += "User      : $env:USERNAME"
$logLines += "Host      : $env:COMPUTERNAME"
$logLines += "----------------------------------------------------------------"
$logLines += "METHOD    : Local file copy to marked drop folder"
$logLines += "REALITY   : No external network transfer occurred"
$logLines += "PURPOSE   : Generate realistic artifacts + Sysmon telemetry"
$logLines += "----------------------------------------------------------------"

foreach ($entry in $transferEntries) {
    $logLines += ""
    $logLines += "Time        : $($entry.Time)"
    $logLines += "Source      : $($entry.Source)"
    $logLines += "Destination : $($entry.Destination)"
    $logLines += "Size        : $($entry.SizeBytes) bytes"
    $logLines += "Method      : $($entry.Method)"
    $logLines += "Technique   : $($entry.Technique)"
}

$logLines | Out-File -FilePath $transferLogFile -Encoding UTF8
Write-Host ""
Write-Host "[+] Transfer log written: $transferLogFile" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Write report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 2 - Exfiltration Demo Marker
----------------------------------------------
Executed   : $timestamp
User       : $env:USERNAME
Computer   : $env:COMPUTERNAME
Techniques : T1041 (simulated), T1020, T1560.001
Report     : $reportFile
TransferLog: $transferLogFile
Drop Folder: $exfilDropDir

IMPORTANT: This was a LOCAL SIMULATION only.
No data left the lab virtual machine.
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Exfiltration simulation complete." -ForegroundColor Green
Write-Host "    Report       : $reportFile" -ForegroundColor Cyan
Write-Host "    Marker       : $markerFile" -ForegroundColor Cyan
Write-Host "    Transfer Log : $transferLogFile" -ForegroundColor Cyan
Write-Host "    Drop Folder  : $exfilDropDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Phase 2 offensive chain is now complete:" -ForegroundColor Green
Write-Host "    Discovery -> Collection -> Exfiltration" -ForegroundColor Green
Write-Host "[*] Remember to clean up the PurpleTeam-Phase2 folder when finished." -ForegroundColor Yellow
Write-Host ""
