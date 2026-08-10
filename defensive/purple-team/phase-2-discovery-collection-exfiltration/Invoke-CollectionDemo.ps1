<#
.SYNOPSIS
    Educational Purple Team demo - Collection techniques (Phase 2)

.DESCRIPTION
    Safely demonstrates common MITRE ATT&CK Collection techniques using only
    benign file staging and archiving. Designed for isolated lab environments
    (SANS SEC504 Windows 10 Enterprise + Sysmon).

    Techniques covered:
    - T1005   Data from Local System
    - T1119   Automated Collection
    - T1560.001 Archive Collected Data (via Compress-Archive)

    This script intentionally reuses the PurpleTeam-Phase2 staging area
    created by Invoke-DiscoveryDemo.ps1 so the two demos form a realistic
    post-execution chain.

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Development assisted by xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    Requires        : PowerShell 5.1+
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.EXAMPLE
    .\Invoke-CollectionDemo.ps1
#>

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 2 : COLLECTION DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY
  This script performs only benign file staging and archiving.
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
# Setup staging locations (shared with Discovery / Exfiltration demos)
# ---------------------------------------------------------------------------
$stagingRoot   = Join-Path $PSScriptRoot "PurpleTeam-Phase2"
$discoveryDir  = Join-Path $stagingRoot "Discovery"
$collectionDir = Join-Path $stagingRoot "Collection"
$archiveDir    = Join-Path $collectionDir "Archive"
$reportFile    = Join-Path $collectionDir "Collection-Report.txt"
$markerFile    = Join-Path $collectionDir "CollectionDemo-Marker.txt"

# Ensure directories exist
foreach ($dir in @($stagingRoot, $collectionDir, $archiveDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report = @()
$report += "=== Purple Team Phase 2 - Collection Demo ==="
$report += "Timestamp : $timestamp"
$report += "User      : $env:USERNAME"
$report += "Host      : $env:COMPUTERNAME"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Staging root     : $stagingRoot" -ForegroundColor Green
Write-Host "[*] Collection dir   : $collectionDir" -ForegroundColor Green
Write-Host "[*] Archive dir      : $archiveDir" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Helper: create a few harmless dummy files so the demo always has content
# ---------------------------------------------------------------------------
function New-DummySensitiveFiles {
    $dummyDir = Join-Path $collectionDir "DummySource"
    if (-not (Test-Path $dummyDir)) {
        New-Item -ItemType Directory -Path $dummyDir -Force | Out-Null
    }

    $files = @{
        "employee_roster_sample.txt" = @"
# SAMPLE DATA ONLY - NOT REAL
Name,Department,Extension
Alice Example,Finance,1001
Bob Example,IT,1002
Carol Example,HR,1003
"@
        "network_notes.txt" = @"
# Lab notes - benign
Default gateway observed during Discovery demo.
This file exists only so Collection has something realistic to stage.
"@
        "config_backup_sample.xml" = @"
<?xml version="1.0"?>
<!-- SAMPLE - NOT A REAL CONFIG -->
<settings>
  <hostname>SEC504-LAB</hostname>
  <role>student-vm</role>
</settings>
"@
    }

    foreach ($name in $files.Keys) {
        $path = Join-Path $dummyDir $name
        if (-not (Test-Path $path)) {
            $files[$name] | Out-File -FilePath $path -Encoding UTF8
        }
    }
    return $dummyDir
}

# ---------------------------------------------------------------------------
# 1. Data from Local System (T1005) + Automated Collection (T1119)
# ---------------------------------------------------------------------------
Write-Host "[+] T1005 / T1119 - Data from Local System + Automated Collection" -ForegroundColor Yellow
Write-Host "    Searching for interesting files and staging them..." -ForegroundColor Gray

# Ensure we always have something to collect
$dummySource = New-DummySensitiveFiles

# Locations to search (limited depth for speed and safety)
$searchRoots = @(
    $dummySource,
    $discoveryDir,                          # reuse Discovery artifacts if present
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "C:\Users\Public"
)

$interestingExtensions = @("*.txt", "*.xml", "*.csv", "*.config", "*.docx", "*.xlsx", "*.pdf", "*.ps1")

$collected = @()
$seen = @{}

foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }

    foreach ($ext in $interestingExtensions) {
        $matches = Get-ChildItem -Path $root -Filter $ext -Recurse -ErrorAction SilentlyContinue -Depth 2 |
                   Where-Object { -not $_.PSIsContainer } |
                   Select-Object -First 8

        foreach ($file in $matches) {
            # Avoid collecting the same file twice and avoid collecting our own output files
            if ($seen.ContainsKey($file.FullName)) { continue }
            if ($file.FullName -like "*\PurpleTeam-Phase2\Collection\*") { continue }

            $seen[$file.FullName] = $true

            $destName = "{0}_{1}" -f $file.Directory.Name, $file.Name
            $destPath = Join-Path $collectionDir $destName

            try {
                Copy-Item -Path $file.FullName -Destination $destPath -Force -ErrorAction Stop
                $collected += [PSCustomObject]@{
                    Source = $file.FullName
                    Dest   = $destPath
                    Size   = $file.Length
                }
                Write-Host ("    [copied] {0}  ({1:N0} bytes)" -f $file.Name, $file.Length) -ForegroundColor Gray
            }
            catch {
                Write-Host ("    [skip]   {0} - {1}" -f $file.Name, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    }
}

$report += "=== T1005 / T1119 Collected Files ==="
if ($collected.Count -eq 0) {
    $report += "No files were collected (unexpected)."
    Write-Host "    [!] No files collected." -ForegroundColor Yellow
}
else {
    $report += ($collected | Format-Table -AutoSize | Out-String)
    Write-Host ("    Total files staged: {0}" -f $collected.Count) -ForegroundColor Green
}
$report += ""

# ---------------------------------------------------------------------------
# 2. Archive Collected Data (T1560.001)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1560.001 - Archive Collected Data" -ForegroundColor Yellow

$archiveName = "CollectedData_{0}.zip" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$archivePath = Join-Path $archiveDir $archiveName

# Only archive the staged copies (not the whole Collection folder recursively)
$filesToZip = Get-ChildItem -Path $collectionDir -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -notlike "Collection-*" -and $_.Name -notlike "CollectionDemo-*" }

if ($filesToZip.Count -gt 0) {
    try {
        Compress-Archive -Path $filesToZip.FullName -DestinationPath $archivePath -Force
        $archiveSize = (Get-Item $archivePath).Length
        Write-Host ("    Archive created: {0}  ({1:N0} bytes)" -f $archiveName, $archiveSize) -ForegroundColor Green

        $report += "=== T1560.001 Archive ==="
        $report += "Archive : $archivePath"
        $report += "Size    : $archiveSize bytes"
        $report += "Contains: $($filesToZip.Count) files"
        $report += ""
    }
    catch {
        Write-Host ("    [!] Failed to create archive: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $report += "=== T1560.001 Archive ==="
        $report += "Failed to create archive: $($_.Exception.Message)"
        $report += ""
    }
}
else {
    Write-Host "    [!] No files available to archive." -ForegroundColor Yellow
    $report += "=== T1560.001 Archive ==="
    $report += "No files available to archive."
    $report += ""
}

# ---------------------------------------------------------------------------
# Write report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 2 - Collection Demo Marker
--------------------------------------------
Executed   : $timestamp
User       : $env:USERNAME
Computer   : $env:COMPUTERNAME
Techniques : T1005, T1119, T1560.001
Report     : $reportFile
Archive    : $archivePath

This marker and the staged/archived files are intentionally created
so the subsequent Exfiltration demo has clear artifacts to work with.
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Collection complete." -ForegroundColor Green
Write-Host "    Report  : $reportFile" -ForegroundColor Cyan
Write-Host "    Marker  : $markerFile" -ForegroundColor Cyan
if (Test-Path $archivePath) {
    Write-Host "    Archive : $archivePath" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "[*] These artifacts will be useful for the Exfiltration phase next." -ForegroundColor Green
Write-Host "[*] Remember to clean up the PurpleTeam-Phase2 folder when finished." -ForegroundColor Yellow
Write-Host ""
