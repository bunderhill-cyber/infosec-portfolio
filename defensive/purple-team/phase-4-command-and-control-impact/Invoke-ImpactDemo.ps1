<#
.SYNOPSIS
    Educational Purple Team demo - Impact techniques (Phase 4)

.DESCRIPTION
    Safely demonstrates MITRE ATT&CK Impact patterns using only a dedicated
    sandbox of dummy files. Designed for the SANS SEC504 lab
    (Windows 10 Enterprise + Sysmon).

    Techniques:
    - T1486  Data Encrypted for Impact
             Reversible transform of dummy files only, inside
             PurpleTeam-Phase4\ImpactSandbox\
    - T1490  Inhibit System Recovery
             ENUMERATION ONLY. Lists shadow copies, restore points, and
             common backup locations. Does not delete, disable, or modify
             any recovery mechanism.

    Safety guarantees:
    - Never touches files outside PurpleTeam-Phase4\ImpactSandbox\
    - Keeps pristine copies in ImpactSandbox\_Originals\
    - Transform is fully reversible (-Restore)
    - No vssadmin delete, no bcdedit changes, no wbadmin delete,
      no disabling of System Restore

.NOTES
    Author          : B. Underhill infosec-portfolio / Purple Team ATT&CK series
                        Developed with assistance from xAI Grok
    Lab             : SANS SEC504 Windows 10 Enterprise
    Requires        : PowerShell 5.1+
                      Administrator recommended only for fuller T1490 output
    Ethical Use     : AUTHORIZED LAB USE ONLY. Never run on production or
                      systems you do not own / lack explicit permission to test.

.PARAMETER Restore
    Reverse the sandbox transform using the copies in _Originals.
    Does not re-run the impact simulation.

.EXAMPLE
    .\Invoke-ImpactDemo.ps1

.EXAMPLE
    .\Invoke-ImpactDemo.ps1 -Restore
#>

param(
    [switch]$Restore
)

# ---------------------------------------------------------------------------
# Safety Banner
# ---------------------------------------------------------------------------
$banner = @"

========================================================================
           PURPLE TEAM - PHASE 4 : IMPACT DEMO

  EDUCATIONAL / AUTHORIZED LAB USE ONLY

  T1486  - Reversible "encryption" of DUMMY files only
           Scope: PurpleTeam-Phase4\ImpactSandbox\
  T1490  - Inhibit System Recovery : ENUMERATION ONLY
           No shadow-copy deletion. No recovery disable.

  Pristine copies are kept in ImpactSandbox\_Originals\
  Restore with:  .\Invoke-ImpactDemo.ps1 -Restore

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
# Staging layout
# ---------------------------------------------------------------------------
$stagingRoot  = Join-Path $PSScriptRoot "PurpleTeam-Phase4"
$impactDir    = Join-Path $stagingRoot "Impact"
$sandboxDir   = Join-Path $stagingRoot "ImpactSandbox"
$originalsDir = Join-Path $sandboxDir "_Originals"
$reportFile   = Join-Path $impactDir "Impact-Report.txt"
$markerFile   = Join-Path $impactDir "ImpactDemo-Marker.txt"
$enumFile     = Join-Path $impactDir "RecoveryEnum.txt"
$noteFile     = Join-Path $sandboxDir "READ_ME_PURPLETEAM.txt"

foreach ($dir in @($stagingRoot, $impactDir, $sandboxDir, $originalsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
# Documented lab-only XOR key (not a secret). Makes files non-plaintext
# while remaining trivially reversible for the restore path.
$labKey = [System.Text.Encoding]::UTF8.GetBytes("PURPLETEAM-PHASE4")

$report = @()
$report += "=== Purple Team Phase 4 - Impact Demo ==="
$report += "Timestamp : $timestamp"
$report += "User      : $env:USERNAME"
$report += "Host      : $env:COMPUTERNAME"
$report += "Sandbox   : $sandboxDir"
$report += "Mode      : $(if ($Restore) { 'RESTORE' } else { 'SIMULATE' })"
$report += "---------------------------------------------"
$report += ""

Write-Host ""
Write-Host "[*] Staging / sandbox : $sandboxDir" -ForegroundColor Green
Write-Host "[*] Originals kept in : $originalsDir" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Helpers - reversible transform (XOR + Base64)
# ---------------------------------------------------------------------------
function Convert-LabBytes {
    param(
        [byte[]]$Bytes,
        [byte[]]$Key
    )
    $out = New-Object byte[] $Bytes.Length
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $out[$i] = $Bytes[$i] -bxor $Key[$i % $Key.Length]
    }
    return $out
}

function Protect-LabFile {
    param([string]$Path, [byte[]]$Key)
    $plain = [System.IO.File]::ReadAllBytes($Path)
    $xored = Convert-LabBytes -Bytes $plain -Key $Key
    $b64   = [Convert]::ToBase64String($xored)
    $dest  = "$Path.purplelocked"
    [System.IO.File]::WriteAllText($dest, $b64)
    Remove-Item -LiteralPath $Path -Force
    return $dest
}

function Unprotect-LabFile {
    param([string]$LockedPath, [byte[]]$Key)
    $b64   = [System.IO.File]::ReadAllText($LockedPath)
    $xored = [Convert]::FromBase64String($b64)
    $plain = Convert-LabBytes -Bytes $xored -Key $Key
    $dest  = $LockedPath -replace '\.purplelocked$', ''
    [System.IO.File]::WriteAllBytes($dest, $plain)
    Remove-Item -LiteralPath $LockedPath -Force
    return $dest
}

# ---------------------------------------------------------------------------
# Dummy file set (clearly fake / educational)
# ---------------------------------------------------------------------------
$dummyFiles = @{
    "FAKE_Invoice_2026-0041.txt" = @"
PURPLE TEAM DUMMY FILE - NOT REAL DATA
Invoice: INV-2026-0041
Customer: Example Logistics LLC (FAKE)
Amount: 12,480.00 USD (FAKE)
Notes: Created by Invoke-ImpactDemo.ps1 for T1486 lab simulation.
"@
    "FAKE_HR_Roster.txt" = @"
PURPLE TEAM DUMMY FILE - NOT REAL PII
Name,Role,Office
A. Example,Analyst,Lab
B. Example,Engineer,Lab
This roster is synthetic and exists only for the Impact sandbox.
"@
    "FAKE_Project_Notes.txt" = @"
PURPLE TEAM DUMMY FILE
Project: Purple Team Phase 4
Status: Educational ransomware-pattern simulation
Do not treat this file as sensitive outside the lab sandbox.
"@
    "FAKE_Backup_Checklist.txt" = @"
PURPLE TEAM DUMMY FILE
- Confirm snapshot taken
- Confirm sandbox path only
- Confirm originals folder populated
- Confirm restore switch works
"@
}

# ---------------------------------------------------------------------------
# Restore path
# ---------------------------------------------------------------------------
if ($Restore) {
    Write-Host "[+] Restore mode - rebuilding sandbox from _Originals" -ForegroundColor Yellow

    Get-ChildItem -Path $sandboxDir -Filter "*.purplelocked" -File -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }

    if (Test-Path $noteFile) {
        Remove-Item -LiteralPath $noteFile -Force
    }

    $restored = 0
    Get-ChildItem -Path $originalsDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $sandboxDir $_.Name) -Force
        $restored++
        Write-Host "    [+] Restored $($_.Name)" -ForegroundColor Green
    }

    $report += "=== Restore ==="
    $report += "Files restored from _Originals : $restored"
    $report += ""
    $report | Out-File -FilePath $reportFile -Encoding UTF8

    Write-Host ""
    Write-Host "[+] Restore complete. $restored file(s) returned to sandbox." -ForegroundColor Green
    Write-Host "    Sandbox : $sandboxDir" -ForegroundColor Cyan
    Write-Host ""
    exit
}

# ---------------------------------------------------------------------------
# 1. Seed dummy files + preserve originals
# ---------------------------------------------------------------------------
Write-Host "[+] Seeding dummy files in sandbox..." -ForegroundColor Yellow

foreach ($name in $dummyFiles.Keys) {
    $sandboxPath   = Join-Path $sandboxDir $name
    $originalsPath = Join-Path $originalsDir $name
    $dummyFiles[$name] | Out-File -FilePath $sandboxPath -Encoding UTF8
    Copy-Item -LiteralPath $sandboxPath -Destination $originalsPath -Force
    Write-Host "    [+] $name" -ForegroundColor Gray
}

$report += "=== Dummy files created ==="
$report += ($dummyFiles.Keys | ForEach-Object { "  $_" })
$report += ""

# ---------------------------------------------------------------------------
# 2. T1486 - reversible transform of sandbox files only
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1486 - Data Encrypted for Impact (sandbox only)" -ForegroundColor Yellow

$locked = @()
Get-ChildItem -Path $sandboxDir -File | Where-Object {
    $_.Name -ne "READ_ME_PURPLETEAM.txt" -and
    $_.Extension -ne ".purplelocked" -and
    $_.DirectoryName -eq $sandboxDir
} | ForEach-Object {
    try {
        $dest = Protect-LabFile -Path $_.FullName -Key $labKey
        $locked += $dest
        Write-Host "    [+] Locked $($_.Name) -> $(Split-Path $dest -Leaf)" -ForegroundColor Green
    }
    catch {
        Write-Host "    [!] Failed to lock $($_.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$note = @"
================================================================
  PURPLE TEAM PHASE 4 - EDUCATIONAL IMPACT NOTE
  THIS IS NOT RANSOMWARE. THIS IS A LAB SIMULATION.
================================================================

Files in this folder were reversibly transformed by
Invoke-ImpactDemo.ps1 (MITRE ATT&CK T1486 pattern).

Scope:
  $sandboxDir

Nothing outside this sandbox was modified.
Shadow copies / restore points / backup catalogs were NOT changed.

Restore (preferred):
  .\Invoke-ImpactDemo.ps1 -Restore

Or copy files back from:
  $originalsDir

Lab key (intentionally public):
  PURPLETEAM-PHASE4

Timestamp: $timestamp
Host     : $env:COMPUTERNAME
User     : $env:USERNAME
================================================================
"@
$note | Out-File -FilePath $noteFile -Encoding UTF8
Write-Host "    [+] Wrote educational note: $noteFile" -ForegroundColor Green

$report += "=== T1486 Data Encrypted for Impact ==="
$report += "Locked files : $($locked.Count)"
$report += ($locked | ForEach-Object { "  $_" })
$report += "Note         : $noteFile"
$report += "Transform    : XOR(PURPLETEAM-PHASE4) + Base64 + .purplelocked"
$report += "Reversible   : Yes ( -Restore or copy from _Originals )"
$report += ""

# ---------------------------------------------------------------------------
# 3. T1490 - Inhibit System Recovery (ENUMERATION ONLY)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[+] T1490 - Inhibit System Recovery (enumeration only)" -ForegroundColor Yellow
Write-Host "    No deletions. No bcdedit changes. No catalog wipes." -ForegroundColor DarkGray

$enum = @()
$enum += "=== Purple Team Phase 4 - Recovery Enumeration (T1490 READ-ONLY) ==="
$enum += "Timestamp : $timestamp"
$enum += "User      : $env:USERNAME"
$enum += "Host      : $env:COMPUTERNAME"
$enum += "NOTE      : Commands below are list/query only."
$enum += ""

function Invoke-EnumCommand {
    param(
        [string]$Title,
        [scriptblock]$Block
    )
    Write-Host "    [*] $Title" -ForegroundColor Gray
    $script:enum += ""
    $script:enum += "--- $Title ---"
    try {
        $output = & $Block 2>&1 | Out-String
        if ([string]::IsNullOrWhiteSpace($output)) {
            $output = "(no output / none found)"
        }
        $script:enum += $output.TrimEnd()
        Write-Host "        collected" -ForegroundColor DarkGray
    }
    catch {
        $script:enum += "ERROR: $($_.Exception.Message)"
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

Invoke-EnumCommand "vssadmin list shadows" {
    & vssadmin list shadows
}

Invoke-EnumCommand "vssadmin list volumes" {
    & vssadmin list volumes
}

Invoke-EnumCommand "Get-ComputerRestorePoint" {
    Get-ComputerRestorePoint | Format-Table -AutoSize | Out-String
}

Invoke-EnumCommand "wbadmin get versions" {
    & wbadmin get versions
}

Invoke-EnumCommand "bcdedit /enum {current} (read-only)" {
    & bcdedit /enum "{current}"
}

Invoke-EnumCommand "Common backup / recovery path existence" {
    $paths = @(
        "C:\Windows\System32\winevt\Logs",
        "C:\Windows\System32\config\RegBack",
        "C:\Recovery",
        "C:\System Volume Information"
    )
    $paths | ForEach-Object {
        "{0,-45} Exists={1}" -f $_, (Test-Path $_)
    }
}

$enum | Out-File -FilePath $enumFile -Encoding UTF8
$report += "=== T1490 Inhibit System Recovery (enum only) ==="
$report += "Enum file : $enumFile"
$report += "Actions   : list shadows, list volumes, restore points,"
$report += "            wbadmin versions, bcdedit enum, path existence"
$report += "Destructive commands issued : NONE"
$report += ""

# ---------------------------------------------------------------------------
# Report + marker
# ---------------------------------------------------------------------------
$report | Out-File -FilePath $reportFile -Encoding UTF8

$markerContent = @"
Purple Team Phase 4 - Impact Demo Marker
----------------------------------------
Executed   : $timestamp
User       : $env:USERNAME
Computer   : $env:COMPUTERNAME
Techniques : T1486 (sandbox only), T1490 (enumeration only)
Sandbox    : $sandboxDir
Originals  : $originalsDir
Note       : $noteFile
Locked     : $($locked.Count) file(s)
Enum file  : $enumFile
Report     : $reportFile

RESTORE:
  .\Invoke-ImpactDemo.ps1 -Restore

Cleanup:
  Remove-Item -Recurse -Force '$stagingRoot'
"@
$markerContent | Out-File -FilePath $markerFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Impact demo complete." -ForegroundColor Green
Write-Host "    Locked files  : $($locked.Count)" -ForegroundColor Cyan
Write-Host "    Sandbox       : $sandboxDir" -ForegroundColor Cyan
Write-Host "    Originals     : $originalsDir" -ForegroundColor Cyan
Write-Host "    Note          : $noteFile" -ForegroundColor Cyan
Write-Host "    Recovery enum : $enumFile" -ForegroundColor Cyan
Write-Host "    Report        : $reportFile" -ForegroundColor Cyan
Write-Host "    Marker        : $markerFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Defenders should look for:" -ForegroundColor Green
Write-Host "    - Sysmon EID 1  : powershell.exe running this script / vssadmin.exe / bcdedit.exe / wbadmin.exe" -ForegroundColor Gray
Write-Host "    - Sysmon EID 11 : FileCreate of *.purplelocked and READ_ME_PURPLETEAM.txt" -ForegroundColor Gray
Write-Host "    - Command-line  : vssadmin list shadows  (list, not delete)" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Restore when finished reviewing:" -ForegroundColor Yellow
Write-Host "    .\Invoke-ImpactDemo.ps1 -Restore" -ForegroundColor Yellow
Write-Host ""
Write-Host "[*] Full cleanup:" -ForegroundColor Yellow
Write-Host "    Remove-Item -Recurse -Force '$stagingRoot'" -ForegroundColor Yellow
Write-Host ""
