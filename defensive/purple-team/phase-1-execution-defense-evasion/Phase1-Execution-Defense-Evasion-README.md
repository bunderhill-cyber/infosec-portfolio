# Phase 1 – Execution & Defense Evasion (Purple Team)

Educational purple-team exercise demonstrating common **Execution** and **Defense Evasion** techniques and the corresponding detection opportunities.

All activity was performed in an isolated SANS SEC504 Windows 10 lab with Sysmon installed. Only benign actions were used.

---

## Overview

This phase pairs offensive simulation with defensive hunting:

| Side       | Script                              | Purpose                                      |
|------------|-------------------------------------|----------------------------------------------|
| Offensive  | `Invoke-LolbinDemo.ps1`             | Demonstrates common LOLBin execution techniques |
| Offensive  | `Invoke-AmsiBypassDemo.ps1`         | Demonstrates a basic reflection-based AMSI bypass |
| Defensive  | `Detect-SuspiciousExecution.ps1` (v2) | Hunts for LOLBin usage and AMSI-related indicators |

---

## Offensive Techniques Demonstrated

### 1. Living-Off-the-Land Binaries (LOLBins)

`Invoke-LolbinDemo.ps1` safely demonstrates:

- PowerShell Encoded Command (`T1059.001`)
- `mshta.exe` with JavaScript (`T1218.005`)
- `rundll32.exe` (`T1218.011`)
- `regsvr32.exe` pattern (shown but not executed against remote content) (`T1218.010`)
- `wmic.exe` (`T1047`)

All actions are benign (whoami, system info, simple message boxes, or marker file creation).

**Lab evidence:**  
Screenshots show the script running, the mshta alert, rundll32 printer UI, and successful wmic output.

### 2. AMSI Bypass (Defense Evasion)

`Invoke-AmsiBypassDemo.ps1` demonstrates a classic reflection-based technique that attempts to disable AMSI scanning within the current PowerShell process (`T1562.001`).

The script is fully educational, creates a marker file, and performs only benign follow-up commands.

---

## Defensive Detection

`Detect-SuspiciousExecution_v2.ps1` queries:

- **Sysmon Event ID 1** (Process Creation) – primary source
- **PowerShell Event ID 4104** (Script Block Logging)

### Successful Detections

The detection script reliably identified the LOLBin activity:

- `mshta.exe` + JavaScript protocol
- Encoded PowerShell command
- `wmic.exe` execution
- `rundll32.exe` execution

**Example detection output** (after running the LOLBin demo):

```
Timestamp           Technique                                      Image
---------           ---------                                      -----
...                 wmic.exe execution                             ...\WMIC.exe
...                 rundll32.exe execution                         ...\rundll32.exe
...                 mshta.exe execution | Scriptlet / javascript   ...\mshta.exe
...                 Encoded PowerShell command                     ...\powershell.exe
```

### AMSI Bypass – Detection Limitation (Important)

During testing, the reflection-based AMSI bypass was **not reliably detected**, even after:

1. Enabling full PowerShell Script Block Logging
2. Iterating the detection script (v1 → v2) with additional AMSI-related patterns
3. Confirming Script Block events were being generated

**Root cause:**  
This type of in-memory AMSI bypass runs inside an existing PowerShell process and often leaves only weak or incomplete footprints in standard process-creation and script-block logs. The core bypass code did not appear in a form that matched the detection rules.

This is a realistic limitation of basic telemetry against pure in-memory techniques.

**Learning outcome:**  
Simple process and script-block hunting is effective against many LOLBin execution patterns but has clear gaps against certain in-memory defense-evasion techniques. Deeper visibility (e.g., more advanced logging, memory inspection, or behavioral analytics) would be required for reliable detection.

---

## MITRE ATT&CK Mapping

| Technique ID   | Name                                      | Coverage                          |
|----------------|-------------------------------------------|-----------------------------------|
| T1059          | Command and Scripting Interpreter         | Encoded PowerShell                |
| T1059.001      | PowerShell                                | Encoded command demo              |
| T1218          | System Binary Proxy Execution             | mshta, rundll32, regsvr32         |
| T1218.005      | Mshta                                     | Demonstrated                      |
| T1218.011      | Rundll32                                  | Demonstrated                      |
| T1047          | Windows Management Instrumentation        | wmic demo                         |
| T1562.001      | Impair Defenses: Disable or Modify Tools  | AMSI bypass demo (detection limited) |

---

## Lab Notes

- Environment: SANS SEC504 Windows 10 Enterprise with Sysmon
- All scripts contain strong educational / lab-only warnings
- Detection script requires Administrator rights to read Sysmon logs
- PowerShell Script Block Logging was enabled during testing to improve visibility

---

## Files

- `Invoke-LolbinDemo.ps1` – Offensive LOLBin demonstration
- `Invoke-AmsiBypassDemo.ps1` – Offensive AMSI bypass demonstration
- `Detect-SuspiciousExecution.ps1` / `Detect-SuspiciousExecution_v2.ps1` – Defensive hunting script
- Screenshots of execution and detection results

---

## Ethical Disclaimer

These materials are for **authorized lab and educational use only**.  
They demonstrate real attacker techniques using only benign actions.  
Never run these scripts on systems you do not own or lack explicit permission to test.

---

*Part of the infosec-portfolio – Purple Team ATT&CK series.*
