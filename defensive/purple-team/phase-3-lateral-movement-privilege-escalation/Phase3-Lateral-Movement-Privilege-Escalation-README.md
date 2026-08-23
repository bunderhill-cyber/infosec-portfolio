# Phase 3 – Lateral Movement & Privilege Escalation (Purple Team)

Educational purple-team exercise demonstrating **Privilege Escalation** and **Lateral Movement** techniques with matching detection opportunities.

All activity was performed in an isolated SANS SEC504 lab (Windows 10 Enterprise + Slingshot Linux) with Sysmon installed on Windows. Only benign actions were used.

---

## Overview

This phase pairs offensive simulation with defensive hunting:

| Side       | Script                            | Purpose                                              |
|------------|-----------------------------------|------------------------------------------------------|
| Offensive  | `Invoke-PrivEscDemo.ps1`          | Scheduled task elevation pattern (RunLevel Highest)  |
| Offensive  | `Invoke-LateralMovementDemo.ps1`  | WinRM / PowerShell Remoting (benign remote commands) |
| Defensive  | `Detect-PrivEscAndLateral.ps1`    | Hunts Sysmon EID 1 for task elevation and WinRM      |

Lab network:
- Windows SEC504 VM: `10.10.0.1`
- Slingshot: `10.10.75.1`
- WinRM enabled on Windows for the Lateral Movement demo

---

## Offensive Techniques Demonstrated

### 1. Privilege Escalation

`Invoke-PrivEscDemo.ps1` safely demonstrates:

- Scheduled Task with **RunLevel Highest** (`T1053.005`)
- Elevation context enumeration (`T1548` pattern — integrity level / groups via `whoami`)

The script:
1. Enumerates current user, groups, and privileges
2. Registers a benign scheduled task (`PurpleTeam-Phase3-PrivEscDemo`) configured to run with highest privileges
3. Starts the task once; the task runs a small helper script that writes an elevated marker
4. Leaves report and markers under `PurpleTeam-Phase3\PrivEsc\`

No UAC bypass exploits or third-party binaries are used — only standard administrative scheduled-task behavior.

**Lab evidence:**
- Console: process showed High Mandatory Level; task registered with RunLevel Highest; elevated marker written
- Sysmon Event ID 1: `powershell.exe` parented by `svchost.exe` (Task Scheduler) at task start time

### 2. Lateral Movement

`Invoke-LateralMovementDemo.ps1` demonstrates:

- Windows Remote Management (`T1021.006`) via PowerShell Remoting

The script:
1. Tests WinRM reachability (`Test-WSMan`)
2. Runs benign remote commands (`whoami`, hostname)
3. Writes a remote marker under `C:\Users\Public\PurpleTeam-Phase3-LM\`
4. Writes local report and marker under `PurpleTeam-Phase3\LateralMovement\`

**Lab evidence:**
- Successful `Invoke-Command` against localhost / `10.10.0.1` (after adding the host to TrustedHosts for non-domain WinRM)
- Remote marker created on the target
- Sysmon Event ID 1: `wsmprovhost.exe` (WinRM host process)

**Cross-host note (Slingshot → Windows):**  
Native `pwsh` on Slingshot cannot use Basic authentication over HTTP (PowerShell-on-Unix limitation). `evil-winrm` was not installed on the lab image. Cross-host WinRM from Slingshot was therefore not completed. Lateral Movement was fully demonstrated and detected on the Windows host via WinRM. This limitation is documented for realism.

---

## Defensive Detection

`Detect-PrivEscAndLateral.ps1` queries:

- **Sysmon Event ID 1** (Process Create) — primary source for both tactics
- **Sysmon Event ID 11** (FileCreate) — secondary source for the LM remote marker path

Requires Administrator rights. Default time window: 90 minutes.

### Successful Detections

After running the offensive demos, the hunter produced:

**Privilege Escalation — 1 finding**
- `powershell.exe` ← `svchost.exe` → T1053.005 Scheduled Task (elevated context)

**Lateral Movement — 1 finding**
- `wsmprovhost.exe` ← `svchost.exe` → T1021.006 WinRM

**Example detection summary:**

```
PrivilegeEscalation : 1 finding(s)
LateralMovement     : 1 finding(s)
```

### Detection Limitations (Important)

1. **FileCreate (EID 11)** for the LM remote marker path was not returned by the hunter. The lab Sysmon configuration often filters many FileCreate events (same class of gap seen in Phase 2 Exfiltration).

2. **Slingshot → Windows WinRM** was blocked by platform limits (Basic auth over HTTP unsupported in Unix PowerShell; no evil-winrm). Detection work therefore focused on Windows-side WinRM telemetry, which was strong.

**Learning outcome:**  
Process-creation telemetry remains the highest-confidence signal for both scheduled-task elevation and WinRM lateral movement. FileCreate coverage depends on Sysmon policy. Cross-platform remoting clients introduce additional practical constraints in mixed Windows/Linux labs.

---

## MITRE ATT&CK Mapping

| Technique ID | Name                                         | Coverage                                      |
|--------------|----------------------------------------------|-----------------------------------------------|
| T1053.005    | Scheduled Task/Job: Scheduled Task           | Demonstrated + detected (EID 1)               |
| T1548        | Abuse Elevation Control Mechanism            | Context / pattern demonstrated                |
| T1021.006    | Remote Services: Windows Remote Management   | Demonstrated + detected (EID 1, wsmprovhost)  |

---

## Lab Notes

- Environment: SANS SEC504 Windows 10 Enterprise + Slingshot; Sysmon on Windows
- WinRM was enabled with `winrm quickconfig` for the LM demo
- Non-domain WinRM required TrustedHosts entry for `10.10.0.1` when targeting by IP
- All scripts use educational banners and explicit `YES` confirmation
- Staging folders: `PurpleTeam-Phase3\PrivEsc\` and `PurpleTeam-Phase3\LateralMovement\`
- Cleanup:
  - `Unregister-ScheduledTask -TaskName 'PurpleTeam-Phase3-PrivEscDemo' -Confirm:$false`
  - `Remove-Item -Recurse -Force` on Phase 3 staging paths and `C:\Users\Public\PurpleTeam-Phase3-LM`

---

## Files

- `Invoke-PrivEscDemo.ps1` — Offensive Privilege Escalation demonstration
- `Invoke-LateralMovementDemo.ps1` — Offensive Lateral Movement (WinRM) demonstration
- `Detect-PrivEscAndLateral.ps1` — Defensive hunting script
- Screenshots / console output of execution, Sysmon events, and hunter results

---

## Ethical Disclaimer

These materials are for **authorized lab and educational use only**.  
They demonstrate real attacker techniques using only benign actions.  
Never run these scripts on systems you do not own or lack explicit permission to test.

---

*Part of the infosec-portfolio – Purple Team ATT&CK series.*
