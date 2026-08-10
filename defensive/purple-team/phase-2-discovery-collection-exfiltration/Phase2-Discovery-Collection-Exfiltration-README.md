# Phase 2 – Discovery, Collection & Exfiltration (Purple Team)

Educational purple-team exercise demonstrating a realistic post-execution chain:
**Discovery → Collection → Exfiltration**, together with the corresponding detection opportunities.

All activity was performed in an isolated SANS SEC504 Windows 10 lab with Sysmon installed. Only benign actions were used. No data left the virtual machine.

---

## Overview

This phase pairs offensive simulation with defensive hunting:

| Side       | Script                                   | Purpose                                              |
|------------|------------------------------------------|------------------------------------------------------|
| Offensive  | `Invoke-DiscoveryDemo.ps1`               | System, process, account, network and file discovery |
| Offensive  | `Invoke-CollectionDemo.ps1`              | Automated staging of local data + archive creation   |
| Offensive  | `Invoke-ExfiltrationDemo.ps1`            | Simulated local exfiltration of the collected archive|
| Defensive  | `Detect-DiscoveryCollectionExfil.ps1`    | Hunts Sysmon EID 1 (Discovery) and EID 11 (staging)  |

The three offensive scripts form a continuous chain and share a common staging folder (`PurpleTeam-Phase2`) created next to the scripts.

---

## Offensive Techniques Demonstrated

### 1. Discovery

`Invoke-DiscoveryDemo.ps1` safely demonstrates:

- System Information Discovery (`T1082`) – `systeminfo.exe` + `Get-ComputerInfo`
- Process Discovery (`T1057`) – `tasklist.exe` + `Get-Process`
- Account Discovery (`T1087`) – `whoami /all` + `Get-LocalUser`
- System Network Configuration Discovery (`T1016`) – `ipconfig /all` + `Get-NetIPConfiguration`
- File and Directory Discovery (`T1083`) – targeted search for interesting file types

All actions are read-only enumeration. The script writes a report and marker under `PurpleTeam-Phase2\Discovery\`.

**Lab evidence:**  
Sysmon Event ID 1 process-creation events for `systeminfo.exe`, `tasklist.exe`, `whoami.exe` and `ipconfig.exe`, all parented by `powershell.exe`.

### 2. Collection

`Invoke-CollectionDemo.ps1` demonstrates:

- Data from Local System (`T1005`)
- Automated Collection (`T1119`)
- Archive Collected Data (`T1560.001`) via `Compress-Archive`

The script locates interesting files (including Discovery artifacts), stages copies under `PurpleTeam-Phase2\Collection\`, and creates a timestamped zip archive.

**Lab evidence:**  
Console output showing 9 files staged + archive creation, File Explorer view of the Collection folder, and Sysmon Event ID 11 FileCreate events for staged `.ps1` files.

### 3. Exfiltration (Simulated)

`Invoke-ExfiltrationDemo.ps1` demonstrates a **lab-only simulation** of:

- Exfiltration Over C2 Channel (`T1041`) – simulated
- Automated Exfiltration (`T1020`)

The script locates the Collection archive and copies it into a clearly marked drop folder (`PurpleTeam-Phase2\Exfiltration\Drop\`) with an `EXFIL_` prefix. A transfer log records source, destination, size and technique. **No real external network transfer occurs.**

**Lab evidence:**  
Console output, Drop folder containing the `EXFIL_...zip`, and the generated `Transfer-Log.txt`.

---

## Defensive Detection

`Detect-DiscoveryCollectionExfil.ps1` queries:

- **Sysmon Event ID 1** (Process Create) – primary source for Discovery
- **Sysmon Event ID 11** (FileCreate) – primary source for Collection / staging

The script requires Administrator rights and accepts a configurable time window (default 90 minutes).

### Successful Detections

After re-running the offensive chain, the hunter produced:

**Discovery (Event ID 1) – 4 findings**
- `systeminfo.exe` → T1082 System Information Discovery
- `tasklist.exe` → T1057 Process Discovery
- `whoami.exe` → T1087 Account Discovery
- `ipconfig.exe` → T1016 Network Configuration Discovery

All four processes were parented by `powershell.exe`.

**Collection (Event ID 11) – 2 findings**
- FileCreate of staged files under `PurpleTeam-Phase2\Collection\`
- Attributed to `powershell.exe`

**Example detection summary:**

```
Discovery   : 4 finding(s)
Collection  : 2 finding(s)
```

### Exfiltration – Detection Limitation (Important)

Sysmon Event ID 11 events for the Exfiltration drop-folder activity (the `EXFIL_...zip` and related text files) were **not logged** on this lab image.

**Root cause:**  
The Sysmon configuration used in the SEC504 lab filters many FileCreate events (particularly certain extensions and paths). Collection produced partial FileCreate visibility; Exfiltration produced none.

This is a realistic limitation of tuned Sysmon configurations that prioritise volume reduction over complete file-system visibility.

**Learning outcome:**  
Process-creation telemetry (EID 1) provided high-confidence detection of Discovery. FileCreate telemetry (EID 11) provided partial visibility into Collection but was insufficient for Exfiltration under the lab’s Sysmon policy. Defenders should not assume FileCreate coverage is complete without validating the active Sysmon configuration.

---

## MITRE ATT&CK Mapping

| Technique ID | Name                                      | Coverage                                      |
|--------------|-------------------------------------------|-----------------------------------------------|
| T1082        | System Information Discovery              | Demonstrated + detected (EID 1)               |
| T1057        | Process Discovery                         | Demonstrated + detected (EID 1)               |
| T1087        | Account Discovery                         | Demonstrated + detected (EID 1)               |
| T1016        | System Network Configuration Discovery    | Demonstrated + detected (EID 1)               |
| T1083        | File and Directory Discovery              | Demonstrated                                  |
| T1005        | Data from Local System                    | Demonstrated + partial detection (EID 11)     |
| T1119        | Automated Collection                      | Demonstrated + partial detection (EID 11)     |
| T1560.001    | Archive Collected Data                    | Demonstrated                                  |
| T1041        | Exfiltration Over C2 Channel              | Simulated (local only)                        |
| T1020        | Automated Exfiltration                    | Simulated (local only)                        |

---

## Lab Notes

- Environment: SANS SEC504 Windows 10 Enterprise with Sysmon
- All scripts contain strong educational / lab-only warnings and require explicit `YES` confirmation
- Detection script requires Administrator rights to read Sysmon logs
- Staging folder is created next to the scripts (`PurpleTeam-Phase2`) for easy cleanup
- Exfiltration is deliberately simulated with local file operations only — no data leaves the VM
- Known telemetry gap: lab Sysmon configuration filters many FileCreate events

---

## Files

- `Invoke-DiscoveryDemo.ps1` – Offensive Discovery demonstration
- `Invoke-CollectionDemo.ps1` – Offensive Collection + archiving demonstration
- `Invoke-ExfiltrationDemo.ps1` – Simulated Exfiltration demonstration
- `Detect-DiscoveryCollectionExfil.ps1` – Defensive hunting script
- Screenshots of execution, staging folders, Sysmon events and hunter output

---

## Ethical Disclaimer

These materials are for **authorized lab and educational use only**.  
They demonstrate real attacker techniques using only benign actions.  
Never run these scripts on systems you do not own or lack explicit permission to test.

---

*Part of the infosec-portfolio – Purple Team ATT&CK series.*
