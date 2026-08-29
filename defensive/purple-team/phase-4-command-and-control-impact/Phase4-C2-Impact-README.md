# Phase 4 – Command and Control & Impact (Purple Team)

Educational purple-team exercise demonstrating **Command and Control** and **Impact** techniques with matching detection opportunities.

All activity was performed in an isolated SANS SEC504 lab (Windows 10 Enterprise + Slingshot Linux) with Sysmon installed on Windows. Only benign, reversible actions were used. Impact was confined to dummy files inside a dedicated sandbox.

---

## Overview

This phase pairs offensive simulation with defensive hunting:

| Side       | Script                     | Purpose                                              |
|------------|----------------------------|------------------------------------------------------|
| Offensive  | `Invoke-C2BeaconDemo.ps1`  | HTTP beacon to a lab listener (T1071.001)            |
| Offensive  | `c2_listener.py`           | Educational HTTP listener for Slingshot              |
| Offensive  | `Invoke-ImpactDemo.ps1`    | Sandbox “encryption” + recovery enumeration          |
| Defensive  | `Detect-C2AndImpact.ps1`   | Hunts Sysmon EID 3 (C2) and EID 1 (Impact tools)     |

Lab network:
- Windows SEC504 VM: `10.10.0.1` (`SEC504STUDENT` / `Sec504`)
- Slingshot: `10.10.75.1`
- C2 listener: `http://10.10.75.1:8080/beacon`

Repo folder: `phase-4-command-and-control-impact`

---

## Offensive Techniques Demonstrated

### 1. Command and Control

`Invoke-C2BeaconDemo.ps1` + `c2_listener.py` demonstrate:

- Application Layer Protocol: Web Protocols (`T1071.001`) — periodic HTTP POST beacons

The Windows script:
1. Requires an explicit `YES` confirmation
2. Sends a limited number of HTTP check-ins (default 8, 15 seconds apart)
3. Includes host context (hostname, user, beacon ID)
4. Executes only a hard-coded allow-list of benign commands if the listener returns `CMD:...`
5. Writes a report, activity log, and marker under `PurpleTeam-Phase4\C2\`

The Slingshot listener is a small Python HTTP server compatible with the lab’s **Python 3.6.9** (`python3`). System `python` on this image is 2.7.17; the lab Python was **not** upgraded.

**Lab evidence (26 Aug 2026):**
- Listener received 8 successful `POST /beacon` check-ins, beacon ID `PT4-133658`, host `SEC504STUDENT`, user `Sec504`
- Check-ins ran about every 15 seconds (13:36:59 through 13:38:45 on Slingshot)
- Sysmon Event ID 3: `powershell.exe` → `10.10.75.1:8080` (9 NetworkConnect events in the hunt window)

Slingshot console (excerpt):

```
[+] POST Beacon  id=PT4-133658  seq=1  host=SEC504STUDENT  user=Sec504
[+] POST Beacon  id=PT4-133658  seq=8  host=SEC504STUDENT  user=Sec504
```

### 2. Impact

`Invoke-ImpactDemo.ps1` demonstrates:

- Data Encrypted for Impact (`T1486`) — reversible transform of **dummy files only**
- Inhibit System Recovery (`T1490`) — **enumeration only** (no delete / disable)

The script:
1. Seeds four clearly labeled `FAKE_*` files under `PurpleTeam-Phase4\ImpactSandbox\`
2. Copies them unchanged to `ImpactSandbox\_Originals\`
3. Applies XOR (`PURPLETEAM-PHASE4`) + Base64 and renames to `*.purplelocked`
4. Writes an educational note (`READ_ME_PURPLETEAM.txt`) that is explicitly not ransomware
5. Runs read-only recovery queries (`vssadmin list shadows/volumes`, `wbadmin get versions`, `bcdedit /enum {current}`, path existence)
6. Supports full restore via `.\Invoke-ImpactDemo.ps1 -Restore`

No `vssadmin delete`, no `bcdedit` recovery disable, no `wbadmin` catalog wipe, and no files outside the sandbox are modified.

**Lab evidence:**
- 4 dummy files locked; originals retained; educational note written
- Sysmon Event ID 1: `vssadmin.exe`, `wbadmin.exe`, and `bcdedit.exe` parented by `powershell.exe` at 13:52
- Restore remains available from `_Originals\`

Runtime staging was nested (`...\PurpleTeam-Phase4\PurpleTeam-Phase4\`) because the script already lived in a folder named `PurpleTeam-Phase4` and creates that name next to `$PSScriptRoot`. Same pattern as Phases 2 and 3.

---

## Defensive Detection

`Detect-C2AndImpact.ps1` queries:

- **Sysmon Event ID 3** (NetworkConnect) — primary C2 signal (`10.10.75.1:8080`)
- **Sysmon Event ID 1** (Process Create) — C2 script + T1490 tool use + T1486 script
- **Sysmon Event ID 11** (FileCreate) — secondary signal for `*.purplelocked` / note / reports

Requires Administrator rights. Default time window: 180 minutes.

### Successful Detections

After both offensive demos, the hunter produced:

```
CommandAndControl        : 9 finding(s)
Impact-Encrypt           : 1 finding(s)   ← first-pass false positive; see below
Impact-InhibitRecovery   : 4 finding(s)
```

**Command and Control — 9 findings (strong)**
- Sysmon EID 3: `powershell.exe` → `10.10.75.1:8080`
- Timestamps align with the listener’s 15-second beacon cadence
- Nine NetworkConnect events vs eight successful application-layer POSTs: one extra EID 3 at 13:35:23 (before the recorded POST sequence) is consistent with an earlier TCP/HTTP attempt

**Inhibit System Recovery — 4 findings (strong)**
- `vssadmin.exe` ← `powershell.exe` (list shadows / list volumes)
- `wbadmin.exe` ← `powershell.exe` (`get versions`)
- `bcdedit.exe` ← `powershell.exe` (`/enum`)

Command lines were list/enum only. Nothing destructive was issued.

### Detection Limitations (Important)

1. **FileCreate (EID 11)** for `*.purplelocked` and `READ_ME_PURPLETEAM.txt` did not match, even though 54 FileCreate events were present in the window. The lab Sysmon configuration continues to filter or omit many FileCreate paths (same class of gap as Phase 2 Exfiltration and Phase 3 LM marker).

2. **C2 Process Create (EID 1)** for `Invoke-C2BeaconDemo.ps1` itself was not flagged. The high-confidence C2 signal in this lab is **EID 3 NetworkConnect**, not the parent PowerShell command line.

3. **First-pass T1486 EID 1 false positive:** the hunter initially flagged `notepad.exe` ← `explorer.exe` at 13:56:05 because the CommandLine contained a sandbox artifact (`READ_ME_PURPLETEAM.txt` / `purplelocked`). That is an operator opening the educational note, not the encrypting script. The hunter was tightened to require `powershell.exe` **and** `Invoke-ImpactDemo` for the T1486 process-create rule.

**Learning outcome:**  
NetworkConnect (EID 3) is the reliable C2 signal for a simple HTTP beacon in this Sysmon policy. Recovery-tool process creation (EID 1) is the reliable T1490 signal. FileCreate cannot be assumed for Impact artifacts on the stock SEC504 Sysmon configuration. Detection rules that match only on path strings will also catch analysts opening the ransom note.

---

## MITRE ATT&CK Mapping

| Technique ID | Name                                      | Coverage                                                         |
|--------------|-------------------------------------------|------------------------------------------------------------------|
| T1071.001    | Application Layer Protocol: Web Protocols | Demonstrated + detected (EID 3 → 10.10.75.1:8080)                |
| T1486        | Data Encrypted for Impact                 | Demonstrated (sandbox only). EID 11 not returned by lab Sysmon   |
| T1490        | Inhibit System Recovery                   | Enum-only demonstrated + detected (EID 1 vssadmin/wbadmin/bcdedit) |

---

## Lab Notes

- Environment: SANS SEC504 Windows 10 Enterprise + Slingshot; Sysmon on Windows
- Slingshot Python: `python` = 2.7.17, `python3` = 3.6.9. Use `python3 c2_listener.py --port 8080`. Do not upgrade system Python on the course image.
- Listener bind: `0.0.0.0:8080`. Confirm with `Test-NetConnection 10.10.75.1 -Port 8080` from Windows if check-ins fail.
- All scripts use educational banners and explicit `YES` confirmation
- Impact key is intentionally public (`PURPLETEAM-PHASE4`) so the transform is reversible
- Staging: `PurpleTeam-Phase4\C2\` and `PurpleTeam-Phase4\ImpactSandbox\` (plus `Impact\` for reports)
- Restore Impact sandbox: `.\Invoke-ImpactDemo.ps1 -Restore`
- Cleanup: `Remove-Item -Recurse -Force` on the Phase 4 staging folder after screenshots

---

## Files

- `Invoke-C2BeaconDemo.ps1` — Offensive HTTP beacon
- `c2_listener.py` — Slingshot educational listener (Python 2.7 / 3.x)
- `Invoke-ImpactDemo.ps1` — Offensive Impact simulation (sandbox + enum-only T1490)
- `Detect-C2AndImpact.ps1` — Defensive hunting script
- Screenshots / console output of listener, beacon, sandbox listing, and hunter results

---

## Ethical Disclaimer

These materials are for **authorized lab and educational use only**.  
They demonstrate real attacker techniques using only benign, reversible actions.  
The Impact module is **not ransomware**: it operates only on dummy files it creates, keeps pristine copies, and never disables recovery.  
Never run these scripts on systems you do not own or lack explicit permission to test.

---

*Part of the infosec-portfolio – Purple Team ATT&CK series.*
