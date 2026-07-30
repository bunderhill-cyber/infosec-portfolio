# Initial Access Simulation: Phishing Link + Malicious Script Delivery

**SEC504 VM Lab Exercise** | **Offensive Security / Red Team Simulation**

## Objective
Demonstrate the Initial Access technique of delivering a script via a simulated phishing link, followed by user execution. This project shows the attack chain from delivery to execution and captures relevant detection artifacts (PowerShell Script Block Logging).

## MITRE ATT&CK Mapping
- **T1566.002** - Phishing: Spearphishing Link
- **T1204.002** - User Execution: Malicious File
- **T1059.001** - Command and Scripting Interpreter: PowerShell

## Lab Environment
- **VM**: SEC504 Lab (isolated)
- **IP**: 10.10.0.1 / localhost (127.0.0.1)
- **Tools**: Python HTTP server, PowerShell, Event Viewer
- Snapshots taken before and after execution

## Execution Steps (Documented)

1. **Start delivery server (attacker simulation)**  
   Created directory and started Python HTTP server:
   ```powershell
   cd "C:\Tools\Python Attack Labs"
   python -m http.server 8080
   ```
   Server log confirmed serving the payload (see screenshot).

2. **Simulate phishing delivery & download**  
   On the target VM, browsed to `http://127.0.0.1:8080/Benign-Payload-Demo.ps1` (or lab IP) and downloaded the file to `Downloads` folder.

3. **User Execution**  
   Right-clicked the downloaded `Benign-Payload-Demo.ps1` → **Run with PowerShell**.

4. **Payload Behavior**  
   The script executed successfully and performed benign system enumeration:
   - Displayed current user context (`whoami`)
   - Timestamp and basic process information

## Evidence & Detection Artifacts

**Screenshots of the Attack Chain:**

![Python HTTP Server](screenshots/Python_Server.png)

*Python HTTP server hosting the payload and logging the download request.*

![Browser Download](screenshots/BenignPayloadDownload.png)

*Simulated phishing link download via browser.*

![Run with PowerShell](screenshots/PayloadRunPS.png)

*User execution of the downloaded payload.*

![PowerShell 4104 Event](screenshots/Eventvwr4104_run.png)

*Event ID 4104 showing script block execution with ExecutionPolicy Bypass.*

These events provide clear indicators for SOC analysts (suspicious download followed by PowerShell execution).

## Blue Team / SOC Perspective
- **Detection Opportunities**: Monitor for 4104 events containing `Set-ExecutionPolicy -Scope Process Bypass`, execution of scripts from the `Downloads` folder, or PowerShell commands that reference recently downloaded files. In this lab exercise the download occurred via browser (not `Invoke-WebRequest`), so the 4104 event captured the bypass + direct script execution.
- **Prevention**: Application whitelisting (AppLocker/WDAC), restricted PowerShell execution policy, email/web filtering, and user awareness training.
- **Investigation**: Correlate download events with script block logging and process creation (Sysmon Event ID 1).

## Ethical Disclaimer
**This content is for educational and authorized lab use only.** All activities were performed in an isolated SEC504 lab environment. The payload is completely benign and performs no harmful actions. Never use these techniques on unauthorized systems.

## Files in This Folder
- `Benign-Payload-Demo.ps1` – Safe demonstration payload
- `screenshots/` – Supporting evidence images
- This README

**Learning Outcome**: Hands-on understanding of common initial access vectors and associated detection artifacts — directly applicable to SOC analysis and defensive engineering.

---
*Last updated: July 11, 2026*
