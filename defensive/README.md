# Windows Persistence Hunting Script
An educational threat hunting tool that enumerates common persistence mechanisms on Windows systems. It scans startup programs, scheduled tasks, registry run keys, selected browser extensions, and WMI event subscriptions. 

This project demonstrates core defensive security concepts and MITRE ATT&CK® techniques frequently leveraged by adversaries for persistence (T1547, T1053, T1546, etc.).

**Tested Environment:** Windows 11 (Personal lab system).

**Author:** B. Underhill  
**Date:** June 2026  

---

## 🎯 Purpose
* **Educational Exploration:** Understand how Windows persistence mechanisms work in practice.
* **System Hygiene:** Perform personal system baseline reviews and artifact checks.
* **Defensive Scripting:** Practice hands-on defensive PowerShell scripting.
* **Foundation Building:** Establish a base for building more advanced threat hunting capabilities.

## ✨ Features
* **Artifact Identification:** Identifies active and visible persistence artifacts.
* **CSV Export:** Exports results to timestamped CSV files for documentation.
* **Interactive Analysis:** Provides interactive `Out-GridView` displays for quick analysis.
* **Organized Reports:** Creates an organized report folder containing all outputs.
* **Zero Dependencies:** Requires no external modules or dependencies.

## 🛡️ MITRE ATT&CK® Techniques Covered
* **T1547.001** – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
* **T1053** – Scheduled Task/Job
* **T1546.003** – Event Triggered Execution: Windows Management Instrumentation Event Subscription
* **Registry Modification & Browser Extension Abuse**

## ⚠️ Disclaimer
Educational and authorized use only. Run this script exclusively on systems you own or have explicit written permission to inspect. Unauthorized use violates laws and ethical standards. The author assumes no liability for any misuse.

## 📋 Prerequisites
* **OS:** Windows 10/11 or Windows Server (Tested on Windows 11)
* **PowerShell:** Version 5.1+
* **Permissions:** Recommended to run in an elevated session (Run as Administrator) for maximum visibility.

## 🚀 Usage

Run the script from an elevated PowerShell console:

```powershell
.\Persistence_Hunting_Script.ps1
```

The script automatically creates a timestamped report folder in your `Documents` directory.

### Expected Output Structure
```text
persistencehunt_20260701_102500/
├── startup-programs.csv
├── scheduled-tasks.csv
└── [Interactive GridView Window Displays]
```

