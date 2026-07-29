# infosec-portfolio

**Author:** B. Underhill

Development assisted by xAI Grok where noted.

A collection of practical **Python** and **PowerShell** scripts for learning and applying cybersecurity concepts across both **offensive** and **defensive** domains (reconnaissance, automation, system analysis, threat hunting, detection engineering, etc.).

## ⚠️ Important Disclaimer

These scripts are for **educational purposes and authorized security testing only**.  
Never use them on systems you do not own or have explicit permission to test.

All testing was performed in isolated lab environments (primarily the SANS SEC504 Windows 10 VM) using synthetic data only.

---

## Folder Structure

```
infosec-portfolio/
├── python/
│   ├── IP_Allow_List_Manager/
│   ├── ATTACK_Matrix_for_Enterprise/
│   └── ... other Python scripts
├── powershell/
│   ├── Persistence_Hunting/
│   └── ... other PowerShell scripts
├── defensive/
│   └── insider-threat-detection/        ← Focused defensive module
│       ├── powershell/
│       ├── python/
│       ├── docs/
│       └── README.md
├── docs/                                ← Study logs and project write-ups
└── images/                              ← Screenshots and examples
```


---

## Featured Project: Insider Threat Detection

A multi-layered defensive capability focused on financial services / regulated environments.  
It demonstrates the progression from **rule-based detection** to **behavioral analytics (UEBA-lite)**.

### Rule-Based Detection (PowerShell)
- **Detect-LogonAnomalies.ps1** — Off-hours logons, unusual workstations, failed logon spikes
- **Detect-USBExfiltration.ps1** — Large file writes to removable media (hybrid Sysmon + filesystem scan)

### Behavioral Analytics (Python)
- **behavioral_anomaly_detector.py** — Compares recent activity against per-user baselines using z-score statistics and produces a ranked anomaly score

**MITRE ATT&CK (Defensive)**  
T1078 Valid Accounts · T1110 Brute Force · T1052 Exfiltration Over Physical Medium · T1091 Replication Through Removable Media

---

## Offensive Scripts & MITRE ATT&CK Mapping

Offensive tools in this portfolio are organized and documented against the **MITRE ATT&CK** framework to demonstrate structured understanding of adversary techniques.

Typical coverage includes tactics such as:
- **Initial Access**
- **Execution**
- **Persistence**
- **Privilege Escalation**
- **Defense Evasion**
- **Credential Access**
- **Discovery**
- **Lateral Movement**
- **Collection**
- **Exfiltration**

Each offensive script includes clear documentation of the relevant ATT&CK technique(s), usage notes, and ethical boundaries.

---

## Skills Development & Continuous Learning

I actively maintain and document my learning through structured study and hands-on application.

**Recent Focus: Python for Cybersecurity Automation**  
Completed the Google Cybersecurity Professional Certificate (Course 7: Automate Cybersecurity Tasks with Python). Built a private spaced-repetition system (Anki) covering core concepts across all modules and immediately began applying them to practical scripting projects.

**Key Areas Strengthened**
- Functions, conditionals, and loops for decision-making logic
- String/list manipulation and regular expressions for log parsing and data extraction
- Safe file operations and data parsing techniques
- Writing clean, documented, and reusable code
- Detection engineering and behavioral analytics
- Combining PowerShell + Python for practical defensive tooling

These skills support both **defensive automation** (detection engineering, log analysis, response playbooks) and **offensive tooling development** in authorized lab environments.

See [Python Fundamentals Study Log](docs/Python-Fundamentals-Study-Log.md) for details on my approach and progress. Current scripting projects are located in the `/python` and `/defensive` folders.

I treat continuous learning as a core professional habit — especially important in cybersecurity where tools, threats, and best practices evolve rapidly.

---

## Next Steps

- Expand the Insider Threat Detection module with additional behavioral signals
- Continue adding well-documented Python and PowerShell scripts mapped to MITRE ATT&CK
- Expand the `docs/` folder with learning logs and project write-ups
- Build complementary offensive and defensive tools that demonstrate end-to-end understanding

---

*This portfolio is designed to demonstrate practical, job-relevant skills for roles such as SOC Analyst, Detection Engineer, Security Engineer, and related cybersecurity positions.*
