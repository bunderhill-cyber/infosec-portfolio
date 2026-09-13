# infosec-portfolio

**Author:** B. Underhill

Development assisted by xAI Grok where noted.

Hands-on **detection engineering**, **purple-team** labs mapped to **MITRE ATT&CK**, and a smaller **Frontier AI finding-validation** track.

This repository is not a script dump. Purple-team exercises pair an authorized offensive demonstration with the defensive telemetry that should catch it. The Frontier AI folder is different: it treats model output as signal and forces a validation gate before anything becomes a ticket. All of it is **PowerShell** and **Python**, tested in an isolated SANS SEC504 Windows 10 lab, using synthetic data only.

Current scope:
- **Purple Team Phases 1–4** — Execution & Defense Evasion; Discovery, Collection & Exfiltration; Privilege Escalation & Lateral Movement; Command and Control & Impact (each with documented detections *and* known telemetry gaps)
- **Insider threat detection** — rule-based logon/USB detections plus a Python behavioral (UEBA-lite) scoring layer
- **Threat hunting** — persistence and suspicious-execution hunts
- **Frontier AI finding validation** — seeded model-style findings, a Python validation funnel, executive one-pager (In Review)
- **ATT&CK-aligned labs** by tactic under `mitre-attack/`

The goal is to show both how an L2 / detection-minded analyst thinks (generate the activity, prove what the logs show, write down what the stack missed) and how a program treats AI-assisted discovery (finding != weakness != exploitable != owned risk).

## ⚠️ Important Disclaimer

These scripts are for **educational purposes and authorized security testing only**.  
Never use them on systems you do not own or have explicit permission to test.

All testing was performed in isolated lab environments (primarily the SANS SEC504 Windows 10 VM) using synthetic data only.

---

## Folder Structure

```
infosec-portfolio/
├── IP_Allow_List_Manager/
├── mitre-attack/                          ← ATT&CK-aligned projects (by Tactic)
│   ├── reconnaissance/
│   ├── initial-access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege-escalation/
│   ├── defense-evasion/
│   ├── credential-access/
│   ├── discovery/
│   ├── lateral-movement/
│   ├── collection/
│   ├── command-and-control/
│   ├── exfiltration/
│   └── impact/
├── defensive/
│   ├── insider-threat-detection/          ← Complete multi-layer detection module
│   │   ├── powershell/
│   │   ├── python/
│   │   ├── docs/
│   │   └── README.md
│   ├── threat-hunting/                    ← Persistence hunting + execution detection scripts
│   ├── purple-team/                       ← Purple Team paired exercises
│   │   ├── phase-1-execution-defense-evasion/
│   │   ├── phase-2-discovery-collection-exfiltration/
│   │   ├── phase-3-lateral-movement-privilege-escalation/
│   │   └── phase-4-command-and-control-impact/
│   └── frontier-ai-findings-validation/   ← Epic: validation funnel, not ATT&CK pairing
│       ├── README.md
│       ├── app.py                         ← Lab Shop (127.0.0.1:8088)
│       ├── secrets.env
│       ├── findings.json                  ← 12 seeded findings
│       ├── validate_findings.py           ← Gate
│       └── program-status.md              ← Executive one-pager
├── docs/                                  ← Study logs and project write-ups
└── images/                                ← Screenshots and examples
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

- Human expert review of the Frontier AI Lab Shop funnel (In Review — do not mark Done yet)
- Backlog on that epic: point the same gate at localhost OWASP Juice Shop; then an Ollama firehose into the same schema
- Expand the Insider Threat Detection module with additional behavioral signals
- Continue adding well-documented Python and PowerShell scripts mapped to MITRE ATT&CK

---

*This portfolio is built to show practical cyber delivery: hands-on labs a detection engineer would recognize, and the validation, prioritization, and executive-ready status work a senior program or technical-program role uses to turn noisy findings into owned risk reduction.*
