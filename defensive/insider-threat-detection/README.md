# Insider Threat Detection

A multi-layered defensive detection module focused on insider threats in financial services and regulated environments.

This project demonstrates the progression from **rule-based detection** to **behavioral analytics (UEBA-lite)** using PowerShell and Python, tested end-to-end in an isolated lab.

---

## Detection Pipeline

```
┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Detect-LogonAnomalies.ps1  │     │ Detect-USBExfiltration.ps1  │
│  (Windows Security Logs)    │     │ (Sysmon + Filesystem)       │
└─────────────┬───────────────┘     └─────────────┬───────────────┘
              │                                   │
              └───────────────┬───────────────────┘
                              ▼
                    Activity Reports (CSV)
                              │
                              ▼
              ┌───────────────────────────────┐
              │ behavioral_anomaly_detector.py│
              │  + Per-user baselines         │
              │  → Ranked anomaly scores      │
              └───────────────────────────────┘
```

**Rule-based layer** generates structured activity data.  
**Behavioral layer** evaluates that data against each user’s normal baseline and produces a ranked risk score.

This approach shows why the same raw activity (e.g. a 75 MB USB write) can be highly anomalous for one user and normal for another.

---

## Components

| Script | Role | Key Signals |
|--------|------|-------------|
| `Detect-LogonAnomalies.ps1` | Rule-based logon analysis | Off-hours logons, unusual workstations, failed logon spikes |
| `Detect-USBExfiltration.ps1` | Rule-based USB monitoring | Large file writes to removable media (Sysmon Event ID 11 + filesystem fallback) |
| `behavioral_anomaly_detector.py` | Behavioral analytics | Compares recent activity against per-user baselines using z-score statistics and produces a ranked anomaly score |

---

## How the Pieces Work Together

1. Run the two PowerShell detection scripts. They produce CSV activity reports.
2. Maintain a simple baseline file containing each user’s normal patterns (average logon hour, typical USB volume, failed logon counts, etc.).
3. Run `behavioral_anomaly_detector.py`. It ingests the latest reports + baselines and calculates how far current behavior deviates from normal for each user.
4. Review the ranked output to prioritize investigation.

The PowerShell scripts act as reliable data collectors. The Python script adds the intelligence layer that turns raw events into prioritized, context-aware alerts.

---

## Lab Validation

All components were tested in the **SANS SEC504 Windows 10 Enterprise** lab environment using synthetic data only. Sysmon was installed to support high-fidelity USB detection.

Example results from the behavioral detector:
- **Sec504** (Score 10.12) — Strong anomaly driven by unusual logon hour + very high USB write volume
- **InsiderTest** (Score 3.61) — Clear off-hours logon anomaly

Screenshots of baselines, input reports, execution, and final ranked scores are available in the `docs/` / screenshots folder.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Coverage |
|--------------|------|----------|
| T1078 | Valid Accounts | Logon anomaly detection |
| T1110 | Brute Force | Failed logon spike detection |
| T1052 | Exfiltration Over Physical Medium | USB write volume monitoring |
| T1091 | Replication Through Removable Media | Removable media activity |
| T1119 | Automated Collection | Supporting context |

---

## Limitations (Intentional for Portfolio Clarity)

- Baselines are currently maintained manually
- Uses straightforward z-score statistics (no machine learning)
- Designed for educational clarity and demonstration value rather than production scale

These limitations keep the project transparent and easy to understand while still illustrating real detection engineering concepts.

---

## Ethical Disclaimer

**For authorized lab and educational use only.**  
All testing was performed in an isolated environment with synthetic data. Unauthorized use on systems you do not own or have explicit permission to test is prohibited.

---

*Part of the infosec-portfolio – practical PowerShell + Python defensive tooling.*
