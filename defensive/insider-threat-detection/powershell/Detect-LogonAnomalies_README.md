# Detect-LogonAnomalies.ps1

**Anomalous Logon Detection** – Insider Threat Hunting Tool

## Overview
Detects suspicious Windows logon activity using Security Event Logs. 
Particularly useful in financial services for identifying potential insider threats or compromised accounts.

**Key Detections**:
- Off-hours logons (outside business hours)
- Logons from unusual workstations
- Failed logon spikes

## Lab Testing (SANS SEC504 Windows 10)
**Setup & Simulation**:
- Created test user (`InsiderTest`)
- Enabled detailed logon auditing
- Simulated off-hours access, explicit credential logons, and failed attempts

**Results**:
Successfully flagged anomalous logons with clear CSV reports and reasoning.

![Screenshots](../docs/create-test-user1.png)
![Simulation](../docs/create-test-user2.png)
![Detection Results](../docs/detect-threat-simulation3.png)

## Usage
```powershell
.\Detect-LogonAnomalies.ps1 -VerboseOutput
```
## MITRE ATT&CK Coverage
- T1078 — Valid Accounts

The script detects abuse of legitimate user accounts, including off-hours logons and logons from unusual workstations. This is a common technique used by insiders or attackers who have obtained valid credentials to blend in with normal activity.
- T1110 — Brute Force

The detection of repeated failed logon attempts helps identify credential guessing or brute-force attempts against user accounts, which is often a precursor to successful account compromise in insider threat or lateral movement scenarios.

## Ethical Disclaimer
**For authorized lab and educational use only.**  
Unauthorized deployment or use is prohibited.
