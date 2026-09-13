# Frontier AI Finding Validation Funnel

Lab exercise that treats **model output as signal, not as a ticket queue**.

A small intentionally weak shop receives 12 seeded "model findings." A Python gate probes the live app and classifies each row before anything is handed to an owner. The deliverable is a one-page status, not a finding dump.

Finding != weakness != exploitable != owned risk.

This is **not** a live frontier-model assessment and **not** a claim that the lab reproduced Project Glasswing. Findings were authored so the funnel could be measured. The public lesson it follows is the one operators are already publishing: discovery scaled; validation, prioritization, and ownership are the constraint.

---

## Disclaimer

Authorized educational use only. Run the shop on `127.0.0.1`. Do not expose it. Do not point the validator at any host you do not own. Credentials and keys in this folder are lab-only (`admin` / `ChangeMe!23`, `sk-lab-not-a-real-key-DO-NOT-USE`).

Tested in an isolated **SANS SEC504 Windows 10 Enterprise** VM with local Python 3.

---

## What is in the folder

Flat layout (this is how the SEC504 run was executed):

| File | Role |
|------|------|
| `app.py` | Lab Shop on `http://127.0.0.1:8088` |
| `secrets.env` | Static lab AI key (non-human identity stand-in) |
| `findings.json` | 12 seeded findings with an `expected_class` for teaching |
| `validate_findings.py` | Validation gate + one-pager writer |
| `program-status.md` | Executive one-pager produced by the validator |

Optional, not required for a first run:

| File | Role |
|------|------|
| `third_party/old_widget.py` | Unused dependency stub for FA-006 |

---

## Funnel

```
findings.json  -->  validate_findings.py  -->  live probes against Lab Shop
                                              -->  class per row
                                              -->  program-status.md
```

Classes the gate can assign:

| Class | Meaning |
|-------|---------|
| `exploitable` | Reproduced against this environment |
| `weakness_not_exploitable` | Real code/file, no path that reaches it here |
| `control_covers` | Compensating control held (encoding / WAF-style strip) |
| `false_positive` | Claimed endpoint or parameter does not do what the model said |
| `duplicate` | Same endpoint + check already confirmed |
| `needs_review` | Probe could not prove the teaching case (usually a missing lab file) |
| `not_reproduced` | Shop reachable, claim did not fire |

Workstreams on the one-pager are the ones a cyber program actually owns: AppSec / VM, identity (including non-human identity), insecure AI features / secrets, WAF / attack-surface, dependency governance.

---

## How to run

Two PowerShell windows on the VM.

**Window 1 — shop**

```powershell
cd C:\Tools\frontier-ai-findings-validation
python app.py
```

Leave it running. Browser check: `http://127.0.0.1:8088`

**Window 2 — validator**

```powershell
cd C:\Tools\frontier-ai-findings-validation
python validate_findings.py
```

Expected last line:

```
Wrote C:\Tools\frontier-ai-findings-validation\program-status.md
```

---

## Lab evidence (13 Sep 2026, SEC504 VM)

Shop bound to `127.0.0.1:8088`. Validator pointed at the same host. Python 3.14 on Windows.

| ID | Title | Result |
|----|-------|--------|
| FA-001 | SQL injection on `/search` | exploitable (3 products returned) |
| FA-002 | IDOR on `/profile?id=1` | exploitable (admin email visible) |
| FA-003 | Missing authn on `/profile` | duplicate of FA-002 |
| FA-004 | Hardcoded admin password | exploitable (`welcome admin`) |
| FA-005 | AI helper leaks lab key | exploitable (`LAB_AI_KEY=` echoed) |
| FA-006 | Insecure deser in `old_widget` | needs_review (stub file not in this copy) |
| FA-007 | Reflected XSS on `/search` | exploitable on this `app.py` copy (script tag still present in SQL debug) |
| FA-008 | Open redirect `next=` on `/login` | false positive |
| FA-009 | SSRF `url` on `/ai-helper` | false positive |
| FA-010 | `/admin/export` PII dump | false positive (404) |
| FA-011 | Static NHI key in `secrets.env` | exploitable |
| FA-012 | SQL echoed to the client | exploitable |

**Counts from that run:** 12 in, 12 validated, 3 false positives, 1 duplicate, 1 needs review, 7 exploitable in this environment.

Those 7 exploitable rows are not 7 tickets. The one-pager collapses them to **two owned items**:

1. AppSec — parameterize `/search` and stop printing SQL (FA-001 + FA-012).
2. Identity / secrets — remove the hardcoded admin password and stop treating a static AI key as an identity (FA-004 + FA-005 + FA-011). Close FA-003 as a duplicate of FA-002.

FA-008 / FA-009 / FA-010 stay off the board. They are how a firehose wastes a sprint if nobody validates.

---

## What this is not

- Not training or evaluating a frontier model.
- Not an exploit kit. Canaries are benign and aimed only at the lab shop.
- Not a SOC detection-engineering lab. Purple-team ATT&CK phases live elsewhere in the portfolio.
- Not enterprise scale. Four pages and 12 findings are enough to show the operating question.

---

## Skills shown

- Turning ambiguous AI-assisted output into a sequenced workstream
- Distinguishing finding volume from exploitable, owned risk
- Lightweight Python (stdlib only: `json`, `urllib`, no pip) against a live local target
- Executive-ready status: what changed, what is blocked, what decision is required, what happens if we wait
