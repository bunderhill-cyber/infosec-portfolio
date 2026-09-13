# Lab Shop - Frontier AI finding validation

**Audience:** Cyber / Product / Risk (one page).
**Target:** `http://127.0.0.1:8088` (isolated lab). **Date:** 2026-09-13.
**What this is not:** a live frontier-model assessment. Findings were seeded so the funnel could be measured.

## What changed

- Findings in: **12**.
- Validation completed: **12 / 12 (100%)**.
- False positives: **3 / 12 (25%)**.
- Exploitable in this environment: **7**.
- Crit/high that are exploitable: **5 / 9**.

Finding != weakness != exploitable != owned risk.

## Funnel

| State | Count |
|---|---|
| exploitable | 7 |
| false positive | 3 |
| duplicate | 1 |
| needs review | 1 |

## Needs an owner this week

| ID | Sev | Workstream | Action |
|---|---|---|---|
| FA-001 | critical | AppSec / vulnerability management | Product owner: fix parameterized query on /search |
| FA-002 | high | AppSec / identity | Product owner: bind profile to session; do not honor raw id |
| FA-004 | critical | Identity | Rotate lab admin password; remove hardcoded credential |
| FA-005 | high | Insecure AI feature / secrets | Stop echoing secrets; add output filter on /ai-helper |
| FA-007 | high | WAF / attack-surface | No ticket — compensating control held. Keep the rule. |
| FA-011 | medium | Identity / non-human identity | Replace static LAB_AI_KEY with a bound, rotatable identity |
| FA-012 | low | AppSec | Same owner as FA-001 — stop printing SQL to the client |

## Do not open tickets

- **FA-003** (duplicate) - Close as duplicate of the first confirmed finding on this endpoint/check.
- **FA-008** (false positive) - Claimed endpoint or parameter does not exist or does not behave as described.
- **FA-009** (false positive) - Claimed endpoint or parameter does not exist or does not behave as described.
- **FA-010** (false positive) - Claimed endpoint or parameter does not exist or does not behave as described.

## Decision required

1. Accept FA-001 / FA-012 as one AppSec item (parameterize `/search`, stop echoing SQL).
2. Accept FA-002 as an identity/session item; close FA-003 as duplicate.
3. Rotate the lab NHI key (FA-004, FA-005, FA-011) rather than filing three secrets tickets.
4. Keep the WAF/output-encoding rule that killed FA-007. Do not spend a sprint on unused `old_widget` (FA-006).

## What happens if we wait

The firehose already produced 12 rows for a four-page app. If every model finding becomes a ticket, Product spends the week on FPs and an unused library while the login, the IDOR, and the AI-helper key stay open. Validation first is what keeps the queue honest.

## Evidence (short)

| ID | Title | Class | Probe |
|---|---|---|---|
| FA-001 | SQL injection in product search | exploitable | status=200 products_returned=3 |
| FA-002 | IDOR on user profile | exploitable | status=200 admin_email_visible=True |
| FA-003 | Missing authentication on /profile | duplicate | status=200 admin_email_visible=True |
| FA-004 | Hardcoded admin password | exploitable | status=200 welcome=True |
| FA-005 | AI helper leaks lab API key from prompt | exploitable | status=200 key_echoed=True |
| FA-006 | Insecure deserialization in old_widget | needs review | widget_exists=False imported_by_app=False |
| FA-007 | Reflected XSS on search | exploitable | status=200 raw_script=True encoded=True |
| FA-008 | Open redirect on /login next= parameter | false positive | status=200 redirected=False param_reflected=False |
| FA-009 | SSRF via /ai-helper url field | false positive | status=200 redirected=False param_reflected=False |
| FA-010 | Unauthenticated PII export at /admin/export | false positive | status=404 exists=False |
| FA-011 | AI helper has no identity binding for the model key | exploitable | secrets.env_present=True static_key=True |
| FA-012 | Search error messages disclose SQL | exploitable | status=200 sql_visible=True |

