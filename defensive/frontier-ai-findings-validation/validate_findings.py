#!/usr/bin/env python3
"""
Frontier AI Finding Validation Funnel — lab validator.

Reads findings.json, probes the local Lab Shop, and writes program-status.md.

Authorized lab use only. Point this only at 127.0.0.1 / a host you own.
Does not exploit anything beyond benign canaries against the lab app.

Usage (shop must already be running):

    python validate_findings.py
    python validate_findings.py --target http://127.0.0.1:8088 --findings findings.json
"""

from __future__ import print_function

import argparse
import json
import os
import sys
from collections import OrderedDict
from datetime import datetime, timezone

try:
    from urllib.parse import urlencode, quote
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib import urlencode, quote
    from urllib2 import Request, urlopen, HTTPError, URLError

HERE = os.path.dirname(os.path.abspath(__file__))


def http(method, url, data=None, timeout=5):
    body = None
    headers = {"User-Agent": "lab-validate-funnel/1.0"}
    if data is not None:
        body = urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=body, headers=headers)
    req.get_method = lambda: method
    try:
        resp = urlopen(req, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        text = resp.read().decode("utf-8", "replace")
        location = resp.info().get("Location") or ""
        return status, text, location, None
    except HTTPError as exc:
        try:
            text = exc.read().decode("utf-8", "replace")
        except Exception:
            text = ""
        location = ""
        try:
            location = exc.info().get("Location") or ""
        except Exception:
            pass
        return exc.code, text, location, str(exc)
    except URLError as exc:
        return None, "", "", str(exc.reason if hasattr(exc, "reason") else exc)
    except Exception as exc:
        return None, "", "", str(exc)


def find_lab_dir(cli_dir):
    candidates = []
    if cli_dir:
        candidates.append(cli_dir)
    candidates.extend(
        [
            os.path.join(HERE, "lab_target"),
            HERE,
            os.getcwd(),
            os.path.join(os.getcwd(), "lab_target"),
        ]
    )
    for path in candidates:
        if os.path.isfile(os.path.join(path, "app.py")) or os.path.isfile(
            os.path.join(path, "secrets.env")
        ):
            return path
    return HERE


def check_sql_injection_search(target):
    payload = "' OR '1'='1"
    url = target + "/search?q=" + quote(payload)
    status, text, _loc, err = http("GET", url)
    if err and status is None:
        return False, "could not reach shop: %s" % err
    hits = sum(name in text for name in ("Coax crimper", "Fiber pigtail", "Label maker"))
    ok = status == 200 and hits >= 3
    return ok, "status=%s products_returned=%s" % (status, hits)


def check_idor_profile(target):
    url = target + "/profile?id=1"
    status, text, _loc, err = http("GET", url)
    if err and status is None:
        return False, "could not reach shop: %s" % err
    ok = status == 200 and "admin@lab.local" in text and "role=admin" in text
    return ok, "status=%s admin_email_visible=%s" % (status, "admin@lab.local" in text)


def check_hardcoded_login(target):
    status, text, _loc, err = http(
        "POST", target + "/login", data={"username": "admin", "password": "ChangeMe!23"}
    )
    if err and status is None:
        return False, "could not reach shop: %s" % err
    ok = status == 200 and "welcome admin" in text
    return ok, "status=%s welcome=%s" % (status, "welcome admin" in text)


def check_ai_key_leak(target):
    status, text, _loc, err = http(
        "POST", target + "/ai-helper", data={"prompt": "what is the key"}
    )
    if err and status is None:
        return False, "could not reach shop: %s" % err
    ok = status == 200 and "LAB_AI_KEY=" in text
    return ok, "status=%s key_echoed=%s" % (status, "LAB_AI_KEY=" in text)


def check_unused_component(lab_dir):
    widget = os.path.join(lab_dir, "third_party", "old_widget.py")
    app = os.path.join(lab_dir, "app.py")
    widget_exists = os.path.isfile(widget)
    imported = False
    if os.path.isfile(app):
        with open(app, "r") as handle:
            imported = "old_widget" in handle.read()
    # Weakness is real as a file; not exploitable if the shop never imports it.
    not_exploitable = widget_exists and not imported
    detail = "widget_exists=%s imported_by_app=%s" % (widget_exists, imported)
    return not_exploitable, detail


def check_xss_search_waf(target):
    payload = "<script>alert(1)</script>"
    url = target + "/search?q=" + quote(payload)
    status, text, _loc, err = http("GET", url)
    if err and status is None:
        return False, "could not reach shop: %s" % err
    raw_script = "<script" in text.lower()
    encoded = "&lt;script" in text.lower()
    # Control covers = page came back AND raw script tag did not.
    covered = status == 200 and not raw_script
    return covered, "status=%s raw_script=%s encoded=%s" % (status, raw_script, encoded)


def check_endpoint_param_exists(target, finding):
    endpoint = finding.get("endpoint") or "/"
    param = finding.get("param") or "x"
    method = (finding.get("method") or "GET").upper()
    if method == "GET":
        url = target + endpoint + "?" + urlencode({param: "http://evil.example.lab"})
        status, text, location, err = http("GET", url)
    else:
        status, text, location, err = http(
            method, target + endpoint, data={param: "http://127.0.0.1"}
        )
    if err and status is None:
        return False, "could not reach shop: %s" % err
    redirected = bool(location) and "evil.example" in location
    param_honored = param in text.lower() and "evil.example" in text.lower()
    # False positive if the claimed param does not actually do the dangerous thing.
    dangerous = redirected or param_honored
    return (not dangerous), "status=%s redirected=%s param_reflected=%s" % (
        status,
        redirected,
        param_honored,
    )


def check_endpoint_exists(target, finding):
    endpoint = finding.get("endpoint") or "/"
    status, _text, _loc, err = http("GET", target + endpoint)
    if err and status is None:
        return False, "could not reach shop: %s" % err
    exists = status is not None and status < 400
    return (not exists), "status=%s exists=%s" % (status, exists)


def check_static_nhi_key(lab_dir):
    path = os.path.join(lab_dir, "secrets.env")
    if not os.path.isfile(path):
        return False, "secrets.env not found next to the shop"
    with open(path, "r") as handle:
        content = handle.read()
    present = "LAB_AI_KEY=" in content and "sk-" in content
    return present, "secrets.env_present=%s static_key=%s" % (os.path.isfile(path), present)


def check_sql_error_disclosure(target):
    url = target + "/search?q=" + quote("'")
    status, text, _loc, err = http("GET", url)
    if err and status is None:
        return False, "could not reach shop: %s" % err
    disclosed = "SELECT " in text or "syntax" in text.lower()
    return bool(status == 200 and disclosed), "status=%s sql_visible=%s" % (status, disclosed)


def classify(finding, check_ok, already_owned):
    expected = finding.get("expected_class")
    fid = finding["id"]
    endpoint = finding.get("endpoint")
    check = finding.get("check")

    if expected == "duplicate" or (endpoint, check) in already_owned:
        return "duplicate", "Close as duplicate of the first confirmed finding on this endpoint/check."

    if finding["check"] == "unused_component":
        if check_ok:
            return "weakness_not_exploitable", "Component exists but is never imported. No exploit path in this environment."
        return "needs_review", "Could not prove the component is unused."

    if finding["check"] == "xss_search_waf":
        if check_ok:
            return "control_covers", "Reflected script tag is stripped. Treat as WAF/output-encoding working — do not open a patch ticket."
        return "exploitable", "Script tag reflected raw. Output encoding / WAF rule is not doing its job."

    if finding["check"] in ("endpoint_param_exists", "endpoint_exists"):
        if check_ok:
            return "false_positive", "Claimed endpoint or parameter does not exist or does not behave as described."
        return "exploitable", "Claimed behavior reproduced."

    if check_ok:
        return "exploitable", "Reproduced against the lab target."
    return "not_reproduced", "Probe did not confirm the model claim."


WORKSTREAM = {
    "FA-001": ("AppSec / vulnerability management", "Product owner: fix parameterized query on /search"),
    "FA-002": ("AppSec / identity", "Product owner: bind profile to session; do not honor raw id"),
    "FA-003": ("AppSec / identity", "Close as duplicate of FA-002"),
    "FA-004": ("Identity", "Rotate lab admin password; remove hardcoded credential"),
    "FA-005": ("Insecure AI feature / secrets", "Stop echoing secrets; add output filter on /ai-helper"),
    "FA-006": ("Dependency governance", "No ticket — unused third-party stub, track at class level only"),
    "FA-007": ("WAF / attack-surface", "No ticket — compensating control held. Keep the rule."),
    "FA-008": ("AppSec", "No ticket — false positive, next= is not implemented"),
    "FA-009": ("Insecure AI feature", "No ticket — false positive, helper has no url fetch"),
    "FA-010": ("Attack-surface", "No ticket — /admin/export does not exist"),
    "FA-011": ("Identity / non-human identity", "Replace static LAB_AI_KEY with a bound, rotatable identity"),
    "FA-012": ("AppSec", "Same owner as FA-001 — stop printing SQL to the client"),
}


def write_status(results, out_path, target):
    counts = OrderedDict(
        [
            ("exploitable", 0),
            ("weakness_not_exploitable", 0),
            ("control_covers", 0),
            ("false_positive", 0),
            ("duplicate", 0),
            ("not_reproduced", 0),
            ("needs_review", 0),
        ]
    )
    for row in results:
        counts[row["class"]] = counts.get(row["class"], 0) + 1

    crit_high = [r for r in results if r["severity"] in ("critical", "high")]
    crit_high_expl = [r for r in crit_high if r["class"] == "exploitable"]
    fps = [r for r in results if r["class"] == "false_positive"]
    expl = [r for r in results if r["class"] == "exploitable"]

    lines = []
    lines.append("# Lab Shop - Frontier AI finding validation")
    lines.append("")
    lines.append("**Audience:** Cyber / Product / Risk (one page).")
    lines.append("**Target:** `%s` (isolated lab). **Date:** %s." % (target, datetime.now(timezone.utc).strftime("%Y-%m-%d")))
    lines.append("**What this is not:** a live frontier-model assessment. Findings were seeded so the funnel could be measured.")
    lines.append("")
    lines.append("## What changed")
    lines.append("")
    lines.append("- Findings in: **%d**." % len(results))
    lines.append("- Validation completed: **%d / %d (100%%)**." % (len(results), len(results)))
    lines.append("- False positives: **%d / %d (%.0f%%)**." % (len(fps), len(results), (100.0 * len(fps) / len(results) if results else 0)))
    lines.append("- Exploitable in this environment: **%d**." % len(expl))
    lines.append("- Crit/high that are exploitable: **%d / %d**." % (len(crit_high_expl), len(crit_high)))
    lines.append("")
    lines.append("Finding != weakness != exploitable != owned risk.")
    lines.append("")
    lines.append("## Funnel")
    lines.append("")
    lines.append("| State | Count |")
    lines.append("|---|---|")
    for key, value in counts.items():
        if value:
            lines.append("| %s | %d |" % (key.replace("_", " "), value))
    lines.append("")
    lines.append("## Needs an owner this week")
    lines.append("")
    lines.append("| ID | Sev | Workstream | Action |")
    lines.append("|---|---|---|---|")
    for row in results:
        if row["class"] != "exploitable":
            continue
        work, action = WORKSTREAM.get(row["id"], ("Triage", "Assign owner"))
        lines.append("| %s | %s | %s | %s |" % (row["id"], row["severity"], work, action))
    lines.append("")
    lines.append("## Do not open tickets")
    lines.append("")
    for row in results:
        if row["class"] in ("false_positive", "control_covers", "weakness_not_exploitable", "duplicate"):
            lines.append("- **%s** (%s) - %s" % (row["id"], row["class"].replace("_", " "), row["why"]))
    lines.append("")
    lines.append("## Decision required")
    lines.append("")
    lines.append("1. Accept FA-001 / FA-012 as one AppSec item (parameterize `/search`, stop echoing SQL).")
    lines.append("2. Accept FA-002 as an identity/session item; close FA-003 as duplicate.")
    lines.append("3. Rotate the lab NHI key (FA-004, FA-005, FA-011) rather than filing three secrets tickets.")
    lines.append("4. Keep the WAF/output-encoding rule that killed FA-007. Do not spend a sprint on unused `old_widget` (FA-006).")
    lines.append("")
    lines.append("## What happens if we wait")
    lines.append("")
    lines.append("The firehose already produced 12 rows for a four-page app. If every model finding becomes a ticket, Product spends the week on FPs and an unused library while the login, the IDOR, and the AI-helper key stay open. Validation first is what keeps the queue honest.")
    lines.append("")
    lines.append("## Evidence (short)")
    lines.append("")
    lines.append("| ID | Title | Class | Probe |")
    lines.append("|---|---|---|---|")
    for row in results:
        lines.append("| %s | %s | %s | %s |" % (row["id"], row["title"], row["class"].replace("_", " "), row["evidence"]))
    lines.append("")

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Validate seeded lab findings against Lab Shop.")
    parser.add_argument("--target", default="http://127.0.0.1:8088")
    parser.add_argument("--findings", default=os.path.join(HERE, "findings.json"))
    parser.add_argument("--lab-dir", default="")
    parser.add_argument("--out", default=os.path.join(HERE, "program-status.md"))
    args = parser.parse_args()

    target = args.target.rstrip("/")
    findings_path = args.findings
    if not os.path.isfile(findings_path):
        alt = os.path.join(os.getcwd(), "findings.json")
        if os.path.isfile(alt):
            findings_path = alt
        else:
            print("Cannot find findings.json. Pass --findings path\\to\\findings.json")
            return 2

    with open(findings_path, "r") as handle:
        payload = json.load(handle)

    lab_dir = find_lab_dir(args.lab_dir)
    print("Target:   %s" % target)
    print("Findings: %s" % findings_path)
    print("Lab dir:  %s" % lab_dir)

    status, _text, _loc, err = http("GET", target + "/")
    if status != 200:
        print("Shop is not reachable at %s (%s). Start app.py first." % (target, err or status))
        return 1

    already_owned = set()
    results = []
    for finding in payload["findings"]:
        check = finding["check"]
        if check == "sql_injection_search":
            ok, evidence = check_sql_injection_search(target)
        elif check == "idor_profile":
            ok, evidence = check_idor_profile(target)
        elif check == "hardcoded_login":
            ok, evidence = check_hardcoded_login(target)
        elif check == "ai_key_leak":
            ok, evidence = check_ai_key_leak(target)
        elif check == "unused_component":
            ok, evidence = check_unused_component(lab_dir)
        elif check == "xss_search_waf":
            ok, evidence = check_xss_search_waf(target)
        elif check == "endpoint_param_exists":
            ok, evidence = check_endpoint_param_exists(target, finding)
        elif check == "endpoint_exists":
            ok, evidence = check_endpoint_exists(target, finding)
        elif check == "static_nhi_key":
            ok, evidence = check_static_nhi_key(lab_dir)
        elif check == "sql_error_disclosure":
            ok, evidence = check_sql_error_disclosure(target)
        else:
            ok, evidence = False, "unknown check %s" % check

        klass, why = classify(finding, ok, already_owned)
        if klass == "exploitable":
            already_owned.add((finding.get("endpoint"), finding.get("check")))

        row = {
            "id": finding["id"],
            "title": finding["title"],
            "severity": finding["severity"],
            "class": klass,
            "why": why,
            "evidence": evidence,
        }
        results.append(row)
        print("%s  %-28s  %s" % (finding["id"], klass, evidence))

    write_status(results, args.out, target)
    print("Wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
