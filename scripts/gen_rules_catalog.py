#!/usr/bin/env python3
"""Generate docs/RULES_CATALOG.md from `codepulse-scan -rules` (read on stdin)."""
import sys
import json
import collections

d = json.load(sys.stdin)
bylang = collections.OrderedDict()
for r in sorted(d, key=lambda r: (r["language"], r["id"])):
    bylang.setdefault(r["language"], []).append(r)
total = len(d)
langs = sorted(bylang)
real_langs = [l for l in langs if l != "any"]

L = []
L.append("# CodePulse Rule Catalogue\n")
L.append("> Auto-generated from `codepulse-scan -rules`. Do not edit by hand —")
L.append("> regenerate with `make rules-catalog`.\n")
L.append(f"**{total} built-in rules** across **{len(real_langs)} languages** (plus language-agnostic secret detection). Each rule carries a")
L.append("type (BUG / VULNERABILITY / CODE_SMELL / SECURITY_HOTSPOT), a default severity,")
L.append("a remediation hint, and — for security rules — CWE and OWASP Top 10 mappings.\n")
L.append("## Summary\n")
L.append("| Language | Rules |")
L.append("|----------|------:|")
for l in langs:
    L.append(f"| {l} | {len(bylang[l])} |")
L.append(f"| **Total** | **{total}** |\n")
for l in langs:
    L.append(f"## {l}\n")
    L.append("| Rule ID | Name | Type | Severity | CWE | OWASP |")
    L.append("|---------|------|------|----------|-----|-------|")
    for r in bylang[l]:
        cwe = ", ".join(r.get("cwe") or []) or "—"
        owasp = ", ".join(r.get("owasp") or []) or "—"
        name = r["name"].replace("|", "\\|")
        L.append(f"| `{r['id']}` | {name} | {r['type']} | {r['severity']} | {cwe} | {owasp} |")
    L.append("")

sys.stdout.write("\n".join(L) + "\n")
