from __future__ import annotations

from ..utils import run, which, finding
from ..watchlists import DANGEROUS_CAPABILITIES


def enum_capabilities(timeout: int = 30):
    findings = []
    if not which("getcap"):
        return {"raw": "", "note": "getcap not installed"}, findings
    out = run("getcap -r / 2>/dev/null", timeout=timeout)
    lines = [l for l in out.splitlines() if l]
    for line in lines:
        lowered = line.lower()
        hit = next((c for c in DANGEROUS_CAPABILITIES if c in lowered), None)
        if hit:
            findings.append(finding(
                category="capabilities",
                detail=f"Dangerous capability set: {line}",
                risk="CRITICAL",
                reference="https://gtfobins.github.io/ (search 'Capabilities' section for the binary)",
            ))
    return {"raw": out}, findings
