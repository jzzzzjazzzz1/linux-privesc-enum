from __future__ import annotations
import re

from ..utils import run, finding, gtfobins_url
from ..watchlists import SUID_WATCHLIST


def enum_sudo():
    findings = []
    out = run("sudo -l -n 2>/dev/null")
    if not out or "password is required" in out.lower():
        return {"raw": "", "parsed_flagged": []}, findings

    flagged = []
    for line in out.splitlines():
        line_stripped = line.strip()
        if "NOPASSWD" in line_stripped:
            findings.append(finding(
                category="sudo",
                detail=f"NOPASSWD sudo rule found: {line_stripped}",
                risk="HIGH",
                reference="https://gtfobins.github.io/ (check the named binary under 'Sudo')",
            ))
            flagged.append(line_stripped)
        for watch in SUID_WATCHLIST:
            if re.search(rf"/{re.escape(watch)}\b", line_stripped):
                findings.append(finding(
                    category="sudo",
                    detail=f"sudo rule references watchlisted binary '{watch}': {line_stripped}",
                    risk="HIGH",
                    reference=gtfobins_url(watch),
                ))
                flagged.append(line_stripped)
                break

    return {"raw": out, "parsed_flagged": flagged}, findings
