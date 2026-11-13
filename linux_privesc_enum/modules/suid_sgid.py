from __future__ import annotations
from pathlib import Path

from ..utils import run, finding, gtfobins_url
from ..watchlists import SUID_WATCHLIST


def enum_suid_sgid(max_results: int = 500, timeout: int = 60):
    findings = []
    out = run(
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null",
        timeout=timeout,
    )
    paths = [p for p in out.splitlines() if p][:max_results]
    flagged_paths = []
    for p in paths:
        name = Path(p).name
        if name in SUID_WATCHLIST:
            findings.append(finding(
                category="suid_sgid",
                detail=f"SUID/SGID binary on watchlist: {p}",
                risk="HIGH",
                reference=gtfobins_url(name),
            ))
            flagged_paths.append(p)
    return {"all_suid_sgid": paths, "flagged": flagged_paths}, findings
