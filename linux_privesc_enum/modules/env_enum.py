from __future__ import annotations
import os
import stat
from pathlib import Path

from ..utils import finding

# Env vars that, if set and pointing somewhere writable, can hijack
# execution of processes that inherit them (e.g. a root cron job).
HIJACKABLE_ENV_VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB")


def enum_path_env():
    findings = []
    path_var = os.environ.get("PATH", "")
    dirs = path_var.split(":")
    issues = []
    for d in dirs:
        if d == "" or d == ".":
            issues.append(d or "(empty = cwd)")
            continue
        p = Path(d)
        try:
            if p.is_dir():
                mode = p.stat().st_mode
                if mode & stat.S_IWOTH:
                    issues.append(f"{d} (world-writable)")
        except PermissionError:
            continue
    if issues:
        findings.append(finding(
            category="path_env",
            detail=(f"PATH contains writable/relative entries: {', '.join(issues)}. "
                    f"If a root process or SUID binary relies on an unqualified command, "
                    f"this can be a PATH-hijack vector."),
            risk="MEDIUM",
        ))
    return {"PATH": path_var, "issues": issues}, findings


def enum_hijackable_env_vars():
    findings = []
    results = {}
    for var in HIJACKABLE_ENV_VARS:
        val = os.environ.get(var)
        if not val:
            continue
        results[var] = val
        for part in val.split(":"):
            p = Path(part)
            try:
                writable = p.exists() and (p.stat().st_mode & stat.S_IWOTH)
            except PermissionError:
                continue
            if writable:
                findings.append(finding(
                    category="env_var",
                    detail=f"{var} includes world-writable path '{part}'. If a root "
                           f"process inherits this env var, it's a code-execution vector.",
                    risk="HIGH",
                    reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload",
                ))
    return results, findings
