from __future__ import annotations
import stat
from pathlib import Path

from ..utils import finding

SENSITIVE_PATHS = {
    "/etc/passwd": "CRITICAL",
    "/etc/shadow": "CRITICAL",
    "/etc/sudoers": "CRITICAL",
    "/etc/sudoers.d": "CRITICAL",
    "/etc/ssh/sshd_config": "HIGH",
}


def enum_writable_sensitive():
    findings = []
    results = {}
    for path, risk in SENSITIVE_PATHS.items():
        p = Path(path)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
        except PermissionError:
            continue
        writable_by_other = bool(mode & stat.S_IWOTH)
        writable_by_group = bool(mode & stat.S_IWGRP)
        results[path] = {"world_writable": writable_by_other, "group_writable": writable_by_group}
        if writable_by_other:
            findings.append(finding(
                category="sensitive_file",
                detail=f"{path} is WORLD-WRITABLE.",
                risk=risk,
            ))
    return results, findings


def enum_nfs_exports():
    """Flags NFS exports with no_root_squash, a classic root-equivalent
    privesc vector when you can mount the share from another host you
    control. Reads /etc/exports only; does nothing with NFS itself."""
    findings = []
    p = Path("/etc/exports")
    if not p.exists():
        return {"present": False}, findings
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return {"present": True, "readable": False}, findings

    flagged_lines = [l for l in content.splitlines() if "no_root_squash" in l and not l.strip().startswith("#")]
    for line in flagged_lines:
        findings.append(finding(
            category="nfs",
            detail=f"/etc/exports entry has no_root_squash: {line.strip()}",
            risk="HIGH",
            reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#nfs",
        ))
    return {"present": True, "readable": True, "raw": content, "flagged_lines": flagged_lines}, findings
