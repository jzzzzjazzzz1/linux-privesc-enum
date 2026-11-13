from __future__ import annotations
import re
import stat
from pathlib import Path

from ..utils import run, finding


def enum_cron():
    findings = []
    cron_dir = Path("/etc/cron.d")
    cron_paths = ["/etc/crontab"] + sorted(str(p) for p in cron_dir.glob("*")) if cron_dir.is_dir() else ["/etc/crontab"]
    details = {}

    for cp in cron_paths:
        p = Path(cp)
        try:
            if not p.is_file():
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            continue
        details[cp] = content

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m = re.search(r"\s(/\S+\.(sh|py|pl))\b", line)
            if not m:
                continue
            script_path = Path(m.group(1))
            try:
                if not script_path.exists():
                    continue
                mode = script_path.stat().st_mode
            except PermissionError:
                continue

            if mode & stat.S_IWOTH:
                findings.append(finding(
                    category="cron",
                    detail=f"Cron job runs world-writable script: {script_path} (from {cp})",
                    risk="CRITICAL",
                ))
            elif mode & stat.S_IWGRP:
                findings.append(finding(
                    category="cron",
                    detail=f"Cron job runs group-writable script: {script_path} (from {cp}). "
                           f"Worth checking if your groups include the writing group.",
                    risk="MEDIUM",
                ))

            # Writable parent directory lets you replace the script even if
            # the file itself isn't writable (classic cron-dir hijack).
            parent = script_path.parent
            try:
                if parent.exists():
                    parent_mode = parent.stat().st_mode
                    if parent_mode & stat.S_IWOTH:
                        findings.append(finding(
                            category="cron",
                            detail=f"Cron job's script directory is world-writable: {parent} "
                                   f"(script: {script_path}, from {cp})",
                            risk="CRITICAL",
                        ))
            except PermissionError:
                pass

    user_cron = run("crontab -l 2>/dev/null")
    if user_cron:
        details["user_crontab"] = user_cron

    return details, findings
