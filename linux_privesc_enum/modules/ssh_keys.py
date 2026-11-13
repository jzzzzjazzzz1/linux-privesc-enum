from __future__ import annotations
from pathlib import Path

from ..utils import finding


def enum_ssh_keys():
    findings = []
    found = []
    home_root = Path("/home")
    search_dirs = list(home_root.glob("*/.ssh")) if home_root.is_dir() else []
    search_dirs.append(Path("/root/.ssh"))

    for d in search_dirs:
        try:
            if not d.is_dir():
                continue
        except PermissionError:
            continue
        try:
            for f in d.iterdir():
                if not f.is_file():
                    continue
                if f.name.endswith(".pub") or f.name in ("known_hosts", "authorized_keys", "config"):
                    continue
                try:
                    content_start = f.read_text(encoding="utf-8", errors="replace")[:40]
                except PermissionError:
                    continue
                if "PRIVATE KEY" in content_start:
                    found.append(str(f))
                    findings.append(finding(
                        category="credentials",
                        detail=f"Readable private SSH key: {f}",
                        risk="HIGH",
                    ))
        except PermissionError:
            continue

    return found, findings
