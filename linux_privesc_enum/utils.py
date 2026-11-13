"""
Shared helpers. Every function here is read-only: it runs a diagnostic
shell command or inspects the filesystem, never modifies anything, and
never contains or constructs an exploitation command.
"""
from __future__ import annotations
import shutil
import subprocess

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def run(cmd, timeout: int = 10) -> str:
    """Run a read-only shell command, return stdout or '' on any failure."""
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str), capture_output=True,
            text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


def gtfobins_url(name: str) -> str:
    return f"https://gtfobins.github.io/gtfobins/{name}/"


def hacktricks_search_url(term: str) -> str:
    return f"https://book.hacktricks.xyz/search?q={term.replace(' ', '+')}"


def finding(category: str, detail: str, risk: str, reference: str | None = None) -> dict:
    """Builds one finding dict in the standard shape every module returns."""
    d = {"category": category, "detail": detail, "risk": risk}
    if reference:
        d["reference"] = reference
    return d
