"""System identification + kernel version CVE-name watchlist check.

The kernel check is deliberately shallow: it flags that a kernel version
*might* be in range of a well-known named CVE, so you know to go check
searchsploit/exploit-db/the CVE database for your EXACT build and distro
patch level. It never guesses or includes exploit code — kernel exploits
are notoriously build-specific and a wrong guess can crash the box.
"""
from __future__ import annotations
import platform
import re
from pathlib import Path

from ..utils import finding
from ..watchlists import KNOWN_KERNEL_CVE_NAMES


def enum_system_info():
    info = {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os_release": "",
    }
    osrel = Path("/etc/os-release")
    if osrel.exists():
        content = osrel.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', content, re.MULTILINE)
        info["os_release"] = m.group(1) if m else content.splitlines()[0]
    return info


def _parse_kernel_version(release: str) -> tuple[int, int] | None:
    m = re.match(r"(\d+)\.(\d+)", release)
    return (int(m.group(1)), int(m.group(2))) if m else None


def enum_kernel_cve_watchlist(kernel_release: str):
    """Flags that the running kernel's MAJOR.MINOR is >= a version where a
    well-known named CVE first applied. This is a coarse heuristic for
    "worth checking", not a determination that the box is vulnerable —
    distros backport fixes constantly."""
    findings = []
    current = _parse_kernel_version(kernel_release)
    if not current:
        return findings

    for version_prefix, cve_name in KNOWN_KERNEL_CVE_NAMES.items():
        watch = _parse_kernel_version(version_prefix)
        if watch and current >= watch:
            findings.append(finding(
                category="kernel_cve_watchlist",
                detail=(f"Kernel {kernel_release} is >= {version_prefix}, the version range "
                        f"where {cve_name} first applied. This does NOT confirm the box is "
                        f"vulnerable (distros backport fixes) — check searchsploit/the CVE "
                        f"database for your exact kernel build and distro patch level."),
                risk="MEDIUM",
                reference=f"https://nvd.nist.gov/vuln/search/results?query={cve_name.split()[0]}",
            ))
    return findings
