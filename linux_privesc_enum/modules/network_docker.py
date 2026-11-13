from __future__ import annotations
from pathlib import Path

from ..utils import run, finding


def enum_listening_ports():
    out = run("ss -tulpn 2>/dev/null") or run("netstat -tulpn 2>/dev/null")
    return {"raw": out}


def enum_docker_socket():
    """Flags whether the Docker socket is reachable by the current user.
    Access to it is commonly root-equivalent (you can run a privileged
    container that mounts the host filesystem) — flagged by name only,
    the actual container command is left for you to look up on GTFOBins."""
    findings = []
    sock = Path("/var/run/docker.sock")
    results = {"socket_exists": sock.exists(), "accessible": False}
    if sock.exists():
        import socket as socket_mod
        try:
            s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
            s.settimeout(2)
            s.connect(str(sock))
            s.close()
            results["accessible"] = True
            findings.append(finding(
                category="docker",
                detail="Docker socket /var/run/docker.sock is accessible from this user. "
                       "If so, you can typically run a privileged container to gain root.",
                risk="CRITICAL",
                reference="https://gtfobins.github.io/gtfobins/docker/",
            ))
        except Exception:
            pass
    return results, findings


def enum_running_root_processes():
    """Lists root-owned processes by name only (for you to review for
    anything unusual — a custom script, an outdated service, etc). Does
    not inspect command-line arguments for secrets to avoid incidentally
    harvesting credentials as a side effect of running this tool."""
    out = run("ps -eo user,comm --no-headers 2>/dev/null")
    root_procs = sorted(set(
        line.split(None, 1)[1] for line in out.splitlines()
        if line.startswith("root ") and len(line.split(None, 1)) == 2
    ))
    return {"root_process_names": root_procs}
