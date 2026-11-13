"""
CLI entrypoint. Runs each enumeration module, collects findings, writes
JSON/Markdown/HTML reports.

DIAGNOSTIC ONLY — reads local system state, flags commonly-risky
conditions by name, and points you to GTFOBins/HackTricks/the CVE
database to look up the technique yourself. Contains no exploitation
code, modifies nothing, sends no network traffic anywhere else.

Only run this on a system you own, a legal lab (HTB/TryHackMe), or an
engagement you have written authorization for.
"""
from __future__ import annotations
import argparse

from .modules.system_info import enum_system_info, enum_kernel_cve_watchlist
from .modules.user_groups import enum_current_user
from .modules.sudo_rules import enum_sudo
from .modules.suid_sgid import enum_suid_sgid
from .modules.capabilities import enum_capabilities
from .modules.cron import enum_cron
from .modules.sensitive_files import enum_writable_sensitive, enum_nfs_exports
from .modules.ssh_keys import enum_ssh_keys
from .modules.env_enum import enum_path_env, enum_hijackable_env_vars
from .modules.network_docker import enum_listening_ports, enum_docker_socket, enum_running_root_processes
from .report import write_reports


def main():
    parser = argparse.ArgumentParser(
        description="Post-exploitation Linux privesc enumeration (diagnostic only)."
    )
    parser.add_argument("--output-dir", default="./enum_out",
                         help="Where to write reports (default: ./enum_out)")
    parser.add_argument("--skip-suid-search", action="store_true",
                         help="Skip the filesystem-wide SUID/SGID search (can be slow on large disks)")
    args = parser.parse_args()

    print("=" * 70)
    print("DIAGNOSTIC ONLY — this tool reads local system state and flags")
    print("conditions. It does not exploit anything. Only run this on a")
    print("system you own, a legal lab (HTB/TryHackMe), or an engagement")
    print("with written authorization.")
    print("=" * 70)

    all_findings = []
    sections = {}

    system_info = enum_system_info()
    all_findings += enum_kernel_cve_watchlist(system_info["kernel"])

    print("[*] Current user & groups...")
    user_info, f = enum_current_user()
    sections["user"] = user_info
    all_findings += f

    print("[*] sudo -l...")
    sudo_info, f = enum_sudo()
    sections["sudo"] = sudo_info
    all_findings += f

    if not args.skip_suid_search:
        print("[*] SUID/SGID binaries (this can take a moment)...")
        suid_info, f = enum_suid_sgid()
        sections["suid_sgid"] = suid_info
        all_findings += f
    else:
        print("[*] Skipping SUID/SGID search (--skip-suid-search)")

    print("[*] Capabilities...")
    cap_info, f = enum_capabilities()
    sections["capabilities"] = cap_info
    all_findings += f

    print("[*] Cron jobs...")
    cron_info, f = enum_cron()
    sections["cron"] = cron_info
    all_findings += f

    print("[*] Sensitive file permissions...")
    sens_info, f = enum_writable_sensitive()
    sections["sensitive_files"] = sens_info
    all_findings += f

    print("[*] NFS exports...")
    nfs_info, f = enum_nfs_exports()
    sections["nfs_exports"] = nfs_info
    all_findings += f

    print("[*] SSH private keys...")
    ssh_info, f = enum_ssh_keys()
    sections["ssh_keys"] = ssh_info
    all_findings += f

    print("[*] PATH environment...")
    path_info, f = enum_path_env()
    sections["path_env"] = path_info
    all_findings += f

    print("[*] Hijackable env vars (LD_PRELOAD etc)...")
    env_info, f = enum_hijackable_env_vars()
    sections["env_vars"] = env_info
    all_findings += f

    print("[*] Docker socket...")
    docker_info, f = enum_docker_socket()
    sections["docker"] = docker_info
    all_findings += f

    print("[*] Listening ports...")
    sections["listening_ports"] = enum_listening_ports()

    print("[*] Root-owned process names...")
    sections["root_processes"] = enum_running_root_processes()

    json_path, md_path, html_path = write_reports(args.output_dir, system_info, sections, all_findings)

    critical = sum(1 for x in all_findings if x["risk"] == "CRITICAL")
    high = sum(1 for x in all_findings if x["risk"] == "HIGH")
    print(f"\n[+] {len(all_findings)} finding(s): {critical} CRITICAL, {high} HIGH")
    print(f"[+] Reports written:\n    {json_path}\n    {md_path}\n    {html_path}")


if __name__ == "__main__":
    main()
