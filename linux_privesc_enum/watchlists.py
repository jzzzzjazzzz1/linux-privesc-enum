"""
Name-only watchlists. These are lookup tables of binary/capability/CVE
NAMES commonly catalogued on GTFOBins or in public CVE databases — never
techniques, commands, or payloads. A hit means "go look this up," not
"here's how."
"""

# GTFOBins-catalogued SUID-abusable binary names.
SUID_WATCHLIST = {
    "nmap", "vim", "vi", "find", "bash", "sh", "more", "less", "nano",
    "cp", "mv", "python", "python2", "python3", "perl", "awk", "man",
    "env", "tar", "zip", "unzip", "ftp", "php", "ruby", "lua", "lua5.1",
    "node", "gdb", "strace", "tcpdump", "xxd", "openssl", "socat", "scp",
    "rsync", "git", "make", "sed", "ed", "expect", "ash", "dash", "zsh",
    "csh", "ksh", "mawk", "nawk", "jrunscript", "nc", "ncat", "netcat",
    "pip", "pip3", "run-parts", "systemctl", "docker", "mount", "umount",
    "chmod", "chown", "cpulimit", "crontab", "dmsetup", "flock", "ionice",
    "ip", "irb", "logsave", "nice", "nohup", "pkexec", "setarch",
    "start-stop-daemon", "stdbuf", "taskset", "time", "timeout", "watch",
    "xargs",
}

# Linux capabilities that, if set on a binary, are commonly abusable.
DANGEROUS_CAPABILITIES = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_sys_rawio",
}

# OS/group names worth flagging if the current user is a member.
RISKY_GROUPS = {"docker", "lxd", "disk", "adm", "shadow", "sudo", "wheel", "video"}

# Well-known kernel privesc CVE names, keyed by the earliest affected
# kernel version prefix. This is a lookup table of NAMES ONLY — no PoC,
# no exploit code, just "this CVE name exists, go check searchsploit /
# the CVE database / exploit-db yourself for your exact kernel build."
KNOWN_KERNEL_CVE_NAMES = {
    "5.8": "CVE-2021-3493 (OverlayFS)",
    "5.1": "CVE-2021-4034 (PwnKit / pkexec)",
    "4.4": "CVE-2016-5195 (Dirty COW)",
    "4.10": "CVE-2017-16995 (eBPF)",
    "5.10": "CVE-2022-0847 (Dirty Pipe)",
}
