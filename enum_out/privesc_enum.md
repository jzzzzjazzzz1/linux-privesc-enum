# Privilege Escalation Enumeration Report
_Generated 2026-11-13T11:25:35.794083+00:00Z_

> Diagnostic only. Nothing here was exploited. Verify manually and only act within an engagement you're authorized for.

## System
- **hostname**: Acer
- **kernel**: 6.6.87.2-microsoft-standard-WSL2
- **arch**: x86_64
- **os_release**: Debian GNU/Linux 12 (bookworm)

## Findings (10 total)

### [HIGH] group_membership
User 'jzz_jazz' is in privilege-relevant group(s): adm, sudo, docker.

Look up the technique: https://gtfobins.github.io/ (search by group-relevant binary, e.g. docker)

### [HIGH] suid_sgid
SUID/SGID binary on watchlist: /usr/bin/crontab

Look up the technique: https://gtfobins.github.io/gtfobins/crontab/

### [HIGH] suid_sgid
SUID/SGID binary on watchlist: /usr/bin/umount

Look up the technique: https://gtfobins.github.io/gtfobins/umount/

### [HIGH] suid_sgid
SUID/SGID binary on watchlist: /usr/bin/mount

Look up the technique: https://gtfobins.github.io/gtfobins/mount/

### [MEDIUM] kernel_cve_watchlist
Kernel 6.6.87.2-microsoft-standard-WSL2 is >= 5.8, the version range where CVE-2021-3493 (OverlayFS) first applied. This does NOT confirm the box is vulnerable (distros backport fixes) — check searchsploit/the CVE database for your exact kernel build and distro patch level.

Look up the technique: https://nvd.nist.gov/vuln/search/results?query=CVE-2021-3493

### [MEDIUM] kernel_cve_watchlist
Kernel 6.6.87.2-microsoft-standard-WSL2 is >= 5.1, the version range where CVE-2021-4034 (PwnKit / pkexec) first applied. This does NOT confirm the box is vulnerable (distros backport fixes) — check searchsploit/the CVE database for your exact kernel build and distro patch level.

Look up the technique: https://nvd.nist.gov/vuln/search/results?query=CVE-2021-4034

### [MEDIUM] kernel_cve_watchlist
Kernel 6.6.87.2-microsoft-standard-WSL2 is >= 4.4, the version range where CVE-2016-5195 (Dirty COW) first applied. This does NOT confirm the box is vulnerable (distros backport fixes) — check searchsploit/the CVE database for your exact kernel build and distro patch level.

Look up the technique: https://nvd.nist.gov/vuln/search/results?query=CVE-2016-5195

### [MEDIUM] kernel_cve_watchlist
Kernel 6.6.87.2-microsoft-standard-WSL2 is >= 4.10, the version range where CVE-2017-16995 (eBPF) first applied. This does NOT confirm the box is vulnerable (distros backport fixes) — check searchsploit/the CVE database for your exact kernel build and distro patch level.

Look up the technique: https://nvd.nist.gov/vuln/search/results?query=CVE-2017-16995

### [MEDIUM] kernel_cve_watchlist
Kernel 6.6.87.2-microsoft-standard-WSL2 is >= 5.10, the version range where CVE-2022-0847 (Dirty Pipe) first applied. This does NOT confirm the box is vulnerable (distros backport fixes) — check searchsploit/the CVE database for your exact kernel build and distro patch level.

Look up the technique: https://nvd.nist.gov/vuln/search/results?query=CVE-2022-0847

### [MEDIUM] path_env
PATH contains writable/relative entries: /mnt/d/Java/bin (world-writable), /mnt/d/Java/bin (world-writable), /mnt/c/php83 (world-writable), /mnt/c/Users/Acer/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Python 3.13 (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Python/Python313 (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Python/Python313/Scripts (world-writable), /mnt/c/Users/Acer/AppData/Local/Muse Hub/lib (world-writable), /mnt/c/xampp/php (world-writable), /mnt/d/Git/cmd (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Python/Python313/ (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Python/Launcher/ (world-writable), /mnt/c/Users/Acer/AppData/Local/Microsoft/WindowsApps (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Microsoft VS Code/bin (world-writable), /mnt/c/Users/Acer/AppData/Roaming/npm (world-writable), /mnt/c/Users/Acer/AppData/Local/Muse Hub/lib (world-writable), /mnt/c/Users/Acer/.local/bin (world-writable), /mnt/c/Users/Acer/AppData/Local/Programs/Ollama (world-writable). If a root process or SUID binary relies on an unqualified command, this can be a PATH-hijack vector.

