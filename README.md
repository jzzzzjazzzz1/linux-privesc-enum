# linux-privesc-enum

Post-exploitation **enumeration** tool for Linux privilege escalation
assessment — modular version. Run this AFTER you already have a foothold
on a box (your own lab VM, a CTF target, or an engagement with written
authorization).

## What this is

A read-only diagnostic scanner, in the same family as LinPEAS/LinEnum:
it reads local system state and flags conditions **commonly associated**
with known privesc techniques, then points you to GTFOBins / HackTricks /
the CVE database **by name** so you look up and verify the actual
technique yourself.

## What this is NOT

- No exploitation code, payloads, or PoCs. A flagged SUID binary gets a
  GTFOBins link, not a command.
- No kernel exploit code, even for the CVE-name watchlist — kernel
  exploits are build-specific and a wrong guess can crash the box.
- Nothing is modified, executed as an exploit, or sent over the network.
- Not a determination that anything IS exploitable — every finding needs
  your manual verification against the exact build/patch level.

## Structure

```
main.py                              entrypoint
linux_privesc_enum/
  cli.py                             orchestrates all modules, writes reports
  utils.py                           run(), which(), finding() helpers
  watchlists.py                      name-only watchlists (SUID bins, capabilities,
                                      risky groups, kernel CVE names)
  report.py                          JSON + Markdown + HTML report generation
  modules/
    system_info.py                   hostname/kernel/OS + kernel CVE-name watchlist
    user_groups.py                   current user, risky group membership
    sudo_rules.py                    sudo -l parsing against the SUID watchlist
    suid_sgid.py                     filesystem-wide SUID/SGID binary search
    capabilities.py                  getcap -r / against dangerous capability names
    cron.py                          cron jobs: writable scripts AND writable parent dirs
    sensitive_files.py               /etc/passwd /etc/shadow /etc/sudoers perms + NFS no_root_squash
    ssh_keys.py                      readable private SSH keys under /home/*/.ssh, /root/.ssh
    env_enum.py                      PATH hijack vectors + LD_PRELOAD/PYTHONPATH hijack vectors
    network_docker.py                listening ports, Docker socket access, root process names
```

## Usage

```bash
python3 main.py                          # full scan, writes to ./enum_out/
python3 main.py --output-dir ./out       # custom output dir
python3 main.py --skip-suid-search       # skip the slow filesystem-wide find
```

Three reports are written: `.json` (for scripting against), `.md`
(for reading in a terminal/editor), `.html` (dark-themed, color-coded by
risk — open it in a browser).

## What's new vs the single-file version

- **Kernel CVE-name watchlist** (`system_info.py`) — flags when the
  running kernel version is in range of a well-known named CVE
  (Dirty Pipe, PwnKit, Dirty COW, etc), with an explicit caveat that this
  doesn't confirm exploitability since distros backport fixes.
- **NFS `no_root_squash` check** (`sensitive_files.py`) — a classic
  root-equivalent vector if you can mount the share from a host you control.
- **Cron parent-directory check** (`cron.py`) — flags a world-writable
  *directory* containing a cron script, not just a world-writable script
  itself (you can replace the whole file).
- **LD_PRELOAD / PYTHONPATH / PERL5LIB hijack check** (`env_enum.py`) —
  flags these env vars pointing at world-writable paths.
- **Docker socket reachability check** (`network_docker.py`) — flags if
  `/var/run/docker.sock` is connectable, commonly root-equivalent.
- **Root-owned process name listing** (`network_docker.py`) — process
  *names* only, deliberately not full command lines, to avoid
  incidentally harvesting credentials that happen to be passed as args.
- **HTML report** alongside the existing JSON/Markdown.

## Only run this with authorization

Your own machine, a legal lab (HackTheBox, TryHackMe), or an engagement
you have explicit written authorization for. Nothing else.
