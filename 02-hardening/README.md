# Phase 2: Hardening log

Target: Ubuntu Server 26.04 LTS (10.10.111.8), administered from the Windows host over SSH. Each step lists the change, the evidence files, and how to roll back.

Status: Step A (updates) and Step B (SSH) done. Pending: C (UFW), D (Apache), E (unused services), F (least privilege), then the after-measurements.

## Snapshots

| Snapshot | Use |
|---|---|
| `upgrade` | Older snapshot of the target |
| `after-updates-before-ssh-hardening` | Taken after the updates, before the SSH hardening |

Before-attack baseline for Phase 3: restore a snapshot and check `sudo sshd -T | grep -i passwordauthentication`. It must say `yes`. If it says `no`, that snapshot is already hardened, so use the older one.

## Step A: system updates

- Change: `sudo apt update`, `sudo apt upgrade`, reboot.
- Result: pending updates 82 to 3. The remaining 3 (`distro-info`, `python3-distro-info`, `snapd`) were deferred by Ubuntu phased updates (`Not upgrading yet due to phasing`). Kernel 7.0.0-42 to 7.0.0-43.
- `openssh-server`, `apache2` and `ufw` were not in the pending list, so their versions did not change: Nmap banners at baseline showed OpenSSH 10.2p1 and Apache 2.4.66; after the update `dpkg` shows openssh-server 1:10.2p1-2ubuntu3.8, apache2 2.4.66-2ubuntu2.7, ufw 0.36.2-9build1.
- Packages Lynis listed as vulnerable before the update: apt, ca-certificates, libapt-pkg7.0, python3-twisted.
- Limitation: `versions-before.txt` was captured empty because of a typo in the command, so the "before" versions are proven by the Nmap baseline and `apt-upgradable-baseline.txt` instead.
- Why: DRAFT, rewrite in your own words. Known fixes come before new locks.
- Evidence: `01-baseline/apt-upgradable-baseline.txt`, `versions-after.txt`, `apt-history-after.txt`, `kernel-before.txt`, `lynis-vulnerable-packages-before.txt`
- Rollback: restore a snapshot.

## Step B: SSH hardening

- Change: ed25519 key pair created on the Windows host (the admin workstation, not on Kali, so the attacker machine has no key). Public key installed in `~/.ssh/authorized_keys`. Key login tested first, then the drop-in file `/etc/ssh/sshd_config.d/00-hardening.conf` added and applied with `systemctl reload ssh`, while the first SSH session stayed open.
- Key fingerprint: `SHA256:u7R6YKV1Kr/3MXFfOeVftG4WD7JFbe8kxhr78vsklGU` (matches the `Accepted publickey` lines in the auth log).
- Effective values (`sshd -T`), from `sshd-diff.txt`:

| Setting | Before | After |
|---|---|---|
| passwordauthentication | yes | no |
| permitrootlogin | prohibit-password | no |
| allowusers | not set | badre |
| maxauthtries | 6 | 3 |
| logingracetime | 120 | 30 |
| loglevel | INFO | VERBOSE |
| maxsessions | 10 | 2 |
| allowtcpforwarding | yes | no |
| allowagentforwarding | yes | no |
| x11forwarding | yes | no |
| clientaliveinterval | 0 | 300 |
| clientalivecountmax | 3 | 2 |

`kbdinteractiveauthentication` is set to `no` in the drop-in but does not appear in the diff, so it was already `no`.

- Tests:
  - Login from Windows with the key and passphrase works; with LogLevel VERBOSE the auth log shows `Accepted key ED25519 SHA256:... found` and `Accepted publickey for badre from 10.10.111.3`.
  - Login with public-key authentication disabled is refused: `Permission denied (publickey).` (password login no longer possible).
- Note: during testing, ProtonVPN on the Windows host blocked access to the host-only network (`Test-NetConnection` failed, then succeeded with the VPN off). This was not caused by the hardening. Lab tests are run with the VPN disconnected.
- Why: DRAFT, rewrite in your own words. A stolen or guessed password is no longer enough, because login needs the private key and its passphrase.
- Evidence: `01-baseline/sshd-effective-baseline.txt`, `sshd-effective-after.txt`, `sshd-diff.txt`, `ssh-auth-after.txt`, `ssh-password-login-refused.txt`
- Rollback: `sudo rm /etc/ssh/sshd_config.d/00-hardening.conf && sudo systemctl reload ssh` (from the VirtualBox console if SSH is locked), or restore the snapshot.

## Before / after so far

| Metric | Before | After |
|---|---|---|
| Pending package updates | 82 | 3 (phased) |
| Kernel | 7.0.0-42 | 7.0.0-43 |
| SSH password login | enabled | disabled |
| SSH MaxAuthTries | 6 | 3 |
| SSH LoginGraceTime | 120 | 30 |
| SSH root login | prohibit-password | no |
| Lynis hardening index | 60 | ? |
| SSH reachable from | Anywhere (no limit) | ? (Step C) |
| Apache Server header | Apache/2.4.66 (Ubuntu) | ? (Step D) |
| Security headers (X-Frame-Options, nosniff) | 0 of 2 | ? (Step D) |
| Services enabled at boot | 53 | ? (Step E) |

The number of open TCP ports (22 and 80) is expected to stay the same. What changes is who can reach them and how they behave.
