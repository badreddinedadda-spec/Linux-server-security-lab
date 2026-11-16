# Phase 2: Hardening log

Target: Ubuntu Server 26.04 LTS (10.10.111.8), administered from the Windows host over SSH. Each step lists the change, the evidence files, and how to roll back.

Status: Step A (updates), Step B (SSH) and Step C (UFW) done. Pending: D (Apache), E (unused services), F (least privilege), then the after-measurements.

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

## Step C: UFW rules (F1)

- Change: added `ufw limit in on enp0s3 from 10.10.111.0/24 to any port 22 proto tcp` and `ufw allow in on enp0s3 from 10.10.111.0/24 to any port 80 proto tcp`; then deleted the old `22/tcp` and `80/tcp` rules for Anywhere (this also removed their IPv6 versions); `ufw logging medium`.
- Result (`ufw status verbose`): default deny incoming, and only two rules remain: `22/tcp on enp0s3 LIMIT IN 10.10.111.0/24` and `80/tcp on enp0s3 ALLOW IN 10.10.111.0/24`.
- Rate-limit test: 8 quick SSH connections from Kali (key not available there, so each is refused at authentication):

| Try | Before | After |
|---|---|---|
| 1 to 5 | Permission denied (publickey) | Permission denied (publickey) |
| 6 to 8 | Permission denied (publickey) | Connection refused |

- Log evidence: three `[UFW LIMIT BLOCK]` entries, `SRC=10.10.111.5 DST=10.10.111.8 DPT=22`, SYN packets, at the time of tries 6 to 8.
- Admin check: `ssh lab-server` from the Windows host still works with the key and passphrase after the change.
- Note on attribution: the before-test ran while Kali was behind its NAT adapter, so the target saw the source as the Windows host (10.10.111.3); the after-test ran with Kali on the lab network (10.10.111.5). IP-based controls act on the source address the server sees, and NAT can hide the real source.
- Note: the NAT adapter (enp0s8) is still enabled. The SSH and HTTP rules apply only to enp0s3, so incoming traffic on enp0s8 falls under default deny (by rule design, not tested from the NAT side). The NAT adapter is disconnected during attack tests.
- Why: DRAFT, rewrite in your own words. Only the lab network can reach SSH and HTTP, and one source cannot hammer SSH with unlimited connections.
- Evidence: `ufw-after.txt`, `ufw-limit-block.txt`, `ufw-limit-before-attack.txt`, `ufw-limit-after-attack.txt`
- Evidence note: the first capture of the two loop outputs lost the error messages (`ssh` prints them on stderr and `tee` only captured stdout, so both files held only `try N: 255`). The after-test was re-run with `2>&1`. The before-test file is transcribed from the terminal output of the original run (header line says so), because the before state no longer exists.
- Rollback: `sudo ufw allow 22/tcp` and `sudo ufw allow 80/tcp`, or restore a snapshot.

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
| SSH reachable from | Anywhere (no limit) | Lab subnet on enp0s3 only, limit: 6 connections per 30 s per source |
| SSH connections 6 to 8 in a quick burst | accepted for authentication | Connection refused |
| UFW logging | low | medium |
| IPv6 SSH and HTTP rules | present | removed (default deny) |
| Apache Server header | Apache/2.4.66 (Ubuntu) | ? (Step D) |
| Security headers (X-Frame-Options, nosniff) | 0 of 2 | ? (Step D) |
| Services enabled at boot | 53 | ? (Step E) |

The number of open TCP ports (22 and 80) is expected to stay the same. What changes is who can reach them and how they behave.
