# Baseline Security Assessment

Date: 2026-11-05
Target: Ubuntu Server 26.04 LTS (10.10.111.8)
Attacker / scanner: Kali Linux (Nmap 7.95, Nikto 2.5.0)
Network: VirtualBox host-only, isolated lab

Raw outputs: `nmap-baseline.txt`, `nmap-baseline-ufw-off.txt`, `nikto-baseline.txt`, `ufw-timeline-journalctl.txt`, `ufw-nft-iptables-baseline.txt`, `stray-8080-ufw-on.txt`, `stray-8080-ufw-off.txt`, `stray-8080-server-log.txt`, `lynis-baseline.txt`

## Timeline of baseline evidence (UTC)

| Time | Event | Source |
|---|---|---|
| Nov 5, ~13:18 | Nikto scan (firewall state at that time not confirmed; the output does not show it) | `nikto-baseline.txt` (08:18 GMT-5 on Kali) |
| 13:23:50 | `ufw status` checked: inactive | `journalctl _COMM=sudo` |
| 13:24:32 / 13:24:42 | `ufw allow 22/tcp`, `ufw allow 80/tcp` | `journalctl _COMM=sudo` |
| 13:24:53 | `ufw enable` | `journalctl _COMM=sudo` |
| Nov 5, ~13:32 | Nmap full scan, firewall already enabled | `nmap-baseline.txt` (08:32 GMT-5 on Kali) |
| Nov 7, ~17:46 | Nmap full scan with UFW temporarily disabled; UFW then re-enabled and verified | `nmap-baseline-ufw-off.txt` (12:46 EST on Kali) |

Note: the order of events is reliable within each machine, but absolute times are not trusted across machines. The VMs have no internet, so nothing keeps their clocks in sync. Measured on Nov 7: Ubuntu `date -u` = 16:04:33 and Kali `date -u` = 18:05:37 (run about a minute apart), so the Ubuntu clock is about 2 hours behind the Kali clock. This offset cannot be assumed for Nov 5. For Nov 5 the firewall conclusion rests on the filtered result in `nmap-baseline.txt`, which shows UFW was on at scan time, not on the clock times. TODO: sync both clocks once the Ubuntu VM has internet.

## Attack surface

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | SSH | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 |
| 80/tcp | open | HTTP | Apache httpd 2.4.66 (Ubuntu) |

All other 65,533 ports: filtered (no response) with UFW enabled. Cause: UFW default deny incoming (verified with `ufw status verbose`, `iptables -S`, `nft list ruleset`).

### Scan comparison: UFW off vs UFW on

| | UFW off (`nmap-baseline-ufw-off.txt`) | UFW on (`nmap-baseline.txt`) |
|---|---|---|
| Open ports | 22, 80 | 22, 80 |
| Other 65,533 ports | closed (reset) | filtered (no response) |
| Scan duration | 41.63 s | 112.57 s |

The firewall did not change the open ports, because 22 and 80 are allowed from anywhere. It changed how every other port behaves: it answers with a reset when UFW is off, and stays silent when UFW is on.

## Stray service test (port 8080)

A Python web server was started by hand on port 8080, from an empty folder, to simulate a service started by mistake.

| UFW state | Nmap result for 8080 | Evidence |
|---|---|---|
| on | filtered | `stray-8080-ufw-on.txt` |
| off | open | `stray-8080-ufw-off.txt`; server log shows `HEAD / HTTP/1.1` 200 from 10.10.111.5 |

Conclusion: with UFW default deny, a service started by mistake (a test web server on port 8080) is filtered and not reachable from the network, while with UFW off it was open immediately. The firewall must stay enabled with default deny incoming. UFW was re-enabled and verified afterwards (`ufw status verbose`: active).

## Lynis audit (before hardening)

Lynis 3.1.6, run with UFW enabled and no package upgrade. Raw output: `lynis-baseline.txt`.

| Metric | Value |
|---|---|
| Hardening index | 60 / 100 |
| Tests performed | 266 |
| Warnings | 1 (vulnerable packages, PKGS-7392) |
| Suggestions | 48 |

Caveat: Lynis 3.1.6 is more than 6 months old and has no end-of-life entry for Ubuntu 26.04, so some checks may not match this OS version. The score is a measuring tool, not a goal.

Suggestions relevant to this project: Fail2ban (DEB-0880), auditd (ACCT-9628), SSH settings (SSH-7408: MaxAuthTries 6 to 3, LogLevel INFO to VERBOSE, AllowTcpForwarding, X11Forwarding, AllowAgentForwarding), Apache mod_evasive (HTTP-6640), system updates (PKGS-7392).

## Findings

### F1. Firewall initially inactive; now active but SSH is open to any source with no rate limiting (Low)
- Evidence: `ufw status` at 13:23:50 showed inactive; UFW was enabled by the administrator at 13:24:53 (see timeline). Current state from `ufw status verbose`: default deny incoming, `22/tcp ALLOW IN Anywhere` and `80/tcp ALLOW IN Anywhere` (IPv4 and IPv6), logging low. The `ufw-user-limit` chain exists in the kernel rules but no rule uses it.
- Impact: Before UFW, a service started by mistake was reachable immediately (confirmed with my port 8080 test). Now, with SSH open to any source and no rate limiting, an attacker can discover the open port by scanning (reconnaissance), then guess passwords without limits (brute force, T1110), and if one works, could use the server for further attacks, for example in a botnet.
- Fix: Restrict SSH in UFW to the admin subnet and rate-limit it (`ufw limit 22/tcp`), lower `MaxAuthTries` to 3, and install Fail2ban to ban the source IP after 3 failed logins until an administrator reviews and unbans it (with the admin address in `ignoreip`).

### F2. Version disclosure and missing security headers (Low)
- Evidence: server banner `Apache/2.4.66 (Ubuntu)`; `X-Frame-Options` and `X-Content-Type-Options` headers missing (Nikto)
- Impact: The Server header and scan results reveal the exact Apache version and operating system. This gives an attacker a starting point: they can look up known vulnerabilities for that version and go straight to exploiting one as the next step, instead of testing blindly. However, the version number alone does not prove the server is vulnerable, because Ubuntu applies security fixes without changing the version string. The two missing headers also leave browsers open to clickjacking and MIME sniffing.
- Fix: Set `ServerTokens Prod` and `ServerSignature Off` so the server stops announcing its exact version, add the `X-Frame-Options` and `X-Content-Type-Options` headers with `mod_headers`, and keep Apache patched.

### F3. SSH: default MaxAuthTries and no user whitelist (Low)
- Evidence: `maxauthtries 6` (default, applies per connection only; Lynis suggests 3); `allowusers` not set (Lynis: AllowUsers and AllowGroups not found). `logingracetime 120` is rated OK by Lynis, so it is a minor note, not a finding.
- Impact: `MaxAuthTries` only limits attempts per connection. An attacker can open a new connection and get six more guesses each time, so it does not stop brute force. With no `AllowUsers` whitelist, any valid account can be targeted.
- Fix: Set `MaxAuthTries` to 3 and add `AllowUsers` for the admin account, and rely on rate limiting (`ufw limit`, Fail2ban) and key authentication to actually stop brute force.

### F4. SSH password authentication enabled (Medium)
- Evidence: `sshd -T` shows `passwordauthentication yes`
- Combined with: F1 (SSH reachable from any source, no rate limiting), no Fail2ban
- Impact: Brute force succeeds if the password is easy to guess and the server lets the attacker make unlimited attempts. Password login is enabled and nothing limits attempts per source (no rate limiting, no Fail2ban), so the only barrier is the strength of the password.
- Fix: Use SSH key authentication with a passphrase and set `PasswordAuthentication no` once key login is tested; add rate limiting and Fail2ban as a second layer, and optionally a second factor (TOTP).
- ATT&CK mapping: T1110 Brute Force

## False positives
- Nikto CVE-2003-1418 (inode leak via ETag): the ETag format was checked manually and the inode is not exposed. Not applicable.

## Positive results
- UFW active with default deny incoming; only ports 22 and 80 reachable
- `PermitRootLogin prohibit-password`
- `PermitEmptyPasswords no`
- No dangerous HTTP methods allowed (PUT, DELETE, TRACE); Nikto lists only POST, OPTIONS, HEAD, GET

## Still to complete
- [x] Save the journalctl output as `ufw-timeline-journalctl.txt`
- [ ] Sync both clocks once the Ubuntu VM has internet (NTP), then record `date -u` from both at the start of every test session
- [x] Re-run Nmap with UFW off (`nmap-baseline-ufw-off.txt`), then re-enable UFW and confirm with `ufw status verbose`
- [x] Add the `maxauthtries` value to F3
- [x] Write the Impact and Fix sentences for F1 to F4 and the stray-service conclusion in your own words
- [x] Copy the two stray-service Nmap files and the server log (`stray-8080-server-log.txt`) into `01-baseline/`
- [x] Lynis hardening index: 60
- [x] Copy `lynis-baseline.txt` into `01-baseline/`
- [ ] Network diagram