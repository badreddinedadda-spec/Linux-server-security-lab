# Baseline Security Assessment

Date: 2026-11-05
Target: Ubuntu Server 26.04 LTS (10.10.111.8)
Attacker / scanner: Kali Linux (Nmap 7.95, Nikto 2.5.0)
Network: VirtualBox host-only, isolated lab

Raw outputs: `nmap-baseline.txt`, `nikto-baseline.txt`

## Attack surface

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | SSH | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 |
| 80/tcp | open | HTTP | Apache httpd 2.4.66 (Ubuntu) |

All other 65,533 ports: filtered (no response).

## Findings

### F1. No host firewall configured in UFW (Low in lab)
- Evidence: `ufw status` = inactive. Nmap reports the other 65,533 ports as filtered, so some packet filtering exists that UFW does not explain.
- Impact: TODO (complete after the investigation below)
- Fix: TODO
- Open question: what is dropping the packets? To check on the server: `sudo ufw status verbose`, `sudo nft list ruleset`, `sudo iptables -S`

### F2. Version disclosure and missing security headers (Low)
- Evidence: server banner `Apache/2.4.66 (Ubuntu)`; `X-Frame-Options` and `X-Content-Type-Options` headers missing (Nikto)
- Impact: DRAFT, rewrite in your own words. The attacker learns the exact web server version and operating system, which helps choose known exploits. Missing headers allow clickjacking and browser MIME sniffing.
- Fix: DRAFT. Set `ServerTokens Prod` and `ServerSignature Off`; add both headers with `mod_headers`.

### F3. SSH: long login grace time and no user whitelist (Low)
- Evidence: `logingracetime 120`; `allowusers` not set; `maxauthtries`: TODO (run `sudo sshd -T | grep -i maxauthtries`)
- Impact: DRAFT, rewrite in your own words. An attacker can keep many unauthenticated connections open for two minutes each, using server resources. Without a whitelist, any valid account may attempt to log in.
- Fix: DRAFT. Set `LoginGraceTime 30`, add `AllowUsers` for the admin account, review `MaxAuthTries`.

### F4. SSH password authentication enabled (Medium)
- Evidence: `sshd -T` shows `passwordauthentication yes`
- Combined with: no rate limiting known yet (see F1), no Fail2ban
- Impact: DRAFT, rewrite in your own words. An attacker can guess passwords against any valid account repeatedly. Success depends only on password strength, and nothing currently slows or blocks repeated attempts.
- Fix: DRAFT. Use key authentication and set `PasswordAuthentication no` after key login is tested; add connection rate limiting and Fail2ban.
- ATT&CK mapping: T1110 Brute Force

## False positives
- Nikto CVE-2003-1418 (inode leak via ETag): the ETag format was checked manually and the inode is not exposed. Not applicable.

## Positive results
- Only two ports reachable from the attacker machine
- `PermitRootLogin prohibit-password`
- `PermitEmptyPasswords no`
- No dangerous HTTP methods allowed (PUT, DELETE, TRACE); Nikto lists only POST, OPTIONS, HEAD, GET

## Still to complete
- [ ] Investigate the filtered ports and finish F1
- [ ] Add the `maxauthtries` value to F3
- [ ] Rewrite the DRAFT sentences in F2, F3 and F4 in your own words
- [ ] Stray-service experiment (port 8080) and its Nmap output
- [ ] Lynis hardening index (needs internet on the Ubuntu VM)
- [ ] Network diagram