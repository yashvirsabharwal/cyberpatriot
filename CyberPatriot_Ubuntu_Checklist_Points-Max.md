# CyberPatriot Ubuntu Checklist — Points‑Max Edition (2025)

> **Use this guide alongside the team README and injects.** When in doubt, follow the README. Steps marked **(IF ALLOWED)** should only be applied if the README and scenario don’t require the feature.

---

## 0) Snapshot & Triage (30–60 seconds)
- Take a VM snapshot or copy the disk if possible.
- Read the README fully; note **required users**, **required services**, **disallowed changes**, and any **service credentials**.
- Log in with an admin user (sudo-capable). If unsure, try `sudo -l` to confirm.

---

## 1) Quick “Safe Anywhere” Patch Block
Copy‑paste the whole block; it is safe, minimal, and scores well.

```bash
# 1) Update and enable unattended security upgrades
sudo apt update && sudo apt -y full-upgrade
sudo apt -y install unattended-upgrades apt-listchanges
sudo dpkg-reconfigure -plow unattended-upgrades

# 2) Time sync (keep defaults) — prefer systemd-timesyncd for simplicity
sudo systemctl enable --now systemd-timesyncd 2>/dev/null || true
timedatectl set-ntp true

# 3) Firewall with IPv6 mirrored rules
sudo sed -ri 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw --force enable
sudo ufw reload
sudo ufw status verbose

# 4) Sticky bit on world-writable temp dirs
sudo chmod a+t /tmp /var/tmp

# 5) Auditd baseline with high‑value watches
sudo apt -y install auditd audispd-plugins
sudo tee /etc/audit/rules.d/10-harder.rules >/dev/null <<'EOF'
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/sudoers  -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/localtime -p wa -k time-change
-e 2
EOF
sudo augenrules --load || sudo service auditd restart

# 6) (IF ALLOWED) Basic SSH bruteforce protection
sudo apt -y install fail2ban
sudo systemctl enable --now fail2ban
sudo tee /etc/fail2ban/jail.d/ssh.local >/dev/null <<'EOF'
[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = 15m
EOF
sudo systemctl restart fail2ban
```

---

## 2) Accounts & Authentication

### 2.1 Users
- **Remove unknown users** that are not in the README’s allowed list.
- **Create required users** and set strong passwords.
- Lock system/service accounts that should not be used interactively.

```bash
# List human users (UID ≥ 1000)
awk -F: '($3>=1000){print $1":"$6":"$7}' /etc/passwd

# Add a required user (example)
sudo adduser <username>
sudo usermod -aG sudo <username>

# Lock an interactive shell on service accounts (example)
sudo usermod -s /usr/sbin/nologin <serviceuser>
```

### 2.2 Password policy (PAM + pwquality)
```bash
sudo apt -y install libpam-pwquality
# Enforce reasonable defaults
sudo tee /etc/security/pwquality.conf >/dev/null <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
reject_username = 1
enforce_for_root
EOF
```

### 2.3 Lockout policy (Deny brute force)
```bash
# Add to /etc/pam.d/common-auth (before pam_unix.so) if not present:
# auth  required  pam_tally2.so deny=5 onerr=fail unlock_time=600 even_deny_root root_unlock_time=600
#
# Newer Ubuntu may use pam_faillock:
# auth required pam_faillock.so preauth silent deny=5 unlock_time=600
# auth [default=die] pam_faillock.so authfail deny=5 unlock_time=600
# account required pam_faillock.so
```

### 2.4 Inactivity & expiration
```bash
# Default inactivity for new users: lock after 30 days of inactivity
sudo useradd -D -f 30
# Apply to existing human users (UID ≥ 1000)
for u in $(awk -F: '($3>=1000){print $1}' /etc/passwd); do sudo chage --inactive 30 "$u"; done
# Force periodic password change (example 90 days)
for u in $(awk -F: '($3>=1000){print $1}' /etc/passwd); do sudo chage -M 90 "$u"; done
```

---

## 3) SSH Hardening (respect services & access needs)

Edit `/etc/ssh/sshd_config` and set:

```
Protocol 2
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes   # switch to 'no' ONLY if keys are deployed and allowed
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 4
# (IF ALLOWED) Restrict to explicit users from README:
# AllowUsers user1 user2
```

```bash
sudo systemctl restart ssh
```

> **Tip:** If you are connected via SSH, keep a second root/sudo session open before restarting `ssh` to avoid lockout.

---

## 4) Services, Ports & Software

### 4.1 Inventory and stop what’s not needed
```bash
ss -tulpen      # list listening sockets
systemctl --type=service --state=running
sudo systemctl disable --now <unneeded.service>
```

### 4.2 Common service hygiene
- **Apache/Nginx**: remove default sites, disable directory listing, minimal modules.
- **Samba**: verify shares match README; lock guest, restrict hosts.
- **MySQL/PostgreSQL**: set strong root/admin creds; bind to localhost unless told otherwise.
- **FTP/VSFTPD** (only if required): chroot users, disable anonymous.

---

## 5) Firewall (UFW) Details

- Default: **deny incoming**, **allow outgoing**.
- Allow only required service ports from the README.
- Confirm IPv6 is enabled so rules mirror to v6.

```bash
sudo ufw status numbered
# Example: allow HTTP/HTTPS if web server required
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Remove mistaken rules:
# sudo ufw delete <rule-number>
```

---

## 6) Logging & Auditing

- `rsyslog` running and enabled (default on server).
- `auditd` loaded (from Quick Block).

Quick checks:
```bash
sudo systemctl is-active rsyslog || sudo systemctl enable --now rsyslog
sudo auditctl -s
sudo ausearch -k identity | tail
```

---

## 7) Filesystem & Permissions

- Ensure `/tmp` and `/var/tmp` are sticky; consider separate mounts only if preconfigured.
- Remove world‑writable bits on sensitive paths:
```bash
sudo find / -xdev -type d -perm -0002 ! -path "/proc/*" -print
```

- Check for SUID/SGID binaries out of place:
```bash
sudo find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null | sort
```

- (IF ALLOWED) Lock USB/automount on desktops:
```bash
# Stop automount helpers
sudo systemctl disable --now autofs 2>/dev/null || true
# GNOME (if present)
gsettings set org.gnome.desktop.media-handling automount false 2>/dev/null || true
# Optional advanced:
# sudo apt -y install usbguard && sudo systemctl enable --now usbguard
```

---

## 8) Banners & Legal (consistent, professional)

Create a professional banner (no jokes/slang) and apply consistently:
```bash
sudo tee /etc/issue >/dev/null <<'EOF'
Authorized use only. This system is monitored. Unauthorized use is prohibited.
EOF
sudo cp /etc/issue /etc/issue.net
```

For SSH:
```
Banner /etc/issue.net
```
```bash
sudo systemctl restart ssh
```

---

## 9) Time Sync

Use one **single** time sync method. Defaults are fine:
```bash
timedatectl
# If you switch to chrony (ONLY if required), disable timesyncd:
# sudo apt -y install chrony
# sudo systemctl disable --now systemd-timesyncd
# sudo systemctl enable --now chrony
```

---

## 10) Final Verification (Copy‑Paste)

```bash
echo "==== System ===="
lsb_release -a 2>/dev/null || cat /etc/os-release
timedatectl
ufw status verbose
getent passwd | awk -F: '($3>=1000){print $1":"$6":"$7}'
echo "==== SSHD ===="
sshd -T | egrep 'permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|logingracetime|allowusers|banner'
echo "==== PAM/Password ===="
grep -E 'minlen|ucredit|lcredit|dcredit|ocredit|maxrepeat|enforce_for_root' /etc/security/pwquality.conf || true
grep -E "pam_(tally2|faillock)" /etc/pam.d/common-auth || true
echo "==== Audit ===="
auditctl -s
ausearch -k identity | tail -n 3
ausearch -k scope    | tail -n 3
echo "==== Listeners ===="
ss -tulpen
echo "==== World-writable dirs (sticky should be set) ===="
find /tmp /var/tmp -maxdepth 0 -printf '%m %p\n'
```

---

## 11) Common Pitfalls to Avoid
- Don’t remove services explicitly required by the README/injects.
- Don’t lock yourself out of SSH; test in a second session before restarting `sshd`.
- Avoid conflicting PAM modules (`cracklib` vs `pwquality`).
- Don’t run two time sync daemons simultaneously.
- Keep banners professional; no playful or joke text.

---

## 12) Quick Undo / Recovery
```bash
# If ufw blocked needed traffic
sudo ufw allow <port>/tcp

# If SSH locked you out (from console)
sudo sed -ri 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo "PermitRootLogin prohibit-password" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh
```
