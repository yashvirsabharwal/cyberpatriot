# CyberPatriot Windows **Server** Hardening Guide (Points‑Max Edition)

> A practical, step‑by‑step checklist for Windows **Server 2016/2019/2022** CyberPatriot images.  
> It includes exact **commands** and **GUI paths**. Always read the image README first—if it says a service/user/app must stay, keep it. Log **every** change.

---

## Table of Contents
2. [Users, Groups, and Passwords](#1-users-groups-and-passwords-big-points)
3. [Windows Update & Microsoft Defender](#2-windows-update--defender-mandatory)
4. [Windows Firewall](#3-windows-firewall-all-profiles-on)
5. [Auditing](#4-auditing-enable-success-and-failure)
6. [Security Options (Local Security Policy)](#5-security-options-local-security-policy)
7. [Services: Disable risky, keep required](#6-services-disable-risky-keep-required)
8. [Roles & Features](#7-roles--features-remove-what-you-dont-need)
9. [Shares & Permissions](#8-shares--permissions-sneaky-points)
10. [Software, Startup, and Scheduled Tasks](#9-software-startup-and-scheduled-tasks)
11. [Browser/SmartScreen/IE ESC](#10-browsersmartscreenescc)
12. [Networking Hygiene](#11-networking-hygiene)
13. [Logging & Forensics](#12-logging--forensics-common-injects)
14. [Remote Desktop & Remote Assistance](#13-remote-desktop--remote-assistance)
15. [System Restore / Recovery / Safe Mode](#14-system-restore--recovery--safe-mode-stability)
16. [Quick Validation Block](#15-quick-validation-pass-copy-paste-block)
17. [Common Scoring Items](#16-dont-miss-these-common-scoring-items)
18. [Domain Controller Extras](#17-if-domain-controller-extra-checklist)
19. [Appendix: Handy Checklists](#appendix-handy-checklists)

---

## 1) Users, groups, and passwords (big points)

> Replace placeholder values with what the README specifies.

### A. Inventory & fix local accounts

**Commands**
```powershell
# List local users and groups
Get-LocalUser | Format-Table Name, Enabled, LastLogon
Get-LocalGroupMember Administrators
Get-LocalGroupMember "Remote Desktop Users"

# Disable Guest and any unknowns
net user Guest /active:no

# If allowed, rename the built-in Administrator (or at least set a strong password)
wmic useraccount where name='Administrator' call rename 'Admin-Local'
net user "Admin-Local" "Strong!Passw0rdChangeMe"
```

**GUI**  
- Computer Management → Local Users and Groups → **Users**  
  - Disable **Guest**.  
  - For Administrator: **rename** (if allowed) and set a strong password.  
- **Groups** → **Administrators**: only authorized admins.  
- Remove random/unauthorized accounts.

> **Domain images (DC)**: Use **Active Directory Users and Computers** (dsa.msc) to manage **domain** users and groups.

### B. Enforce strong password & lockout policies

**Local (workgroup/server not a DC)**
```cmd
:: Password history, min length, ages, lockout:
net accounts /UNIQUEPW:24 /MINPWLEN:14 /MAXPWAGE:90 /MINPWAGE:1
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
```

**Domain (DC) – Default Domain Policy (GPMC)**
- **Group Policy Management** → Forest… → Domains → *yourdomain*  
  Right‑click **Default Domain Policy** → Edit →  
  **Computer Configuration** → Policies → Windows Settings → Security Settings → **Account Policies**  
  - **Password Policy**:  
    - Enforce password history **24**  
    - Maximum password age **90** days  
    - Minimum password age **1** day  
    - Minimum password length **14**  
    - Password must meet complexity **Enabled**  
    - Store passwords using reversible encryption **Disabled**  
  - **Account Lockout Policy**: threshold **5**, duration **30** mins, reset counter **30** mins.

**PowerShell (Domain)**
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
  -LockoutThreshold 5 -LockoutDuration "0:30" -LockoutObservationWindow "0:30" `
  -MaxPasswordAge "90.00:00:00" -MinPasswordAge "1.00:00:00" -MinPasswordLength 14 `
  -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false
```

---

## 2) Windows Update & Defender (mandatory)

### A. Turn on and run updates

**GUI**  
- Settings → Update & Security → Windows Update → **Check for updates** (install everything).  
- Server Core (if applicable): `sconfig` → **6) Download and Install Updates**.

**Commands (version‑dependent; safe to run)**
```cmd
wuauclt /detectnow
wuauclt /updatenow
usoclient StartScan
usoclient StartDownload
usoclient StartInstall
```

### B. Enable Microsoft Defender AV & scan

**Check/enable Defender feature (Server)**
```powershell
Get-WindowsFeature | ? Name -like "*Defender*"
Install-WindowsFeature Windows-Defender

Set-MpPreference -DisableRealtimeMonitoring $false
Update-MpSignature
Start-MpScan -ScanType FullScan
```

---

## 3) Windows Firewall (all profiles ON)

**Commands**
```cmd
netsh advfirewall set allprofiles state on

:: Disable Remote Assistance rules (no points if RA left open)
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

:: If not required by README, restrict RDP:
netsh advfirewall firewall set rule group="remote desktop" new enable=no
```

**GUI**  
- Windows Defender Firewall with Advanced Security → **Windows Defender Firewall Properties** → Domain/Private/Public → **State: On**, Inbound: **Block**, Outbound: **Allow**.  
- **Inbound Rules**: Disable **Remote Assistance**; limit **RDP** if not required.

---

## 4) Auditing (enable Success **and** Failure)

**Commands**
```cmd
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
```

**GUI (Advanced Audit Policy)**  
- Local Security Policy (secpol.msc) → Advanced Audit Policy Configuration → Audit Policies → enable Success & Failure broadly, **especially**:  
  - Logon/Logoff, Account Logon, Account Management, Policy Change, Privilege Use, Object Access (as needed), Detailed Tracking, System.

---

## 5) Security Options (Local Security Policy)

**GUI**  
Run `secpol.msc` → Security Settings → **Local Policies → Security Options**  
Set (common scoring items):

- **Accounts: Guest account status** → **Disabled**  
- **Accounts: Rename administrator account** → set non‑obvious name (if allowed)  
- **Accounts: Limit local account use of blank passwords** → **Enabled**  
- **Interactive logon: Do not display last user name** → **Enabled**  
- **Interactive logon: Message title/text** → set a benign **legal banner** (typical scoring item)  
- **Network security: LAN Manager auth level** → **Send NTLMv2 response only. Refuse LM & NTLM**  
- **Network security: Do not store LAN Manager hash** → **Enabled**  
- **User Account Control** items → **Enabled** (Always notify is safest)  
- **Microsoft network client: Digitally sign communications (always)** → **Enabled**  
- **Microsoft network server: Digitally sign communications (always)** → **Enabled**

**Optional Registry (when GUI missing)**
```cmd
:: Disable AutoRun for all drives
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

:: UAC to highest (if not via GUI)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

> **Tip:** Keep **SmartScreen** **On/Warn** and **IE Enhanced Security Configuration** enabled unless the README requires otherwise.

---

## 6) Services: disable risky, keep required

> **Check the README first** (web, print, fax, SNMP, etc. may be required).

**High‑risk to disable if not needed:**  
**Remote Registry**, **Telnet**, **TFTP**, **SNMP**, **SSDP/UPnP**, **Fax**, **Bluetooth** (on servers), **PNRP/Peer** services, **Xbox\*** services, **Remote Assistance**, **ICS (SharedAccess)**, **IIS/Web** (unless required), **Net.Tcp Port Sharing**, **Link-Layer Topology Discovery** (if not needed).

**Commands (examples)**
```cmd
:: Disable unnecessary services
sc config RemoteRegistry start= disabled & sc stop RemoteRegistry
sc config TlntSvr start= disabled & sc stop TlntSvr
sc config SSDPSRV start= disabled & sc stop SSDPSRV
sc config upnphost start= disabled & sc stop upnphost
sc config SharedAccess start= disabled & sc stop SharedAccess

:: Ensure good ones are running/auto
sc config wuauserv start= auto & sc start wuauserv
sc config MpsSvc start= auto & sc start MpsSvc
```

**GUI**  
`services.msc` → sort by Status/Startup Type → disable what’s not needed; set critical security services to **Automatic**.

---

## 7) Roles & Features: remove what you don’t need

**Server Manager → Manage → Remove Roles and Features**  
Remove if not needed: **Telnet Client/Server**, **TFTP**, **SNMP**, **IIS/Web‑Server**, **Simple TCP/IP services**, **Legacy Components**, **Fax Server**, **SMB 1.0/CIFS**, **FTP**.

**Commands**
```powershell
# Turn off SMB1 (points + security)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Remove IIS/FTP if not required
Uninstall-WindowsFeature Web-Server, Web-Ftp-Server -Restart:$false
```

---

## 8) Shares & permissions (sneaky points)

**Commands**
```cmd
:: List shares
net share

:: Remove unknown shares (leave C$, ADMIN$, IPC$)
net share TempShare /delete
```

**GUI**  
- Computer Management → System Tools → **Shared Folders → Shares**  
- Remove anything not in the README.  
- Check **Sessions** and **Open Files** for odd access.  
- For allowed shares, restrict **Everyone** and assign **Authenticated Users**/**Users** minimal rights; verify NTFS perms (Properties → Security).

---

## 9) Software, startup, and scheduled tasks

**Uninstall unauthorized software**
- `appwiz.cpl` (Programs and Features) → remove hacking tools, media players, torrent/P2P, old Java, toolbars, etc.
- CLI inventory:
  ```powershell
  Get-WmiObject -Class Win32_Product | Select-Object Name, Version
  # (wmic is deprecated but often present)  wmic product get name,version
  ```

**Startup items & scheduled tasks**
- **Task Scheduler** → **Task Scheduler Library** → disable/delete suspicious items.  
- `shell:startup` (per-user) and `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` → remove junk.  
- **Sysinternals Autoruns** (if allowed) → disable suspicious Run keys, services, drivers.

---

## 10) Browser/SmartScreen/ESCC

- **Server Manager** → **Local Server** → **IE Enhanced Security Configuration** → generally **On** for admins/users unless README requires web tasks.  
- **SmartScreen** (Edge/IE policies): keep **On** or **Warn**.

---

## 11) Networking hygiene

- **Disable IPv6** only if specifically required (otherwise leave).  
- **Disable NetBIOS over TCP/IP** if not needed:  
  NIC Properties → IPv4 → Advanced → WINS → **Disable NetBIOS**.  
- **Disable LLMNR** (GPO):  
  Computer Config → Admin Templates → Network → DNS Client → **Turn Off Multicast Name Resolution = Enabled**.  
- **No ICS** (already disabled the **SharedAccess** service above).

---

## 12) Logging & forensics (common injects)

**Event Viewer** (`eventvwr.msc`)  
- Windows Logs → Security/System/Application → filter by warnings/errors since image start.  
- Custom Views → Administrative Events.  
- Look for: failed logons, unexpected shutdowns, new service installs, privilege escalation.

**Hunt persistence**
- `Task Scheduler`, `services.msc`, `msconfig` (if present), registry **Run/RunOnce** keys.  
- **Sysinternals**: Process Explorer, TCPView, Autoruns for deep checks.

**Quick CLI sweep**
```cmd
whoami /groups
net user
net localgroup administrators
net share
ipconfig /all
netstat -abno
schtasks /query /fo LIST /v
wmic service get name,startmode,state
```

---

## 13) Remote Desktop & Remote Assistance

- If **not required**, **disable/limit RDP** and **Remote Assistance**.

**Commands**
```cmd
:: Disable RA (belt-and-suspenders)
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

:: Disable RDP (if allowed)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

**GUI**  
- System Properties → Remote → uncheck **Allow Remote Assistance**; uncheck **Allow remote connections** (RDP) unless needed.

---

## 14) System Restore / Recovery / Safe Mode (stability)

- **System Restore** isn’t always used on Server; if present, set a **restore point** after stabilizing.  
- **Recovery**: keep Windows RE enabled.  
- **Safe Mode** knowledge: F8/Shift+Restart → Troubleshoot → Advanced Options → Startup Settings.

---

## 15) Quick validation pass (copy‑paste block)

Run this block near the end to validate common scoring levers; adjust where the README says otherwise.

```cmd
:: FIREWALL ON (all profiles)
netsh advfirewall set allprofiles state on

:: AUDIT (success + failure)
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

:: PASSWORD & LOCKOUT (local)
net accounts /UNIQUEPW:24 /MINPWLEN:14 /MAXPWAGE:90 /MINPWAGE:1
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

:: GUEST OFF, RDP/RA tight
net user Guest /active:no
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

:: UPDATE & DEFENDER
wuauclt /detectnow
usoclient StartScan
powershell -c "Update-MpSignature; Start-MpScan -ScanType QuickScan"
```

---

## 16) Don’t miss these common scoring items

- Legal **logon banner** set (title + text).  
- **Guest** disabled.  
- Only **authorized users** exist; only authorized users in **Administrators** and **Remote Desktop Users**.  
- **AutoPlay/AutoRun** disabled.  
- **Firewall ON** all profiles.  
- **Windows Update configured** and run.  
- **Antivirus active** and updated; scan done.  
- **Auditing enabled** success + failure.  
- **RDP/RA** disabled unless required.  
- **Unapproved software removed**.  
- **Suspicious shares removed**; permissions corrected.  
- **Unnecessary services/features removed** (Telnet, TFTP, SNMP, SMBv1, IIS/FTP if not required).  
- **UAC enabled**; **LM/NTLM** hardened; **SmartScreen ON/Warn**.

---

## 17) (If Domain Controller) extra checklist

- Default Domain Policy: password + lockout as above.  
- Default Domain **Controllers** Policy: auditing, security options, RDP policy.  
- Review **Domain Admins** membership (only listed admins).  
- **DNS** service healthy; no rogue zones or forwarders.  
- **SYSVOL/NETLOGON** shares present and clean (no scripts you don’t recognize).

---

## Appendix: Handy Checklists

### Quick Triage Order
1. **Accounts & Groups** → remove/disable unauthorized, set policies.  
2. **Firewall** → on, RA/RDP tightened.  
3. **Updates & Defender** → fully updated, scan complete.  
4. **Services/Features** → prune risky, ensure core security services.  
5. **Shares & Software** → remove unknown shares and apps.  
6. **Auditing & Logs** → enable and review.  
7. **Validation Block** → run and re‑check GUI items.

### GUI Panels to Remember
- `secpol.msc`, `gpedit.msc` / GPMC, `services.msc`, `eventvwr.msc`, `lusrmgr.msc`, `compmgmt.msc`, **Server Manager**, **Group Policy Management**, **Windows Defender Firewall with Advanced Security**.

---

**Final tip:** Work in passes: **(1) Accounts → (2) Policies → (3) Firewall → (4) Updates/Defender → (5) Services/Features → (6) Shares → (7) Software/Startup/Tasks → (8) Audit/Logs → (9) Validation block**. Keep that change log open the whole time.
