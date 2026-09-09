# HTB Next Machines — Runbook, Dev Steps & Security Checks

| Field | Value |
| --- | --- |
| **Audience** | Operator + ARK developer |
| **Labs covered so far** | Support, Logging, Ghostlink, DanglingTree, FireFlow, DarkZero, Garfield, plus later reports under `docs/private/reports/htb-*/` |
| **ARK P0 shipped** | WinRM PTH, LDAP hash/`interesting`, remote SMB client; **Sprint D** MQTT + HTTP NTLM relay; host `adcs` / `rbcd` / shadow / AES tickets |
| **Related** | `docs/AD_ENGAGEMENT.md`, `docs/plans/FILL_AD_SKELETON.md`, `docs/OPERATOR_PRE_IMPLANT.md`, `docs/OPERATOR_INBOUND.md`, `docs/private/reports/htb-*/` |
| **Last updated** | 2026-09-04 |

Authorized HTB / lab use only. Do not use against systems without permission.

**Agent skills:** `/ark-htb` (C2 + HTB) · `/htb-pentest` (general HTB). Installed for Grok and Claude under project `.grok/skills/`, `.claude/skills/`, and user `~/.grok/skills/`, `~/.claude/skills/`.

---

## 1. Goals for the next few boxes

1. **Exercise ARK on the critical path** (host AD tools + C implant), not as a victory-lap shell after Impacket.
2. **QA P0 features** on a real Windows/AD target (SMB → LDAP interesting → WinRM PTH, host `adcs` / `rbcd` / shadow where the box needs them).
3. **Drive remaining gaps** with machines that need live PKINIT UnPAC proof, DNS write, ATSVC deploy, or Windows C SOCKS.
4. **Keep OPSEC and lab hygiene** consistent so reports and framework QA stay trustworthy.

---

## 2. Status snapshot

| Machine | Difficulty | Status | Flags | ARK use so far |
| --- | --- | --- | --- | --- |
| **Support** | Easy (Win/AD) | Solved | user + root | Mostly external tools; good first implant-drop target |
| **Logging** | Medium (Win/AD) | **Solved** | user + root | C2 local implant OK; AD chain mostly external — see `docs/private/reports/htb-logging/ARK_AFTER_ACTION.md` |
| **Ghostlink** | Hard (Win/AD) | **Solved** | user + root | Drove Sprint D pre-implant toolkit; report `docs/private/reports/htb-ghostlink/` |
| **DanglingTree** | Medium (Win/AD) | **Solved** | user + root | Host LDAP/SMB/AD password; dangling ESC1 now `ark adcs` (PKINIT still Certipy) |
| Lab-perf (Juice/Meta) | N/A | Passed | N/A | Implant recon only |

**Pre-implant (MQTT / NTLM relay):** `docs/OPERATOR_PRE_IMPLANT.md` · `ark mqtt` · `ark relay`

---

## 3. Recommended next HTB queue

Order is intentional: in-framework critical path → validate P0 on Easy AD → push Medium techniques that map to remaining gaps.

### Priority 0 — In-framework critical path

Logging is **solved** (notes in `docs/private/reports/htb-logging/`). Do not treat it as open work.

Next session: pick a current Easy/Medium AD box and run the **host tools + C implant** path from `docs/AD_ENGAGEMENT.md` before falling back to Impacket/Certipy. Scorecard: `docs/private/reports/ARK_HTB_CORPUS_SCORECARD.md`.

### Priority 1 — Validate ARK soft-compromise path (Easy AD)

| # | Machine | Techniques to exercise | ARK tools to prefer |
| --- | --- | --- | --- |
| 1 | **Support** (re-run as QA, if available / retired clone / similar Easy AD) | Anon SMB, LDAP free-text secret, WinRM, optional RBCD | `smb`, `ldap-enum interesting`, `lateral winrm` (+ `--hash` if available) |
| 2 | Next **Easy Windows/AD** from your HTB path (e.g. classic “soft AD” boxes: share → cred → WinRM/RDP → ACL) | Same soft chain without needing C2 mid-path | Drop implant after first shell; run soft path from `docs/AD_ENGAGEMENT.md` |

**QA acceptance (P0 features):**

- [ ] `smb list_shares` / `list_dir` / `download` without leaving ARK  
- [ ] `ldap-enum interesting` recovers free-text secret class attrs  
- [ ] `lateral winrm … --pass` **and** at least one `--hash` shell if hash exists  
- [ ] Agent Plan mode lists `smb` + soft path; Auto does not DA-abuse without objective  

### Priority 2 — Medium AD that force P1 ARK work

Pick **one** primary Medium at a time. Prefer machines that stress gaps still missing in ARK.

| Theme | What the box should force | Product work it unlocks |
| --- | --- | --- |
| **ACL / RBCD** | GenericAll / Write on computer objects, machine account abuse | ACL enum module, RBCD + machine-account helpers |
| **gMSA / Shadow Creds** | GenericWrite on MSA/user + cert path | Minimal shadow-creds module |
| **Protected Users / AES Kerberos** | Password works only with AES TGT (no NTLM) | Kerberos AES TGT + ticket-aware lateral |
| **Delegation / tickets** | Constrained / unconstrained / tgtdeleg-style | Ticket export, lateral with `ticket` field |
| **Multi-host** | Jump via SOCKS / second implant | SOCKS polish, deploy-via-WinRM |

Examples of HTB themes (names rotate; pick current retired/active equivalents with writeups matching the theme):

- Easy→Medium “Support-like”: share + LDAP attribute + WinRM + ACL  
- Medium “Logging-like”: log secret → gMSA/shadow → DLL/hijack → DNS/WSUS  
- Medium Kerberos-heavy: AS-REP/Kerberoast → ticket abuse (good for roast modules already in tree)

### Priority 3 — Linux C primary (Sprint L) + after AD core

| Track | Purpose |
| --- | --- |
| Linux Easy/Medium (web → shell) | **C** implant HTTPS callback, shell, file, process, portscan (`make implant-c-linux`) |
| Linux pivot | **C reverse SOCKS** (`socks start`); reverse tunnel if no session yet; Go only as fallback |
| Cloud / hybrid (if on path) | `cloud_harvest` validation |
| Hard AD / forest | Only after P1 RBCD/shadow/tickets land |

**Linux habit (every eng):** drop C first; fill checklist §6; if Go used, log why. Plan: `docs/plans/SPRINT_L_C_LINUX.md`.

---

## 4. Per-machine engagement procedure

Use this every time so reports stay comparable and ARK gaps get logged.

### 4.1 Pre-flight

Full inbound / auth / firewall / tunnel checklist: **`docs/OPERATOR_INBOUND.md`**.

```text
[ ] HTB VPN connected (machines_us-5 or current)
[ ] Target IP reachable (nmap -Pn -n -p 445,389,88,5985,5986 --open <IP>)
[ ] Workdir: ~/htb-<machine>/  (secrets as files only — never bash $$)
[ ] Clock: note skew vs DC if Kerberos will be used
[ ] Firewall: open implant/relay ports on tun0 (or reverse tunnel)
[ ] ARK: make ark && ark teamserver  (if testing C2 this session; not `serve`)
[ ] Windows implant built if callback path planned (**prefer C**)
[ ] Linux implant: **prefer C** (`make implant-c-linux` + CA pin; tunnel if firewalled)
[ ] If 404 beacons: check teamserver logs for reason=hmac|skew|replay|unknown_implant|parse
```

### 4.2 Attack phases (record in report)

1. Recon (ports, SMB shares, web, LDAP anon if any)  
2. Initial access  
3. User flag  
4. Privilege escalation / domain path  
5. Root flag  
6. **ARK section** — what ran in-framework vs external tools  
7. **Gap list** — missing module / bug / UX pain (feeds §5)  

### 4.3 Report locations

```text
docs/private/reports/htb-<machine>/
  PENTEST_REPORT.md          # findings-oriented (target issues)
  PROGRESS_AND_FIXES.md      # if incomplete / tooling notes
```

Support template: `docs/private/reports/htb-support/PENTEST_REPORT.md`.  
Logging template: `docs/private/reports/htb-logging/PROGRESS_AND_FIXES.md`.

### 4.4 ARK soft path (after foothold)

```text
sessions → use <id>
shell whoami / ifconfig
smb list_shares --host <DC_or_target> [--anon | --user --pass|--hash]
smb list_dir / download …
ldap-enum interesting --domain … --dc … --user … --pass|--hash …
ldap-enum kerberoastable …
lateral winrm <host> "whoami" --user … --pass … --domain …
# or:  --hash <NT>
loot
```

AI: `ai` → Plan with soft-compromise objective → Auto with approvals.

---

## 5. Development steps (ARK) — ordered for next boxes

### Done (do not re-do unless bugs found)

| Item | Notes |
| --- | --- |
| WinRM PTH | `lateral winrm … --hash` |
| LDAP hash bind | `ldap-enum … --hash` |
| LDAP `interesting` / `secrets` / `rbcd` query types | Free-text + RBCD presence |
| Remote SMB module | `smb` list/download |
| Agent soft path + AD_ENGAGEMENT updates | Catalog tools `smb`, expanded prompt |

### Sprint B — before/during next Medium ACL/Kerberos box

| Step | Work | Validates on |
| --- | --- | --- |
| B1 | ACL / dangerous-rights LDAP surface (GenericAll, WriteDacl, WriteProperty on computers/users/gMSA) | Support-style, Logging GenericWrite |
| B2 | Kerberos AES TGT request + export loot; wire `LateralMoveConfig.ticket` if feasible | Protected Users accounts |
| B3 | Machine account create + RBCD write + S4U ticket path (approval: critical) | Support root path in-framework |
| B4 | Operator CLI + agent catalog + suggestions for B1–B3 | Auto Plan lists tools |
| B5 | Unit tests + one GOAD or HTB replay smoke | CI / smoke_test |

### Sprint C — Logging-class / modern AD

| Step | Work | Validates on |
| --- | --- | --- |
| C1 | Minimal shadow credentials (KeyCredentialLink write/clear + usable auth) | Logging mid-chain |
| C2 | Creds/loot → next-hop suggestions (loot id refs, no secret echo) | All AD boxes |
| C3 | Deploy implant via WinRM (upload + exec helper or documented sequence) | Post-user on any Win box |
| C4 | PsExec/SCMR completeness from non-Windows implant if needed | Lateral payload staging |

### Lab-host tooling (not implant, still unblocks HTB)

| Pri | Item | Status intent |
| --- | --- | --- |
| P0 | `scripts/htb_krb_env.sh` (LDAP time skew + faketime Docker) | Build before next Kerberos-heavy box |
| P0 | Secrets only via files (document in every report SOP) | Habit |
| P1 | Docker images: `logging-krb`, `mingw-i686`, `wsuks-tool` | Logging root + DLL work |
| P2 | pypsrp PTH helper only if ARK WinRM unavailable | Fallback |

### Definition of done (product)

- Soft path on Easy AD fully inside ARK (no smbclient/ldap3/pypsrp required for user).  
- At least one Medium root uses a **new** ARK module (ACL/RBCD/shadow/ticket).  
- Every eng produces a short **ARK gaps** bullet list in the report.

---

## 6. Security checks (every engagement)

### 6.1 Authorization & scope

| Check | Rule |
| --- | --- |
| Scope | Only assigned HTB machine IP(s) via HTB VPN |
| Out of scope | Other players, VPN infra, production, non-lab hosts |
| Cleanup | Remove lab machine accounts, RBCD blobs, DNS records, local users created for privesc when box is shared/reused |
| Implants | Kill implant; no persistence left after eng unless explicitly testing persist (then remove) |

### 6.2 Credential & secret hygiene (operator host)

| Check | Rule |
| --- | --- |
| Shell expansion | Never put passwords with `$` in double-quoted bash (`$$` → PID). Write to file via Python/`printf` |
| Files | Store secrets under `~/htb-<machine>/` with mode `600`; do not commit to git |
| Reports | Prefer redaction in public commits; lab-only flags/creds stay under `docs/private/reports/` |
| Loot | ARK loot DB under `~/.ark/` — treat as sensitive |
| Logs | Do not paste full NT hashes/passwords into public issues/PRs |

### 6.3 Kerberos / time

| Check | Rule |
| --- | --- |
| Skew | Before TGT: compare local UTC vs DC LDAP `currentTime` |
| Fix | Prefer faketime/Docker wrapper over `date -s` without need |
| Caches | Treat `.ccache` / `.kirbi` as expiring secrets; delete after eng |

### 6.4 ARK / C2 safety

| Check | Rule |
| --- | --- |
| Approvals | Keep high/critical gate on; dual-control for DA-class tasks |
| Sleep | Lab interactive: low sleep OK; never leave loud implant on shared box overnight |
| Callbacks | Listener only on intended interface; confirm implant points at your C2, not a shared lab IP |
| Generate | Prefer C implant for Windows when toolchain available (`docs/AD_ENGAGEMENT.md`) |
| SOCKS | Stop SOCKS when done; do not tunnel non-scope traffic |
| Builds | Rebuild implant per eng if secret/callback changes; do not reuse old ldflag secrets across long-lived ops |

### 6.5 Target OPSEC (lab-aware)

| Check | Rule |
| --- | --- |
| Noise | Prefer targeted LDAP queries over full domain dumps |
| Service accounts | Prefer PTH/WinRM over LSASS until objective needs creds_dump |
| DA actions | RBCD / DCSync / shadow only when root objective requires; log in report |
| Evidence | Capture command + output snippets for findings; avoid unnecessary second DA paths |

### 6.6 Pre-submit / end-of-session checklist

```text
[ ] user.txt / root.txt submitted if obtained
[ ] Report updated (flags, path, ARK gaps)
[ ] Lab artifacts cleaned (ARK01$, RBCD, DNS, local users) if reusing box
[ ] Implant dead; listeners stopped if not needed
[ ] No secrets staged in git status (git status clean of ~/htb-* copies)
[ ] Open product issues filed or gaps listed in report § ARK
```

---

## 7. Quick command cheat sheet

### Host / VPN

```bash
sudo openvpn --config /path/to/machines_us-*.ovpn
ip -br a show tun0
nmap -Pn -n -p 445,389,88,5985,5986,8530,8531 --open <TARGET_IP>
```

### Secrets without `$$`

```bash
python3 -c 'open("svc_pass.txt","w").write("Em3rg3ncyPa$$2026")'
# tools read from file — never: --pass "Em3rg3ncyPa$$2026" in bash double quotes
```

### ARK operator (post-implant)

```text
ark teamserver     # C2 daemon
ark operator       # REPL in another terminal
sessions
use <session-id>
smb list_shares --host <IP> --anon
ldap-enum interesting --domain DOM --dc DC --user u --pass p
lateral winrm <IP> "whoami /all" --user u --hash <NT> --domain DOM
pending
approve <id>
loot
```

### Builds

```bash
make proto ark
# Windows / Linux primary (C). Empty generate language is c.
ark op generate --os windows --language c --callback https://<C2>:1750 --out implant.exe
# or: make implant-c / implant-c-linux + ark op register-secret
# Go Windows fallback only: make implant-win
# Go Linux is archived (make implant fails)
bash scripts/smoke_test.sh
```

---

## 8. Suggested calendar (example)

| Session | Focus |
| --- | --- |
| 1 | A.1 live WinRM PTH QA (GOAD) + inbound checklist hygiene |
| 2 | Sprint 0C Golden Demo 5/5 Auto on **C** implant |
| 3 | Sprint B coding — see `docs/plans/SPRINT_B_AD.md` (AES/ticket/shadow/ACL) |
| 4 | Medium ACL/Kerberos box — exercise B; gap log |
| 5 | Sprint 1 C lateral — see `docs/plans/SPRINT_1_C_LATERAL.md` |

Adjust to your HTB rank path; keep the **finish open → QA P0 → code P1 → Medium that needs P1** loop.

---

## 9. Gap log template (paste into each report)

```markdown
## ARK gaps this eng

| Gap | Severity | Workaround used | Wanted module/fix |
| --- | --- | --- | --- |
| e.g. no DNS write | medium | bloodyAD | ad_dns module |
| e.g. no shadow creds | high | certipy | shadow_creds |

## What worked in-framework

- smb / ldap / winrm / …
```

---

## 10. References

- `docs/AD_ENGAGEMENT.md` — operator AD cookbook  
- `docs/GOLDEN_DEMO.md` — Sprint 1 Auto path  
- `docs/GOAD_LAB.md` — offline AD lab alternative  
- `docs/private/reports/htb-support/PENTEST_REPORT.md` — Support findings  
- `docs/private/reports/htb-logging/PROGRESS_AND_FIXES.md` — Logging progress + root checklist  
- Plan (product): soft compromise → ACL/RBCD → shadow/tickets  

---

*Lab only. Keep this file updated when a machine is finished or a Sprint ships.*
