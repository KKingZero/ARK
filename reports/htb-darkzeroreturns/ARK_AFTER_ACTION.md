# ARK After-Action — DarkZeroReturns / Linux portion (2026-08-04)

| Field | Value |
| --- | --- |
| **Lab** | DarkZeroReturns (Pro Lab entry) · Linux SRV01 + dual-forest AD |
| **Target** | `10.129.78.204` · `dzcampaigns.htb` · internal `172.16.20.3` |
| **Domains** | `darkzero.ext` · `darkzero.htb` |
| **Objective** | User + root flags **and** exercise ARK **Linux** implant / operator path |
| **Outcome** | **Box solved** (flags) · ARK used as **post-root C2 plane**, not as engagement plane |
| **Operator C2** | `tun0` `10.10.14.15` · teamserver HTTPS `:8443` · gRPC `127.0.0.1:50051` |
| **Related** | `reports/htb-darkzeroreturns/PENTEST_REPORT.md` · Logging after-action for Windows comparison |

---

## 1. Executive scorecard

| Dimension | Score (1–5) | Notes |
| --- | --- | --- |
| **Teamserver reliability** | **4** | `./build/teamserver` stayed up; HTTPS `:8443` + gRPC; session recovery from DB OK |
| **Operator / approvals UX** | **4** | `ark op sessions` / `op shell` oneshot with dual-seat auto-approve worked cleanly once session alive |
| **Implant lifecycle (build → check-in)** | **2.5** | CA + secret + reverse tunnel + clock sync all required; easy to get silent 404 |
| **Linux implant runtime** | **4** | Register → session key → shell as `root@SRV01` solid after connectivity/time fixed |
| **Linux post-ex modules** | **1** | Shell only used; no AD/LDAP/Kerberos/Gitea path from implant |
| **AD / forest chain support** | **0–1** | Entire soft+hard AD path was **external** (impacket, Gitea API, samba-tool, ksu) |
| **C2 reachability on HTB** | **1.5** | ICMP to `tun0` OK; TCP `:8443` **rejected** by host firewall → mandatory reverse tunnel |
| **End-to-end “use ARK for this eng”** | **2** | Flags without ARK; ARK proved Linux beacon after root |

**Bottom line:** ARK did **well as a Linux C2 shell** once the implant was on the box. It did **poorly as the engagement framework** for this chain: initial access, Gitea CI abuse, Kerberos/`ksu`, DCSync, golden ticket, and backup-intent file read all lived outside the product. Same pattern as Logging — C2 plane OK, engagement plane not ready for multi-stage AD.

---

## 2. What ARK did well

### 2.1 Teamserver + dual-seat operator

- **HTTPS listener + gRPC** came up cleanly via `build/teamserver` (note: `ark serve` also spun an interactive operator and shut down when stdin closed — teamserver binary is the right daemon for agents).
- **`ark op` oneshots** with operator + approver certs auto-approved high-risk shell and returned structured output.
- **Session listing** showed implant ID, host, user, OS, alive flag — enough for multi-session ops.
- **Approval gate** still enforced (approved task ID printed) without blocking lab automation.

### 2.2 Linux implant core (once online)

| Capability | Evidence |
| --- | --- |
| Go Linux build with ldflags | `CALLBACK_URL`, `IMPLANT_SECRET`, `CA_CERT_PATH` (base64 CA pin) |
| TLS pinning | No `InsecureSkipVerify`; failed closed without CA (good security default) |
| Register + session key | Log: `session key established` / `registered: session=d16365fc…` |
| Beacon + task shell | `op shell -- 'id; hostname; cat …/user.txt'` → `uid=0(root)` on SRV01 |
| Identity fidelity | Session metadata: `host=SRV01 user=root os=linux` |

### 2.3 Security / product discipline that helped

- **CA required for HTTPS** prevented accidental MITM-friendly lab builds (painful, but correct).
- **HMAC auth** on register/beacon (when clocks agreed).
- **Silent 404** anti-fingerprint for bad auth — good OPSEC; bad debuggability (see below).
- Secrets stayed out of git (`~/htb-linux-ark/`, `~/.ark/`).

### 2.4 What improved vs Logging after-action

| Logging pain | This eng |
| --- | --- |
| Empty `implantID` when `xxd` missing | Did not hit; ID generated in ldflags |
| No non-interactive operator | **`ark op`** used end-to-end for shell |
| WinRM PTH failure | N/A (Linux entry); not re-tested |
| Only local implant demo | **Remote** Linux implant on real HTB host (via tunnel) |

---

## 3. What ARK did poorly

### 3.1 Almost none of the attack path ran through ARK

```text
Web recon / RCE          ░░░░░░░░░░  external (curl/python Handlebars AST)
MySQL / hash crack       ░░░░░░░░░░  external (mysql via RCE, hashcat)
SSH / Kerberos kinit     ░░░░░░░░░░  external (sshpass, kinit)
Gitea fork/Actions       ░░░░░░░░░░  external (curl SPNEGO API)
svc-runner foothold      ░░░░░░░░░░  external (workflow + SSH key)
ksu root                 ░░░░░░░░░░  external (samba-tool + ksu)
DCSync / golden ticket   ░░░░░░░░░░  external (impacket via SOCKS)
Cross-forest CIFS flag   ░░░░░░░░░░  external (backup-intent SMB)
C2 shell demo            ████████░░  ARK after root
```

ARK was a **victory lap**, not the vehicle.

### 3.2 C2 callback still fights HTB reality

| Issue | Symptom | Workaround used |
| --- | --- | --- |
| Host firewall on operator | ICMP to `10.10.14.15` OK; TCP `:8443` → `no route to host` | SSH `-R 127.0.0.1:8443:127.0.0.1:8443` |
| Implant built for `tun0` first | Register dial failed | Rebuild `CALLBACK_URL=https://127.0.0.1:8443` |
| No first-class “tunnel recipe” | Agent reinvented reverse tunnel | Document in skill/runbook |
| `ark serve` not daemon-friendly | Started listener then attached operator REPL and exited on EOF | Use `build/teamserver` |

### 3.3 Build / auth UX is still a footgun

| Issue | Symptom | Impact |
| --- | --- | --- |
| **CA_CERT_PATH easy to omit** | `CA certificate required for HTTPS transport` | Wasted deploy cycle |
| **Secret must match server.yaml** | Silent failure risk if wrong secret | Silent 404 |
| **Clock skew (~7h SRV01 vs operator)** | Implant: `HTTP 404 from /register` | Looked like wrong URL/tunnel until clocks synced |
| **Silent 404 on HMAC fail** | Same response as unknown path | Hard to distinguish skew vs secret vs protobuf |
| **No operator-side “why 404”** | Teamserver log only after successful register | Debug required SSH to target + log read |

HMAC window is 8h; we were inside it once synced, but skew still broke first attempts and wasted time.

### 3.4 Capability gap vs this box’s techniques

| Technique needed | In ARK? | Used instead |
| --- | --- | --- |
| Web/RCE (Handlebars AST) | No (correctly not a web scanner) | Python exploit |
| Linux file loot / shell | Yes (shell) | Implant only post-root |
| Kerberos kinit / keytab | Partial modules exist; not used / not lab-ready | system `kinit` / keytab |
| Gitea / CI abuse | No | curl + API |
| LDAP CreateChild / samba-tool user create | No | samba-tool over GSSAPI |
| ksu / local MIT Kerberos root | No | interactive ksu stdin |
| DCSync | No | secretsdump via SOCKS |
| Golden ticket + SID history | No | ticketer.py |
| Cross-realm kvno | No | kvno on pivot |
| SMB with backup intent / SeBackupPrivilege | No | custom impacket openFile flags |
| SOCKS pivot / ligolo | SOCKS exists in product; not used this eng | `ssh -D` + PySocks |

### 3.5 Linux module surface is thin for “Linux portion of ARK”

Roadmap already notes Windows-heavy modules with Linux stubs. This eng confirmed:

- **What we needed after shell:** path enumeration, credential file read, internal port use, optional SOCKS — all doable via **raw shell**, so modules did not matter.
- **What we needed before shell:** nothing ARK offers (external recon + web RCE).
- **C implant Linux** (`implant_c_linux`) was built in tree earlier but **not** the deploy vehicle this run; Go implant only.

---

## 4. Inside ARK vs outside (this eng)

### Inside ARK (worked)

| Capability | Evidence |
| --- | --- |
| Teamserver HTTPS + gRPC | `:8443` / `:50051` |
| Dual-seat `ark op` | Auto-approve shell |
| Go Linux implant | Register + shell as root |
| CA-pinned TLS | Build-time base64 PEM |
| Session metadata | SRV01 / root / linux |

### Outside ARK (required to finish)

| Step | Tool |
| --- | --- |
| Port/vhost recon | nmap, curl Host header |
| Handlebars AST RCE | custom `exploit.py` |
| DB dump / bcrypt crack | mysql via RCE, hashcat |
| SSH + AD kinit | sshpass, kinit |
| Gitea fork / workflow / PR | curl `--negotiate` |
| svc-runner SSH | planted ed25519 key |
| AD user create + ksu | samba-tool, ksu |
| Pivot SOCKS | `ssh -D 1080` |
| DCSync / ticketer / lookupsid | impacket |
| root.txt on DC01 | impacket SMB + `FILE_OPEN_FOR_BACKUP_INTENT` |
| C2 path | SSH reverse remote-forward |

---

## 5. Product gaps (ordered by pain this eng)

### P0 — Fix before next Linux HTB eng

| # | Gap | Why it hurt | Wanted |
| --- | --- | --- | --- |
| P0.1 | **Callback blocked by operator firewall** | TCP to tun0:8443 rejected | Runbook: firewalld/`iptables` allow `:8443` on `tun0`; optional `ark serve --check-inbound` |
| P0.2 | **Silent 404 on HMAC / skew** | Register looked identical to “wrong path” | Log reason server-side always; implant log distinguish 401-class vs path; optional `skew` diagnostic |
| P0.3 | **`ark serve` exits with REPL** | Agent thought server was up then dead | Separate `serve` daemon from operator; document `teamserver` binary |
| P0.4 | **Build checklist incomplete in skill** | Missing CA/secret/clock on first try | Skill: `CA_CERT_PATH`, matching `IMPLANT_SECRET`, reverse-tunnel recipe, clock check |
| P0.5 | **No first-class reverse-tunnel helper** | Manual `ssh -R` | Doc or `scripts/c2_rssh.sh` (RemoteForward 8443) |

### P1 — Needed if ARK should own AD-on-Linux pivots

| # | Gap | Wanted |
| --- | --- | --- |
| P1.1 | Kerberos AES TGT + keytab kinit from implant/operator | `krb kinit --keytab` / password file; ccache export |
| P1.2 | LDAP GSSAPI (with SASL_NOCANON story) | ldap-enum over GSSAPI from pivot |
| P1.3 | DCSync / secretsdump class | Operator or implant module (or explicit “shell out to impacket” wrapper with loot import) |
| P1.4 | Ticket forge / import (golden, SID history) | ticketer-class or import ccache + use for SMB |
| P1.5 | SMB Kerberos + backup-intent read | Read `root.txt`-class files without full admin |
| P1.6 | SOCKS start/stop polish | One command: implant SOCKS → operator tools |

### P2 — Quality / velocity

| # | Gap | Wanted |
| --- | --- | --- |
| P2.1 | Implant default sleep guidance for lab | Document 1–5s lab vs long sleep prod |
| P2.2 | Multi-session `op shell` defaults | Prefer newest alive session without flags |
| P2.3 | C Linux implant parity QA | Same register/shell checklist as Go |
| P2.4 | Agent catalog honesty | Plan mode: “web RCE / Gitea / ksu / golden” marked external until modules exist |

---

## 6. Honest grade for “Linux portion of ARK”

| Question | Answer |
| --- | --- |
| Can we drop a Linux implant and get a shell? | **Yes** (with tunnel + CA + clock) |
| Can we run a full HTB Linux→AD chain *inside* ARK? | **No** |
| Is ARK better than raw SSH for post-root? | **Marginally** — tasking/approvals/session meta; shell is still the workhorse |
| Did ARK speed up this eng? | **No** — it added build/tunnel/skew tax after the box was already owned |
| Primary product value this eng | Confirmed Linux beacon path + ops oneshot; exposed C2 reachability and silent-auth UX |

---

## 7. Recommendations (next sprints)

1. **Operator inbound checklist** (30 min doc): firewall on `tun0`, `teamserver` vs `serve`, reverse-tunnel snippet, clock check before drop.
2. **Auth failure observability** (half day): never return identical 404 without a teamserver log line including `skew|hmac|parse|unknown_implant`.
3. **Do not chase web RCE modules** for Handlebars AST — stay post-foothold; invest in Kerberos + LDAP + SMB-Kerb on Linux pivot instead.
4. **Accept external tools for forest trust** until P1 tickets land; track gaps, don’t pretend soft-path P0 covers Pro Labs.
5. **Re-run Logging P0 items** (WinRM PTH) on next Windows box; this eng did not invalidate or validate them.

---

## 8. Flags (for report completeness)

| Flag | Value |
| --- | --- |
| user.txt | `8a01ba4190c0284f7ebb73ea4b7408a7` |
| root.txt | `fc269ccb5eb9741f3c846593a456fdf6` |

---

## 9. One-line summary

**ARK is a credible Linux C2 for post-compromise shell on HTB once connectivity and time are fixed; it is still not an engagement platform for AD forests, CI abuse, or Kerberos privilege paths — those remain impacket/ssh territory, and the product should document that honestly while closing callback/auth UX gaps.**
