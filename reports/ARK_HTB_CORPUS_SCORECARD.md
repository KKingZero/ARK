# ARK HTB corpus scorecard

**Date:** 2026-08-16  
**Question:** across the lab reports, where did ARK do well vs poorly?  
**Sources:** the 11 report dirs listed below. Scoring is 0–10 from those writeups (Logging / DarkZero already used 1–5 scorecards; those are doubled here).

This file is the baseline for `docs/plans/FIX_CYCLE_SERVE_SKEW_PTH.md`. The fix cycle is allowed to claim a win only against these three tax items: stdin-close crashes, clock-skew 404s, WinRM PTH vs pypsrp. It is **not** a claim that critical-path % moved.

## Corpus

| Dir | Kind | Box solved? | ARK on critical path? |
|---|---|---|---|
| `reports/htb-bedside/` | HTB Linux | yes | no |
| `reports/htb-c-linux-peer/` | local C Linux QA | n/a | n/a (host QA) |
| `reports/htb-danglingtree/` | HTB Windows/AD | yes | flags re-read via C implant after DA |
| `reports/htb-darkzeroreturns/` | HTB Linux→AD | yes | post-root Go implant only |
| `reports/htb-fireflow/` | HTB Linux + C2 QA | yes | Go+C implant after root |
| `reports/htb-garfield/` | HTB Windows/AD | yes | no |
| `reports/htb-ghostlink/` | HTB Windows/AD | yes | no (MQTT/relay later shipped) |
| `reports/htb-logging/` | HTB Windows/AD | yes | local C2 demo only |
| `reports/htb-nimbus/` | HTB Linux/cloud | yes | no |
| `reports/htb-support/` | HTB Windows/AD | yes | unused (retired; noted as future QA) |
| `reports/lab-perf/` | local recon | n/a | implant portscan+shell vs Zypheron nikto |

`lab-perf` and `c-linux-peer` are local QA, not HTB kill chains.

---

## Verdict

ARK is a working C2 once a beacon is up. It is not the engagement framework that solved these boxes. Across 9 HTB solves plus local QA, flags came from Impacket / certipy / pypsrp / custom exploits. ARK showed up after the fact as a shell, or not at all.

---

## C2 plane vs engagement plane

```
                    C2 (register / beacon / shell)     Engagement (did ARK own the path?)
lab-perf            █████████░  9                      n/a  (local recon only)
c-linux-peer        ████████░░  8                      n/a  (host QA; HTB re-run still open)
FireFlow            ████████░░  8  Go+C via SSH -R     ██░░░░░░░░  2  victory-lap implant
DanglingTree        ███████░░░  7  C implant SYSTEM    ███░░░░░░░  3  flags re-read via op shell
DarkZero            ███████░░░  7  Go root@SRV01       ██░░░░░░░░  2  post-root only
Logging             ██████░░░░  6  local implant demo  ██░░░░░░░░  2  pypsrp/certipy did the work
Ghostlink           ████░░░░░░  4  unused on critical  █░░░░░░░░░  1  MQTT/relay/ADCS external
Garfield            ██░░░░░░░░  2  unused              █░░░░░░░░░  1  Rubeus/impacket/chisel
Support             █░░░░░░░░░  1  unused (noted as    ░░░░░░░░░░  0  entire chain external
                                    "good future QA")
Bedside             █░░░░░░░░░  1  unused              ░░░░░░░░░░  0  SSH + pickle
Nimbus              █░░░░░░░░░  1  unused              ░░░░░░░░░░  0  SQS/CodeBuild external
                    ─────────────────────────────      ─────────────────────────────
HTB mean (9 boxes)  ████░░░░░░  3.7                    █░░░░░░░░░  1.2
```

Every HTB box was **solved**. ARK was on the critical path for **zero** of them.

---

## Where it did well

```
Local recon speed (lab-perf vs Zypheron nikto)     █████████░  9
Teamserver HTTPS + gRPC stay-up                    ████████░░  8
Approval gate / dual-seat auto-approve             ████████░░  8
Linux implant shell once online                    ████████░░  8
Security defaults (CA pin, HMAC, silent 404 OPSEC) ████████░░  8
C implant (FireFlow + DanglingTree SYSTEM)         ███████░░░  7
ark op oneshots (later engs)                    ███████░░░  7
C Linux SOCKS on workstation (c-linux-peer)        ███████░░░  7
```

**What that looked like**

- **FireFlow** is the best C2 proof: Go (~16 MB) and C (~70 KB) both registered over an SSH reverse tunnel and ran `op shell` as `nightfall`.
- **DanglingTree** dropped a C implant as SYSTEM and re-read flags through `ark op shell`.
- **DarkZero** got `root@SRV01` after tunnel + clock sync; `op sessions` / `op shell` with dual-seat approve worked.
- **lab-perf:** implant portscan + curl finished in **~8s** and succeeded; prior Zypheron nikto on Juice Shop took **45s and failed**.
- **c-linux-peer:** host tests + live local register / shell / file / ps / ifconfig / SOCKS5 CONNECT all **PASS**. HTB re-run still open.
- Teamserver reliability is consistently a 4/5. Dual-control is called out as something **not** to remove.

---

## Where it did poorly

```
ADCS (ESC1/7/8/11, PKINIT, UnPAC, shadow)          █░░░░░░░░░  1
Kerberos (AES TGT, tickets, golden, KeyList)       █░░░░░░░░░  1
AD writes (RBCD, FCP, DCSync, DNS, ksu)            █░░░░░░░░░  1
WinRM PTH vs pypsrp                                ██░░░░░░░░  2
HTB inbound C2 (firewall / no-route)               ██░░░░░░░░  2
Clock-skew handling                                ██░░░░░░░░  2
Pre-implant (web RCE, MQTT*, relay*, CI)           ██░░░░░░░░  2
Linux post-ex beyond raw shell                     ██░░░░░░░░  2
Engagement velocity (did it speed the solve?)      ██░░░░░░░░  2
Implant build / auth UX (xxd, CA, silent 404)      ███░░░░░░░  3
```

\*Ghostlink later shipped `ark mqtt` and `ark relay http` — those P0s were **open during the solve**.

| Needed on the box | ARK | What actually finished it |
|---|---|---|
| Langflow / Handlebars / SQS / pickle / Gogs RCE | no | custom Python |
| MQTT coerce + HTTP NTLM relay | no (then) | paho + GhostSurf |
| WinRM PTH | **failed** (timeout/401/seal) | pypsrp |
| AES TGT + Protected Users | no | faketime + getTGT |
| Shadow creds / ESC1 / ESC11 / PKINIT | no | certipy + bloodyAD |
| RBCD / RODC KeyList / golden + SID history | no | Impacket + Rubeus 2.3.3 |
| ForceChangePassword | no | `net rpc password` |
| DCSync / backup-intent SMB | no | secretsdump / custom flags |
| Loopback pivot (`:3000`, CA, kubelet) | Linux C SOCKS missing on HTB | SSH `-L` / chisel / Ligolo |

DarkZero already drew this for one box. Across the corpus it is the same shape:

```
Web / RCE / CI / MQTT          ░░░░░░░░░░  external on every Linux/web box
Kerberos / tickets / skew      ░░░░░░░░░░  external on every AD box
ADCS / certs / UnPAC           ░░░░░░░░░░  external wherever it appeared
WinRM foothold                 ██░░░░░░░░  pypsrp; ARK PTH broken
SMB / LDAP pre-implant         █░░░░░░░░░  smbclient / ldap3 (implant needs a session first)
C2 shell after ownership       ████████░░  this is the product
```

Logging’s own grade still holds for the AD half of the catalog: **C+ as a C2, D as an AD engagement framework.**

---

## Recurring pain (how many reports hit it)

```
C2 blocked by tun0/firewall / "no route"     ████████████████████  6   FireFlow DarkZero Logging Nimbus Bedside Ghostlink
Clock skew (~7–8h) → HMAC 404 / KRB fail     █████████████████░░░  5   Logging Garfield DarkZero DanglingTree Ghostlink
ADCS left to certipy                         █████████████░░░░░░░  4   Logging Ghostlink DanglingTree (ESC) + shadow
ark serve dies when stdin closes          ██████████░░░░░░░░░░  3   DarkZero DanglingTree (skill note)
WinRM PTH lose to pypsrp                     ███████░░░░░░░░░░░░░  2   Logging Garfield
Empty implantID (xxd missing)                ████░░░░░░░░░░░░░░░░  1   Logging
C implant silent if CA PEM≠DER               ████░░░░░░░░░░░░░░░░  1   FireFlow (fixed later in Makefile)
Beacon 500ms replay → 404                    ████░░░░░░░░░░░░░░░░  1   Logging
```

The two tax items that burned time **after the box was already owned**: inbound C2 and clock/HMAC 404s that look identical to “wrong URL.”

---

## Inside ARK vs outside (kill-chain share)

Approximate share of **critical-path steps** that ran in-framework:

```
Support          [░░░░░░░░░░]   0%   SMB RE → LDAP → WinRM → RBCD
Bedside          [░░░░░░░░░░]   0%   SSH key → watcher → torch pickle
Nimbus           [░░░░░░░░░░]   0%   SSRF → SQS YAML → CodeBuild escape
Garfield         [█░░░░░░░░░]  ~5%   soft recon notes; Rubeus/impacket owned RODC
Ghostlink        [█░░░░░░░░░]  ~5%   MQTT/relay/Gogs/ADCS all external
Logging          [██░░░░░░░░] ~15%   C2/approvals proven; AD chain external
DarkZero         [██░░░░░░░░] ~15%   post-root Linux shell
FireFlow         [██░░░░░░░░] ~20%   Go+C QA after Langflow/k8s root
DanglingTree     [███░░░░░░░] ~25%   C implant after ESC1/PKINIT
                 ────────────────────────────────
HTB corpus       [██░░░░░░░░] ~10%
```

---

## What improved vs what did not

```
                    Logging     FireFlow    DarkZero    DanglingTree   c-linux-peer
                    Jul 30      Aug 03      Aug 04      Aug 15         Aug 09
Teamserver          ████░░░░    ████████    ████████    ████████       ████████
ark op oneshot   ██░░░░░░    ██████░░    ████████    ████████       ████████
Linux Go implant    ████ local  ████████    ████████    ──────         ──────
Linux C implant     ──────      ███████░    unused      ████████       ████████
Windows / WinRM     █ fail      n/a         n/a         filtered       n/a
ADCS / Kerberos     ░ unused    n/a         ░ unused    ░ unused       n/a
HTB inbound C2      █ fw        █ tunnel    █ tunnel    █ late drop    local only
```

C2 got real. Engagement modules did not. Ghostlink’s MQTT + NTLM-relay P0s shipped **after** that box was solved; ADCS / Kerberos / PTH are still the same holes DanglingTree and Garfield hit in August.

---

## Bottom line

| Question the reports actually answer | Answer |
|---|---|
| Can you drop a Linux implant and get a shell? | **Yes**, after CA + secret + tunnel + clock |
| Can you drop C Linux (~80 KB) and task it? | **Yes** on FireFlow and DanglingTree; SOCKS proven only on the workstation |
| Did ARK speed any of these HTB solves? | **No.** DarkZero: “it added build/tunnel/skew tax after the box was already owned.” |
| Is the C2 architecture the problem? | **No.** Approval gate, protobuf, compiled modules, CA-pin are repeatedly called correct. |
| What would move the engagement score? | WinRM PTH parity, Kerberos+skew, ADCS enroll/auth, ForceChangePassword/RBCD, and inbound C2 — not more web-RCE modules. |

The product that exists is a **post-compromise tasking plane**. The product the reports keep asking for is an **AD + pivot operator** that can replace pypsrp / certipy / Impacket on the soft path. Those are still different things.

### This cycle’s slice (not the whole table)

`docs/plans/FIX_CYCLE_SERVE_SKEW_PTH.md` takes only three tax items: `ark serve` stdin close, clock-skew 404s, WinRM PTH vs pypsrp. Inbound C2 (6/9) is the next sprint. ADCS/Kerberos/RBCD are out of scope.
