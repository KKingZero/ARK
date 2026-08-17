# Fill the AD skeleton — beat BloodHound + Impacket on the HTB corpus

**Duration:** 4–6 weeks solo  
**Bar:** same 9 HTB boxes + `c-linux-peer`. A primitive that only demos on GOAD does not count.  
**Consumer:** agent executes, human sees and approves. Dual-seat stays.  
**Authorized labs only.**  
**Baseline:** `reports/EREBUS_HTB_CORPUS_SCORECARD.md`

Related: `SPRINT_B_AD.md`, `SPRINT_E_ADCS.md`, `FIX_CYCLE_SERVE_SKEW_PTH.md`, `docs/AD_ENGAGEMENT.md`.

---

## What is locked

| Axis | Call |
|---|---|
| Surface | Whole AD weapon (Sprint B Kerberos + soft writes + shadow + dangling ESC1 + DCSync + golden/silver) |
| Demo | Find the path **and** pull the trigger in-Erebus on the same box Impacket/BloodHound would |
| PTH | Soft gate — live pypsrp in parallel, do not block writes |
| Home | **Host first, then lean C.** Shared `pkg/` is the brain |
| Inbound | **Thin slice first**, then AD |
| Proof | HTB corpus, not a private forest |
| Time | 4–6 weeks (Sprint B envelope) |

---

## Honest scope cut

This cycle ships **Impacket-shaped verbs + a BloodHound-lite path finder**. It does not ship SharpHound, a graph database, or a Certipy/Rubeus clone.

| In | Out (wave 2, after week 6) |
|---|---|
| Thin inbound (tunnel + SOCKS as one operator path) | Implant listen-inbound-by-default |
| ACL / dangerous-rights enum + 1–3 step path suggestions | Full BloodHound collector / neo4j |
| Ticket store + AskTGT AES + S4U AES + KeyList MVP | Diamond, renew-all, overpass kitchen sink |
| RBCD write (required for S4U to be a path) | Unconstrained-delegation hunt as a product |
| scriptPath, ForceChange (shipped), addcomputer | Arbitrary LDAP set-attr |
| Shadow creds (one account) | Shadow at scale |
| Dangling-name ESC1 + PKINIT UnPAC | ESC2–11, web enroll, golden cert |
| DCSync (one object, not the domain) | Domain-wide dump as the default verb |
| Golden + silver from a known AES key | Ticket forging without a key |
| Host `pkg/krb` + `pkg/ldapcli` + `pkg/smbcli` | Second Kerberos stack in C |
| C consumes hash/ticket and executes WinRM/SMB | C reimplements AS-REQ/S4U/DRSUAPI |
| Agent catalog + suggestions for every new verb | Agent Auto “own the domain” without approve |

If a week slips, **cut from the bottom** (golden, then DCSync, then ESC1), not from inbound or ACL/path suggestions.

---

## Architecture

```
                    human (sees + approves)
                            │
                     erebus operator / AI
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
     host CLI          teamserver      C implant
  erebus ldap/ad/      approval +      lean: shell, SMB,
  kerberos/smb         ticket loot     WinRM PTH, SOCKS
              │                           │
              └──────── pkg/ ─────────────┘
                 krb  ldapcli  smbcli
```

Operator host talks to the DC when it can (VPN, or SOCKS after inbound). C implant does **not** grow an AD crypto stack. Tickets/hashes land in loot; agent uses loot ids.

---

## Implementation order (locked)

```
W0–1  inbound verb + SOCKS→host-tools proxy + live SOCKS prove
W1–2  ldap acl + ForACL suggestions + ticket import + catalog
      ║  parallel: PTH live vs pypsrp
W2–3  ldap set scriptPath + addcomputer + kerberos asktgt AES
W3–4  rbcd write + s4u AES + shadow + keylist (fixture if no RODC)
W5–6  dangling ESC1 + PKINIT UnPAC + dcsync(one) + golden/silver
      corpus retest table
```

## C implant policy (lean)

C this cycle: WinRM password + PTH quality, consume NT/ticket, reverse SOCKS (already written).  
C does not: AskTGT / S4U / KeyList / DCSync / ADCS / shadow write / inbound listen.

If a host verb cannot reach the DC, the fix is **SOCKS / tunnel**, not a C port of `pkg/krb`.

## Agent + human

Every write is **critical** approval. Do not let Plan/Auto chain two critical writes without a human approve in between.

## Sprint-wide rules

- No extra beacon types, no clock-sync opcode, no retry storms.
- One precise failure per write/auth path.
- Fail closed. No placeholder hashes or fake success.
- Secrets in files mode 600. Suggestions use loot ids.
- Dual-control stays.

## Definition of done

- [ ] Inbound: host `ldap` works through SOCKS or reverse tunnel
- [ ] ACL enum + suggestions name a real next verb
- [ ] Ticket import used by at least one of SMB / LDAP / WinRM
- [ ] AskTGT AES + S4U AES + RBCD write lab-green or HTB-green
- [ ] Soft set: scriptPath + addcomputer; password already shipped
- [ ] At least two of: shadow, KeyList, dangling ESC1, DCSync — live on corpus or recorded fixture + one live
- [ ] Golden **or** silver from a key obtained in-Erebus
- [ ] Agent can propose each write; human must approve
- [ ] C did not gain a Kerberos stack
- [ ] Corpus table updated; claim only boxes whose critical path ran in Erebus
