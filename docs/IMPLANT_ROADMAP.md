# ARK Implant Roadmap

**Status:** v0.1.0 lab / research  
**Last updated:** 2026-09-04 (docs pass: C primary both OS; Go Linux archived; host ADCS/RBCD/shadow; PKINIT still incomplete)  
**Audience:** maintainers planning the next implant sprint(s)

This document inventories **what the implant can do today**, **what is left**, and **how a possible Zig implant branch fits**. It does not authorize use against unauthorized targets — authorized labs and engagements only.

---

## 1. Architecture snapshot

```
                    c2.proto (protobuf wire)
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   Go implant          C implant            Zig implant
   implant/            cimplant/            (future branch)
   fallback            PRIMARY (Win+Linux)  deferred peer
        │                   │                   │
        └───────────────────┴───────────────────┘
                            │
                     Teamserver listeners
                     (HTTPS / DNS)
```

| Language | Path | Platforms | Role |
|----------|------|-----------|------|
| **Go** | `implant/`, `cmd/implant/` | Linux + Windows | Fallback / demo; reverse SOCKS until C M4c; **not** product growth path |
| **C** | `cimplant/` | Windows PE + **Linux primary** | **Primary implant** both OS; Linux deep post-ex track (Sprint L) |
| **Zig** | *(not started)* | TBD | Possible third peer on same wire protocol |

**Shared (do not rewrite per language):**

- `proto/c2.proto` — task types, register/beacon, results  
- Teamserver, sessions, approval gate, operator API  
- DNS chunking rules (`pkg/dnstransport/`)  
- Crypto contract: HMAC-SHA256 identity, AES-256-GCM session payloads  
- Build-time identity: implant ID, secret, callback URL, sleep/jitter  

**Builder today:** `language: "c"` (default for empty language — Windows PE or Linux) or `language: "go"` (explicit fallback / dll/shellcode). A Zig path would add `language: "zig"` later without changing the server contract.

---

## 2. Task surface (`c2.proto`)

All implants should eventually honor the same task enum. Current coverage:

| Task | Go | C | Notes |
|------|----|----|-------|
| `TASK_SHELL` | Yes | Yes | |
| `TASK_FILE_DOWNLOAD` / `UPLOAD` | Yes (+ path jail) | Yes (+ path jail) | Absolute / `..` rejected |
| `TASK_PROCESS_LIST` / `KILL` | Yes | Yes | |
| `TASK_NET_IFCONFIG` / `PORTSCAN` | Yes | Yes | |
| `TASK_SCREENSHOT` | Windows | Windows | Stub on non-Windows Go |
| `TASK_KEYLOG_*` | Windows | Windows | Stub on non-Windows Go |
| `TASK_INJECT` | Windows | Windows | Method matrix incomplete |
| `TASK_PE_LOAD` / `PE_LOAD_EXEC` | Windows | Windows | Stub on non-Windows Go |
| `TASK_SOCKS_START` / `STOP` | Yes | Linux yes; Windows stub | Windows C `socks_api_stub.c` fail-closed |
| `TASK_EXIT` / sleep handling | Yes | Yes | Sleep updates via server/checkin |
| `TASK_MODULE` | Yes | Yes | Dispatches to module registry |
| `TASK_LDAP_ENUM` | Yes | Partial | C: basic LDAP |
| `TASK_KERBEROAST` | Yes | Yes | C: real hashes, no placeholders; lab-verify still open |
| `TASK_ASREPROAST` | Yes | Yes | Same |
| `TASK_CREDS_DUMP` | Windows | Partial | Go: LSASS/SAM/browser |
| `TASK_LATERAL_MOVE` | WinRM/WMI/DCOM/PsExec | WinRM/PsExec/WMI/DCOM | C: WinRM password+PTH; PsExec password+SCM (no hash); Windows C SOCKS stub |
| `TASK_PERSIST` / `PRIVESC` | Windows | Partial | Linux Go: not supported stubs |
| `TASK_PIVOT_*` | Via SOCKS path | Via SOCKS | Confirm no half-wired pivot tasks |

---

## 3. Go implant — what works

**Core**

- Beacon loop, configurable sleep/jitter  
- HTTPS transport (TLS, optional domain fronting / pin hooks)  
- DNS transport client  
- HMAC auth + AES-GCM session encryption  
- Module registry via `init()` registration  
- Build outputs: **EXE**, **shellcode** (donut), **DLL** (c-shared)

**Tasks / modules (lab-proven paths)**

- Shell, files (path jail), process, network recon  
- SOCKS pivot  
- AD: LDAP enum, Kerberoast, AS-REP  
- Cloud harvest (AWS / Azure / GCP / IMDS)  
- Creds on Windows (LSASS minidump, SAM, browser — decrypt best-effort)  
- Lateral: WinRM (incl. PTH paths), WMI, DCOM, PsExec (stage + service start on Windows)  
- Persist / privesc on Windows  
- Screenshot, keylog, inject, PE load on Windows  

**Non-Windows by design**

Many modules have `_stub.go` (`//go:build !windows`) and return clear “not supported” errors: persist, privesc, creds dump, WMI/DCOM, inject, keylog, screenshot, PE load, PsExec service start.

---

## 4. Go implant — what is left

### P0 — if Go is retained at all (secondary / Linux peer)

| # | Item | Why |
|---|------|-----|
| G1 | **Honest Linux post-ex story** | Either ship a minimal Linux persist/privesc/creds set **or** document forever “Windows-first for post-ex” |
| G2 | **PsExec end-to-end clarity** | Service start is Windows-tagged; ensure errors are clear when incomplete; cleanup paths solid |
| G3 | **WMI path quality** | Prefer COM over shelling `wmic.exe` where possible (noise / EDR) |
| G4 | **Creds / browser loot quality** | Reduce silent/partial decrypt failures; consistent structured loot |

### P1 — capability depth

| # | Item | Why |
|---|------|-----|
| G5 | **Inject method matrix** | Beyond CRT/APC baseline: more techniques, better error handling (`VirtualAllocEx` failures, etc.) |
| G6 | **SMB module completeness** | Lateral/helpers consistency with operator commands |
| G7 | **Cloud module edge cases** | Env/file parsers, managed identity, Azure AD Connect depth |

### P2 — evasion / “next gen” (architecture backlog)

| # | Item | Why |
|---|------|-----|
| G8 | Sleep masking (encrypt memory while sleeping) | Memory scanners |
| G9 | ETW / AMSI patching for CLR/PowerShell paths | Common blue-team hooks |
| G10 | Interactive (non-beacon) mode | Time-sensitive ops |
| G11 | Self-update / module push without full rebuild | Ops convenience |
| G12 | Malleable C2 (implant-side of profiles) | Needs teamserver profiles too |

---

## 5. C implant — what works

**Windows PE** (`make implant-c` / `generate --language c --os windows`)

- Beacon, HTTPS + DNS, HMAC + AES-GCM  
- Shell, file (+ path jail), process, network  
- Screenshot, keylog, SOCKS, inject, PE load  
- Modules: shell, LDAP (basic), cloud, creds (partial), persist/privesc (partial)  
- Lateral **WMI** + WinRM password (WSMan); Kerberoast wire (RC4 MVP)  
- Indirect syscall scaffolding  

**Linux primary** (`make implant-c-linux` / `generate --language c --os linux`) — Sprint L

- Beacon + HTTPS (libcurl + OpenSSL, CA pin required)  
- Shell (`/bin/sh -c`), file download/upload + path jail, process list/kill, ifconfig + portscan  
- Modules: shell, cloud, Linux-native creds collection, persist, and privesc enum  
- Windows post-ex / AD / lateral hard-fail with explicit strings  
- Reverse SOCKS is Linux-native; screenshot/keylog/inject/PE-load remain explicit unsupported tasks  
- Host unit tests: path jail, pb-copy, kerberoast-pb, ntlm-parse; smoke: `scripts/c_linux_e2e_smoke.sh`  
- Sign-off: `reports/htb-c-linux-peer/SIGN_OFF.md` · plan: `docs/plans/SPRINT_L_C_LINUX.md`  

---

## 6. C implant — what is left

### Explicit stubs / gaps

| # | Item | Current behavior |
|---|------|------------------|
| C1 | **Kerberoast** | Wire Kerberos (RC4 + AES, hashcat format) — **no placeholder hashes**; clear fail strings; **lab-verify GOAD/HTB** still open |
| C2 | **AS-REP roast** | Real AS-REQ without pre-auth + hashcat lines — lab-verify still open |
| C3 | **Lateral PsExec** | Password: ADMIN$ stage + SCM create/start; PTH via hash not on WNet (use WinRM PTH) |
| C4 | **Lateral WinRM** | Password via WSMan; PTH via WinHTTP+NTLMv2+SOAP — **clearer errors + parse tests**; **live pypsrp parity eng-verify** |
| C5 | **Lateral DCOM** | MMC20 ExecuteShellCommand (password) |
| C6 | **TLS pinning** | **Makefile/builder PEM→DER b64**; empty CA fail-closed at build + runtime |
| C7 | **Module depth** | Linux: unsupported modules return explicit error strings |
| C8 | **Output formats** | PE EXE only (no shellcode/DLL pipeline) |
| C9 | **Tests** | Host: pathjail, pb-copy, kerberoast-pb, **ntlm-parse**; no Windows integration CI |
| C10 | **Beacon timestamps** | **Unix ms** (was seconds → same-second replay on SLEEP_MS=500) |
| C11 | **Auth observability** | Server logs `unknown_implant|hmac|skew|replay` on drop; wire still 404 |
| C12 | **Linux drop UX** | Tunnel + smoke scripts done; reverse SOCKS → Sprint L M4c (`SPRINT_L_C_LINUX.md`) |

### Policy (locked)

**C is #1.** Implement C1–C5 for real capability (parity investment on Windows). Do not leave placeholder Kerberoast/lateral success paths.

---

## 7. Zig implant (optional future branch)

### Intent

A **third language peer** on the same wire protocol — not a rewrite of the teamserver.

### Why someone would want it

- Smaller / more controllable static binaries than Go  
- No Go runtime  
- Fine-grained memory and linking control  
- Learning / differentiation experiment  

### Why it costs

- Re-implement crypto, HTTP(S), DNS chunking, every task handler  
- Windows API surface is large  
- Feature parity with Go will lag for a long time  

### Recommended Zig MVP (if greenlit)

**In scope**

1. Register + beacon + sleep/jitter  
2. HTTPS transport + HMAC + AES-GCM (match Go)  
3. `TASK_SHELL`  
4. `TASK_FILE_DOWNLOAD` / `UPLOAD` with same path-jail rules  
5. `TASK_PROCESS_LIST`  
6. `TASK_EXIT`  

**Out of scope for MVP**

- Full AD (LDAP/Kerberoast/AS-REP)  
- Lateral, inject, PE load, keylog  
- DNS transport (phase 2)  
- Shellcode/DLL packaging  

### Repo hygiene if Zig proceeds

| Rule | Detail |
|------|--------|
| Branch | e.g. `implant/zig` — do not break Go default on `main` |
| Tree | e.g. `zigimplant/` or `zimplant/` |
| Build | `zig build` + Makefile target; optional CI when Zig present |
| Config | Same ldflags concept: ID, secret, callback, sleep, jitter |
| Builder | Later: `GenerateImplant` `language: "zig"` |
| Wire | Same `c2.proto` field layout (hand encode or generate) |

### Decision rule

- Choose Zig only if **size/control/evasion** is a product goal.  
- Do **not** choose Zig to “finish features faster” — Go is faster for capability.  
- Prefer **one** experimental native implant (C *or* Zig) unless staffing allows both.

---

## 8. Priority order (post-decision)

| Phase | Focus | Outcome |
|-------|--------|---------|
| **0** | Golden Demo 5/5 Auto on best available path | Prove AI + C2 reliability |
| **A** | **C implant = #1** (Windows) — real AD + lateral, no fake stubs | C is the engagement implant on Windows |
| **B** | Lateral vertical (WinRM → PsExec → WMI quality → DCOM) | Demo-grade movement on C |
| **C** | Linux ambition | **L3 C Linux primary** (Sprint L) — reverse SOCKS then native post-ex |
| **D** | Zig | Only after C Windows path is proven |
| **E** | Evasion P2 | After lab demos are boring |

### Strategic note (resolved tensions)

Locked product intent:

- **C implant primary** on Windows; **teamserver stays Go**; **Go implant not product focus**
- **Full Linux post-ex ambition** (long horizon)
- **Zig after** the stack is proven (not now)
- **Lateral** as first capability vertical
- **Golden Demo 5/5 Auto** as sprint success metric

**Resolved:** C owns **Windows** (AD + lateral) and **Linux** (Sprint L deep track). Go implant is fallback only.

**Practical interpretation used in §13:**

1. **Near term:** C owns **Windows** implant surface (AD real; lateral vertical) **in parallel** with Linux reverse SOCKS + post-ex.
2. **Linux:** **L3 C primary** — grow reverse SOCKS then native creds/persist/privesc enum (not Windows ports).
3. **"Zig after stack proven":** after control plane + C Windows + C Linux baseline demos—not "finish Go first."
4. **Golden Demo** needs working **LDAP + Kerberoast** on **Windows C**.

---

## 9. Non-goals (for this roadmap)

- Rewriting teamserver/operator (stays **Go**)
- Claiming C/Zig parity with Cobalt Strike
- Public "EDR-proof" guarantees
- Unauthorized targeting features
- Expanding **Go Windows** modules as the product path (maintenance/demo only)
- **LLM browser OAuth / “Sign in with Anthropic|OpenAI|xAI” in the current sprints** — API keys + env vars only for now (see §17)

---

## 10. Related docs

| Doc | Role |
|-----|------|
| [README.md](../README.md) | Public v0.1 status |
| [SECURITY.md](../SECURITY.md) | Authorized use + vuln reporting |
| [ARCHITECTURE_DECISIONS.md](../ARCHITECTURE_DECISIONS.md) | Historical design decisions |
| [GOLDEN_DEMO.md](GOLDEN_DEMO.md) | Lab demo script (sprint success metric) |
| [HTB_NEXT_RUNBOOK.md](HTB_NEXT_RUNBOOK.md) | Engagement runbook |

---

## 11. Planning questions (answered 2026-07-31)

1. Primary implant → **C #1; teamserver Go; no Go implant as product focus**
2. C policy → **C is number one** (invest for real capability, not narrow/sunset)
3. Linux post-ex → **Full Linux parity ambition** (long multi-sprint; see §8)
4. Zig → **After** C Windows + demos proven (not now)
5. First vertical → **Lateral movement**
6. Sprint success → **Golden Demo 5/5 Auto**

---

## 12. Decisions (locked)

| Topic | Decision | Date |
|-------|----------|------|
| Control plane | **Go** teamserver, operator, AI, listeners | 2026-07-31 |
| Primary implant | **C (Windows)** | 2026-07-31 |
| Go implant | **Not product focus**; Linux/Windows **fallback** until archived after C proven | 2026-07-31; Linux demoted 2026-08-09 |
| C policy | **#1 investment** — real AD + lateral, no placeholder "success" | 2026-07-31 |
| Linux post-ex | **Full parity ambition** via **L3: C Linux primary** (Sprint L) | **2026-08-09** (was L1 Go) |
| Zig | **After** C Windows + demos proven; MVP peer only | 2026-07-31 |
| First vertical | **Lateral**, starting with **WinRM** on C (after C Kerberoast for demo) | 2026-07-31 |
| Sprint success metric | **Golden Demo 5/5 Auto on C only** (requires real C Kerberoast first) | 2026-07-31 |
| Golden Demo implant | **C-only after Kerberoast port** (no Go credit for the 5/5 gate) | 2026-07-31 |
| First C lateral | **WinRM first**, then PsExec, WMI COM, DCOM | 2026-07-31 |

---

## 13. Implementation plan

### Sprint 0 — Golden Demo 5/5 Auto

**Goal:** Five consecutive Auto runs with `mission_complete` (or clear summary) and ≥1 successful `ldap_enum` after approval.

**Frozen objective:** recon → LDAP kerberoastable → kerberoast if found → summarize. **No** LSASS, persist, or lateral.

#### 0A. Demo implant (locked)

**C only.** Do **not** count Golden Demo 5/5 on Go.

Order: **0B (C Kerberoast + LDAP)** → **0C (5× Auto on C session)**.

#### 0B. C AD minimum (blocking for demo-on-C)

| Task | Acceptance |
|------|------------|
| C LDAP enum vs lab DC | Returns kerberoastable principals |
| C Kerberoast **real tickets** | Hashcat-compatible; no placeholder strings |
| Builder | `generate --language c` / `make implant-c` used for demo host |
| Auto path | Agent can schedule ldap_enum + kerberoast on C session |

#### 0C. Demo harness

| Task | Acceptance |
|------|------------|
| Lab checklist filled | Domain, DC, listener, LLM |
| Dual-control approvals | LDAP/Kerberoast approvable |
| 5 consecutive runs logged | Table in `reports/` or runbook appendix |
| Failures captured | Error text saved |

**Exit Sprint 0:** metric green, or written "deferred until C Kerberoast."

---

### Sprint 1 — C is primary (Windows)

#### 1A. Kill fake paths

| Task | Acceptance |
|------|------------|
| Kerberoast/AS-REP placeholders | Real extraction **or** hard fail with clear error |
| Lateral stubs (PsExec/WinRM/DCOM) | `Success=false` + clear message until implemented |
| Docs | README/status: C = primary Windows implant |

#### 1B. Lateral vertical (chosen depth)

Implement **in order**:

| # | Method | Acceptance |
|---|--------|------------|
| 1 | **WinRM** (PTH if portable from Go) | Remote command; structured result |
| 2 | **PsExec** | Stage + service start (or honest partial) |
| 3 | **WMI** | Prefer COM; reduce `wmic.exe` |
| 4 | **DCOM** | After 1–3 |

#### 1C. Transport / quality

| Task | Acceptance |
|------|------------|
| TLS pin / CA verify | Documented behavior; no silent disable |
| Path jail regressions | Host tests still pass |
| Smoke checklist | register → beacon → shell → file → one lateral |

#### 1D. Tooling

| Task | Acceptance |
|------|------------|
| Default Windows generate language → **c** | Operators get C by default |
| Go implant | Not default for Windows; keep for demo/Linux peer |

**Exit Sprint 1:** C can do Golden Demo path (if not already) **and** ≥1 real lateral beyond stub-class `wmic` only.

---

### Sprint 2 — AD depth on C + loot

| Task | Acceptance |
|------|------------|
| AS-REP real extraction | Hashcat-style output |
| Kerberoast hardening | Multi-SPN / enc types; lab parity with prior Go quality bar |
| Creds triage | LSASS/SAM/browser: real or explicit unsupported |
| AI interpreter | Structured kerberoast/lateral results parse cleanly |

**Exit Sprint 2:** Short AD + lateral lab story **without** falling back to Go Windows implant.

---

### Sprint 3 / Sprint L — Linux ambition (**L3 locked**)

Full Linux parity is **multi-sprint**. Track chosen:

| Track | Near term | Long term |
|-------|-----------|-----------|
| L1 — Thin Go Linux peer | Superseded | — |
| L2 — Wait for Zig | Not chosen | — |
| **L3 — C on Linux** (**locked 2026-08-09**) | Baseline peer + reverse SOCKS + native post-ex | C is cross-platform primary |

**Plan:** `docs/plans/SPRINT_L_C_LINUX.md`  
**Exit Sprint L baseline:** M4a host+live sign-off + M4c reverse SOCKS.

---

### Sprint 4+ — Zig (deferred)

Gates:

- [ ] Golden Demo 5/5 stable
- [ ] C Windows AD + lateral not stubbed
- [ ] Explicit go-ahead for `implant/zig`

Zig MVP: register, beacon, shell, path-jailed files, process list, exit — **no** AD/lateral.

---

### Later — Evasion backlog

Sleep mask, ETW/AMSI, inject matrix, malleable C2 — after demos are boring.

---

## 14. Acceptance matrix

| Milestone | Done when |
|-----------|-----------|
| **M0 Golden Demo** | 5/5 Auto runs logged |
| **M1 C primary** | Windows default language = C; docs match |
| **M2 C lateral** | ≥1 real lateral (WinRM or PsExec) in lab |
| **M3 C AD** | Real Kerberoast + AS-REP (no placeholders) |
| **M4 Linux track** | L1/L2/L3 chosen + first milestone |
| **M5 Zig** | Optional MVP beacon |

---

## 15. Immediate next actions (this week)

1. **Sprint 0B code:** C Kerberoast is **real** (wire AS-REQ/TGS, hashcat format, no placeholders, operator-facing errors). **Remaining:** lab-verify on GOAD/HTB (`docs/C_IMPLANT_LAB_CHECKLIST.md` §2).
2. **Run Golden Demo 5/5 Auto on a C implant session** only (**Sprint 0C**) — eng gate, not code.
3. Default Windows builder language is **c** (empty language → C).
4. **Do not start Zig.** Do not expand Go Windows modules.
5. After M0 lab gate: **Sprint 1** C lateral vertical — plan: `docs/plans/SPRINT_1_C_LATERAL.md`.
6. Parallel product: **Sprint B** AD engagement modules — plan: `docs/plans/SPRINT_B_AD.md`.
7. **Sprint L:** C Linux habit + reverse SOCKS (M4c); schedule Go archive after M2–M3 Windows **and** M4c Linux.

---

## 16. Implementation forks (resolved)

| Fork | Decision |
|------|----------|
| Golden Demo implant | **C-only after Kerberoast port** |
| Linux track | **L3 — C Linux primary** (Sprint L) |
| First C lateral | **WinRM first** |
| Go Windows long-term | **Archive eventually** (after C AD + lateral proven) |

---

## 17. AI / LLM auth backlog (related product — not implant)

This section tracks **console AI provider auth**, separate from implant work. Recorded so it is not forgotten, but **not scheduled** against Sprint 0–2.

### Today (shipped)

| Mechanism | Status |
|-----------|--------|
| API key via `ai setup` (hidden prompt) | Yes |
| Environment variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `OLLAMA_API_KEY`, …) | Yes |
| Multi-provider config in `~/.ark/llm.yaml` | Yes |
| Providers | Ollama (local/remote/cloud), Anthropic, OpenAI, **Grok (xAI)**, Gemini, Kimi, Bedrock bearer |

All hosted providers use the **OpenAI-compatible HTTP client** with a **Bearer API key** (except Ollama local dummy key).

### Future (eventually — **not now**)

| Item | Notes |
|------|--------|
| **OAuth / browser login** for Anthropic, OpenAI, xAI (Grok), etc. | Device-code or redirect flow; per-provider OAuth apps; refresh tokens; secure token store under `~/.ark/` |
| Token refresh / expiry handling | Required if OAuth ships |
| Revoke / re-auth in `ai setup` | UX for expired sessions |
| Optional multi-account seats per provider | Nice-to-have after single-account OAuth works |

**Why deferred**

- Implant C-primary + Golden Demo 5/5 is higher priority.
- API keys already unblock all current providers (including Grok).
- OAuth is a large cross-cutting feature (security review, token storage, provider-specific apps).

**When to reopen:** After M0–M2 implant milestones, or if design partners refuse raw API keys.

**Decision:** OAuth for LLM providers is **planned eventually**, **not implemented in the current plan**. Stay on API keys + env vars.
