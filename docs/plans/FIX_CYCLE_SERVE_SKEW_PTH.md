# ARK Fix Cycle — 2–3 Week Plan

**Scope:** `ark serve` stdin close → clock skew handling → WinRM PTH parity vs pypsrp  
**Solo. Re-test gate: same 9-box HTB corpus + c-linux-peer.**  
**Baseline:** `docs/private/reports/ARK_HTB_CORPUS_SCORECARD.md`  
**Rule:** no new modules, no ADCS/Kerberos, no RBCD/DCSync, no inbound-C2-by-default, no “while I’m in here.”

Sequencing is the original cycle. Adjustments are OPSEC/speed and acceptance tests only. Inbound C2 stays the **next** sprint.

**Design principle:** compensate server-side, reuse existing traffic, reuse sessions, never solve reliability by adding network chatter.

**Sprint-wide acceptance rule:** no fix may materially increase steady-state beacon size, beacon frequency, auth retries, or network round trips unless the protocol requires it. Benchmark **before/after** for registration latency, beacon bytes, command latency, and request count. Fail the change if those go up without a protocol reason.

---

## Week 1, Days 1–2 — `ark serve` dies on stdin close — **shipped**

**Why first:** DarkZero + DanglingTree. Reliability under the 8/10 teamserver score.

**Network path:** this fix stays **entirely off** the implant/operator wire. No beacon, HMAC, or listener-shape change. systemd/nohup docs are host-local only.

**What it is in tree:** `ark serve` = teamserver + REPL (`pkg/arkcli.Start`). REPL/stdin EOF no longer calls `ts.Stop()`; process waits for SIGINT/SIGTERM. `ark teamserver` and `serve --teamserver` remain the daemon-only path.

**Tasks:**
1. Reproduce: pipe EOF, `/dev/null`, simulated SSH/nohup detach, interactive EOF. Confirm listeners die (REPL return + `Stop()`).
2. Detach teamserver from stdin. REPL closure logs + no-op. Listeners die only on SIGINT/SIGTERM.
3. Point `OPERATOR_INBOUND`, `GOLDEN_DEMO`, `HTB_NEXT_RUNBOOK`, `GOAD_LAB` at `ark teamserver` / surviving `serve`. systemd unit optional; do not spend Day 2 inventing a service manager.

**Acceptance:**
- Survives SSH-drop / detached session. Soak 30+ min (no silent later death after EOF).
- **Automated regression in-repo:** `/dev/null`, pipe EOF, detached/nohup-style, interactive EOF. After EOF: still listening, implant can register. Soak is not a substitute.
- Benchmark: N/A for wire (must be identical). Process must not spawn extra listeners or callbacks.

**Effort:** 1–2 days. If past Day 2, stop and flag.

---

## Week 1, Days 3–5 — Clock skew handling

**Why second:** 5 of 9 reports (Logging, Garfield, DarkZero, DanglingTree, Ghostlink). Highest-frequency tax. Looks like “wrong URL” / 404s.

**What is in tree:** HMAC window already 8h absolute; server logs `skew|hmac|replay|unknown_implant`; wire 404 stays; Go unique-ms timestamps; C has no increment-guard.

**OPSEC/speed constraints:**
- **No dedicated sync traffic.** No clock-sync endpoint, no periodic sync beacon, no extra field if the existing register/beacon timestamp already carries implant time. Derive offset from that authenticated timestamp only.
- **Keep the normal replay window narrow.** Apply stored offset first, then validate against the **existing tight window** — do not widen production tolerance globally.
- Bootstrap: first register may still use the **already-shipped** 8h window so a 7h HTB host can check in once. After offset is stored, subsequent beacons are `ts + offset` vs server now, then the **narrow** window. That is a tightening vs today’s 8h-on-every-packet, not a widening.
- ±10h lab mode: explicit flag, **off by default**. Never the production default.
- Bound offset change rate; dampen re-estimates from later check-ins. Do not permanently trust one client timestamp.
- 500ms replay is a **separate** C increment-guard leftover, same week, not the same root cause.

**Tasks:**
1. Audit HMAC / replay / cert time checks (grep first).
2. Implement server-side offset as above. Implant binary and beacon shape stay the same.
3. Surface in operator UI/logs: `implant clock offset: +7h42m`. Wire 404 may stay; operator + teamserver must name `skew`.
4. C unique-ms guard if still missing.

**Acceptance:**
- 6–9h offset implant registers, beacons, runs tasks **with no extra round trips**.
- After offset lock-in, production window is **not** wider than today; prefer narrower.
- Beacon size and frequency unchanged vs before/after benchmark.
- No silent 404s on the operator side.

**Effort:** 2–3 days if isolated to HMAC.

---

## Week 2–3 — WinRM PTH parity vs pypsrp

**Why third:** 2/9 reports (Logging, Garfield); capability signal. Do not swap for inbound C2.

**What is in tree:** `winrm_ntlm_hash.go` + `winrm_ntlm_seal.go` + `winrm_pth_layer.go` + session pool. Hash path is **one flow** (no seal→plain retry). Failures are tagged `pth_layer=`. Sequential hash commands reuse one WinRM client. **Live pypsrp parity still open** — Day-3 gate: if a live failure has no layer, stop and instrument.

**OPSEC/speed constraints:**
- **Persistent WinRM session:** authenticate once, reuse for sequential commands. Do not renegotiate NTLM per task.
- **Deterministic failure:** no broad automatic auth fallback/retry loops. One path, one failure, one error. Remove or do not add seal→plain ping-pong if that is what is generating 401/415 noise.
- Request count for N sequential commands should be ~1 handshake + N ops, not N handshakes.

**Tasks:**
1. Diagnose current hash path vs pypsrp on one Windows target (timeout vs 401 vs seal).
2. Study pypsrp (no copy) for message types / encryption / framing.
3. **Hard diagnostic gate — PTH Day 3:** name the layer: transport, HTTP Negotiate, NTLM TYPE1/2/3, key derivation, sign/seal, WinRM MIME framing, or session lifecycle. If unnamed, stop feature work and instrument.
4. Patch that layer. Hash-only, exec, file transfer if supported, **multiple sequential commands on the reused session**.

**Acceptance:**
- Hash-only PTH succeeds; ≥3 sequential commands without re-auth; same ops as pypsrp on that host.
- No extra auth retries vs the single correct flow.
- Command latency / request count benchmarked before/after.

**Effort:** rest of cycle. If Day 5 of PTH still has no named layer, reassess.

---

## Re-test gate (end of week 2–3)

Same 9 HTB boxes + c-linux-peer. Not new solves.

- Zero stdin-close crashes.
- Zero clock-skew-caused 404s (Logging, Garfield, DarkZero, DanglingTree, Ghostlink conditions).
- WinRM PTH succeeds on Logging/Garfield-equivalent targets.
- Wire shape: no new beacon types, no extra check-ins, no retry storms.

Automated tests are required, not a substitute for the corpus. Retired/down box (Support): record it, use closest live equivalent, do not silently drop the gate.

Tax cycle: win even if critical-path % does not move.

---

## Explicitly not this cycle

Kerberos (AES TGT, golden, KeyList), ADCS (ESC1/7/8/11, PKINIT, UnPAC), AD writes (RBCD, DCSync), inbound C2 / reverse-tunnel-by-default, any new implant opcode or extra beacon for clock sync.

Inbound C2 was the most frequent recurring issue (6 reports). It is the **top of the next sprint**, not a swap-in.

---

## Implementation order

serve + EOF tests → skew offset from existing timestamps + narrow window after lock-in + operator surface + C ms guard → PTH diagnose → Day-3 layer gate → one-flow persistent session patch → corpus retest.
