# C Linux implant — baseline sign-off (Sprint L / M4a)

| Field | Value |
| --- | --- |
| **Date** | 2026-08-09 |
| **Binary** | `build/implant_c_linux` (~83 KB) |
| **Build** | `make implant-c-linux` + `CA_CERT_PATH` PEM→DER pin |
| **Smoke script** | `./scripts/c_linux_e2e_smoke.sh` |
| **Plan** | `docs/plans/SPRINT_L_C_LINUX.md` |

## Host matrix (operator machine)

| Check | Result | Evidence |
| --- | --- | --- |
| Host unit tests (`make -C cimplant test-host`) | **PASS** | pathjail, pb-copy, kerberoast-pb, ntlm-parse, socks-pb, unique-ms |
| Build `implant_c_linux` with real CA | **PASS** | ELF 64-bit, size 83256 bytes |
| Empty CA HTTPS build fails closed | **PASS** | make exit 2 |
| `c_linux_e2e_smoke.sh` SKIP_LIVE=1 | **PASS** | 2026-08-09 |

## Live local session (2026-08-09, workstation)

| Check | Result | Notes |
| --- | --- | --- |
| Register + session | **PASS** | implant `5c65f7b7…` session `0cb31501…` os=linux |
| Shell `whoami` / `id` | **PASS** | `zero` / uid=1000 |
| File download | **PASS** relative path (`ark_rel_qa.txt`); **absolute `/tmp/...` rejected** by pathjail (by design) |
| Process list | **PASS** | shows `implant_c_linux` |
| ifconfig | **PASS** | lo, wlo1, tun0 |
| SOCKS start | **PASS** | hub `127.0.0.1:1080`; SOCKS5 CONNECT granted |
| SOCKS data plane | **PASS** 2026-08-09 | curl via socks → HTTP 200 (1345 B). Fix: no CLOSE on clean EOF same batch as DATA |
| SOCKS re-prove (2026-08-18) | **PASS** | C-only `implant_c_linux` session `f82e7157…`; `ark op socks start --port 1080`; curl --socks5-hostname 127.0.0.1:1080 → :8443 (48 B HTTPS-plain-HTTP body). `inbound env` exported `ARK_PROXY`. |

## HTB re-run (FireFlow-class)

| Check | Result | Notes |
| --- | --- | --- |
| C-only drop (no Go primary) | **Pending** | Prefer FireFlow or firewalled Linux + reverse tunnel |
| Register via tunnel if needed | **Pending** | `scripts/htb_reverse_tunnel.sh` |
| Shell + file + process + net | **Pending** | |

Historical: FireFlow eng already proved C Linux shell via reverse tunnel (`reports/htb-fireflow/PENTEST_REPORT.md`) — formal §6 re-run still required for C-only + full task matrix.

## Pivot policy

- Reverse SOCKS over beacon: **code + local live PASS** (2026-08-09). Host AD tools honor `ARK_PROXY` / `eval "$(ark inbound env --port 1080)"`.
- HTB-green SOCKS (ldap/smb through the implant on a firewalled box) is still **open**.
- Until that HTB proof: SSH reverse tunnel / Ligolo remain valid with report justification.

## Sign-off status

| Milestone | Status |
| --- | --- |
| **M4a host baseline** | **PASS** 2026-08-09 |
| **M4a live local** | **PASS** 2026-08-09 (matrix above) |
| **M4a HTB** | Open (FireFlow-class C-only re-run) |
| **M4b habit** | In progress (docs/skills) |
| **M4c reverse SOCKS code** | **PASS** 2026-08-09 (host tests + build) |
| **M4c reverse SOCKS live (local)** | **PASS** 2026-08-09; **re-prove 2026-08-18** (`ark op socks` + curl via hub) |
| **M4c reverse SOCKS HTB + host ldap via proxy** | Open (no tun0 this session) |
