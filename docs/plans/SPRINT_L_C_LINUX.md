# Sprint L — C Linux primary + deep post-ex

| Field | Value |
| --- | --- |
| **Status** | Active (2026-08-09) |
| **Goal** | C is the **primary Linux implant**; baseline signed off; reverse SOCKS then Linux-native post-ex |
| **Metric** | M4a–M4f (see below); habitual C drop on every Linux HTB eng |
| **Sources** | `docs/IMPLANT_ROADMAP.md`, `docs/C_IMPLANT_LAB_CHECKLIST.md` §6–7, session plan C Linux track |
| **Depends on** | Linux basic peer already shipped (`make implant-c-linux`) |

## Policy (locked)

| Topic | Decision |
| --- | --- |
| Linux track | **L3 — C Linux primary** (replaces L1 thin Go peer growth path) |
| Default generate | `language=c` for empty language; Linux → `implant_c_linux` |
| Go Linux | **Archived** (2026-08-18) — `generate --language go --os linux` fails; C only |
| Windows C | Still #1 for AD/lateral — **parallel**, do not block Sprint 1 / B |
| Deep post-ex | Linux-**native** methods (not Windows ports) |

## Exit criteria

| # | Criterion |
| --- | --- |
| M4a | Checklist §6 baseline: host smoke + local live + one HTB re-run |
| M4b | Docs/skills default C Linux; eng reports use C primary |
| M4c | Reverse SOCKS over beacon on Linux C (parity with Go hub) |
| M4d | Creds MVP (`ssh_keys` / `history` / `env`) |
| M4e | Persist MVP (user-level: cron / systemd_user / bashrc) |
| M4f | Privesc `enum` (sudo -l / SUID / caps) |

## Work packages

### Phase 0 — §6 sign-off

| ID | Work | Status |
| --- | --- | --- |
| L.0.1 | `./scripts/c_linux_e2e_smoke.sh` host + empty-CA fail | Done 2026-08-09 |
| L.0.2 | Local live session task matrix (shell/file/process/net) | Pending teamserver eng |
| L.0.3 | HTB FireFlow-class re-run C-only | Pending VPN/box |
| L.0.4 | Fill checklist §6 + `reports/htb-c-linux-peer/SIGN_OFF.md` | Partial (host) |

### Phase 1 — Habitual use

| ID | Work | Status |
| --- | --- | --- |
| L.1.1 | Roadmap flip L1→L3; GOLDEN/runbook/inbound/pre-implant | This sprint |
| L.1.2 | `ark-htb` skill + commands.md C Linux first | This sprint |
| L.1.3 | Builder default already `language=""` → c (linux supported) | Verified |

### Phase 2 — Reverse SOCKS

| ID | Work | Paths |
| --- | --- | --- |
| L.2.1 | PB `SocksFrame` + field 2 on results/tasks payloads | **Done** `cimplant/src/pb/c2.c` |
| L.2.2 | Beacon drain/handle/requeue frames; short sleep when active | **Done** `beacon.c` |
| L.2.3 | `socks_linux.c` reverse agent (pthread) | **Done**; stub removed |
| L.2.4 | Host tests | **Done** `socks_pb_host_test` |
| L.2.5 | Local/HTB live proof | **Open** |
| L.2.6 | Review fixes: async OPEN + connect timeout, FD gen, decode free, IPv6 `[addr]:port`, EXIT shutdown | **Done** 2026-08-09 |

### Phase 3 — Post-ex modules

| Order | Module | MVP methods | Non-goals v1 |
| --- | --- | --- | --- |
| 1 | SOCKS | reverse over beacon | Windows listen-stub fix (separate) |
| 2 | creds | `ssh_keys`, `history`, `env`, `files` — **coded** (`linux_postex.c`); live eng open | LSASS/SAM |
| 3 | persist | `cron`, `systemd_user`, `bashrc` — **coded** (user-level, `--trigger remove`); live eng open | rootkits |
| 4 | privesc | `enum` — **coded**; live eng open | auto exploit chains |
| 5 | cloud | env + well-known paths | Entra Windows |

## Acceptance demo (M4c)

```text
1. make implant-c-linux + CA pin → session
2. shell whoami
3. socks start → teamserver reverse proxy
4. curl --socks5 127.0.0.1:<port> http://127.0.0.1:<internal>
5. socks stop
```

## Pivot until M4c

```bash
./scripts/htb_reverse_tunnel.sh user@TARGET
# or Ligolo / Go implant reverse SOCKS with justification in report
```

## Definition of done (Sprint L baseline)

- [x] Policy L3 locked in roadmap + this plan  
- [x] Host smoke green  
- [ ] Local live matrix  
- [ ] HTB C-only re-run  
- [ ] Habit docs/skills landed  
- [x] Reverse SOCKS code + host tests  
- [x] Reverse SOCKS lab-green (local 2026-08-18; HTB optional)  
- [x] Go Linux archived (`generate --language go --os linux` fails)  
 

## Related

- Checklist: `docs/C_IMPLANT_LAB_CHECKLIST.md` §6–7  
- Sign-off: `reports/htb-c-linux-peer/SIGN_OFF.md`  
- Windows lateral (parallel): `docs/plans/SPRINT_1_C_LATERAL.md`  
