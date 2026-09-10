# ARK — agent notes

This file is the current product snapshot for coding agents. Do not treat May 2026 memory dumps as current: the implant is **not** Go-only, DNS listeners are **not** stubs, and high-risk `ExecuteTask` **does** go through the server approval gate.

Full conventions: `CLAUDE.md`. Public how-to: `README.md`. Implant plan: `docs/IMPLANT_ROADMAP.md`.

## What this is

Lab-grade C2 for **authorized** offensive work (HTB, GOAD, owned labs). Teamserver and operator API are Go. Implants speak protobuf over HTTPS or DNS.

**C is the engagement implant** (Windows PE and Linux). Go Windows remains the fallback for the full module set, DLL, and shellcode. **Go Linux is archived.**

## Commands that match the tree

```text
ark                 interactive console
ark teamserver      C2 daemon (prefer this)
ark serve           teamserver + operator REPL; stdin/EOF does not stop C2
ark operator        REPL
ark op              one-shot (sessions / shell / generate / …)
ark certs seats     operator + approver mTLS certs
ark inbound …       tun0 / drop / httpdrop / redirector / SOCKS env
ark ldap / smb / ad / adcs / rbcd / kerberos / winrm / http / dns / mssql / mqtt / relay
```

Data dir: `~/.ark/` (`ARK_HOME` overrides; populated `~/.erebus` is still accepted as a legacy tree).

Default **fresh** HTTPS listener: **1750**. Existing `server.yaml` is not rewritten.

## Implants

| Build | What |
| --- | --- |
| `make implant-c` | Windows C PE (primary) |
| `make implant-c-linux` | Linux C (primary) |
| `make implant-win` / `implant-dll` / `implant-shellcode` | Go Windows fallback |
| `make implant` | **Fails** — Go Linux archived |
| `ark op generate --language c` | Default empty language is **c**; registers HMAC secret |

Bare Makefile C builds do **not** register the HMAC secret. Use `op generate`, `inbound drop`, or `op register-secret`.

## Honest gaps (do not claim otherwise)

- Native PKINIT UnPAC: `ark kerberos pkinit` assembles PA-PK-AS-REQ (CMS AuthPack + DH) and UnPACs the NT hash. Live DC still required; Certipy remains a fallback if the KDC rejects the request.
- ADCS ESC2–11 / web enroll / golden cert: out of scope. Dangling ESC1 template create/grant/req/auto **is** `ark adcs`.
- Windows C reverse SOCKS over beacon is implemented (same reverse-agent wire as Linux C / Go). Live Windows proof still open. Linux C reverse SOCKS is implemented.
- Go PsExec from a non-Windows implant still cannot create the remote service.
- No malleable C2 profiles, no sleep mask, no multi-teamserver.

## Tests

```bash
bash scripts/smoke_test.sh
make -C cimplant test-host
go test ./server/e2e/... -v -count=1
```
