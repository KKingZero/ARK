# ARK C2

Custom C2 framework for AI-driven offensive security operations.

## Agent skills (HTB)

- **`ark-htb`** — run authorized HTB labs with this C2 (`.claude/skills/` and `.grok/skills/`)
- **`htb-pentest`** — general HTB methodology (also user-global under `~/.claude/skills/` / `~/.grok/skills/`)
- Runbook: `docs/HTB_NEXT_RUNBOOK.md` · AD cookbook: `docs/AD_ENGAGEMENT.md`

## Build

```bash
make proto              # Generate protobuf code
make ark                # Unified ark CLI (console + operator + host tools)
make install            # Install ark (+ ARK/erebus compatibility symlinks) to ~/.local/bin
make teamserver         # Teamserver binary
make implant-c          # C implant, Windows PE (primary; needs mingw)
make implant-c-linux    # C implant, Linux (primary)
make implant-win        # Go Windows fallback (EXE)
make implant-dll        # Go Windows DLL
make implant-shellcode  # Go Windows shellcode (via pe2shellcode)
make operator           # Operator REPL binary
make agent              # Standalone AI agent binary

# `make implant` (Go Linux) is archived and fails closed.
# `make all` still depends on that target — use the explicit list above.

bash scripts/smoke_test.sh              # Build + unit smoke checks
go test ./server/e2e/... -v -count=1    # Live teamserver e2e
```

Go 1.25 (`go.mod`). C PE: mingw or `scripts/setup_c_toolchain.sh`.

## Architecture

- **Teamserver** (Go): gRPC API + HTTPS/DNS listeners. Default HTTPS **1750** (existing `~/.ark/server.yaml` is not rewritten). gRPC `127.0.0.1:50051` (mTLS).
- **C implant** (`cimplant/`): **primary** on Windows PE **and** Linux. `make implant-c` / `implant-c-linux`, or `GenerateImplant` with `language: "c"` (empty language defaults to C).
- **Go implant** (`implant/`): Windows fallback for full modules / DLL / shellcode. **Go Linux is archived** (`generate --language go --os linux` fails).
- **Operator CLI**: unified `ark` — interactive console, `ark operator` REPL, one-shot `ark op`. Dual seats (`operator` + `approver`) for approve/deny.
- **Host tools** (no session): `ark inbound` `ldap` `smb` `ad` `adcs` `rbcd` `kerberos` `winrm` `mssql` `mqtt` `relay`
- **Wire protocol**: protobuf (`c2.proto` implant, `api.proto` operator). Proto package name is still `erebus.c2`.
- **DB**: SQLite at `~/.ark/ark.db` (legacy `~/.erebus` still used if that tree already exists; `ARK_HOME` overrides)
- **Config**: YAML at `~/.ark/server.yaml`

Prefer `ark teamserver` as the C2 daemon. `ark serve` is teamserver + operator REPL; stdin/REPL EOF does **not** stop C2 (SIGINT/SIGTERM does).

## Key Conventions

- All implant-facing comms use protobuf (`c2.proto`)
- AI/operator API uses gRPC (`api.proto`)
- Implant authenticates via HMAC-SHA256 pre-shared secret (injected via ldflags). `op generate` / `inbound drop` register the secret in the DB; bare `make implant-c*` does not.
- Session encryption: AES-256-GCM with negotiated keys
- HTTPS implants pin the teamserver CA (fail closed if empty). C pin is base64 **DER**.
- Module registry is compiled-in (no dynamic loading) via `init()` (Go) / `cimplant/src/modules/registry.c` (C)
- Task results carry structured data for AI consumption
- Platform-specific Go code uses build tags (`//go:build windows` / `//go:build !windows`)
- Task handler pattern: unmarshal proto → execute → marshal result → switch case in executor
- High-risk operations require server-side approval gate on `ExecuteTask` (`server/grpc.go` → `server/approval/`)
- New Go modules go in `implant/modules/<category>/` with `_stub.go` fallbacks for non-Windows
- New Go task handlers go in `implant/tasks/` with a case added to `executor.go`
- Transport selection via ldflags: `TRANSPORT_TYPE=https|dns`
- DNS transport uses base32-encoded subdomain labels in TXT queries; chunking in `pkg/dnstransport/`
- C modules register in `cimplant/src/modules/registry.c`; new handlers in `cimplant/src/tasks/`
