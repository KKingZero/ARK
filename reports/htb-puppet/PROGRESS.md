# HTB Puppet (Mini Pro Lab) — progress

Authorized HTB Pro Lab only. Entry `10.13.38.33`.

## Flags

| Name | Value | Where |
|---|---|---|
| Sleep | `PUPPET{1c1740d66f707111a911e5f6a96d7d36}` | `C:\Users\bruce.smith\Desktop\flag.txt` on File01 |
| Nightmare | `PUPPET{3b3072985c0759f048842861ef5aac55}` | `C:\Users\Administrator\Desktop\flag.txt` via SYSTEM beacon |
| Dance | `PUPPET{c093652c9a73eaee0b43e039a04eff77}` | PM01 `/root/flag.txt` via `sudo puppet apply` |
| Puppet Master | `PUPPET{8b6626457fbee7a7e2b74a2aa6754aa9}` | DC01 SYSTEM DPAPI scheduled-task cred `PUPPET\root` |

## Access

- Pro Lab VPN (not machines pack). Entry: 21/ftp, 22/ssh, 8443, 31337.
- Anon FTP: `red_127.0.0.1.cfg` + `sliver-client_linux`.
- `socat TCP-LISTEN:31337,reuseaddr,fork,bind=127.0.0.1 TCP:10.13.38.33:31337`
- Beacon `BLUSHING_ERROR` as `PUPPET\bruce.smith` on File01 `172.16.40.50`. C2: `mtls://172.16.40.200:8443` (PM01).

## Puppet Master path

1. File01 SYSTEM copied `C:\ProgramData\Puppet\puppet-update.exe` → `C:\files\update.exe` (`\\file01.puppet.vl\files`).
2. PM01 SUID bash (Dance) wrote `node 'dc01.puppet.vl'` exec into `/etc/puppet/code/environments/production/manifests/site.pp`. Agent `runinterval=60`.
3. DC01 beacon as `PUPPET\svc_puppet_win_t0` (High IL). Desktop `root.txt` says flag is password of `root@puppet.vl`.
4. SharpDPAPI `machinetriage` as SYSTEM via schtask: scheduled-task DPAPI cred `PUPPET\root` = flag.
5. Catalog reverted to empty `node default` so DC01 stops re-execing the implant.

## ARK

Lab starts on the provided Sliver beacon; C2 for this path was Sliver on PM01 (`mtls://172.16.40.200:8443`), not ARK.

## ARK gaps this eng

| Gap | Workaround | Wanted |
| --- | --- | --- |
| No host Puppet catalog / apply | SSH + `sudo puppet` / SUID bash | not in scope |
| No SharpDPAPI / machine DPAPI | uploaded GhostPack SharpDPAPI via Sliver | later, host-side DPAPI optional |
| SMB Kerberos initiator still missing | NTLM / existing session copy | already tracked |
