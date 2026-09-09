# Ghostlink flags

| Flag | Value |
|------|--------|
| user | `d7061bf38c7455d54176097af52df692` |
| root | `33fc86179f59b9e200c2dae3b0979ba1` |

Full report: `PENTEST_REPORT.md`  
ARK backlog: `ARK_IMPROVEMENTS.md`

## Creds (lab)
- vroth / mOo03jpsqx8JQYMBwvFP (Gogs/KeePass)
- nvirelli / u47YUclrDiwWxBheaSzI (domain + Linux)
- Administrator NT: 8190e067f478002ddd63eb209b016696

## Path
MQTT healthcheck → NTLM svc_canary → GhostSurf relay → LFI → KeePass → Gogs CVE-2025-8110 → gogs.db crack → user → Admin PTH (hash reused on this instance) → root
