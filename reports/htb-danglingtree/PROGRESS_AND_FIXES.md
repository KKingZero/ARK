# DanglingTree — progress

| Field | Value |
|---|---|
| Machine | DanglingTree (HTB #936, Medium Windows) |
| Target | `10.129.87.77` |
| Domain | `danglingtree.htb` / `dc.danglingtree.htb` |
| Status | **Solved — user + root 2026-08-15** |
| Report | `reports/htb-danglingtree/PENTEST_REPORT.md` |

Previous spawn `10.129.8.47` was fully filtered (free VPN vs Season/VIP). This session used a reachable instance.

## Flags

- user.txt `C:\Users\noah.b\Desktop\user.txt` = `0a5a7cb438fe02cc51ff0241a68a708d`
- root.txt `C:\Users\Administrator\Desktop\root.txt` = `7fe49300cabb212e81a459a18fb6112c`

## Blocker resolved

`alex.o` was **not** in the mailbox dump. Password is Noah's Credential Manager / DPAPI secret `SunsetMountainPeak@2025` (confirmed SMB bind this spawn). Then:

1. `net rpc password jake.h` as alex.o (avoid passwords containing `Jake`)
2. Recreate CA-published missing template `VPNUserTemplate` as ESC1
3. Owner GenericAll → certipy req Administrator SAN+SID
4. faketime +7h PKINIT UnPAC → Admin NT `8cacb3a97e460c65d105ca7cd9913925`

## ARK

Teamserver up (`ark teamserver`). At the time of this eng, `serve` died on stdin close and ADCS / ForceChangePassword / PKINIT were gaps (report §7).

**Later (2026-09):** `ark serve` EOF no longer stops C2. Host `ark ad password`, `ark adcs` dangling ESC1 template+req, and `ark rbcd` shipped. Native PKINIT UnPAC is still not assembled.
