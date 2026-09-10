# Sprint G — live proof (Track G locked)

| Field | Value |
| --- | --- |
| **Status** | Locked 2026-09-09 |
| **Track G** | Host AD brain + agent catalog. C implant is the drop, not a new AD stack. |
| **Goal** | One Easy/Medium AD lab where the **critical path runs in ARK** |
| **Code** | No new features unless a live miss is a one-file fail-closed fix |
| **Out** | Zig, sleep mask, ETW/AMSI, malleable C2, ESC2–11, LLM OAuth, Go Windows growth |

Cookbook: `docs/AD_ENGAGEMENT.md`. Inbound: `docs/OPERATOR_INBOUND.md`. Scorecard: `docs/private/reports/ARK_HTB_CORPUS_SCORECARD.md`.

## Gates

| Gate | Pass |
| --- | --- |
| G0 | `ark teamserver` + `ark certs seats` + C implant check-in (`generate --language c`) |
| G1 | Soft recon in ARK: `smb` **or** `ldap enum --type interesting` |
| G2 | One host write or ticket the box actually needs (password / add-computer / rbcd / asktgt / pkinit / …) |
| G3 | C session: `shell whoami` + `socks start` **or** `lateral winrm` |
| G4 | Agent Plan names the G2 verb; Auto does not DA-abuse unless the objective says so |
| G5 | Report table: every critical-path step is `ARK` or `external` |

G2 is box-dependent. Do not force RBCD on a box that has none.

## Order

1. Host-first if 445/389 reachable (`smb` → `ldap interesting` → `acl` → the write the ACL gives).
2. C implant after first shell. SOCKS + `ARK_PROXY` if the operator host cannot hit the DC.
3. Agent Plan (Auto only if Plan is accurate). Dual-seat: approval text must show `dc=` / `target=` / `to=`.
4. `docs/private/reports/htb-<box>/` + scorecard. Impacket/Certipy only after the miss is written down.

## Anti-patterns

- Impacket first, ARK for screenshots
- Porting `pkg/krb` into C
- Claiming SAMR/PKINIT/PRP lab-green without a table row
- `/usr/bin/ark` (KDE archive manager) — `~/.local/bin` first
