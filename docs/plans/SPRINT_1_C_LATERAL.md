# Sprint 1 — C implant primary + lateral vertical

| Field | Value |
| --- | --- |
| **Status** | Planned (after / overlapping late Sprint 0 Golden Demo) |
| **Goal** | C is the Windows engagement implant; ≥1 real lateral beyond stub-class |
| **Metric** | Golden Demo path already on C (Sprint 0); then lateral vertical depth |
| **Sources** | `docs/IMPLANT_ROADMAP.md` §13 Sprint 1, `docs/C_IMPLANT_LAB_CHECKLIST.md` §5 |
| **Depends on** | Sprint 0B real Kerberoast (implementation done; lab-verify open) |

## Exit criteria

| # | Criterion |
| --- | --- |
| 1A | No fake success stubs for Kerberoast / lateral — real or clear fail |
| 1B | **WinRM** password + PTH (parity notes vs Go / pypsrp) |
| 1C | **PsExec** stage + service start (password; hash → document use WinRM PTH) |
| 1D | **WMI** prefer COM over `wmic.exe` |
| 1E | **DCOM** MMC20 after 1B–1D |
| 1F | Smoke: register → beacon → shell → file → one lateral on lab Windows |
| 1G | Default Windows generate language remains **c**; docs match |

## Implementation order (locked)

```text
1. WinRM (password + PTH)     ← first
2. PsExec (password + payload)
3. WMI COM
4. DCOM MMC20
```

## Work packages

| ID | Work | Paths | Notes |
| --- | --- | --- | --- |
| **1.1** | WinRM quality + clearer errors + host tests | `cimplant/src/modules/lateral_winrm.c`, `ntlm_pth.c` | Live eng-verify still required |
| **1.2** | PsExec end-to-end cleanup / honest partial | `lateral_psexec.c` | Hash-only via WNet not supported |
| **1.3** | WMI COM path | `lateral_wmi_dcom.c` | Reduce shell noise |
| **1.4** | DCOM MMC20 | same | After WMI stable |
| **1.5** | TLS pin / CA verify docs + smoke checklist | Makefile, lab checklist | Already fail-closed |
| **1.6** | Lab sign-off matrix | `docs/C_IMPLANT_LAB_CHECKLIST.md` | Fill GOAD/HTB boxes |

## Out of scope

- Zig implant  
- Expanding Go Windows modules as product path  
- Full Linux post-ex inside C  
- Message encryption for Go PTH (tracked under A.1 follow-up; separate from C WSMan)

## Acceptance demo

```text
1. make implant-c + CA pin → session
2. shell whoami
3. kerberoast (Sprint 0) → real $krb5tgs$
4. lateral winrm <host> whoami --pass …
5. lateral winrm … --hash … (if lab allows unencrypted or C seals)
6. Optional: PsExec with payload bytes
```

## Risks

| Risk | Mitigation |
| --- | --- |
| WinRM library / encryption on hardened hosts | Clear errors; password vs PTH matrix in checklist |
| No Windows CI | Host unit tests + mandatory GOAD checklist |
| Scope into inject/evasion | Stop after lateral vertical |

## Definition of done

- [ ] M1: Windows default language = C (already) + docs honest  
- [ ] M2: ≥1 real lateral proven in lab on C  
- [ ] Checklist §5 filled for WinRM at minimum  
- [ ] No placeholder lateral “success” paths  

## Relationship to Sprint B

| Sprint B (Go engagement modules) | Sprint 1 (C implant) |
| --- | --- |
| Kerberos AES, shadow, tickets, ACL enum for operator path | Lateral execution surface on Windows PE |
| Can run **in parallel** after Sprint 0 | Prefer WinRM on C before claiming “C-only eng” |

Do not block Sprint B coding on full C DCOM.
