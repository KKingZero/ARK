# Garfield (10.129.244.207) — COMPLETE

## Target
- DC01.garfield.htb / GARFIELD + RODC01 (192.168.100.2)
- Win Server 2019, +8h clock skew
- Ports: 53,88,135,139,389,445,636,3268,3389,5985,9389

## Flags
| Flag | Value |
|------|-------|
| user | `5bfd6dd3d4d26dbecbf1631beb51fe2d` |
| root | `5113c5cac5934e412073ed88a9b810fa` |

## Creds / keys
| Account | Secret | Source |
|---------|--------|--------|
| j.arbuckle | `Th1sD4mnC4t!@1978` | starting |
| l.wilson_adm | `LizAdm_P@ss1!` | ForceChangePassword |
| ATTACK2$ | `Attack2Pass123!` | MAQ create |
| krbtgt_8245 AES256 | `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240` | mimikatz on RODC |
| krbtgt_8245 NTLM | `445aa4221e751da37a10241d962780e2` | mimikatz on RODC |
| RODC01$ NTLM | `0a3f810964bb5e1f0e52245f73700172` | mimikatz on RODC |
| Administrator NTLM | `EE238F6DEBC752010428F20875B092D5` | KeyList |

## Attack chain
1. Soft recon as j.arbuckle → scriptPath write on l.wilson + SYSVOL scripts write
2. Logon script hijack → shell as l.wilson → ForceChangePassword on l.wilson_adm
3. WinRM as l.wilson_adm → user flag; AddSelf RODC Administrators
4. ATTACK2$ + RBCD on RODC01 → S4U2Proxy Administrator host/cifs
5. schtasks SYSTEM on RODC → dump krbtgt_8245 AES256
6. Clear msDS-NeverRevealGroup; add Admin/Domain Users to RevealOnDemand
7. **Rubeus v2.3.3** `golden /rodcNumber:8245` + `asktgs /keyList` → Admin NTLM
8. PTH wmiexec → root.txt

## Critical notes
- Clock skew +8h — use faketime or sync clock for Kerberos
- WinRM `/ptt` fails with LSA error 1312 — use `/createnetonly` with separate cifs then host tickets
- Rubeus **v2.2.0 lacks** `/rodcNumber` + `/keyList` — need **v2.3.3+** (Flangvik SharpCollection works)
- Impacket keylistattack returned TGT_REVOKED even with open PRP; Rubeus keyList succeeded
- RODC at 192.168.100.2 only reachable via pivot (DC01); chisel reverse flaky on some ports

## ARK gaps this eng
| Gap | Workaround | Wanted |
| --- | --- | --- |
| No RBCD helpers | rbcd.py + getST.py | implant/operator RBCD |
| No RODC KeyList | Rubeus 2.3.3 keyList | Kerberos KeyList module |
| No AES TGT/ticket forge | Rubeus/impacket | AES ticket support |
| WinRM PTH seal issues | pypsrp password path | fix hash-path message seal |
| Clock skew handling | libfaketime | operator clock check |

## Workdir
`~/htb-win-10.129.244.207/`
