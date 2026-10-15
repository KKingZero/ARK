# Next slice — proof, holes, three host verbs

Sprint G stays the eng track: one Easy or Medium AD lab whose critical path runs in ARK, then Golden Demo 5/5 Auto on a C session. This note is the code that has to land before that eng. Live proof is not a merge gate.

## Already in the tree (audit, no new code)

- Inbound `drop`, `httpdrop`, and the firewalld mismatch line. When SSH is filtered, use `ark inbound httpdrop --listen`.
- dMSA / badSuccessor: `ark ad dmsa create|enroll-self|delete` and `ark kerberos s4u --dmsa` (AS-REQ as the attacker, PA-S4U-X509-USER as `dmsa$`, previous-keys from KERB-DMSA-KEY-PACKAGE). AES only.

## This slice

| Item | What landed |
| --- | --- |
| Linux C glibc | `-include` forces `__GLIBC_USE_C23_STRTOL` off. `cimplant/scripts/check_glibc.py` fails the link if any symbol needs glibc above 2.35. |
| Register failure | Linux HTTPS prints `curl=` and `http=` on the existing register error line. |
| `ark op` | The one-shot client approves the single matching in-flight task with the approver seat. The operator REPL does not. Agent Auto stays human dual-seat. |
| Data dir | Always `~/.ark`. Copy a legacy `~/.erebus` once. Do not clobber an `~/.ark` that already has `server.yaml`, `certs/`, or `ark.db`. Do not delete `~/.erebus`. `ARK_HOME` / `EREBUS_HOME` skip the copy. |
| `ark smb --kerberos` | Password AES TGT, or NT-hash overpass, then the existing native cifs dial. `--ticket` wins. |
| `ark psexec` | Host verb. Upload to `ADMIN$\NAME.exe`, then MS-SCMR CreateService + Start. NTLM or `--kerberos`. Does not delete the service. The Go and C implants are unchanged. |

Linux C still has no Kerberos stack. After a C session, host ldap / kerberos / smb / psexec go through `ark inbound through`.

## Out

Zig, sleep mask, ETW/AMSI, malleable C2, ESC2–11, LLM OAuth, more Go Windows modules, per-box web RCE helpers, host DPAPI.

## After the code

1. Operator picks the next Easy/Medium HTB AD box and drives it with ark-htb.
2. Report table: every critical-path step is ARK or external.
3. Then Golden Demo 5/5 Auto on a domain-joined Windows C host. A human approves agent tasks.
