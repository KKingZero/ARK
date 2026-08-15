# Sprint E — ADCS dangling-template MVP

| Field | Value |
| --- | --- |
| **Status** | Planned (scoped by DanglingTree 2026-08-15) |
| **Goal** | Recreate a **CA-published missing template** as ESC1, enroll, PKINIT UnPAC — without a full Certipy clone |
| **Depends on** | Host LDAP (`erebus ldap dangling` shipped), `kerberos with-skew` (P1) |

Sprint B still **excludes** full ADCS (ESC2–11, web enroll, golden cert). This sprint is only the dangling-name path.

## MVP

1. Create schema-v1 template whose **cn equals a dangling published name** (ESS + Client Auth). Do not copy the `User` SD.
2. Grant Enroll/GenericAll to the creator (owner WriteDACL).
3. Request cert with UPN + object SID; PKINIT UnPAC → NT hash (under clock skew apply).
4. Cleanup: delete template we created.

Approval: **critical**. Host-side first. Replay: DanglingTree from `jake.h` after password reset.

See `docs/AD_ENGAGEMENT.md` § dangling templates and `reports/htb-danglingtree/`.
