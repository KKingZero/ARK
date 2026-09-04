# Sprint E — ADCS dangling-template MVP

| Field | Value |
| --- | --- |
| **Status** | Partial (2026-09) — template create / grant / WCCE req / auto shipped as `ark adcs`. Native PKINIT UnPAC **not** assembled. |
| **Goal** | Recreate a **CA-published missing template** as ESC1, enroll, PKINIT UnPAC — without a full Certipy clone |
| **Depends on** | Host LDAP (`ark ldap dangling` / `ark adcs dangling` shipped), `kerberos with-skew` |

Sprint B still **excludes** full ADCS (ESC2–11, web enroll, golden cert). This sprint is only the dangling-name path.

## MVP

1. Create schema-v1 template whose **cn equals a dangling published name** (ESS + Client Auth). Do not copy the `User` SD. **Shipped:** `ark adcs template create`.
2. Grant Enroll/GenericAll to the creator (owner WriteDACL). **Shipped:** `ark adcs template grant` / `auto`.
3. Request cert with UPN + object SID. **Shipped:** `ark adcs req`. PKINIT UnPAC → NT hash: **`ark kerberos pkinit` still errors** (`PA-PK-AS-REQ not assembled`). Last hop stays Certipy.
4. Cleanup: delete template we created. **Shipped:** `ark adcs template delete`.

Approval: **critical**. Host-side first. Replay: DanglingTree from `jake.h` after password reset.

See `docs/AD_ENGAGEMENT.md` § dangling templates and `reports/htb-danglingtree/`.
