#ifndef ARK_MOD_UTIL_H
#define ARK_MOD_UTIL_H

#include <stddef.h>
#include <stdint.h>

int ark_mod_run_cmd(const char *cmdline, char **stdout_out, char **stderr_out, int32_t *exit_code);
uint32_t ark_mod_find_pid(const char *name);
void ark_mod_domain_to_base_dn(const char *domain, char *out, size_t out_cap);

#endif