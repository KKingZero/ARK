#ifndef ARK_LINUX_POSTEX_H
#define ARK_LINUX_POSTEX_H

#include <stddef.h>

#include "ark/pb_modules.h"

#define ARK_LINUX_CRED_MAX 64

const char *ark_linux_home(void);
void ark_linux_redact_secrets(char *s);

int ark_linux_creds_collect(const char *method, const char *home,
    ark_credential *out, size_t cap, size_t *n);

int ark_linux_payload_allowed(const char *path);

int ark_linux_persist_apply(const ark_persist_config *cfg, const char *home,
    char *details, size_t details_cap);

int ark_linux_privesc_enum(char *out, size_t out_cap);

#endif
