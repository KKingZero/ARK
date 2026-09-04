#include <stdlib.h>
#include <string.h>

#include "ark/pb_modules.h"
#include "ark/pb_wire.h"

static int decode_string_field(ark_pb_reader *r, uint8_t wire, char *dst, size_t cap) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !ark_pb_read_bytes(r, &b, &n)) return 0;
    ark_pb_copy_bytes(dst, cap, b, n);
    return 1;
}

static int decode_bytes_field(ark_pb_reader *r, uint8_t wire, uint8_t **out, size_t *out_len) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !ark_pb_read_bytes(r, &b, &n)) return 0;
    *out = (uint8_t *)malloc(n);
    if (!*out) return 0;
    memcpy(*out, b, n);
    *out_len = n;
    return 1;
}

static int decode_uint32_field(ark_pb_reader *r, uint8_t wire, uint32_t *out) {
    uint64_t v;
    if (wire != 0 || !ark_pb_read_varint(r, &v)) return 0;
    *out = (uint32_t)v;
    return 1;
}

int ark_pb_decode_module_task(const uint8_t *in, size_t in_len, ark_module_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, t->module_name, sizeof(t->module_name)); break;
        case 2: decode_bytes_field(&r, wire, &t->config, &t->config_len); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return t->module_name[0] != '\0';
}

void ark_pb_free_module_task(ark_module_task *t) {
    free(t->config);
    t->config = NULL;
    t->config_len = 0;
}

int ark_pb_decode_cloud_harvest_config(const uint8_t *in, size_t in_len, ark_cloud_harvest_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->provider, sizeof(c->provider)); break;
        case 2: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int ark_pb_decode_cred_dump_config(const uint8_t *in, size_t in_len, ark_cred_dump_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_uint32_field(&r, wire, &c->target_pid); break;
        case 3: decode_string_field(&r, wire, c->output_format, sizeof(c->output_format)); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int ark_pb_decode_persist_config(const uint8_t *in, size_t in_len, ark_persist_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_string_field(&r, wire, c->name, sizeof(c->name)); break;
        case 3: decode_string_field(&r, wire, c->payload_path, sizeof(c->payload_path)); break;
        case 4: decode_string_field(&r, wire, c->trigger, sizeof(c->trigger)); break;
        case 5: decode_bytes_field(&r, wire, &c->payload, &c->payload_len); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void ark_pb_free_persist_config(ark_persist_config *c) {
    free(c->payload);
    c->payload = NULL;
    c->payload_len = 0;
}

int ark_pb_decode_privesc_config(const uint8_t *in, size_t in_len, ark_privesc_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_uint32_field(&r, wire, &c->target_pid); break;
        case 3: decode_string_field(&r, wire, c->command, sizeof(c->command)); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int ark_pb_decode_lateral_config(const uint8_t *in, size_t in_len, ark_lateral_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_string_field(&r, wire, c->target, sizeof(c->target)); break;
        case 3: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 4: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 5: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 6: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 7: decode_bytes_field(&r, wire, &c->ticket, &c->ticket_len); break;
        case 8: decode_string_field(&r, wire, c->command, sizeof(c->command)); break;
        case 9: decode_bytes_field(&r, wire, &c->payload, &c->payload_len); break;
        case 10: decode_string_field(&r, wire, c->service_name, sizeof(c->service_name)); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void ark_pb_free_lateral_config(ark_lateral_config *c) {
    free(c->ticket);
    free(c->payload);
    c->ticket = NULL;
    c->payload = NULL;
    c->ticket_len = c->payload_len = 0;
}

int ark_pb_decode_ldap_enum_config(const uint8_t *in, size_t in_len, ark_ldap_enum_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 4: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 5: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 6: decode_string_field(&r, wire, c->query_type, sizeof(c->query_type)); break;
        case 7: decode_string_field(&r, wire, c->custom_filter, sizeof(c->custom_filter)); break;
        case 8:
            if (wire == 2 && c->attribute_count < ARK_LDAP_ATTR_MAX) {
                const uint8_t *b;
                size_t n;
                if (ark_pb_read_bytes(&r, &b, &n)) {
                    char *attr = (char *)malloc(n + 1);
                    if (!attr) return 0;
                    memcpy(attr, b, n);
                    attr[n] = '\0';
                    c->attributes[c->attribute_count++] = attr;
                }
            }
            break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void ark_pb_free_ldap_enum_config(ark_ldap_enum_config *c) {
    for (size_t i = 0; i < c->attribute_count; i++) free(c->attributes[i]);
    c->attribute_count = 0;
}

int ark_pb_decode_kerberoast_config(const uint8_t *in, size_t in_len, ark_kerberoast_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 4: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 5: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 6:
            if (wire == 2 && c->target_spn_count < 64) {
                const uint8_t *b;
                size_t n;
                if (ark_pb_read_bytes(&r, &b, &n)) {
                    char *spn = (char *)malloc(n + 1);
                    if (!spn) return 0;
                    memcpy(spn, b, n);
                    spn[n] = '\0';
                    c->target_spns[c->target_spn_count++] = spn;
                }
            }
            break;
        case 7: decode_string_field(&r, wire, c->encryption, sizeof(c->encryption)); break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void ark_pb_free_kerberoast_config(ark_kerberoast_config *c) {
    for (size_t i = 0; i < c->target_spn_count; i++) free(c->target_spns[i]);
    c->target_spn_count = 0;
}

int ark_pb_decode_asreproast_config(const uint8_t *in, size_t in_len, ark_asreproast_config *c) {
    memset(c, 0, sizeof(*c));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3:
            if (wire == 2 && c->target_user_count < 256) {
                const uint8_t *b;
                size_t n;
                if (ark_pb_read_bytes(&r, &b, &n)) {
                    char *u = (char *)malloc(n + 1);
                    if (!u) return 0;
                    memcpy(u, b, n);
                    u[n] = '\0';
                    c->target_users[c->target_user_count++] = u;
                }
            }
            break;
        default: ark_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void ark_pb_free_asreproast_config(ark_asreproast_config *c) {
    for (size_t i = 0; i < c->target_user_count; i++) free(c->target_users[i]);
    c->target_user_count = 0;
}

int ark_pb_encode_persist_result(int success, const char *method, const char *details, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 128)) return 0;
    ark_pb_write_bool(&w, 1, success);
    if (method) ark_pb_write_string(&w, 2, method);
    if (details) ark_pb_write_string(&w, 3, details);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_privesc_result(int success, const char *method, const char *new_integrity, uint32_t new_pid, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 128)) return 0;
    ark_pb_write_bool(&w, 1, success);
    if (method) ark_pb_write_string(&w, 2, method);
    if (new_integrity) ark_pb_write_string(&w, 3, new_integrity);
    ark_pb_write_uint32(&w, 4, new_pid);
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_credential(const ark_credential *c, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    if (c->type[0]) ark_pb_write_string(&w, 1, c->type);
    if (c->domain[0]) ark_pb_write_string(&w, 2, c->domain);
    if (c->username[0]) ark_pb_write_string(&w, 3, c->username);
    if (c->value[0]) ark_pb_write_string(&w, 4, c->value);
    if (c->source[0]) ark_pb_write_string(&w, 5, c->source);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_cred_dump_result(const char *method, const ark_credential *creds, size_t cred_count, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    if (method) ark_pb_write_string(&w, 1, method);
    for (size_t i = 0; i < cred_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_credential(&creds[i], &sub, &sub_len)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_bytes(&w, 2, sub, sub_len);
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_cloud_token(const ark_cloud_token *t, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    if (t->provider[0]) ark_pb_write_string(&w, 1, t->provider);
    if (t->token_type[0]) ark_pb_write_string(&w, 2, t->token_type);
    if (t->access_token[0]) ark_pb_write_string(&w, 3, t->access_token);
    if (t->refresh_token[0]) ark_pb_write_string(&w, 4, t->refresh_token);
    if (t->tenant_id[0]) ark_pb_write_string(&w, 5, t->tenant_id);
    if (t->client_id[0]) ark_pb_write_string(&w, 6, t->client_id);
    if (t->resource[0]) ark_pb_write_string(&w, 7, t->resource);
    if (t->expires_at) ark_pb_write_int64(&w, 8, t->expires_at);
    if (t->source[0]) ark_pb_write_string(&w, 9, t->source);
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_cloud_credential(const ark_cloud_credential *c, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    if (c->provider[0]) ark_pb_write_string(&w, 1, c->provider);
    if (c->cred_type[0]) ark_pb_write_string(&w, 2, c->cred_type);
    if (c->identity[0]) ark_pb_write_string(&w, 3, c->identity);
    if (c->secret[0]) ark_pb_write_string(&w, 4, c->secret);
    if (c->extra[0]) ark_pb_write_string(&w, 5, c->extra);
    if (c->source[0]) ark_pb_write_string(&w, 6, c->source);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_cloud_harvest_result(const char *provider, const char *method,
    const ark_cloud_token *tokens, size_t token_count,
    const ark_cloud_credential *creds, size_t cred_count,
    const char *metadata, const char *error, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 1024)) return 0;
    if (provider) ark_pb_write_string(&w, 1, provider);
    if (method) ark_pb_write_string(&w, 2, method);
    for (size_t i = 0; i < token_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_cloud_token(&tokens[i], &sub, &sub_len)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_bytes(&w, 3, sub, sub_len);
        free(sub);
    }
    for (size_t i = 0; i < cred_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_cloud_credential(&creds[i], &sub, &sub_len)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_bytes(&w, 4, sub, sub_len);
        free(sub);
    }
    if (metadata) ark_pb_write_string(&w, 5, metadata);
    if (error) ark_pb_write_string(&w, 6, error);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_lateral_result(const char *method, const char *target, int success, const char *output, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    if (method) ark_pb_write_string(&w, 1, method);
    if (target) ark_pb_write_string(&w, 2, target);
    ark_pb_write_bool(&w, 3, success);
    if (output) ark_pb_write_string(&w, 4, output);
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_ldap_entry_msg(const ark_ldap_entry *e, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    if (e->dn[0]) ark_pb_write_string(&w, 1, e->dn);
    for (size_t i = 0; i < e->attr_count; i++) {
        ark_pb_writer mapw;
        if (!ark_pb_writer_init(&mapw, 128)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_string(&mapw, 1, e->attr_names[i]);
        ark_pb_writer valw;
        if (!ark_pb_writer_init(&valw, 64)) { ark_pb_writer_free(&mapw); ark_pb_writer_free(&w); return 0; }
        ark_pb_write_string(&valw, 1, e->attr_values[i]);
        ark_pb_write_bytes(&mapw, 2, valw.data, valw.len);
        ark_pb_writer_free(&valw);
        ark_pb_write_bytes(&w, 2, mapw.data, mapw.len);
        ark_pb_writer_free(&mapw);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_ldap_enum_result(const char *domain, const char *dc, const char *query_type,
    const ark_ldap_entry *entries, size_t entry_count, int32_t total, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 1024)) return 0;
    if (domain) ark_pb_write_string(&w, 1, domain);
    if (dc) ark_pb_write_string(&w, 2, dc);
    if (query_type) ark_pb_write_string(&w, 3, query_type);
    for (size_t i = 0; i < entry_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_ldap_entry_msg(&entries[i], &sub, &sub_len)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_bytes(&w, 4, sub, sub_len);
        free(sub);
    }
    ark_pb_write_uint32(&w, 5, (uint32_t)total);
    return ark_pb_writer_finish(&w, out, out_len);
}

void ark_pb_free_ldap_entries(ark_ldap_entry *entries, size_t count) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < entries[i].attr_count; j++) {
            free(entries[i].attr_names[j]);
            free(entries[i].attr_values[j]);
        }
        entries[i].attr_count = 0;
    }
}

static int encode_kerberoast_hash(const char *spn, const char *sam, const char *hash, const char *enc, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    if (spn) ark_pb_write_string(&w, 1, spn);
    if (sam) ark_pb_write_string(&w, 2, sam);
    if (hash) ark_pb_write_string(&w, 3, hash);
    if (enc) ark_pb_write_string(&w, 4, enc);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_kerberoast_result_multi(const ark_kerberoast_hash *hashes, size_t count,
    uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_kerberoast_hash(hashes[i].spn, hashes[i].sam, hashes[i].hash, hashes[i].enc,
                &sub, &sub_len)) {
            ark_pb_writer_free(&w);
            return 0;
        }
        if (!ark_pb_write_bytes(&w, 1, sub, sub_len)) {
            free(sub);
            ark_pb_writer_free(&w);
            return 0;
        }
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_kerberoast_result(const char *spn, const char *sam, const char *hash, const char *enc, uint8_t **out, size_t *out_len) {
    ark_kerberoast_hash h = { spn, sam, hash, enc };
    return ark_pb_encode_kerberoast_result_multi(&h, 1, out, out_len);
}

int ark_pb_encode_asreproast_result_multi(const ark_asreproast_hash *hashes, size_t count,
    uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    for (size_t i = 0; i < count; i++) {
        size_t mark;
        if (!ark_pb_write_submsg_begin(&w, 1, &mark)) {
            ark_pb_writer_free(&w);
            return 0;
        }
        if (hashes[i].username) ark_pb_write_string(&w, 1, hashes[i].username);
        if (hashes[i].hash) ark_pb_write_string(&w, 2, hashes[i].hash);
        ark_pb_write_submsg_end(&w, mark);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_asreproast_result(const char *username, const char *hash, uint8_t **out, size_t *out_len) {
    ark_asreproast_hash h = { username, hash };
    return ark_pb_encode_asreproast_result_multi(&h, 1, out, out_len);
}