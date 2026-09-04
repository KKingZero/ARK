#ifndef ARK_KRB5_INTERNAL_H
#define ARK_KRB5_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ark/krb5.h"

/* ---- DER ---- */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ark_der_buf;

typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} ark_der_reader;

int  ark_der_init(ark_der_buf *b, size_t cap);
void ark_der_free(ark_der_buf *b);
int  ark_der_append(ark_der_buf *b, const uint8_t *p, size_t n);
int  ark_der_append_byte(ark_der_buf *b, uint8_t v);
/* tag + length + value (raw content, not including tag/len). */
int  ark_der_put_tl(ark_der_buf *b, uint8_t tag, const uint8_t *val, size_t n);
int  ark_der_put_int(ark_der_buf *b, uint8_t tag, int32_t v);
int  ark_der_put_general_string(ark_der_buf *b, uint8_t tag, const char *s);
int  ark_der_put_octet(ark_der_buf *b, uint8_t tag, const uint8_t *p, size_t n);
int  ark_der_put_bitstring_unused0(ark_der_buf *b, uint8_t tag, const uint8_t *bits, size_t nbytes);
int  ark_der_put_ctx_seq(ark_der_buf *b, uint8_t ctx_num, const uint8_t *seq_content, size_t n);
int  ark_der_put_seq(ark_der_buf *b, const uint8_t *content, size_t n);
int  ark_der_put_app(ark_der_buf *b, uint8_t app_num, const uint8_t *content, size_t n);

void ark_der_r_init(ark_der_reader *r, const uint8_t *data, size_t len);
int  ark_der_r_tag_len(ark_der_reader *r, uint8_t *tag, const uint8_t **val, size_t *vlen);
int  ark_der_r_expect(ark_der_reader *r, uint8_t want_tag, const uint8_t **val, size_t *vlen);
int  ark_der_r_int(const uint8_t *val, size_t n, int32_t *out);
int  ark_der_r_find_ctx(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        uint8_t *out_tag, const uint8_t **val, size_t *vlen);
int  ark_der_r_ctx_inner(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        uint8_t want_inner_tag, const uint8_t **val, size_t *vlen);
int  ark_der_r_ctx_int(const uint8_t *seq, size_t seq_len, uint8_t ctx_num, int32_t *out);
int  ark_der_r_ctx_octet(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        const uint8_t **val, size_t *vlen);

/* ---- crypto (RC4-HMAC etype 23) ---- */
void ark_md4(const uint8_t *msg, size_t msg_len, uint8_t out[16]);
int  ark_nt_hash(const char *password_utf8, uint8_t out[16]);
int  ark_rc4_hmac_encrypt(const uint8_t key[16], int32_t usage,
        const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len);
int  ark_rc4_hmac_decrypt(const uint8_t key[16], int32_t usage,
        const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len);
int  ark_krb_random(uint8_t *buf, size_t n);

/* ---- crypto (AES128/256-CTS-HMAC-SHA1-96 etype 17/18) ---- */
int ark_aes_string_to_key(int etype, const char *password, const char *realm, const char *user,
        uint8_t *key_out, size_t *key_len_out);
int ark_aes_cts_hmac_encrypt(const uint8_t *key, size_t key_len, int32_t usage,
        const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len);
int ark_aes_cts_hmac_decrypt(const uint8_t *key, size_t key_len, int32_t usage,
        const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len);

/* ---- ticket blob ---- */
typedef struct {
    int32_t  etype;
    uint8_t *cipher;
    size_t   cipher_len;
    uint8_t *ticket_der; /* full Ticket APPLICATION 1 for reuse in AP-REQ */
    size_t   ticket_der_len;
} ark_krb_enc_data;

typedef struct {
    uint8_t session_key[32];
    size_t  session_key_len;
    int32_t session_etype;
    ark_krb_enc_data tgt; /* TGT ticket */
} ark_krb_creds;

void ark_krb_enc_data_free(ark_krb_enc_data *e);
void ark_krb_creds_free(ark_krb_creds *c);

/* ---- wire ---- */
int ark_krb_tcp_exchange(const char *host, uint16_t port,
    const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);

int ark_krb_as_req(const char *dc, const char *realm, const char *user, const char *password,
    ark_krb_creds *out_creds);

int ark_krb_tgs_req(const char *dc, const char *realm, const char *spn,
    const ark_krb_creds *creds, ark_krb_enc_data *out_service_ticket);

#endif
