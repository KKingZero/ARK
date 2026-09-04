#include <stdlib.h>
#include <string.h>

#include "ark/krb5_internal.h"

/* ---- writer ---- */

int ark_der_init(ark_der_buf *b, size_t cap) {
    if (!cap) cap = 256;
    b->data = (uint8_t *)malloc(cap);
    if (!b->data) return 0;
    b->len = 0;
    b->cap = cap;
    return 1;
}

void ark_der_free(ark_der_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int der_grow(ark_der_buf *b, size_t need) {
    if (need <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < need) ncap *= 2;
    uint8_t *p = (uint8_t *)realloc(b->data, ncap);
    if (!p) return 0;
    b->data = p;
    b->cap = ncap;
    return 1;
}

int ark_der_append(ark_der_buf *b, const uint8_t *p, size_t n) {
    if (!der_grow(b, b->len + n)) return 0;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 1;
}

int ark_der_append_byte(ark_der_buf *b, uint8_t v) {
    return ark_der_append(b, &v, 1);
}

static int der_len_bytes(size_t len, uint8_t *out, size_t *out_n) {
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        *out_n = 1;
        return 1;
    }
    if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        *out_n = 2;
        return 1;
    }
    if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)((len >> 8) & 0xFF);
        out[2] = (uint8_t)(len & 0xFF);
        *out_n = 3;
        return 1;
    }
    out[0] = 0x83;
    out[1] = (uint8_t)((len >> 16) & 0xFF);
    out[2] = (uint8_t)((len >> 8) & 0xFF);
    out[3] = (uint8_t)(len & 0xFF);
    *out_n = 4;
    return 1;
}

int ark_der_put_tl(ark_der_buf *b, uint8_t tag, const uint8_t *val, size_t n) {
    uint8_t lb[8];
    size_t ln = 0;
    if (!der_len_bytes(n, lb, &ln)) return 0;
    if (!ark_der_append_byte(b, tag)) return 0;
    if (!ark_der_append(b, lb, ln)) return 0;
    return ark_der_append(b, val, n);
}

int ark_der_put_int(ark_der_buf *b, uint8_t tag, int32_t v) {
    uint8_t tmp[5];
    size_t n = 0;
    uint32_t u = (uint32_t)v;
    /* Minimal signed encoding */
    if (v >= 0) {
        if (u <= 0x7F) {
            tmp[0] = (uint8_t)u;
            n = 1;
        } else if (u <= 0x7FFF) {
            tmp[0] = (uint8_t)((u >> 8) & 0xFF);
            tmp[1] = (uint8_t)(u & 0xFF);
            n = 2;
        } else if (u <= 0x7FFFFF) {
            tmp[0] = (uint8_t)((u >> 16) & 0xFF);
            tmp[1] = (uint8_t)((u >> 8) & 0xFF);
            tmp[2] = (uint8_t)(u & 0xFF);
            n = 3;
        } else {
            tmp[0] = (uint8_t)((u >> 24) & 0xFF);
            tmp[1] = (uint8_t)((u >> 16) & 0xFF);
            tmp[2] = (uint8_t)((u >> 8) & 0xFF);
            tmp[3] = (uint8_t)(u & 0xFF);
            n = 4;
            if (tmp[0] & 0x80) {
                /* need leading 0x00 for positive */
                memmove(tmp + 1, tmp, 4);
                tmp[0] = 0x00;
                n = 5;
            }
        }
        if (n == 1 && (tmp[0] & 0x80)) {
            tmp[1] = tmp[0];
            tmp[0] = 0x00;
            n = 2;
        } else if (n == 2 && (tmp[0] & 0x80)) {
            memmove(tmp + 1, tmp, 2);
            tmp[0] = 0x00;
            n = 3;
        } else if (n == 3 && (tmp[0] & 0x80)) {
            memmove(tmp + 1, tmp, 3);
            tmp[0] = 0x00;
            n = 4;
        }
    } else {
        /* negative — encode as two's complement minimal */
        int32_t x = v;
        tmp[0] = (uint8_t)((x >> 24) & 0xFF);
        tmp[1] = (uint8_t)((x >> 16) & 0xFF);
        tmp[2] = (uint8_t)((x >> 8) & 0xFF);
        tmp[3] = (uint8_t)(x & 0xFF);
        n = 4;
        while (n > 1 && ((tmp[0] == 0xFF && (tmp[1] & 0x80)) || (tmp[0] == 0x00 && !(tmp[1] & 0x80)))) {
            memmove(tmp, tmp + 1, n - 1);
            n--;
        }
    }
    return ark_der_put_tl(b, tag, tmp, n);
}

int ark_der_put_general_string(ark_der_buf *b, uint8_t tag, const char *s) {
    if (!s) s = "";
    return ark_der_put_tl(b, tag, (const uint8_t *)s, strlen(s));
}

int ark_der_put_octet(ark_der_buf *b, uint8_t tag, const uint8_t *p, size_t n) {
    return ark_der_put_tl(b, tag, p, n);
}

int ark_der_put_bitstring_unused0(ark_der_buf *b, uint8_t tag, const uint8_t *bits, size_t nbytes) {
    ark_der_buf inner;
    if (!ark_der_init(&inner, nbytes + 1)) return 0;
    if (!ark_der_append_byte(&inner, 0)) { ark_der_free(&inner); return 0; }
    if (!ark_der_append(&inner, bits, nbytes)) { ark_der_free(&inner); return 0; }
    int ok = ark_der_put_tl(b, tag, inner.data, inner.len);
    ark_der_free(&inner);
    return ok;
}

/* Context-specific constructed: [n] IMPLICIT SEQUENCE content */
int ark_der_put_ctx_seq(ark_der_buf *b, uint8_t ctx_num, const uint8_t *seq_content, size_t n) {
    uint8_t tag = (uint8_t)(0xA0 | (ctx_num & 0x1F));
    return ark_der_put_tl(b, tag, seq_content, n);
}

int ark_der_put_seq(ark_der_buf *b, const uint8_t *content, size_t n) {
    return ark_der_put_tl(b, 0x30, content, n);
}

int ark_der_put_app(ark_der_buf *b, uint8_t app_num, const uint8_t *content, size_t n) {
    uint8_t tag = (uint8_t)(0x60 | (app_num & 0x1F)); /* constructed application */
    return ark_der_put_tl(b, tag, content, n);
}

/* ---- reader ---- */

void ark_der_r_init(ark_der_reader *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

static int der_read_len(ark_der_reader *r, size_t *out) {
    if (r->pos >= r->len) return 0;
    uint8_t b = r->data[r->pos++];
    if ((b & 0x80) == 0) {
        *out = b;
        return 1;
    }
    size_t n = b & 0x7F;
    if (n == 0 || n > 4 || r->pos + n > r->len) return 0;
    size_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | r->data[r->pos++];
    *out = v;
    return 1;
}

int ark_der_r_tag_len(ark_der_reader *r, uint8_t *tag, const uint8_t **val, size_t *vlen) {
    if (r->pos >= r->len) return 0;
    *tag = r->data[r->pos++];
    size_t ln = 0;
    if (!der_read_len(r, &ln)) return 0;
    if (r->pos + ln > r->len) return 0;
    *val = r->data + r->pos;
    *vlen = ln;
    r->pos += ln;
    return 1;
}

int ark_der_r_expect(ark_der_reader *r, uint8_t want_tag, const uint8_t **val, size_t *vlen) {
    uint8_t tag;
    if (!ark_der_r_tag_len(r, &tag, val, vlen)) return 0;
    return tag == want_tag;
}

int ark_der_r_int(const uint8_t *val, size_t n, int32_t *out) {
    if (n == 0 || n > 4) return 0;
    int32_t v = (val[0] & 0x80) ? -1 : 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | val[i];
    *out = v;
    return 1;
}

int ark_der_r_find_ctx(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
    uint8_t *out_tag, const uint8_t **val, size_t *vlen) {
    ark_der_reader r;
    ark_der_r_init(&r, seq, seq_len);
    uint8_t want = (uint8_t)(0xA0 | (ctx_num & 0x1F));
    uint8_t want_prim = (uint8_t)(0x80 | (ctx_num & 0x1F));
    while (r.pos < r.len) {
        uint8_t tag;
        const uint8_t *v;
        size_t vn;
        if (!ark_der_r_tag_len(&r, &tag, &v, &vn)) return 0;
        if (tag == want || tag == want_prim) {
            if (out_tag) *out_tag = tag;
            *val = v;
            *vlen = vn;
            return 1;
        }
    }
    return 0;
}

/* Unwrap [n] that contains a single universal element (INTEGER/OCTET/etc). */
int ark_der_r_ctx_inner(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
    uint8_t want_inner_tag, const uint8_t **val, size_t *vlen) {
    const uint8_t *ctx_val;
    size_t ctx_len;
    uint8_t t;
    if (!ark_der_r_find_ctx(seq, seq_len, ctx_num, &t, &ctx_val, &ctx_len)) return 0;
    /* Constructed context: content is the inner TLV */
    if (t & 0x20) {
        ark_der_reader r;
        ark_der_r_init(&r, ctx_val, ctx_len);
        uint8_t itag;
        if (!ark_der_r_tag_len(&r, &itag, val, vlen)) return 0;
        return itag == want_inner_tag;
    }
    /* Primitive context: content is raw value */
    if (want_inner_tag == 0x04 || want_inner_tag == 0x1B || want_inner_tag == 0x1E) {
        *val = ctx_val;
        *vlen = ctx_len;
        return 1;
    }
    if (want_inner_tag == 0x02) {
        *val = ctx_val;
        *vlen = ctx_len;
        return 1;
    }
    return 0;
}

int ark_der_r_ctx_int(const uint8_t *seq, size_t seq_len, uint8_t ctx_num, int32_t *out) {
    const uint8_t *v;
    size_t n;
    if (!ark_der_r_ctx_inner(seq, seq_len, ctx_num, 0x02, &v, &n)) return 0;
    return ark_der_r_int(v, n, out);
}

int ark_der_r_ctx_octet(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
    const uint8_t **val, size_t *vlen) {
    return ark_der_r_ctx_inner(seq, seq_len, ctx_num, 0x04, val, vlen);
}
