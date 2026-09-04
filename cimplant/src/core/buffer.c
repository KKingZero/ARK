#include <stdlib.h>
#include <string.h>

#include "ark/buffer.h"

int ark_buf_init(ark_buf *b, size_t initial_cap) {
    b->data = (uint8_t *)malloc(initial_cap ? initial_cap : 256);
    if (!b->data) return 0;
    b->len = 0;
    b->cap = initial_cap ? initial_cap : 256;
    return 1;
}

void ark_buf_free(ark_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

int ark_buf_reserve(ark_buf *b, size_t need) {
    if (need <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < need) ncap *= 2;
    uint8_t *p = (uint8_t *)realloc(b->data, ncap);
    if (!p) return 0;
    b->data = p;
    b->cap = ncap;
    return 1;
}

int ark_buf_append(ark_buf *b, const void *data, size_t len) {
    if (!ark_buf_reserve(b, b->len + len)) return 0;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 1;
}

void ark_buf_reset(ark_buf *b) {
    b->len = 0;
}