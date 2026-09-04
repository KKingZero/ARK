#ifndef ARK_BUFFER_H
#define ARK_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct ark_buf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ark_buf;

int  ark_buf_init(ark_buf *b, size_t initial_cap);
void ark_buf_free(ark_buf *b);
int  ark_buf_append(ark_buf *b, const void *data, size_t len);
int  ark_buf_reserve(ark_buf *b, size_t need);
void ark_buf_reset(ark_buf *b);

#endif