#ifndef ARK_PB_WIRE_H
#define ARK_PB_WIRE_H

#include <stddef.h>
#include <stdint.h>

typedef struct ark_pb_reader {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} ark_pb_reader;

typedef struct ark_pb_writer {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    int      failed;
} ark_pb_writer;

int ark_pb_writer_init(ark_pb_writer *w, size_t cap);
void ark_pb_writer_free(ark_pb_writer *w);
int ark_pb_writer_finish(ark_pb_writer *w, uint8_t **out, size_t *out_len);
int ark_pb_write_tag(ark_pb_writer *w, uint32_t field, uint8_t wire);
int ark_pb_write_varint(ark_pb_writer *w, uint64_t v);
int ark_pb_write_string(ark_pb_writer *w, uint32_t field, const char *s);
int ark_pb_write_bytes(ark_pb_writer *w, uint32_t field, const uint8_t *b, size_t n);
int ark_pb_write_bool(ark_pb_writer *w, uint32_t field, int v);
int ark_pb_write_int64(ark_pb_writer *w, uint32_t field, int64_t v);
int ark_pb_write_uint32(ark_pb_writer *w, uint32_t field, uint32_t v);
int ark_pb_write_submsg_begin(ark_pb_writer *w, uint32_t field, size_t *mark);
int ark_pb_write_submsg_end(ark_pb_writer *w, size_t mark);

void ark_pb_reader_init(ark_pb_reader *r, const uint8_t *data, size_t len);
int ark_pb_reader_next(ark_pb_reader *r, uint32_t *field, uint8_t *wire);
int ark_pb_read_varint(ark_pb_reader *r, uint64_t *v);
int ark_pb_read_bytes(ark_pb_reader *r, const uint8_t **b, size_t *n);
int ark_pb_skip(ark_pb_reader *r, uint8_t wire);

/* Bounded copy of a protobuf length-delimited field into a C string.
 * Does not require src to be NUL-terminated (protobuf strings are not). */
void ark_pb_copy_bytes(char *dst, size_t cap, const uint8_t *src, size_t n);

#endif
