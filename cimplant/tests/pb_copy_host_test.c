/* Host unit test: protobuf string fields are not NUL-terminated. */
#include <stdio.h>
#include <string.h>

#include "ark/pb_wire.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

int main(void) {
    /* Buffer: "hi" (2 bytes) followed by canary "XXX" with no NUL after hi. */
    uint8_t blob[] = { 'h', 'i', 'X', 'X', 'X', 'X' };
    char dst[8];
    memset(dst, 'Z', sizeof(dst));

    ark_pb_copy_bytes(dst, sizeof(dst), blob, 2);
    expect("len", strlen(dst) == 2);
    expect("content", strcmp(dst, "hi") == 0);
    expect("no canary", dst[2] == '\0');

    /* Truncate to cap-1 */
    memset(dst, 'Z', sizeof(dst));
    ark_pb_copy_bytes(dst, 3, blob, 6); /* would be "hiXXXX" but cap=3 → "hi" */
    expect("trunc", strcmp(dst, "hi") == 0);

    /* Empty / null src */
    ark_pb_copy_bytes(dst, sizeof(dst), NULL, 5);
    expect("null src", dst[0] == '\0');
    ark_pb_copy_bytes(dst, sizeof(dst), blob, 0);
    expect("zero n", dst[0] == '\0');

    /* Encode+decode a length-delimited string without trailing NUL in wire. */
    ark_pb_writer w;
    expect("writer init", ark_pb_writer_init(&w, 64));
    /* field 1, wire type 2, length 5, bytes "hello" (no extra NUL) */
    ark_pb_write_string(&w, 1, "hello");

    ark_pb_reader r;
    ark_pb_reader_init(&r, w.data, w.len);
    uint32_t field;
    uint8_t wire;
    expect("next", ark_pb_reader_next(&r, &field, &wire));
    expect("field1", field == 1 && wire == 2);
    const uint8_t *b;
    size_t n;
    expect("read_bytes", ark_pb_read_bytes(&r, &b, &n));
    expect("n=5", n == 5);
    char cmd[16];
    memset(cmd, 'Q', sizeof(cmd));
    ark_pb_copy_bytes(cmd, sizeof(cmd), b, n);
    expect("decoded", strcmp(cmd, "hello") == 0);

    ark_pb_writer_free(&w);

    ark_pb_writer failw;
    uint8_t *out = (uint8_t *)1;
    size_t out_len = 99;
    expect("writer init failw", ark_pb_writer_init(&failw, 8));
    expect("huge write rejected", !ark_pb_write_bytes(&failw, 2, blob, (size_t)-1));
    expect("failed finish rejected", !ark_pb_writer_finish(&failw, &out, &out_len));
    expect("failed finish clears out", out == NULL && out_len == 0);

    if (fails) {
        fprintf(stderr, "%d pb_copy host tests failed\n", fails);
        return 1;
    }
    printf("pb_copy host tests ok\n");
    return 0;
}
