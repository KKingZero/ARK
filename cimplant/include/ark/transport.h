#ifndef ARK_TRANSPORT_H
#define ARK_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct ark_transport ark_transport;

typedef struct ark_transport_ops {
    int (*register_call)(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
    int (*beacon_call)(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
    void (*destroy)(ark_transport *t);
    /* Optional: DNS needs session id in queries; HTTPS must be NULL or no-op (do not overwrite ctx). */
    void (*set_session_id)(ark_transport *t, const char *session_id);
} ark_transport_ops;

struct ark_transport {
    const ark_transport_ops *ops;
    void *ctx;
};

int ark_transport_create(const char *type, ark_transport **out);
void ark_transport_destroy(ark_transport *t);
int ark_transport_register(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
int ark_transport_beacon(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
void ark_transport_set_session_id(ark_transport *t, const char *session_id);

int ark_transport_create_https(ark_transport **out);
int ark_transport_create_dns(ark_transport **out);

#endif