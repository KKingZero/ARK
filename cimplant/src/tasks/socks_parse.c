#include <string.h>

#include "ark/socks.h"

/* host/port parse: "h:p", "1.2.3.4:80", "[::1]:443". Bare multi-colon IPv6 rejected. */
int ark_socks_parse_host_port(const char *target, char *host, size_t host_cap,
                              char *port, size_t port_cap) {
    if (!target || !target[0] || !host || host_cap < 2 || !port || port_cap < 2)
        return 0;

    if (target[0] == '[') {
        const char *rb = strchr(target, ']');
        if (!rb || rb[1] != ':' || rb[2] == '\0')
            return 0;
        size_t hlen = (size_t)(rb - (target + 1));
        if (hlen == 0 || hlen >= host_cap)
            return 0;
        memcpy(host, target + 1, hlen);
        host[hlen] = '\0';
        strncpy(port, rb + 2, port_cap - 1);
        port[port_cap - 1] = '\0';
        return port[0] ? 1 : 0;
    }

    const char *first = strchr(target, ':');
    const char *last = strrchr(target, ':');
    if (!first || first == target || first[1] == '\0')
        return 0;
    /* Multiple colons without brackets → ambiguous IPv6; require [addr]:port. */
    if (first != last)
        return 0;

    size_t hlen = (size_t)(first - target);
    if (hlen >= host_cap)
        return 0;
    memcpy(host, target, hlen);
    host[hlen] = '\0';
    strncpy(port, first + 1, port_cap - 1);
    port[port_cap - 1] = '\0';
    return port[0] ? 1 : 0;
}
