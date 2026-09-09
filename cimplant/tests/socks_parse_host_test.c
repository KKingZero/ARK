/* Host test: ark_socks_parse_host_port (IPv4, [IPv6]:port, bare IPv6 reject). */
#include <stdio.h>
#include <string.h>

#include "ark/socks.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

int main(void) {
    char host[256], port[16];

    expect("ipv4", ark_socks_parse_host_port("1.2.3.4:80", host, sizeof(host), port, sizeof(port)));
    expect("ipv4 host", strcmp(host, "1.2.3.4") == 0);
    expect("ipv4 port", strcmp(port, "80") == 0);

    expect("hostname", ark_socks_parse_host_port("dc.lab.htb:445", host, sizeof(host), port, sizeof(port)));
    expect("hostname host", strcmp(host, "dc.lab.htb") == 0);
    expect("hostname port", strcmp(port, "445") == 0);

    expect("ipv6 bracket", ark_socks_parse_host_port("[::1]:443", host, sizeof(host), port, sizeof(port)));
    expect("ipv6 host", strcmp(host, "::1") == 0);
    expect("ipv6 port", strcmp(port, "443") == 0);

    expect("ipv6 full", ark_socks_parse_host_port("[2001:db8::1]:389", host, sizeof(host), port, sizeof(port)));
    expect("ipv6 full host", strcmp(host, "2001:db8::1") == 0);
    expect("ipv6 full port", strcmp(port, "389") == 0);

    expect("bare ipv6 reject", !ark_socks_parse_host_port("2001:db8::1:80", host, sizeof(host), port, sizeof(port)));
    expect("empty reject", !ark_socks_parse_host_port("", host, sizeof(host), port, sizeof(port)));
    expect("no port reject", !ark_socks_parse_host_port("host", host, sizeof(host), port, sizeof(port)));
    expect("empty host reject", !ark_socks_parse_host_port(":80", host, sizeof(host), port, sizeof(port)));
    expect("empty port reject", !ark_socks_parse_host_port("host:", host, sizeof(host), port, sizeof(port)));
    expect("empty ipv6 reject", !ark_socks_parse_host_port("[]:80", host, sizeof(host), port, sizeof(port)));
    expect("null reject", !ark_socks_parse_host_port(NULL, host, sizeof(host), port, sizeof(port)));

    if (fails) {
        fprintf(stderr, "socks_parse_host_test: %d failure(s)\n", fails);
        return 1;
    }
    printf("socks_parse_host_test: ok\n");
    return 0;
}
