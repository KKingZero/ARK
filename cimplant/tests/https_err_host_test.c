#include "ark/transport.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return 1;
}

int main(void) {
    char b[128];
    ark_format_https_fail(b, sizeof b, "SSL peer certificate", 0);
    if (!strstr(b, "curl=SSL peer certificate") || strstr(b, "http="))
        return fail(b);
    ark_format_https_fail(b, sizeof b, "ok", 404);
    if (!strstr(b, "curl=ok") || !strstr(b, "http=404"))
        return fail(b);
    ark_format_https_fail(b, sizeof b, NULL, 0);
    if (strcmp(b, "curl=unknown") != 0)
        return fail(b);
    ark_format_https_fail(NULL, 0, "x", 1);
    return 0;
}
