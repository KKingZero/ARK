#include "ark/transport.h"

#include <stdio.h>

void ark_format_https_fail(char *dst, size_t cap, const char *curl_err, long http_code) {
    if (!dst || cap == 0) return;
    if (!curl_err || !curl_err[0]) curl_err = "unknown";
    if (http_code > 0)
        snprintf(dst, cap, "curl=%s http=%ld", curl_err, http_code);
    else
        snprintf(dst, cap, "curl=%s", curl_err);
}
