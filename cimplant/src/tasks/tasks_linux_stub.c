/*
 * Windows-only task surfaces on Linux C implant: fail with an explicit reason
 * so operator/AI does not spin on empty errors.
 *
 * Reverse SOCKS: socks_linux.c (not stubbed). Other Windows-only tasks remain here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/task_handlers.h"

static int fail_msg(const char *msg, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return 0;
    size_t n = strlen(msg);
    *out = (uint8_t *)malloc(n + 1);
    if (!*out) {
        *out_len = 0;
        return 0;
    }
    memcpy(*out, msg, n + 1);
    *out_len = n;
    return 0;
}

int ark_task_screenshot(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: screenshot", out, out_len);
}

int ark_task_keylog_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_start", out, out_len);
}

int ark_task_keylog_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_stop", out, out_len);
}

int ark_task_keylog_dump(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_dump", out, out_len);
}

int ark_task_inject(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: inject", out, out_len);
}

int ark_task_peload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: pe_load", out, out_len);
}

/* socks_start / socks_stop: reverse SOCKS in socks_linux.c */
