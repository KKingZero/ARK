/* Host test: Linux C Windows-only task surfaces fail closed with clear errors. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/task_handlers.h"

static int fails;

typedef int (*stub_handler)(const uint8_t *, size_t, uint8_t **, size_t *);

static void expect_msg(const char *name, stub_handler fn, const char *want) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int ok = fn(NULL, 0, &out, &out_len);
    if (ok) {
        fprintf(stderr, "FAIL: %s unexpectedly succeeded\n", name);
        fails++;
    }
    if (!out || out_len == 0 || !strstr((const char *)out, want)) {
        fprintf(stderr, "FAIL: %s error missing %s\n", name, want);
        fails++;
    }
    free(out);
}

int main(void) {
    expect_msg("screenshot", ark_task_screenshot, "not supported on linux c implant: screenshot");
    expect_msg("keylog_start", ark_task_keylog_start, "not supported on linux c implant: keylog_start");
    expect_msg("keylog_stop", ark_task_keylog_stop, "not supported on linux c implant: keylog_stop");
    expect_msg("keylog_dump", ark_task_keylog_dump, "not supported on linux c implant: keylog_dump");
    expect_msg("inject", ark_task_inject, "not supported on linux c implant: inject");
    expect_msg("pe_load", ark_task_peload, "not supported on linux c implant: pe_load");

    if (fails) {
        fprintf(stderr, "%d linux task stub tests failed\n", fails);
        return 1;
    }
    printf("linux task stub tests ok\n");
    return 0;
}
