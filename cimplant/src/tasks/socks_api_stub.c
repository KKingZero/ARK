/*
 * Windows: reverse SOCKS over beacon not wired yet (listen-stub lives in socks.c).
 * Provide no-op drain/handle so shared beacon.c links.
 */
#include <stdlib.h>
#include <string.h>

#include "ark/socks.h"

int ark_socks_active(void) { return 0; }

void ark_socks_drain(ark_socks_frame **out, size_t *count) {
    if (out) *out = NULL;
    if (count) *count = 0;
}

void ark_socks_requeue(ark_socks_frame *frames, size_t count) {
    ark_socks_frames_free(frames, count);
}

void ark_socks_handle(const ark_socks_frame *frames, size_t count) {
    (void)frames;
    (void)count;
}

void ark_socks_frames_free(ark_socks_frame *frames, size_t count) {
    if (!frames) return;
    for (size_t i = 0; i < count; i++) {
        free(frames[i].data);
        frames[i].data = NULL;
    }
    free(frames);
}

void ark_socks_shutdown(void) { /* no-op on Windows stub */ }
