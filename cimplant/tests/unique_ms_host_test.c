/* Host test: HMAC timestamps stay unique when wall ms does not advance. */
#include <stdio.h>
#include <stdint.h>

#include "ark/platform.h"

static int fails;
static int64_t g_now = 1700000000000LL; /* frozen wall clock (ms) */

int64_t ark_unix_ms(void) {
    return g_now;
}

static void expect_eq(const char *name, int64_t got, int64_t want) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s got %lld want %lld\n", name, (long long)got, (long long)want);
        fails++;
    }
}

int main(void) {
    int64_t last = 0;
    int64_t a = ark_unique_unix_ms(&last);
    expect_eq("first is wall", a, g_now);
    expect_eq("last stored", last, g_now);

    int64_t b = ark_unique_unix_ms(&last);
    expect_eq("same wall increments", b, g_now + 1);
    int64_t c = ark_unique_unix_ms(&last);
    expect_eq("third increments", c, g_now + 2);

    g_now += 5;
    int64_t d = ark_unique_unix_ms(&last);
    expect_eq("wall jump used", d, g_now);

    if (fails) {
        fprintf(stderr, "%d unique_ms host tests failed\n", fails);
        return 1;
    }
    return 0;
}
