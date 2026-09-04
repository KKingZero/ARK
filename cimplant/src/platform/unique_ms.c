#include "ark/platform.h"

int64_t ark_unique_unix_ms(int64_t *last) {
    int64_t ts = ark_unix_ms();
    if (last && ts <= *last)
        ts = *last + 1;
    if (last)
        *last = ts;
    return ts;
}
