#include "erebus/platform.h"

int64_t erebus_unique_unix_ms(int64_t *last) {
    int64_t ts = erebus_unix_ms();
    if (last && ts <= *last)
        ts = *last + 1;
    if (last)
        *last = ts;
    return ts;
}
