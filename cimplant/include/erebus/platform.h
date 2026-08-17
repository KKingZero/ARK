#ifndef EREBUS_PLATFORM_H
#define EREBUS_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Portable sleep (milliseconds). */
void erebus_sleep_ms(uint32_t ms);

/* Unix time in milliseconds (for HMAC timestamps; avoids same-second replay). */
int64_t erebus_unix_ms(void);

/* Monotonic-per-implant HMAC timestamp. If wall ms did not advance since *last,
 * returns *last+1 so ReplayCache does not treat SLEEP_MS=500 bursts as replays.
 * *last may be 0 on first use. */
int64_t erebus_unique_unix_ms(int64_t *last);

/* Host identity for Register messages. */
void erebus_get_identity(char *hostname, size_t hcap, char *username, size_t ucap,
    uint32_t *pid, char *integrity, size_t icap);

/* "linux" / "windows" and "amd64" / "arm64" for Register.os / .arch */
const char *erebus_os_name(void);
const char *erebus_arch_name(void);

/* Optional platform init (syscalls on Windows). Returns 1 on success. */
int erebus_platform_init(void);

#endif
