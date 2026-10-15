#ifndef ARK_GLIBC_COMPAT_H
#define ARK_GLIBC_COMPAT_H
/*
 * _GNU_SOURCE turns on _ISOC23_SOURCE. glibc >= 2.38 then redirects
 * strtol/sscanf to __isoc23_* (symbol version GLIBC_2.38). Ubuntu 22.04
 * is glibc 2.35, so a Fedora-built implant dies at startup.
 *
 * features.h computes __GLIBC_USE_C23_STRTOL once, and the header comment
 * says that redirect may be forced off after the header runs. This file
 * is -include'd first so stdio.h/stdlib.h see the override.
 */
#ifdef __linux__
#include <features.h>
#undef __GLIBC_USE_C23_STRTOL
#define __GLIBC_USE_C23_STRTOL 0
#endif
#endif
