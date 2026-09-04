#ifndef ARK_PATHJAIL_H
#define ARK_PATHJAIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve remote_path relative to the implant working directory.
 * Rejects absolute paths and ".." traversal (Go implant parity).
 * On success writes a NUL-terminated absolute path into out (capacity out_cap).
 * Returns 1 on success, 0 on reject/error. */
int ark_resolve_jailed_path(const char *remote_path, char *out, size_t out_cap);

/* Pure helpers (host-testable). Return 1 if the path is absolute / escapes. */
int ark_path_is_absolute(const char *path);
int ark_path_has_dotdot_escape(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* ARK_PATHJAIL_H */
