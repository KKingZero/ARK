#ifndef ARK_DNS_CHUNK_H
#define ARK_DNS_CHUNK_H

#include <stddef.h>

#define ARK_DNS_SEQ_WIDTH   3
#define ARK_DNS_TOTAL_WIDTH 3
#define ARK_DNS_MAX_LABEL   63

int ark_dns_max_chunk_len(const char *session_label, const char *domain);
int ark_dns_build_query(char *out, size_t out_cap, int seq, int total,
    const char *chunk, const char *session_label, const char *domain);

#endif