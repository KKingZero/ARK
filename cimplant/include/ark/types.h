#ifndef ARK_TYPES_H
#define ARK_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef struct ark_buffer {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ark_buffer;

typedef struct ark_task {
    char     task_id[64];
    char     implant_id[64];
    int32_t  task_type;
    uint8_t *data;
    size_t   data_len;
    int64_t  timeout_ms;
} ark_task;

typedef struct ark_task_result {
    char     task_id[64];
    int      success;
    uint8_t *data;
    size_t   data_len;
    char     error[256];
    int64_t  execution_time_ms;
} ark_task_result;

#endif