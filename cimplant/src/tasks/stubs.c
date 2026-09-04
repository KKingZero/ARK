#include <stdlib.h>
#include <string.h>

#include "ark/modules.h"
#include "ark/pb_modules.h"
#include "ark/task_handlers.h"

int ark_task_module(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    ark_module_task mt;
    if (!ark_pb_decode_module_task(data, data_len, &mt)) return 0;

    int ok = ark_module_execute(mt.module_name, mt.config, mt.config_len, out, out_len);
    ark_pb_free_module_task(&mt);
    return ok;
}