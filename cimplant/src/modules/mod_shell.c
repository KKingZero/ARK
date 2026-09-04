#include "ark/modules.h"
#include "ark/task_handlers.h"

int ark_mod_shell(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    return ark_task_shell_execute(config, config_len, out, out_len);
}