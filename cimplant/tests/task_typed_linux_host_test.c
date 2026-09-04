/* Host test: dedicated TaskTypes reach real Linux modules and surface
 * platform capability errors (not "unsupported task type").
 *
 * Core task handlers are stubs; modules_linux.c is linked for real.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/pb_wire.h"
#include "ark/task_handlers.h"
#include "ark/tasks.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

static int stub_ok(const char *name, uint8_t **out, size_t *out_len) {
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
        return stub_ok(name, out, out_len); \
    }

#define STUB_NOARG(fn, name) \
    int fn(uint8_t **out, size_t *out_len) { \
        return stub_ok(name, out, out_len); \
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

static ark_task_result run_type(int32_t type, const uint8_t *data, size_t data_len) {
    ark_task task;
    memset(&task, 0, sizeof(task));
    strncpy(task.task_id, "t1", sizeof(task.task_id) - 1);
    task.task_type = type;
    task.data = (uint8_t *)data;
    task.data_len = data_len;
    return ark_execute_task(&task);
}

static void expect_linux_cap(const char *label, int32_t type, const char *mod) {
    ark_task_result r = run_type(type, NULL, 0);
    char want[160];
    snprintf(want, sizeof(want), "not supported on linux c implant: %s", mod);
    if (r.success) {
        fprintf(stderr, "FAIL: %s expected capability error\n", label);
        fails++;
    }
    if (strstr(r.error, "unsupported task type")) {
        fprintf(stderr, "FAIL: %s still unrouted: %s\n", label, r.error);
        fails++;
    }
    if (!strstr(r.error, want)) {
        fprintf(stderr, "FAIL: %s error \"%s\" missing \"%s\"\n", label, r.error, want);
        fails++;
    }
    free(r.data);
}

int main(void) {
    expect_linux_cap("LDAP_ENUM", ARK_TASK_LDAP_ENUM, "ldap_enum");
    expect_linux_cap("KERBEROAST", ARK_TASK_KERBEROAST, "kerberoast");
    expect_linux_cap("ASREPROAST", ARK_TASK_ASREPROAST, "asreproast");
    expect_linux_cap("LATERAL_MOVE", ARK_TASK_LATERAL_MOVE, "lateral_move");

    ark_task_result creds = run_type(ARK_TASK_CREDS_DUMP, NULL, 0);
    expect("CREDS_DUMP routed", !creds.success && !strstr(creds.error, "unsupported task type"));
    expect("CREDS_DUMP decode/method error", strstr(creds.error, "creds_dump") != NULL);
    free(creds.data);

    ark_task_result persist = run_type(ARK_TASK_PERSIST, NULL, 0);
    expect("PERSIST not unrouted", !strstr(persist.error, "unsupported task type"));
    expect("PERSIST invoked module", persist.success || strstr(persist.error, "persist") != NULL);
    free(persist.data);

    ark_task_result privesc = run_type(ARK_TASK_PRIVESC, NULL, 0);
    expect("PRIVESC routed", !privesc.success && !strstr(privesc.error, "unsupported task type"));
    expect("PRIVESC decode error", strstr(privesc.error, "privesc") != NULL);
    free(privesc.data);

    ark_pb_writer w;
    expect("module task encode", ark_pb_writer_init(&w, 64) && ark_pb_write_string(&w, 1, "ldap_enum"));
    ark_task_result mod = run_type(ARK_TASK_MODULE, w.data, w.len);
    expect("TASK_MODULE ldap_enum not unrouted", !strstr(mod.error, "unsupported task type"));
    expect("TASK_MODULE ldap_enum linux cap",
        !mod.success && strstr(mod.error, "not supported on linux c implant: ldap_enum") != NULL);
    free(mod.data);
    ark_pb_writer_free(&w);

    ark_task_result pivot = run_type(ARK_TASK_PIVOT_START, NULL, 0);
    expect("PIVOT capability", !pivot.success && strstr(pivot.error, "pivot") != NULL);
    free(pivot.data);

    if (fails) {
        fprintf(stderr, "%d typed-linux host tests failed\n", fails);
        return 1;
    }
    return 0;
}
