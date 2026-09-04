#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pathjail.h"
#include "ark/pb_c2.h"
#include "ark/task_handlers.h"

static const char *path_basename(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

int ark_task_file_download(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    ark_file_download_task task;
    if (!ark_pb_decode_file_download_task(data, data_len, &task) || !task.remote_path[0])
        return 0;

    char resolved[520];
    if (!ark_resolve_jailed_path(task.remote_path, resolved, sizeof(resolved)))
        return 0;

    FILE *f = fopen(resolved, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0 || (size_t)sz > ARK_MAX_FILE_SIZE) { fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }

    size_t flen = (size_t)sz;
    uint8_t *buf = (uint8_t *)malloc(flen ? flen : 1);
    if (!buf) { fclose(f); return 0; }
    if (flen && fread(buf, 1, flen, f) != flen) {
        free(buf);
        fclose(f);
        return 0;
    }
    fclose(f);

    int ok = ark_pb_encode_file_download_result(path_basename(resolved), buf, flen, out, out_len);
    free(buf);
    return ok;
}

int ark_task_file_upload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    ark_file_upload_task task;
    if (!ark_pb_decode_file_upload_task(data, data_len, &task) || !task.remote_path[0] || !task.data)
        return 0;

    char resolved[520];
    if (!ark_resolve_jailed_path(task.remote_path, resolved, sizeof(resolved))) {
        ark_pb_free_file_upload_task(&task);
        return 0;
    }

    FILE *f = fopen(resolved, "wb");
    if (!f) {
        ark_pb_free_file_upload_task(&task);
        return ark_pb_encode_file_upload_result(0, out, out_len);
    }
    size_t written = fwrite(task.data, 1, task.data_len, f);
    fclose(f);
    int success = (written == task.data_len) ? 1 : 0;
    ark_pb_free_file_upload_task(&task);
    return ark_pb_encode_file_upload_result(success, out, out_len);
}
