#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/pathjail.h"
#include "ark/task_handlers.h"

static const char *path_basename(const char *path) {
    const char *s1 = strrchr(path, '\\');
    const char *s2 = strrchr(path, '/');
    const char *s = s1 > s2 ? s1 : s2;
    return s ? s + 1 : path;
}

int ark_task_file_download(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    ark_file_download_task task;
    if (!ark_pb_decode_file_download_task(data, data_len, &task) || !task.remote_path[0])
        return 0;

    char resolved[520];
    if (!ark_resolve_jailed_path(task.remote_path, resolved, sizeof(resolved)))
        return 0;

    HANDLE hf = CreateFileA(resolved, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hf, &sz) || sz.QuadPart > (LONGLONG)ARK_MAX_FILE_SIZE) {
        CloseHandle(hf);
        return 0;
    }

    size_t flen = (size_t)sz.QuadPart;
    uint8_t *buf = (uint8_t *)malloc(flen);
    if (!buf) { CloseHandle(hf); return 0; }

    DWORD read = 0;
    if (!ReadFile(hf, buf, (DWORD)flen, &read, NULL) || read != flen) {
        free(buf);
        CloseHandle(hf);
        return 0;
    }
    CloseHandle(hf);

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

    HANDLE hf = CreateFileA(resolved, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ark_pb_free_file_upload_task(&task);
        return 0;
    }

    DWORD written = 0;
    BOOL ok_write = WriteFile(hf, task.data, (DWORD)task.data_len, &written, NULL);
    CloseHandle(hf);
    ark_pb_free_file_upload_task(&task);

    if (!ok_write || written != (DWORD)task.data_len)
        return ark_pb_encode_file_upload_result(0, out, out_len);
    return ark_pb_encode_file_upload_result(1, out, out_len);
}
