/* Host test: SocksFrame encode/decode + results payload field 2 + decode fail free. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/pb_c2.h"
#include "ark/socks.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

int main(void) {
    ark_socks_frame f;
    memset(&f, 0, sizeof(f));
    f.conn_id = 42;
    f.op = ARK_SOCKS_OPEN;
    strncpy(f.target, "127.0.0.1:80", sizeof(f.target) - 1);
    f.status = 0;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    expect("encode open", ark_pb_encode_socks_frame(&f, &wire, &wire_len));
    expect("wire non-empty", wire_len > 0);

    ark_socks_frame g;
    memset(&g, 0, sizeof(g));
    expect("decode open", ark_pb_decode_socks_frame(wire, wire_len, &g));
    expect("conn_id", g.conn_id == 42);
    expect("op", g.op == ARK_SOCKS_OPEN);
    expect("target", strcmp(g.target, "127.0.0.1:80") == 0);
    free(wire);
    free(g.data);

    /* DATA with payload + status -1 OPEN_RESULT */
    ark_socks_frame d;
    memset(&d, 0, sizeof(d));
    d.conn_id = 7;
    d.op = ARK_SOCKS_DATA;
    static const uint8_t payload[] = {0x48, 0x49};
    d.data = (uint8_t *)payload;
    d.data_len = 2;
    expect("encode data", ark_pb_encode_socks_frame(&d, &wire, &wire_len));
    memset(&g, 0, sizeof(g));
    expect("decode data", ark_pb_decode_socks_frame(wire, wire_len, &g));
    expect("data len", g.data_len == 2 && g.data && g.data[0] == 0x48 && g.data[1] == 0x49);
    free(wire);
    free(g.data);

    ark_socks_frame r;
    memset(&r, 0, sizeof(r));
    r.conn_id = 1;
    r.op = ARK_SOCKS_OPEN_RESULT;
    r.status = -1;
    expect("encode fail result", ark_pb_encode_socks_frame(&r, &wire, &wire_len));
    memset(&g, 0, sizeof(g));
    expect("decode fail result", ark_pb_decode_socks_frame(wire, wire_len, &g));
    expect("status -1", g.status == -1);
    free(wire);

    /* results payload with only socks frames */
    ark_socks_frame frames[1];
    memset(frames, 0, sizeof(frames));
    frames[0].conn_id = 9;
    frames[0].op = ARK_SOCKS_CLOSE;
    expect("encode results+socks",
        ark_pb_encode_results_payload(NULL, 0, frames, 1, &wire, &wire_len));

    ark_task *tasks = NULL;
    size_t tcount = 0;
    ark_socks_frame *socks = NULL;
    size_t scount = 0;
    expect("decode tasks payload socks",
        ark_pb_decode_tasks_payload(wire, wire_len, &tasks, &tcount, &socks, &scount));
    expect("no tasks", tcount == 0);
    expect("one socks", scount == 1 && socks && socks[0].op == ARK_SOCKS_CLOSE && socks[0].conn_id == 9);
    free(wire);
    ark_pb_free_tasks(tasks, tcount);
    ark_socks_frames_free(socks, scount);

    /* Truncated length-delimited field: decode must fail and clear out-params. */
    {
        uint8_t bad[] = { 0x0a, 0x10 }; /* field 1, claims 16 bytes, buffer ends */
        tasks = NULL;
        tcount = 0;
        socks = NULL;
        scount = 0;
        int ok = ark_pb_decode_tasks_payload(bad, sizeof(bad), &tasks, &tcount, &socks, &scount);
        expect("truncated payload fails", ok == 0);
        expect("tasks cleared", tasks == NULL && tcount == 0);
        expect("socks cleared", socks == NULL && scount == 0);
    }

    /* Partial success then failure path: valid socks frame then truncated second field. */
    {
        uint8_t *okwire = NULL;
        size_t oklen = 0;
        ark_socks_frame one;
        memset(&one, 0, sizeof(one));
        one.conn_id = 1;
        one.op = ARK_SOCKS_CLOSE;
        expect("encode one socks", ark_pb_encode_results_payload(NULL, 0, &one, 1, &okwire, &oklen));
        /* Append truncated field 1 (task) after good socks field 2. */
        uint8_t *combo = (uint8_t *)malloc(oklen + 2);
        expect("combo alloc", combo != NULL);
        if (combo) {
            memcpy(combo, okwire, oklen);
            combo[oklen] = 0x0a;
            combo[oklen + 1] = 0x20; /* claims 32 bytes missing */
            tasks = NULL;
            tcount = 0;
            socks = NULL;
            scount = 0;
            int ok = ark_pb_decode_tasks_payload(combo, oklen + 2, &tasks, &tcount, &socks, &scount);
            expect("partial then fail", ok == 0);
            expect("partial tasks cleared", tasks == NULL && tcount == 0);
            expect("partial socks cleared", socks == NULL && scount == 0);
            free(combo);
        }
        free(okwire);
    }

    /* IPv6 bracket form still encodes as target string on wire (parse is implant-side). */
    memset(&f, 0, sizeof(f));
    f.conn_id = 3;
    f.op = ARK_SOCKS_OPEN;
    strncpy(f.target, "[2001:db8::1]:443", sizeof(f.target) - 1);
    expect("encode ipv6 bracket", ark_pb_encode_socks_frame(&f, &wire, &wire_len));
    memset(&g, 0, sizeof(g));
    expect("decode ipv6 bracket", ark_pb_decode_socks_frame(wire, wire_len, &g));
    expect("ipv6 target roundtrip", strcmp(g.target, "[2001:db8::1]:443") == 0);
    free(wire);
    free(g.data);

    if (fails) {
        fprintf(stderr, "socks_pb_host_test: %d failure(s)\n", fails);
        return 1;
    }
    printf("socks_pb_host_test: ok\n");
    return 0;
}
