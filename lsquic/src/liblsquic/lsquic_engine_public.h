/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_engine_public.h -- Engine's "public interface"
 *
 * This structure is used to bundle things in engine that connections
 * need.  This way, the space per mini connection is one pointer instead
 * of several.
 */

#ifndef LSQUIC_ENGINE_PUBLIC_H
#define LSQUIC_ENGINE_PUBLIC_H 1


struct lsquic_cid;
struct lsquic_conn;
struct lsquic_engine;
struct stack_st_X509;
struct lsquic_hash;
struct lsquic_stream_if;
struct ssl_ctx_st;
struct crand;
struct evp_aead_ctx_st;
struct lsquic_server_config;
struct sockaddr;

#ifndef LSQUIC_ENGINE_H
#define LSQUIC_ENGINE_H 1

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#endif

#ifndef NDEBUG
#include <sys/types.h>
#endif

#if defined(WIN32) || defined(NDEBUG)
#define CAN_LOSE_PACKETS 0
#else
#define CAN_LOSE_PACKETS 1
#endif

#if CAN_LOSE_PACKETS
#include <regex.h>      /* For code that loses packets */
#endif

#if LOG_PACKET_CHECKSUM
#include <zlib.h>
#endif

#include <openssl/aead.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_copa.h"
#include "lsquic_pacer.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_set.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_full_conn.h"
#include "lsquic_util.h"
#include "lsquic_qtags.h"
#include "lsquic_enc_sess.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_eng_hist.h"
#include "lsquic_ev_log.h"
#include "lsquic_version.h"
#include "lsquic_pr_queue.h"
#include "lsquic_mini_conn.h"
#include "lsquic_trechist.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_stock_shi.h"
#include "lsquic_purga.h"
#include "lsquic_tokgen.h"
#include "lsquic_attq.h"
#include "lsquic_min_heap.h"
#include "lsquic_http1x_if.h"
#include "lsquic_handshake.h"
#include "lsquic_crand.h"
#include "lsquic_ietf.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ENGINE
#include "lsquic_logger.h"

#ifndef LSQUIC_DEBUG_NEXT_ADV_TICK
#define LSQUIC_DEBUG_NEXT_ADV_TICK 1
#endif

#if LSQUIC_DEBUG_NEXT_ADV_TICK || LSQUIC_CONN_STATS
#include "lsquic_alarmset.h"
#endif



enum warning_type
{
    WT_ACKPARSE_MINI,
    WT_ACKPARSE_FULL,
    WT_NO_POISON,
    N_WARNING_TYPES,
};

#define WARNING_INTERVAL (24ULL * 3600ULL * 1000000ULL)

struct lsquic_engine_public {
    struct lsquic_mm                enp_mm;
    struct lsquic_engine_settings   enp_settings;
    struct token_generator         *enp_tokgen;
    lsquic_lookup_cert_f            enp_lookup_cert;
    void                           *enp_cert_lu_ctx;
    struct ssl_ctx_st *           (*enp_get_ssl_ctx)(void *peer_ctx,
                                                     const struct sockaddr *);
    const struct lsquic_shared_hash_if
                                   *enp_shi;
    void                           *enp_shi_ctx;
    lsquic_time_t                   enp_last_warning[N_WARNING_TYPES];
    const struct lsquic_stream_if  *enp_stream_if;
    void                           *enp_stream_if_ctx;
    const struct lsquic_hset_if    *enp_hsi_if;
    void                           *enp_hsi_ctx;
    void                          (*enp_generate_scid)(void *,
                        struct lsquic_conn *, struct lsquic_cid *, unsigned);
    void                           *enp_gen_scid_ctx;
    int                           (*enp_verify_cert)(void *verify_ctx,
                                            struct stack_st_X509 *chain);
    void                           *enp_verify_ctx;
    const struct lsquic_packout_mem_if
                                   *enp_pmi;
    void                           *enp_pmi_ctx;
    struct lsquic_engine           *enp_engine;
    struct lsquic_hash             *enp_srst_hash;
    enum {
        ENPUB_PROC  = (1 << 0), /* Being processed by one of the user-facing
                                 * functions.
                                 */
        ENPUB_CAN_SEND = (1 << 1),
        ENPUB_HTTP  = (1 << 2), /* Engine in HTTP mode */
    }                               enp_flags;
    unsigned char                   enp_ver_tags_buf[ sizeof(lsquic_ver_tag_t) * N_LSQVER ];
    unsigned                        enp_ver_tags_len;
    struct crand                   *enp_crand;
    struct evp_aead_ctx_st         *enp_retry_aead_ctx;
    unsigned char                  *enp_alpn;   /* May be set if not HTTP */
    /* es_noprogress_timeout converted to microseconds for speed */
    lsquic_time_t                   enp_noprog_timeout;
    lsquic_time_t                   enp_mtu_probe_timer;
    /* Certs used by gQUIC server: */
    struct lsquic_hash             *enp_compressed_server_certs;
    struct lsquic_hash             *enp_server_certs;
    /* gQUIC server configuration: */
    struct lsquic_server_config    *enp_server_config;
    /* Serialized subset of server engine transport parameters that is used
     * as SSL QUIC context.  0 is for version <= LSQVER_ID27, 1 is for others.
     */
    unsigned char                   enp_quic_ctx_buf[2][200];
    unsigned                        enp_quic_ctx_sz[2];
#if LSQUIC_CONN_STATS
    struct batch_size_stats {
        unsigned    min, max,   /* Minimum and maximum batch sizes */
                    count;      /* Number of batches sent */
        float       avg;        /* Average batch size */
    }                               enp_batch_size_stats;
#endif
};

/* Put connection onto the Tickable Queue if it is not already on it.  If
 * connection is being destroyed, this is a no-op.
 */
void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *,
                                                        lsquic_conn_t *);

/* Put connection onto Advisory Tick Time  Queue if it is not already on it.
 */
void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                                lsquic_conn_t *, lsquic_time_t, unsigned why);

void
lsquic_engine_retire_cid (struct lsquic_engine_public *,
    struct lsquic_conn *, unsigned cce_idx, lsquic_time_t now,
    lsquic_time_t drain_time);

int
lsquic_engine_add_cid (struct lsquic_engine_public *,
                              struct lsquic_conn *, unsigned cce_idx);

struct lsquic_conn *
lsquic_engine_find_conn (const struct lsquic_engine_public *pub,
                         const lsquic_cid_t *cid);

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* The batch of outgoing packets grows and shrinks dynamically */
/* Batch sizes do not have to be powers of two */
#define MAX_OUT_BATCH_SIZE 1024
#define MIN_OUT_BATCH_SIZE 4
#define INITIAL_OUT_BATCH_SIZE 32

struct out_batch
{
    lsquic_conn_t           *conns  [MAX_OUT_BATCH_SIZE];
    struct lsquic_out_spec   outs   [MAX_OUT_BATCH_SIZE];
    unsigned                 pack_off[MAX_OUT_BATCH_SIZE];
    lsquic_packet_out_t     *packets[MAX_OUT_BATCH_SIZE * 2];
    struct iovec             iov    [MAX_OUT_BATCH_SIZE * 2];
};

typedef struct lsquic_conn * (*conn_iter_f)(struct lsquic_engine *);

static void
process_connections (struct lsquic_engine *engine, conn_iter_f iter,
                     lsquic_time_t now);

static void
engine_incref_conn (lsquic_conn_t *conn, enum lsquic_conn_flags flag);

static lsquic_conn_t *
engine_decref_conn (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                        enum lsquic_conn_flags flag);

static void
force_close_conn (lsquic_engine_t *engine, lsquic_conn_t *conn);

#if LSQUIC_CONN_STATS
static void
update_busy_detector (struct lsquic_engine *, struct lsquic_conn *, int);
#endif

#if LSQUIC_COUNT_ENGINE_CALLS
#define ENGINE_CALLS_INCR(e) do { ++(e)->n_engine_calls; } while (0)
#else
#define ENGINE_CALLS_INCR(e)
#endif

/* Nested calls to some LSQUIC functions are not supported.  Functions that
 * iterate over connections cannot be nested.
 */
#define ENGINE_IN(e) do {                               \
    assert(!((e)->pub.enp_flags & ENPUB_PROC));         \
    (e)->pub.enp_flags |= ENPUB_PROC;                   \
    ENGINE_CALLS_INCR(e);                               \
} while (0)

#define ENGINE_OUT(e) do {                              \
    assert((e)->pub.enp_flags & ENPUB_PROC);            \
    (e)->pub.enp_flags &= ~ENPUB_PROC;                  \
} while (0)

/* A connection can be referenced from one of six places:
 *
 *   1. A hash is used to find connections in order to dispatch an incoming
 *      packet.  Connections can be hashed by CIDs or by address.  In the
 *      former case, each connection has one or more mappings in the hash
 *      table.  IETF QUIC connections have up to eight (in our implementation)
 *      source CIDs and each of those would have a mapping.  In client mode,
 *      depending on QUIC versions and options selected, it is may be
 *      necessary to hash connections by address, in which case incoming
 *      packets are delivered to connections based on the address.
 *
 *   2. Outgoing queue.
 *
 *   3. Tickable queue
 *
 *   4. Advisory Tick Time queue.
 *
 *   5. Closing connections queue.  This is a transient queue -- it only
 *      exists for the duration of process_connections() function call.
 *
 *   6. Ticked connections queue.  Another transient queue, similar to (5).
 *
 * The idea is to destroy the connection when it is no longer referenced.
 * For example, a connection tick may return TICK_SEND|TICK_CLOSE.  In
 * that case, the connection is referenced from two places: (2) and (5).
 * After its packets are sent, it is only referenced in (5), and at the
 * end of the function call, when it is removed from (5), reference count
 * goes to zero and the connection is destroyed.  If not all packets can
 * be sent, at the end of the function call, the connection is referenced
 * by (2) and will only be removed once all outgoing packets have been
 * sent.
 */
#define CONN_REF_FLAGS  (LSCONN_HASHED          \
                        |LSCONN_HAS_OUTGOING    \
                        |LSCONN_TICKABLE        \
                        |LSCONN_TICKED          \
                        |LSCONN_CLOSING         \
                        |LSCONN_ATTQ)




struct cid_update_batch
{
    lsquic_cids_update_f    cub_update_cids;
    void                   *cub_update_ctx;
    unsigned                cub_count;
    lsquic_cid_t            cub_cids[20];
    void                   *cub_peer_ctxs[20];
};

static void
cub_init (struct cid_update_batch *, lsquic_cids_update_f, void *);


struct lsquic_engine
{
    struct lsquic_engine_public        pub;
    enum {
        ENG_SERVER      = LSENG_SERVER,
        ENG_HTTP        = LSENG_HTTP,
        ENG_COOLDOWN    = (1 <<  7),    /* Cooldown: no new connections */
        ENG_PAST_DEADLINE
                        = (1 <<  8),    /* Previous call to a processing
                                         * function went past time threshold.
                                         */
        ENG_CONNS_BY_ADDR
                        = (1 <<  9),    /* Connections are hashed by address */
        ENG_FORCE_RETRY = (1 << 10),    /* Will force retry packets to be sent */
#ifndef NDEBUG
        ENG_COALESCE    = (1 << 24),    /* Packet coalescing is enabled */
#endif
#if CAN_LOSE_PACKETS
        ENG_LOSE_PACKETS= (1 << 25),    /* Lose *some* outgoing packets */
#endif
#ifndef NDEBUG
        ENG_DTOR        = (1 << 26),    /* Engine destructor */
#endif
    }                                  flags;
    lsquic_packets_out_f               packets_out;
    void                              *packets_out_ctx;
    lsquic_cids_update_f               report_new_scids;
    lsquic_cids_update_f               report_live_scids;
    lsquic_cids_update_f               report_old_scids;
    void                              *scids_ctx;
    struct lsquic_hash                *conns_hash;
    struct min_heap                    conns_tickable;
    struct min_heap                    conns_out;
    struct eng_hist                    history;
    unsigned                           batch_size;
    unsigned                           min_batch_size, max_batch_size;
    struct lsquic_conn                *curr_conn;
    struct pr_queue                   *pr_queue;
    struct attq                       *attq;
    /* Track time last time a packet was sent to give new connections
     * priority lower than that of existing connections.
     */
    lsquic_time_t                      last_sent;
#if CAN_LOSE_PACKETS
    regex_t                            lose_packets_re;
    const char                        *lose_packets_str;
#endif
    unsigned                           n_conns;
    lsquic_time_t                      deadline;
    lsquic_time_t                      resume_sending_at;
    lsquic_time_t                      mem_logged_last;
    unsigned                           mini_conns_count;
    struct lsquic_purga               *purga;
#if LSQUIC_CONN_STATS
    struct {
        unsigned                conns;
    }                                  stats;
    struct conn_stats                  conn_stats_sum;
    FILE                              *stats_fh;
#endif
    struct cid_update_batch            new_scids;
    struct out_batch                   out_batch;
#if LSQUIC_COUNT_ENGINE_CALLS
    unsigned long                      n_engine_calls;
#endif
#if LSQUIC_DEBUG_NEXT_ADV_TICK
    uintptr_t                          last_logged_conn;
    unsigned                           last_logged_ae_why;
    int                                last_tick_diff;
#endif
    struct crand                       crand;
    EVP_AEAD_CTX                       retry_aead_ctx[N_IETF_RETRY_VERSIONS];
#if LSQUIC_CONN_STATS
    struct {
        uint16_t            immed_ticks;    /* bitmask */
#define MAX_IMMED_TICKS UINT16_MAX
        struct lsquic_conn *last_conn,      /* from last call */
                           *pin_conn,       /* last connection with packet in */
                           *current;        /* currently busy connection */
        lsquic_time_t       last_log;
    }                                  busy;
#endif
};
#endif

#endif