#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#define _USE_MATH_DEFINES   /* Need this for M_E on Windows */
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/aead.h>
#include <openssl/rand.h>

#include "fiu-local.h"

#include "lsquic.h"
#include "lsxpack_header.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rechist.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_copa.h"
#include "lsquic_pacer.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_send_ctl.h"
#include "lsquic_alarmset.h"
#include "lsquic_ver_neg.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_set.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_version.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_enc_sess.h"
#include "lsquic_ev_log.h"
#include "lsquic_malo.h"
#include "lsquic_frab_list.h"
#include "lsquic_hcso_writer.h"
#include "lsquic_hcsi_reader.h"
#include "lsqpack.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_trechist.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_tokgen.h"
#include "lsquic_full_conn.h"
#include "lsquic_spi.h"
#include "lsquic_min_heap.h"
#include "lsquic_hpi.h"
#include "lsquic_ietf.h"
#include "lsquic_push_promise.h"
#include "lsquic_headers.h"
#include "lsquic_crand.h"
#include "ls-sfparser.h"
#include "lsquic_qpack_exp.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
//#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&conn->ifc_conn) //LZJ
#include "lsquic_logger.h"

#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define MAX_ANY_PACKETS_SINCE_LAST_ACK 20
#define ACK_TIMEOUT                    (TP_DEF_MAX_ACK_DELAY * 1000)
#define INITIAL_CHAL_TIMEOUT            250000
#define HSK_PING_TIMEOUT                200000

/* Retire original CID after this much time has elapsed: */
#define RET_CID_TIMEOUT                 2000000

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* IETF QUIC push promise does not contain stream ID.  This means that, unlike
 * in GQUIC, one cannot create a stream immediately and pass it to the client.
 * We may have to add a special API for IETF push promises.  That's in the
 * future: right now, we punt it.
 */
#define CLIENT_PUSH_SUPPORT 0



/* IMPORTANT: Keep values of IFC_SERVER and IFC_HTTP same as LSENG_SERVER
 * and LSENG_HTTP.
 */
enum ifull_conn_flags
{
    IFC_SERVER        = LSENG_SERVER,   /* Server mode */
    IFC_HTTP          = LSENG_HTTP,     /* HTTP mode */
    IFC_ACK_HAD_MISS  = 1 << 2,
#define IFC_BIT_ERROR 3
    IFC_ERROR         = 1 << IFC_BIT_ERROR,
    IFC_TIMED_OUT     = 1 << 4,
    IFC_ABORTED       = 1 << 5,
    IFC_HSK_FAILED    = 1 << 6,
    IFC_GOING_AWAY    = 1 << 7,
    IFC_CLOSING       = 1 << 8,   /* Closing */
    IFC_RECV_CLOSE    = 1 << 9,  /* Received CONNECTION_CLOSE frame */
    IFC_TICK_CLOSE    = 1 << 10,  /* We returned TICK_CLOSE */
    IFC_CREATED_OK    = 1 << 11,
    IFC_HAVE_SAVED_ACK= 1 << 12,
    IFC_ABORT_COMPLAINED
                      = 1 << 13,
    IFC_DCID_SET      = 1 << 14,
#define IFCBIT_ACK_QUED_SHIFT 15
    IFC_ACK_QUED_INIT = 1 << 15,
    IFC_ACK_QUED_HSK  = IFC_ACK_QUED_INIT << PNS_HSK,
    IFC_ACK_QUED_APP  = IFC_ACK_QUED_INIT << PNS_APP,
#define IFC_ACK_QUEUED (IFC_ACK_QUED_INIT|IFC_ACK_QUED_HSK|IFC_ACK_QUED_APP)
    IFC_HAVE_PEER_SET = 1 << 18,
    IFC_GOT_PRST      = 1 << 19,
    IFC_IGNORE_INIT   = 1 << 20,
    IFC_RETRIED       = 1 << 21,
    IFC_SWITCH_DCID   = 1 << 22, /* Perform DCID switch when a new CID becomes available */
    IFC_GOAWAY_CLOSE  = 1 << 23,
    IFC_FIRST_TICK    = 1 << 24,
    IFC_IGNORE_HSK    = 1 << 25,
    IFC_PROC_CRYPTO   = 1 << 26,
    IFC_MIGRA         = 1 << 27,
    IFC_HTTP_INITED   = 1 << 28, /* HTTP initialized */
    IFC_DELAYED_ACKS  = 1 << 29, /* Delayed ACKs are enabled */
    IFC_TIMESTAMPS    = 1 << 30, /* Timestamps are enabled */
    IFC_DATAGRAMS     = 1u<< 31, /* Datagrams are enabled */
};


enum more_flags
{
    MF_VALIDATE_PATH    = 1 << 0,
    MF_NOPROG_TIMEOUT   = 1 << 1,
    MF_CHECK_MTU_PROBE  = 1 << 2,
    MF_IGNORE_MISSING   = 1 << 3,
    MF_CONN_CLOSE_PACK  = 1 << 4,   /* CONNECTION_CLOSE has been packetized */
    MF_SEND_WRONG_COUNTS= 1 << 5,   /* Send wrong ECN counts to peer */
    MF_WANT_DATAGRAM_WRITE  = 1 << 6,
    MF_DOING_0RTT       = 1 << 7,
    MF_HAVE_HCSI        = 1 << 8,   /* Have HTTP Control Stream Incoming */
};


#define N_PATHS 4

enum send
{
    /* PATH_CHALLENGE and PATH_RESPONSE frames are not retransmittable.  They
     * are positioned first in the enum to optimize packetization.
     */
    SEND_PATH_CHAL,
    SEND_PATH_CHAL_PATH_0 = SEND_PATH_CHAL + 0,
    SEND_PATH_CHAL_PATH_1 = SEND_PATH_CHAL + 1,
    SEND_PATH_CHAL_PATH_2 = SEND_PATH_CHAL + 2,
    SEND_PATH_CHAL_PATH_3 = SEND_PATH_CHAL + 3,
    SEND_PATH_RESP,
    SEND_PATH_RESP_PATH_0 = SEND_PATH_RESP + 0,
    SEND_PATH_RESP_PATH_1 = SEND_PATH_RESP + 1,
    SEND_PATH_RESP_PATH_2 = SEND_PATH_RESP + 2,
    SEND_PATH_RESP_PATH_3 = SEND_PATH_RESP + 3,
    SEND_MAX_DATA,
    SEND_PING,
    SEND_NEW_CID,
    SEND_RETIRE_CID,
    SEND_CONN_CLOSE,
    SEND_STREAMS_BLOCKED,
    SEND_STREAMS_BLOCKED_BIDI = SEND_STREAMS_BLOCKED + SD_BIDI,
    SEND_STREAMS_BLOCKED_UNI = SEND_STREAMS_BLOCKED + SD_UNI,
    SEND_MAX_STREAMS,
    SEND_MAX_STREAMS_BIDI = SEND_MAX_STREAMS + SD_BIDI,
    SEND_MAX_STREAMS_UNI = SEND_MAX_STREAMS + SD_UNI,
    SEND_STOP_SENDING,
    SEND_NEW_TOKEN,
    SEND_HANDSHAKE_DONE,
    SEND_ACK_FREQUENCY,
    N_SEND
};

enum send_flags
{
    SF_SEND_MAX_DATA                = 1 << SEND_MAX_DATA,
    SF_SEND_PING                    = 1 << SEND_PING,
    SF_SEND_PATH_CHAL               = 1 << SEND_PATH_CHAL,
    SF_SEND_PATH_CHAL_PATH_0        = 1 << SEND_PATH_CHAL_PATH_0,
    SF_SEND_PATH_CHAL_PATH_1        = 1 << SEND_PATH_CHAL_PATH_1,
    SF_SEND_PATH_CHAL_PATH_2        = 1 << SEND_PATH_CHAL_PATH_2,
    SF_SEND_PATH_CHAL_PATH_3        = 1 << SEND_PATH_CHAL_PATH_3,
    SF_SEND_PATH_RESP               = 1 << SEND_PATH_RESP,
    SF_SEND_PATH_RESP_PATH_0        = 1 << SEND_PATH_RESP_PATH_0,
    SF_SEND_PATH_RESP_PATH_1        = 1 << SEND_PATH_RESP_PATH_1,
    SF_SEND_PATH_RESP_PATH_2        = 1 << SEND_PATH_RESP_PATH_2,
    SF_SEND_PATH_RESP_PATH_3        = 1 << SEND_PATH_RESP_PATH_3,
    SF_SEND_NEW_CID                 = 1 << SEND_NEW_CID,
    SF_SEND_RETIRE_CID              = 1 << SEND_RETIRE_CID,
    SF_SEND_CONN_CLOSE              = 1 << SEND_CONN_CLOSE,
    SF_SEND_STREAMS_BLOCKED         = 1 << SEND_STREAMS_BLOCKED,
    SF_SEND_STREAMS_BLOCKED_BIDI    = 1 << SEND_STREAMS_BLOCKED_BIDI,
    SF_SEND_STREAMS_BLOCKED_UNI     = 1 << SEND_STREAMS_BLOCKED_UNI,
    SF_SEND_MAX_STREAMS             = 1 << SEND_MAX_STREAMS,
    SF_SEND_MAX_STREAMS_BIDI        = 1 << SEND_MAX_STREAMS_BIDI,
    SF_SEND_MAX_STREAMS_UNI         = 1 << SEND_MAX_STREAMS_UNI,
    SF_SEND_STOP_SENDING            = 1 << SEND_STOP_SENDING,
    SF_SEND_NEW_TOKEN               = 1 << SEND_NEW_TOKEN,
    SF_SEND_HANDSHAKE_DONE          = 1 << SEND_HANDSHAKE_DONE,
    SF_SEND_ACK_FREQUENCY           = 1 << SEND_ACK_FREQUENCY,
};

#define SF_SEND_PATH_CHAL_ALL \
            (((SF_SEND_PATH_CHAL << N_PATHS) - 1) & ~(SF_SEND_PATH_CHAL - 1))

#define IFC_IMMEDIATE_CLOSE_FLAGS \
            (IFC_TIMED_OUT|IFC_ERROR|IFC_ABORTED|IFC_HSK_FAILED|IFC_GOT_PRST)

#define MAX_ERRMSG 256

#define MAX_SCID 8

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->ifc_errmsg)                                                \
    {                                                                       \
        (conn)->ifc_errmsg = malloc(MAX_ERRMSG);                            \
        if ((conn)->ifc_errmsg)                                             \
            snprintf((conn)->ifc_errmsg, MAX_ERRMSG, __VA_ARGS__);          \
    }                                                                       \
} while (0)

#define ABORT_WITH_FLAG(conn, log_level, flag, ...) do {                    \
    SET_ERRMSG(conn, __VA_ARGS__);                                          \
    if (!((conn)->ifc_flags & IFC_ABORT_COMPLAINED))                        \
        LSQ_LOG(log_level, "Abort connection: " __VA_ARGS__);               \
    (conn)->ifc_flags |= flag|IFC_ABORT_COMPLAINED;                         \
} while (0)

#define ABORT_ERROR(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_ERROR, IFC_ERROR, __VA_ARGS__)
#define ABORT_WARN(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_WARN, IFC_ERROR, __VA_ARGS__)

#define CONN_ERR(app_error_, code_) (struct conn_err) { \
                            .app_error = (app_error_), .u.err = (code_), }

/* Use this for protocol errors; they do not need to be as loud as our own
 * internal errors.
 */
#define ABORT_QUIETLY(app_error, code, ...) do {                            \
    conn->ifc_error = CONN_ERR(app_error, code);                            \
    ABORT_WITH_FLAG(conn, LSQ_LOG_INFO, IFC_ERROR, __VA_ARGS__);            \
} while (0)

static enum stream_id_type
gen_sit (unsigned server, enum stream_dir sd)
{
    return (server > 0) | ((sd > 0) << SD_SHIFT);
}


struct stream_id_to_ss
{
    STAILQ_ENTRY(stream_id_to_ss)   sits_next;
    lsquic_stream_id_t              sits_stream_id;
    enum http_error_code            sits_error_code;
};

struct http_ctl_stream_in
{
    struct hcsi_reader  reader;
};

struct conn_err
{
    int                         app_error;
    union
    {
        enum trans_error_code   tec;
        enum http_error_code    hec;
        unsigned                err;
    }                           u;
};


struct dplpmtud_state
{
    lsquic_packno_t     ds_probe_packno;
#ifndef NDEBUG
    lsquic_time_t       ds_probe_sent;
#endif
    enum {
        DS_PROBE_SENT   = 1 << 0,
    }                   ds_flags;
    unsigned short      ds_probed_size,
                        ds_failed_size; /* If non-zero, defines ceiling */
    unsigned char       ds_probe_count;
};


struct conn_path
{
    struct network_path         cop_path;
    uint64_t                    cop_path_chals[8];  /* Arbitrary number */
    uint64_t                    cop_inc_chal;       /* Incoming challenge */
    lsquic_packno_t             cop_max_packno;
    enum {
        /* Initialized covers cop_path.np_pack_size and cop_path.np_dcid */
        COP_INITIALIZED = 1 << 0,
        /* This flag is set when we received a response to one of path
         * challenges we sent on this path.
         */
        COP_VALIDATED   = 1 << 1,
        /* Received non-probing frames.  This flag is not set for the
         * original path.
         */
        COP_GOT_NONPROB = 1 << 2,
        /* Spin bit is enabled on this path. */
        COP_SPIN_BIT    = 1 << 3,
        /* Allow padding packet to 1200 bytes */
        COP_ALLOW_MTU_PADDING = 1 << 4,
        /* Verified that the path MTU is at least 1200 bytes */
        COP_VALIDATED_MTU = 1 << 5,
    }                           cop_flags;
    unsigned char               cop_n_chals;
    unsigned char               cop_cce_idx;
    unsigned char               cop_spin_bit;
    struct dplpmtud_state       cop_dplpmtud;
};


struct packet_tolerance_stats
{
    unsigned        n_acks;     /* Number of ACKs between probes */
    float           integral_error;
    lsquic_time_t   last_sample;
};


union prio_iter
{
    struct stream_prio_iter spi;
    struct http_prio_iter   hpi;
};


struct prio_iter_if
{
    void (*pii_init) (void *, struct lsquic_stream *first,
             struct lsquic_stream *last, uintptr_t next_ptr_offset,
             struct lsquic_conn_public *, const char *name,
             int (*filter)(void *filter_ctx, struct lsquic_stream *),
             void *filter_ctx);

    struct lsquic_stream * (*pii_first) (void *);

    struct lsquic_stream * (*pii_next) (void *);

    void (*pii_drop_non_high) (void *);

    void (*pii_drop_high) (void *);

    void (*pii_cleanup) (void *);
};


static const struct prio_iter_if orig_prio_iter_if = {
    lsquic_spi_init,
    lsquic_spi_first,
    lsquic_spi_next,
    lsquic_spi_drop_non_high,
    lsquic_spi_drop_high,
    lsquic_spi_cleanup,
};


static const struct prio_iter_if ext_prio_iter_if = {
    lsquic_hpi_init,
    lsquic_hpi_first,
    lsquic_hpi_next,
    lsquic_hpi_drop_non_high,
    lsquic_hpi_drop_high,
    lsquic_hpi_cleanup,
};


struct ietf_full_conn
{
    struct lsquic_conn          ifc_conn;
    struct conn_cid_elem        ifc_cces[MAX_SCID];
    struct lsquic_rechist       ifc_rechist[N_PNS];
    /* App PNS only, used to calculate was_missing: */
    lsquic_packno_t             ifc_max_ackable_packno_in;
    struct lsquic_send_ctl      ifc_send_ctl;
    struct lsquic_conn_public   ifc_pub;
    lsquic_alarmset_t           ifc_alset;
    struct lsquic_set64         ifc_closed_stream_ids[N_SITS];
    lsquic_stream_id_t          ifc_n_created_streams[N_SDS];
    /* Not including the value stored in ifc_max_allowed_stream_id: */
    lsquic_stream_id_t          ifc_max_allowed_stream_id[N_SITS];
    uint64_t                    ifc_closed_peer_streams[N_SDS];
    /* Maximum number of open stream initiated by peer: */
    unsigned                    ifc_max_streams_in[N_SDS];
    uint64_t                    ifc_max_stream_data_uni;
    enum ifull_conn_flags       ifc_flags;
    enum more_flags             ifc_mflags;
    enum send_flags             ifc_send_flags;
    enum send_flags             ifc_delayed_send;
    struct {
        uint64_t    streams_blocked[N_SDS];
    }                           ifc_send;
    struct conn_err             ifc_error;
    unsigned                    ifc_n_delayed_streams;
    unsigned                    ifc_n_cons_unretx;
    const struct prio_iter_if  *ifc_pii;
    char                       *ifc_errmsg;
    struct lsquic_engine_public
                               *ifc_enpub;
    const struct lsquic_engine_settings
                               *ifc_settings;
    STAILQ_HEAD(, stream_id_to_ss)
                                ifc_stream_ids_to_ss;
    lsquic_time_t               ifc_created;
    lsquic_time_t               ifc_saved_ack_received;
    lsquic_packno_t             ifc_max_ack_packno[N_PNS];
    lsquic_packno_t             ifc_max_non_probing;
    struct {
        uint64_t    max_stream_send;
        uint8_t     ack_exp;
    }                           ifc_cfg;
    int                       (*ifc_process_incoming_packet)(
                                                struct ietf_full_conn *,
                                                struct lsquic_packet_in *);
    /* Number ackable packets received since last ACK was sent: */
    unsigned                    ifc_n_slack_akbl[N_PNS];
    unsigned                    ifc_n_slack_all;    /* App PNS only */
    unsigned                    ifc_max_retx_since_last_ack;
    unsigned short              ifc_max_udp_payload;    /* Cached TP */
    lsquic_time_t               ifc_max_ack_delay;
    uint64_t                    ifc_ecn_counts_in[N_PNS][4];
    lsquic_stream_id_t          ifc_max_req_id;
    struct hcso_writer          ifc_hcso;
    struct http_ctl_stream_in   ifc_hcsi;
    struct qpack_enc_hdl        ifc_qeh;
    struct qpack_dec_hdl        ifc_qdh;
    struct {
        uint64_t    header_table_size,
                    qpack_blocked_streams;
    }                           ifc_peer_hq_settings;
    struct dcid_elem           *ifc_dces[MAX_IETF_CONN_DCIDS];
    TAILQ_HEAD(, dcid_elem)     ifc_to_retire;
    unsigned                    ifc_n_to_retire;
    unsigned                    ifc_scid_seqno;
    lsquic_time_t               ifc_scid_timestamp[MAX_SCID];
    /* Last 8 packets had ECN markings? */
    uint8_t                     ifc_incoming_ecn;
    unsigned char               ifc_cur_path_id;    /* Indexes ifc_paths */
    unsigned char               ifc_used_paths;     /* Bitmask */
    unsigned char               ifc_mig_path_id;
    /* ifc_active_cids_limit is the maximum number of CIDs at any one time this
     * endpoint is allowed to issue to peer.  If the TP value exceeds cn_n_cces,
     * it is reduced to it.  ifc_active_cids_count tracks how many CIDs have
     * been issued.  It is decremented each time a CID is retired.
     */
    unsigned char               ifc_active_cids_limit;
    unsigned char               ifc_active_cids_count;
    unsigned char               ifc_first_active_cid_seqno;
    unsigned char               ifc_ping_unretx_thresh;
    unsigned                    ifc_last_retire_prior_to;
    unsigned                    ifc_ack_freq_seqno;
    unsigned                    ifc_last_pack_tol;
    unsigned                    ifc_last_calc_pack_tol;
#if LSQUIC_CONN_STATS
    unsigned                    ifc_min_pack_tol_sent;
    unsigned                    ifc_max_pack_tol_sent;
#endif
    unsigned                    ifc_max_ack_freq_seqno; /* Incoming */
    unsigned short              ifc_min_dg_sz,
                                ifc_max_dg_sz;
    lsquic_time_t               ifc_last_live_update;
    struct conn_path            ifc_paths[N_PATHS];
    union {
        struct {
            struct lsquic_stream   *crypto_streams[N_ENC_LEVS];
            struct ver_neg
                        ifcli_ver_neg;
            uint64_t    ifcli_max_push_id;
            uint64_t    ifcli_min_goaway_stream_id;
            enum {
                IFCLI_PUSH_ENABLED    = 1 << 0,
                IFCLI_HSK_SENT_OR_DEL = 1 << 1,
            }           ifcli_flags;
            unsigned    ifcli_packets_out;
        }                           cli;
        struct {
            uint64_t    ifser_max_push_id;
            uint64_t    ifser_next_push_id;
            enum {
                IFSER_PUSH_ENABLED    = 1 << 0,
                IFSER_MAX_PUSH_ID     = 1 << 1,   /* ifser_max_push_id is set */
            }           ifser_flags;
        }                           ser;
    }                           ifc_u;
    lsquic_time_t               ifc_idle_to;
    lsquic_time_t               ifc_ping_period;
    struct lsquic_hash         *ifc_bpus;
    uint64_t                    ifc_last_max_data_off_sent;
    struct packet_tolerance_stats
                                ifc_pts;
#if LSQUIC_CONN_STATS
    struct conn_stats           ifc_stats,
                               *ifc_last_stats;
#endif
    struct ack_info             ifc_ack;
};

#define CUR_CPATH(conn_) (&(conn_)->ifc_paths[(conn_)->ifc_cur_path_id])
#define CUR_NPATH(conn_) (&(CUR_CPATH(conn_)->cop_path))
#define CUR_DCID(conn_) (&(CUR_NPATH(conn_)->np_dcid))

#define DCES_END(conn_) ((conn_)->ifc_dces + (sizeof((conn_)->ifc_dces) \
                                            / sizeof((conn_)->ifc_dces[0])))

#define NPATH2CPATH(npath_) ((struct conn_path *) \
            ((char *) (npath_) - offsetof(struct conn_path, cop_path)))

#if LSQUIC_CONN_STATS
#define CONN_STATS(what_, count_) do {                                  \
    conn->ifc_stats.what_ += (count_);                                  \
} while (0)
#else
#define CONN_STATS(what_, count_)
#endif

static const struct ver_neg server_ver_neg;

static const struct conn_iface *ietf_full_conn_iface_ptr;
static const struct conn_iface *ietf_full_conn_prehsk_iface_ptr;

static int
process_incoming_packet_verneg (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static int
process_incoming_packet_fast (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *, struct lsquic_packet_in *);

static int
handshake_ok (struct lsquic_conn *);

static void
ignore_init (struct ietf_full_conn *);

static void
ignore_hsk (struct ietf_full_conn *);

static unsigned
ietf_full_conn_ci_n_avail_streams (const struct lsquic_conn *);

static void
ietf_full_conn_ci_destroy (struct lsquic_conn *);

static int
insert_new_dcid (struct ietf_full_conn *, uint64_t seqno,
    const lsquic_cid_t *, const unsigned char *token, int update_cur_dcid);

static struct conn_cid_elem *
find_cce_by_cid (struct ietf_full_conn *, const lsquic_cid_t *);

static void
mtu_probe_too_large (struct ietf_full_conn *, const struct lsquic_packet_out *);

static int
apply_trans_params (struct ietf_full_conn *, const struct transport_params *);

static void
packet_tolerance_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now);

static int
init_http (struct ietf_full_conn *);

static unsigned
highest_bit_set (unsigned sz)
{
#if __GNUC__
    unsigned clz = __builtin_clz(sz);
    return 31 - clz;
#else
    unsigned n, y;
    n = 32;
    y = sz >> 16;   if (y) { n -= 16; sz = y; }
    y = sz >>  8;   if (y) { n -=  8; sz = y; }
    y = sz >>  4;   if (y) { n -=  4; sz = y; }
    y = sz >>  2;   if (y) { n -=  2; sz = y; }
    y = sz >>  1;   if (y) return 31 - n + 2;
    return 31 - n + sz;
#endif
}

