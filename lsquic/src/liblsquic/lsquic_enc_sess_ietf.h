/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_enc_sess_ietf.c -- Crypto session for IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#if LSQUIC_PREFERRED_ADDR
#include <arpa/inet.h>
#endif

#include <openssl/chacha.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "fiu-local.h"

#include "lsquic_types.h"
#include "lsquic_hkdf.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_util.h"
#include "lsquic_byteswap.h"
#include "lsquic_ev_log.h"
#include "lsquic_trans_params.h"
#include "lsquic_version.h"
#include "lsquic_ver_neg.h"
#include "lsquic_frab_list.h"
#include "lsquic_tokgen.h"
#include "lsquic_ietf.h"
#include "lsquic_alarmset.h"

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
//#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(enc_sess->esi_conn) //LZJ
#include "lsquic_logger.h"

#define N_HSK_PAIRS (N_ENC_LEVS - 1)

static const struct alpn_map {
    enum lsquic_version  version;
    const unsigned char *alpn;
} s_h3_alpns[] = {
        {   LSQVER_ID27, (unsigned char *) "\x05h3-27",     },
        {   LSQVER_ID29, (unsigned char *) "\x05h3-29",     },
        {   LSQVER_I001, (unsigned char *) "\x02h3",        },
        {   LSQVER_I002, (unsigned char *) "\x02h3",        },
        {   LSQVER_RESVED, (unsigned char *) "\x02h3",      },
};

struct enc_sess_iquic;
struct crypto_ctx;
struct crypto_ctx_pair;
struct header_prot;

static const int s_log_seal_and_open;
static char s_str[0x1000];

static const SSL_QUIC_METHOD cry_quic_method;

static int s_idx = -1;

static int
setup_handshake_keys (struct enc_sess_iquic *, const lsquic_cid_t *);

static void
free_handshake_keys (struct enc_sess_iquic *);

static struct stack_st_X509 *
iquic_esf_get_server_cert_chain (enc_session_t *);

static void
maybe_drop_SSL (struct enc_sess_iquic *);

static void
no_sess_ticket (enum alarm_id alarm_id, void *ctx,
                lsquic_time_t expiry, lsquic_time_t now);

static int
iquic_new_session_cb (SSL *, SSL_SESSION *);

static enum ssl_verify_result_t
verify_server_cert_callback (SSL *, uint8_t *out_alert);

static void
iquic_esfi_destroy (enc_session_t *);

#define SAMPLE_SZ 16

typedef void (*gen_hp_mask_f)(struct enc_sess_iquic *,
                              struct header_prot *, unsigned rw,
                              const unsigned char *sample, unsigned char *mask, size_t sz);

#define CHACHA20_KEY_LENGTH 32

struct header_prot
{
    gen_hp_mask_f       hp_gen_mask;
    enum enc_level      hp_enc_level;
    enum {
        HP_CAN_READ  = 1 << 0,
        HP_CAN_WRITE = 1 << 1,
    }                   hp_flags;
    union {
        EVP_CIPHER_CTX      cipher_ctx[2];                  /* AES */
        unsigned char       buf[2][CHACHA20_KEY_LENGTH];    /* ChaCha */
    }                   hp_u;
};

#define header_prot_inited(hp_, rw_) ((hp_)->hp_flags & (1 << (rw_)))


struct crypto_ctx
{
    enum {
        YK_INITED = 1 << 0,
    }                   yk_flags;
    EVP_AEAD_CTX        yk_aead_ctx;
    unsigned            yk_key_sz;
    unsigned            yk_iv_sz;
    unsigned char       yk_key_buf[EVP_MAX_KEY_LENGTH];
    unsigned char       yk_iv_buf[EVP_MAX_IV_LENGTH];
};


struct crypto_ctx_pair
{
    lsquic_packno_t     ykp_thresh;
    struct crypto_ctx   ykp_ctx[2]; /* client, server */
};


struct hsk_crypto
{
    struct crypto_ctx_pair pair;
    struct header_prot     hp;
};


struct label_set
{
    const char *key;
    const char *iv;
    const char *hp;
    int key_len;
    int iv_len;
    int hp_len;
};

static struct label_set hkdf_labels[2] =
{
        {   "quic key", "quic iv", "quic hp", 8, 7, 7 },
        {   "quicv2 key", "quicv2 iv", "quicv2 hp", 10, 9, 9 }
};

/* [draft-ietf-quic-tls-12] Section 5.3.6 */
static int
init_crypto_ctx (struct crypto_ctx *crypto_ctx, const EVP_MD *md,
                 const EVP_AEAD *aead, const unsigned char *secret,
                 size_t secret_sz, enum evp_aead_direction_t dir,
                 struct label_set *key_iv)
{
    crypto_ctx->yk_key_sz = EVP_AEAD_key_length(aead);
    crypto_ctx->yk_iv_sz = EVP_AEAD_nonce_length(aead);

    if (crypto_ctx->yk_key_sz > sizeof(crypto_ctx->yk_key_buf)
        || crypto_ctx->yk_iv_sz > sizeof(crypto_ctx->yk_iv_buf))
    {
        return -1;
    }

    lsquic_qhkdf_expand(md, secret, secret_sz, key_iv->key, key_iv->key_len,
                        crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, key_iv->iv, key_iv->iv_len,
                        crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    if (!EVP_AEAD_CTX_init_with_direction(&crypto_ctx->yk_aead_ctx, aead,
                                          crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz, IQUIC_TAG_LEN, dir))
        return -1;

    crypto_ctx->yk_flags |= YK_INITED;

    return 0;
}


static void
cleanup_crypto_ctx (struct crypto_ctx *crypto_ctx)
{
    if (crypto_ctx->yk_flags & YK_INITED)
    {
        EVP_AEAD_CTX_cleanup(&crypto_ctx->yk_aead_ctx);
        crypto_ctx->yk_flags &= ~YK_INITED;
    }
}


#define HP_BATCH_SIZE 8

struct enc_sess_iquic {
    struct lsquic_engine_public
            *esi_enpub;
    struct lsquic_conn *esi_conn;
    void **esi_streams;
    const struct crypto_stream_if *esi_cryst_if;
    const struct ver_neg
            *esi_ver_neg;
    SSL *esi_ssl;

    /* These are used for forward encryption key phase 0 and 1 */
    struct header_prot esi_hp;
    struct crypto_ctx_pair
            esi_pairs[2];
    /* These are used during handshake.  There are three of them. */
    struct hsk_crypto *esi_hsk_crypto;
    struct hsk_crypto *esi_vn_save;
    lsquic_packno_t esi_max_packno[N_PNS];
    lsquic_cid_t esi_odcid;
    lsquic_cid_t esi_rscid; /* Retry SCID */
    lsquic_cid_t esi_iscid; /* Initial SCID */
    unsigned esi_key_phase;
    enum {
        ESI_UNUSED0 = 1 << 0,
        ESI_LOG_SECRETS = 1 << 1,
        ESI_HANDSHAKE_OK = 1 << 2,
        ESI_ODCID = 1 << 3,
        ESI_ON_WRITE = 1 << 4,
        ESI_SERVER = 1 << 5,
        ESI_USE_SSL_TICKET = 1 << 6,
        ESI_HAVE_PEER_TP = 1 << 7,
        ESI_ALPN_CHECKED = 1 << 8,
        ESI_CACHED_INFO = 1 << 9,
        ESI_HSK_CONFIRMED = 1 << 10,
        ESI_WANT_TICKET = 1 << 11,
        ESI_RECV_QL_BITS = 1 << 12,
        ESI_SEND_QL_BITS = 1 << 13,
        ESI_RSCID = 1 << 14,
        ESI_ISCID = 1 << 15,
        ESI_RETRY = 1 << 16, /* Connection was retried */
        ESI_MAX_PACKNO_INIT = 1 << 17,
        ESI_MAX_PACKNO_HSK = ESI_MAX_PACKNO_INIT << PNS_HSK,
        ESI_MAX_PACKNO_APP = ESI_MAX_PACKNO_INIT << PNS_APP,
        ESI_HAVE_0RTT_TP = 1 << 20,
        ESI_SWITCH_VER = 1 << 21,
    } esi_flags;
    enum enc_level esi_last_w;
    unsigned esi_trasec_sz;
#ifndef NDEBUG
    char *esi_sni_bypass;
#endif
    const unsigned char *esi_alpn;
    /* Need MD and AEAD for key rotation */
    const EVP_MD *esi_md;
    const EVP_AEAD *esi_aead;
    struct {
        const char *cipher_name;
        int alg_bits;
    } esi_cached_info;
    /* Secrets are kept for key rotation */
    unsigned char esi_traffic_secrets[2][EVP_MAX_KEY_LENGTH];
    /* We never use the first two levels, so it seems we could reduce the
     * memory requirement here at the cost of adding some code.
     */
    struct frab_list esi_frals[N_ENC_LEVS];
    struct transport_params
            esi_peer_tp;
    struct lsquic_alarmset
            *esi_alset;
    unsigned esi_max_streams_uni;
    unsigned esi_hp_batch_idx;
    unsigned esi_hp_batch_packno_len[HP_BATCH_SIZE];
    unsigned esi_hp_batch_packno_off[HP_BATCH_SIZE];
    struct lsquic_packet_out *
            esi_hp_batch_packets[HP_BATCH_SIZE];
    unsigned char esi_hp_batch_samples[HP_BATCH_SIZE][SAMPLE_SZ];
    unsigned char esi_grease;
    signed char esi_have_forw;
};
