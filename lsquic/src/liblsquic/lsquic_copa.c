/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE.chrome file.

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_minmax.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_copa.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_util.h"
#include "lsquic_malo.h"
#include "lsquic_crand.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"

#define LSQUIC_LOGGER_MODULE LSQLM_BBR
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(bbr->bbr_conn_pub->lconn)
#include "lsquic_logger.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ms(val_) ((val_) * 1000)
#define sec(val_) ((val_) * 1000 * 1000)

// lzj: copy from xquic copa
#define kDefaultTCPMSS 1460
#define XQC_COPA_MSS                   (kDefaultTCPMSS) //lzj: XQC_MSS -> kDefaultTCPMSS
#define XQC_COPA_MIN_WIN               (4 * XQC_COPA_MSS)
#define XQC_COPA_MAX_INIT_WIN          (100 * XQC_COPA_MSS)
#define XQC_COPA_INIT_WIN              (32 * XQC_COPA_MSS)
#define XQC_COPA_RTT_MIN_WINDOW        (10000000) /* 10s */
#define XQC_COPA_RTT_MAX_WINDOW        (4) /* 4 RTTs */
#define XQC_COPA_RTT_STA_WINDOW        (0.5) /* 0.5 RTT */
/* mode switching threshold: 5 RTTs */
#define XQC_COPA_MS_THRESHOLD          (5)
/* the default value recommended by Facebook */
#define XQC_COPA_DEFAULT_DELTA         (0.5) //0.05
/* the upper bound of delta for the competitive mode */
#define XQC_COPA_DEFAULT_DELTA_MAX     (0.5) //0.5
#define XQC_COPA_MAX_DELTA             (1.0) //1.0
#define XQC_COPA_INF_U64               (~0ULL)
#define XQC_COPA_INIT_VELOCITY         (1.0)
#define XQC_COPA_MAX_RATE              (1.0 * (~0ULL))
#define XQC_COPA_USEC2SEC              (1000000)
#define XQC_COPA_DEFAULT_DELTA_AI_UNIT (1.0)

/* interface to adapt to xquic */
#define xqc_min(a, b) ((a) < (b) ? (a) : (b))
#define xqc_max(a, b) ((a) > (b) ? (a) : (b))
#define xqc_clamp(a, min, max) xqc_max(xqc_min(a, max), min)

static uint64_t
xqc_win_filter_get(const struct minmax *w)
{
    return w->samples[0].value;
    //return w->s[0].val;
}

static uint64_t
xqc_win_filter_reset(struct minmax *w, uint64_t t, uint64_t nval)
{
    struct minmax_sample nsample = {.time = t, .value = nval };
    w->samples[0] = w->samples[1] = w->samples[2] = nsample;
    return w->samples[0].value;
}

static uint64_t
xqc_win_filter_update(struct minmax *w, uint64_t win,
                      struct minmax_sample *nsample)
{
    uint32_t dt = nsample->time - w->samples[0].time;

    if (dt > win) {
        w->samples[0] = w->samples[1];
        w->samples[1] = w->samples[2];
        w->samples[2] = *nsample;
        if (nsample->time - w->samples[0].time > win) {
            w->samples[0] = w->samples[1];
            w->samples[1] = w->samples[2];
            w->samples[2] = *nsample;
        }

    } else if ((w->samples[1].time == w->samples[0].time) && dt > win/4) {
        w->samples[2] = w->samples[1] = *nsample;

    } else if ((w->samples[2].time == w->samples[1].time) && dt > win/2) {
        w->samples[2] = *nsample;
    }

    return w->samples[0].value;
}

uint64_t
xqc_win_filter_max(struct minmax *w, uint64_t win,
                   uint64_t t, uint64_t nval)
{
    struct minmax_sample nsample = {.time = t, .value = nval};

    if ((nval >= w->samples[0].value) || (t - w->samples[2].time > win)) {
        return xqc_win_filter_reset(w, t, nval);
    }

    if (nval >= w->samples[1].value) {
        w->samples[2] = w->samples[1] = nsample;

    } else if (nval >= w->samples[2].value) {
        w->samples[2] = nsample;
    }

    return xqc_win_filter_update(w, win, &nsample);
}

uint64_t
xqc_win_filter_min(struct minmax *w, uint64_t win,
                   uint64_t t, uint64_t nval)
{
    struct minmax_sample nsample = {.time = t, .value = nval};

    if ((nval <= w->samples[0].value) || (t - w->samples[2].time > win)) {
        return xqc_win_filter_reset(w, t, nval);
    }

    if (nval <= w->samples[1].value) {
        w->samples[2] = w->samples[1] = nsample;

    } else if (nval <= w->samples[2].value) {
        w->samples[2] = nsample;
    }

    return xqc_win_filter_update(w, win, &nsample);
}

//xqc_usec_t
//xqc_now()
//{
//    /* get microsecond unit time */
//    struct timeval tv;
//    gettimeofday(&tv, NULL);
//    xqc_usec_t ul = tv.tv_sec * (xqc_usec_t)1000000 + tv.tv_usec;
//    return  ul;
//}



static void
xqc_copa_set_pacing_rate(struct lsquic_copa *copa)
{
    /* 2*cwnd / rtt_standing */
    lsquic_time_t rtt_standing = xqc_win_filter_get(&copa->rtt_standing);
    if (rtt_standing == XQC_COPA_INF_U64) {
        /* initialization */
        //rtt_standing = copa->ctl_ctx->ctl_srtt;
        rtt_standing = lsquic_rtt_stats_get_srtt(copa->copa_rtt_stats); //lzj-todo
    }
    if (rtt_standing == 0) {
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN,
//                "|copa|rtt_standing_error:%ui|", rtt_standing);
        /* initialization */

//        printf("rtt_standing to fixed\n"); //lzj-tests: only hit 1 time
        rtt_standing = 250 * 1000;
        xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);
    }
    copa->pacing_rate = ((copa->cwnd_bytes) * XQC_COPA_USEC2SEC) << 1;
    copa->pacing_rate /= rtt_standing;
//    copa->pacing_rate /= 8;
    copa->pacing_rate = xqc_max(copa->pacing_rate, XQC_COPA_MSS);
//    copa->pacing_rate = 1; //lzj:

//    printf("rtt_standing is %lld\n", rtt_standing);
//    printf("cwnd_bytes is %lld\n", copa->cwnd_bytes);
//    printf("pacing_rate is %lld\n", copa->pacing_rate);
}

//static size_t
//xqc_copa_size()
//{
//    return sizeof(struct lsquic_copa);
//}

static void
init_copa (struct lsquic_copa *copa)
{
    //lsquic_copa *copa = (lsquic_copa*)cong;
    copa->init_cwnd_bytes = XQC_COPA_INIT_WIN;
    copa->delta_base = XQC_COPA_DEFAULT_DELTA;
    copa->delta_max  = XQC_COPA_DEFAULT_DELTA_MAX;
    copa->delta_ai_unit = XQC_COPA_DEFAULT_DELTA_AI_UNIT;

    xqc_win_filter_reset(&copa->rtt_min, 0, XQC_COPA_INF_U64);
    xqc_win_filter_reset(&copa->rtt_max, 0, 0);
    xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);

    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->curr_dir = COPA_UNDEF; /* slow start */
    copa->prev_dir = COPA_UNDEF;
    copa->same_dir_cnt = 0;
    copa->mode = COPA_DELAY_MODE;
    copa->t_last_delay_min = 0;
    copa->in_slow_start = 1;

    /* lzj-todo
    copa->ctl_ctx = ctl_ctx;
    */

    // default init setting
    int customize_on = 1;
    int init_cwnd = 32;
    double copa_delta_ai_unit = 1.0;
    double copa_delta_max = 0;
    double copa_delta_base = 0.05;
//    double copa_delta_base = 0.001;

    if (customize_on) {
        copa->init_cwnd_bytes = xqc_clamp(init_cwnd * XQC_COPA_MSS,
                                          XQC_COPA_MIN_WIN,
                                          XQC_COPA_MAX_INIT_WIN);
        if (copa_delta_base > 0) {
            copa->delta_base = copa_delta_base;
        }

        if (copa_delta_max > 0) {
            copa->delta_max = copa_delta_max;
        }

        if (copa_delta_ai_unit > 1.0) {
            copa->delta_ai_unit = copa_delta_ai_unit;
        }

        copa->delta_max = xqc_min(copa->delta_max, XQC_COPA_MAX_DELTA);
        copa->delta_base = xqc_min(copa->delta_base, copa->delta_max);
    }
    copa->delta = copa->delta_base; //lzj: success 0.001
    copa->cwnd_bytes = copa->init_cwnd_bytes;
    copa->last_round_cwnd_bytes = 0;
    xqc_copa_set_pacing_rate(copa);
    copa->recovery_start_time = 0;
    copa->next_round_delivered = 0;
    copa->round_cnt = 0;
    copa->round_start = 0;
    copa->cwnd_adjustment_accumulated = 0;
}


static void
lsquic_copa_init (void *cong_ctl, const struct lsquic_conn_public *conn_pub,
                  enum quic_ft_bit retx_frames) //lzj:used by bbr
{
    struct lsquic_copa *const copa = cong_ctl;
    copa->copa_conn_pub = conn_pub;

    // use conn_pub or retx_frames
//    lsquic_bw_sampler_init(&copa->bbr_bw_sampler, conn_pub->lconn, retx_frames);
//    bbr->bbr_rtt_stats = &conn_pub->rtt_stats;

    copa->copa_rtt_stats = &conn_pub->rtt_stats;

    init_copa(copa);

    LSQ_DEBUG("initialized");
}


static void
lsquic_copa_reinit (void *cong_ctl)
{
    struct lsquic_copa *const copa = cong_ctl;

    init_copa(copa);

    LSQ_DEBUG("re-initialized");
}

static void
lsquic_copa_loss(void *cong, lsquic_time_t largest_lost_sent_time)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    /* already in recovery mode */
//    lsquic_time_t lost_sent_time = ~(uint64_t)0; // lzj-todo: future need accurate value
    lsquic_time_t lost_sent_time = largest_lost_sent_time;
    if (lost_sent_time < copa->recovery_start_time) {
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|loss_before_recovery|loss_sent_time:%ui|"
//                "recovery_start_time:%ui|",
//                lost_sent_time, copa->recovery_start_time);

//        printf("copa lost but not deal\n");
    } else {
        /* start a new recovery epoch */
        //copa->recovery_start_time = xqc_monotonic_timestamp();
        copa->recovery_start_time = lsquic_time_now(); // lzj-todo: future need accurate value
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|recovery_start_at:%ui|", copa->recovery_start_time);
        if (copa->mode == COPA_COMPETITIVE_MODE) {
            /*
             * multiplicative decrease on 1 / delta,
             * once per epoch (RTT) at most.
             */
            copa->delta = xqc_min(copa->delta * 2, copa->delta_max);
//            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                    "|copa|MD_on_delta:%.4f|", copa->delta);
        }
    }

//    XQC_COPA_LOG_STATE("on_lost", XQC_LOG_DEBUG);
    LSQ_DEBUG("on_lost");
//    printf("copa lost\n");
    return;
}

static inline void
xqc_copa_handle_sudden_direction_change(struct lsquic_copa *copa,
                                        copa_direction_t new_dir)
{
    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->same_dir_cnt = 0;
    copa->last_round_cwnd_bytes = copa->cwnd_bytes;
    copa->prev_dir = copa->curr_dir;
    copa->curr_dir = new_dir;
//    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//            "|copa|handle_sudden_direction_change|cwnd_bytes:%ui|"
//            "last_round_cwnd_bytes:%ui|curr_dir:%d|prev_dir:%d|",
//            copa->cwnd_bytes, copa->last_round_cwnd_bytes,
//            copa->curr_dir, copa->prev_dir);
}

//static void
//lsquic_copa_ack(void *cong, xqc_sample_t *sampler)
static void
lsquic_copa_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  unsigned n_bytes, lsquic_time_t now_time, int app_limited,
                  lsquic_time_t recv_time_cur_ack, uint64_t size_total_sent_prior_ack, uint64_t size_total_sent_curr_ack)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong_ctl;
//    lsquic_time_t  largest_pkt_sent_time = sampler->po_sent_time;
    lsquic_time_t  largest_pkt_sent_time = packet_out->po_sent;
//    uint32_t    newly_acked_bytes = sampler->acked;
    uint32_t    newly_acked_bytes = size_total_sent_curr_ack - size_total_sent_prior_ack;
//    printf("newly_acked_bytes is %d\n", newly_acked_bytes);
//    lsquic_time_t  ack_recv_time = sampler->now;
    lsquic_time_t  ack_recv_time = recv_time_cur_ack;
//    lsquic_time_t  latest_rtt = copa->ctl_ctx->ctl_latest_rtt;
//    lsquic_time_t  srtt = copa->ctl_ctx->ctl_srtt;
//    lsquic_time_t  latest_rtt = lsquic_rtt_stats_get_srtt(copa->copa_rtt_stats); //lzj-todo
    lsquic_time_t  latest_rtt = now_time - packet_out->po_sent;
    lsquic_time_t  srtt = lsquic_rtt_stats_get_srtt(copa->copa_rtt_stats);

//    printf("latest_rtt is %lld\n", latest_rtt);
//    printf("srtt is %lld\n", srtt);

    lsquic_time_t  rtt_min_win = XQC_COPA_RTT_MIN_WINDOW;
    lsquic_time_t  rtt_sta_win = XQC_COPA_RTT_STA_WINDOW * srtt;
    lsquic_time_t  rtt_max_win = XQC_COPA_RTT_MAX_WINDOW;

//    XQC_COPA_LOG_STATE("before_on_ack", XQC_LOG_DEBUG);

//    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, "|copa|sampler|"
//                                                         "ack_time:%ui|prior_delivered:%ui|delivered:%ud|acked:%ud|"
//                                                         "bytes_inflight:%ud|prior_inflight:%ud|rtt:%ui|"
//                                                         "is_applimit:%ud|srtt:%ui|loss:%ud|total_acked:%ui|",
//            sampler->now, sampler->prior_delivered, sampler->delivered,
//            sampler->acked, sampler->bytes_inflight, sampler->prior_inflight,
//            sampler->rtt, sampler->is_app_limited, sampler->srtt,
//            sampler->loss, sampler->total_acked);

    /* check if we have recovered from losses */
    if (copa->recovery_start_time > 0
        && largest_pkt_sent_time > copa->recovery_start_time)
    {
        copa->recovery_start_time = 0;
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|loss_recovered|sent_time:%ui|ack_time:%ui|",
//                largest_pkt_sent_time, ack_recv_time);
    }
    /*
     * Copa does not care about if it is in recovery mode.
     * It always adjusts cwnd with the AIAD law.
     */

    copa->round_start = 0;

    /* update packet-timed round trip counter */
    if (size_total_sent_curr_ack >= copa->next_round_delivered) {
        copa->round_cnt++;
        copa->next_round_delivered = size_total_sent_curr_ack;
        copa->round_start = 1;
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|round_cnt_advanced|round_cnt:%ud|"
//                "next_round_delivered:%ui|",
//                copa->round_cnt, copa->next_round_delivered);
    }

    /* update delta */
    if (copa->mode == COPA_COMPETITIVE_MODE && copa->round_start) {
        /*
         * additive increase on 1 / delta.
         * 1 / delta = 1 / delta + 1 = (delta + 1) / delta
         */
        copa->delta = copa->delta / (copa->delta * copa->delta_ai_unit + 1);
    }

    /* Once we have a valid ack sample, rtt statistics must not be zero */
    if (latest_rtt == 0) {
        /* invalid latest_rtt */
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN,
//                "|copa|invalid_latest_rtt:%ui|ack_time:%ui|",
//                ack_recv_time, latest_rtt);
        goto on_ack_end;
    }

    /* update rtt statistics */
    xqc_win_filter_min(&copa->rtt_min, rtt_min_win,
                       ack_recv_time, latest_rtt);
    xqc_win_filter_min(&copa->rtt_standing, rtt_sta_win,
                       ack_recv_time, latest_rtt);
    xqc_win_filter_max(&copa->rtt_max, rtt_max_win,
                       copa->round_cnt, latest_rtt);

    /* calculate data */
    double     target_rate, current_rate;
    lsquic_time_t rtt_standing, rtt_min, rtt_max, delay;

    rtt_standing = xqc_win_filter_get(&copa->rtt_standing);
    rtt_min = xqc_win_filter_get(&copa->rtt_min);

//    rtt_min = 2000;

    if (rtt_standing < rtt_min) {
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN,
//                "|copa|negative_queuing_delay|srtt:%ui|"
//                "rtt_standing:%ui|rtt_min:%ui|",
//                srtt, rtt_standing, rtt_min);
        goto on_ack_end;
    }

    delay = rtt_standing - rtt_min;

    /* update the time when a low queuing delay is observed */
    /* <= guarantees the update the timestamp when delay is zero */
    if (delay <= ((xqc_win_filter_get(&copa->rtt_max) - rtt_min) / 10)) {
        copa->t_last_delay_min = ack_recv_time;
        if (copa->mode != COPA_DELAY_MODE) {
            /* switch to delay mode and reset delta */
            copa->mode = COPA_DELAY_MODE;
            copa->delta = copa->delta_base;
        }
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|low_delay_is_observed_at:%ui|mode:%d|",
//                ack_recv_time, copa->mode);
    }

    if (delay == 0) {
        /* no queuing delay */
        target_rate = XQC_COPA_MAX_RATE;

    } else {
        target_rate = XQC_COPA_MSS * 1.0
                      * XQC_COPA_USEC2SEC / (delay * copa->delta);
//        printf("target_rate is %f\n", target_rate);
    }

    target_rate /= 8;

    current_rate = copa->cwnd_bytes * 1.0 * XQC_COPA_USEC2SEC / rtt_standing;

//    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//            "|copa|rate_generated|target_rate:%.4f|current_rate:%.4f|"
//            "delay:%ui|",
//            target_rate, current_rate, delay);

//    printf("current_rate is %f, target_rate is %f, rtt_standing is %lld\n", current_rate, target_rate, rtt_standing);

    /* slow start */
    if (copa->in_slow_start) {
        if (current_rate > target_rate) {
            /* exit slow start */
            copa->in_slow_start = 0;
//            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                    "|copa|slow_start_exit|");
            /* @TODO: we may set Copa's direction to DOWN at here */

        } else {
            /*
             * We make sure that cwnd must NOT increase by more than 2x
             * at a time.
             */
            if (newly_acked_bytes > copa->cwnd_bytes) {
                copa->cwnd_bytes <<= 1;
            } else {
                copa->cwnd_bytes += newly_acked_bytes;
            }
            //printf("cwnd_bytes is %lld\n", copa->cwnd_bytes); //lzj-test: hit 5 times
            xqc_copa_set_pacing_rate(copa);
            goto on_ack_end;
        }
    }

    /* steady phase start */

    /* check mode switching conditions at round start */
    /* @TODO: may switch to packet-timed rounds for t_last_delay_min */
    if (copa->round_start
        && copa->mode != COPA_COMPETITIVE_MODE
        && ((ack_recv_time - copa->t_last_delay_min)
            >= (XQC_COPA_MS_THRESHOLD * srtt)))
    {
        copa->mode = COPA_COMPETITIVE_MODE;
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|switch_to_competitive_mode_at:%ui|"
//                "round_cnt:%ud|t_last_delay_min:%ui|",
//                ack_recv_time, copa->round_cnt, copa->t_last_delay_min);
    }

    /* check & update the direction for cwnd adjustment */
    if (copa->round_start) {
        copa_direction_t new_dir;
        if (copa->cwnd_bytes > copa->last_round_cwnd_bytes) {
            new_dir = COPA_UP;

        } else {
            new_dir = COPA_DOWN;
        }

        copa->last_round_cwnd_bytes = copa->cwnd_bytes;

        if (new_dir != copa->curr_dir) {
            copa->v = XQC_COPA_INIT_VELOCITY;
            copa->same_dir_cnt = 0;

        } else {
            copa->same_dir_cnt++;
        }

        copa->prev_dir = copa->curr_dir;
        copa->curr_dir = new_dir;

//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|direction_update|curr_dir:%d|prev_dir:%d|"
//                "same_dir_cnt:%ud|velocity:%.4f|",
//                copa->curr_dir, copa->prev_dir, copa->same_dir_cnt, copa->v);

        /*
        * if cnt == 3, it means the direction remains the same for
        * a bit less than 3 RTTs.
        */
        if (copa->same_dir_cnt > 3) {
            /*
            * double v every RTT once the direction has remained the same
            * for 3 RTTs.
            */
            copa->v *= 2.0;
//            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                    "|copa|velocity_update|velocity:%.4f|", copa->v);
        }

        /*
         * if v makes cwnd grow faster than slow start,
         * we should reduce it
         */
        if ((copa->v * XQC_COPA_MSS) >= (copa->delta * copa->cwnd_bytes)) {
            copa->v /= 2.0;
//            printf("copa v is: %f", copa->v);
//            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                    "|copa|velocity_too_large|velocity:%.4f|", copa->v);
        }
        /* but, we need to ensure v is at least XQC_COPA_INIT_VELOCITY */
        copa->v = xqc_max(copa->v, XQC_COPA_INIT_VELOCITY);
    }

    int aiad_sign;
    /* update cwnd */
    if (current_rate > target_rate) {
        /*
         * According to Facebook's Copa implementation, they reset the velocity
         * to 1.0, if the current direction indicates the opposite cwnd
         * adjustment direction of what current_rate and target_rate indicate
         * and the velocity is greater than XQC_COPA_INIT_VELOCITY.
         */
        if (copa->curr_dir != COPA_DOWN && copa->v > XQC_COPA_INIT_VELOCITY) {
            xqc_copa_handle_sudden_direction_change(copa, COPA_DOWN);
        }
        aiad_sign = -1;

    } else {
        if (copa->curr_dir != COPA_UP && copa->v > XQC_COPA_INIT_VELOCITY) {
            xqc_copa_handle_sudden_direction_change(copa, COPA_UP);
        }
        aiad_sign = 1;
    }

    uint64_t numerator_bytes = (uint64_t)(copa->v * newly_acked_bytes
                                          / copa->delta);
//    printf("numerator_bytes is %lld", numerator_bytes);s
    /* v * delta should be always greater than 1.0 */
    if (numerator_bytes == 0) {
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN,
//                "|copa|acked_bytes_too_less|velocity:%.4f|delta:%.4f|"
//                "newly_acked_bytes:%ui|",
//                copa->v, copa->delta, newly_acked_bytes);
    }
    copa->cwnd_adjustment_accumulated += (aiad_sign * numerator_bytes);
//    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//            "|copa|aiad_bytes_accumulated|aiad_sign:%d|numertor_bytes:%ui|"
//            "cwnd_adjustment_accumulated:%i|",
//            aiad_sign, numerator_bytes, copa->cwnd_adjustment_accumulated);

    if (copa->cwnd_adjustment_accumulated > 0
        && copa->cwnd_adjustment_accumulated >= copa->cwnd_bytes) {
        int64_t d = copa->cwnd_adjustment_accumulated / copa->cwnd_bytes;
        copa->cwnd_adjustment_accumulated -= (d * copa->cwnd_bytes);
        copa->cwnd_bytes += (d * XQC_COPA_MSS);
        //printf("cwnd_bytes is %lld\n", copa->cwnd_bytes); //lzj-test: always hit
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|aiad_bytes_applied|UP|cwnd_bytes:%ui|"
//                "cwnd_adjustment_accumulated:%i|",
//                copa->cwnd_bytes, copa->cwnd_adjustment_accumulated);

    } else if (copa->cwnd_adjustment_accumulated < 0
               && copa->cwnd_adjustment_accumulated <= -copa->cwnd_bytes) {
        int64_t d = -copa->cwnd_adjustment_accumulated / copa->cwnd_bytes;
        copa->cwnd_adjustment_accumulated += (d * copa->cwnd_bytes);
        /* avoid underflow */
        d = d * XQC_COPA_MSS;
        if (d <= copa->cwnd_bytes) {
            copa->cwnd_bytes -= d;
        } else {
            copa->cwnd_bytes = 0;
        }
//        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG,
//                "|copa|aiad_bytes_applied|DOWN|cwnd_bytes:%ui|"
//                "cwnd_adjustment_accumulated:%i|",
//                copa->cwnd_bytes, copa->cwnd_adjustment_accumulated);
    }

    copa->cwnd_bytes = xqc_max(XQC_COPA_MIN_WIN, copa->cwnd_bytes);
    xqc_copa_set_pacing_rate(copa);

    on_ack_end:
//    XQC_COPA_LOG_STATE("after_on_ack", XQC_LOG_DEBUG);
    return;
}

static uint64_t
lsquic_copa_get_cwnd(void *cong)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    return copa->cwnd_bytes;
}

static void
xqc_copa_reset_cwnd(void *cong)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    /*
     * @NOTE: We reinitialize Copa and do slow start again. After recovering
     * from a persistent congestion event, the network path may have changed
     * significantly. Therefore, the safest way to do congestion control is to
     * cut the cwnd to the minimal value and re-probe the network path by
     * slow start.
     */
    xqc_win_filter_reset(&copa->rtt_min, 0, XQC_COPA_INF_U64);
    xqc_win_filter_reset(&copa->rtt_max, 0, 0);
    xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);
    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->curr_dir = COPA_UNDEF; /* slow start */
    copa->prev_dir = COPA_UNDEF;
    copa->same_dir_cnt = 0;
    copa->mode = COPA_DELAY_MODE;
    copa->t_last_delay_min = 0;
    copa->in_slow_start = 1;
    copa->delta = copa->delta_base;
    copa->recovery_start_time = 0;
    copa->cwnd_adjustment_accumulated = 0;
    copa->cwnd_bytes = XQC_COPA_MIN_WIN;
    xqc_copa_set_pacing_rate(copa);

//    XQC_COPA_LOG_STATE("persistent_congestion", XQC_LOG_DEBUG);
    return;
}

static int
xqc_copa_in_slow_start(void *cong)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    return copa->in_slow_start;
}

static void
xqc_copa_restart_from_idle(void *cong, uint64_t arg)
{
    /*
     * @TODO: may do something here in the future,
     * e.g. resetting congestion state and restarting from slow start.
     */
    return;
}

static int
xqc_copa_in_recovery(void *cong)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    return copa->recovery_start_time > 0;
}

/* @TODO: use u64 for pacing rate all the time */
static uint64_t
lsquic_copa_get_pacing_rate(void *cong, int in_recovery)
{
    struct lsquic_copa *copa = (struct lsquic_copa *)cong;
    return copa->pacing_rate;
}

static void
lsquic_copa_timeout (void *cong_ctl)
{
    struct lsquic_copa *const cubic = cong_ctl;
//    printf("Copa TIMEOUT\n");
}

static void
lsquic_copa_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    struct lsquic_copa *const copa = cong_ctl;
}

static void
lsquic_copa_cleanup (void *cong_ctl)
{
}

const struct cong_ctl_if lsquic_cong_copa_if =
{
        .cci_ack           = lsquic_copa_ack, //xquic copa and bbr both need "xqc_sample_t"
//        .cci_begin_ack     = lsquic_bbr_begin_ack, //null, cubic and copa don't need
//        .cci_end_ack       = lsquic_bbr_end_ack, //null, cubic and copa don't need
        .cci_cleanup       = lsquic_copa_cleanup, //null, cubic and copa don't need
        .cci_get_cwnd      = lsquic_copa_get_cwnd, //ok
        .cci_init          = lsquic_copa_init, //xquic copa need "xqc_send_ctl_t" to get "->ctl_ctx->ctl_latest_rtt, ctl_srtt"
        .cci_pacing_rate   = lsquic_copa_get_pacing_rate, //ok
        .cci_loss          = lsquic_copa_loss, //xquic copa need "lsquic_time_t" to start new epoch
//        .cci_lost          = lsquic_bbr_lost, //null, cubic and copa don't need
        .cci_reinit        = lsquic_copa_reinit, //ok
        .cci_timeout       = lsquic_copa_timeout, //future, need to check what to do
//        .cci_sent          = lsquic_bbr_sent, //null, cubic and copa don't need
        .cci_was_quiet     = lsquic_copa_was_quiet, //future, need to check what to do
};