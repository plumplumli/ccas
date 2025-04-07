/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_COPA_H
#define LSQUIC_COPA_H

#include "lsquic_int_types.h"
#include "lsquic_minmax.h"

typedef enum {
    COPA_UNDEF = 0,
    COPA_UP = 1,
    COPA_DOWN = 2,
} copa_direction_t;

typedef enum {
    COPA_DELAY_MODE = 0, /* to operate with copa's delay-based control */
    COPA_COMPETITIVE_MODE = 1, /* to co-exist with loss-based CCAs */
} copa_mode_t;

struct lsquic_copa
{
    //const struct lsquic_conn_public  *bbr_conn_pub;
    const struct lsquic_conn_public  *copa_conn_pub;

    /*
     * The parameter to control copa's tradeoff between latency and throughput.
     * Smaller values lead copa to more favor throughput over latency. 0.5 is
     * the default value recommended by the paper. It should be always greater
     * than zero.
     */
    double               delta_ai_unit;
    double               delta_base;
    double               delta_max;
    double               delta;
    uint64_t             init_cwnd_bytes;
    uint64_t             cwnd_bytes;
    uint64_t             last_round_cwnd_bytes;
    /* copa paces packets out at the rate of 2*cwnd/rtt_standing */
    uint64_t             pacing_rate;
    /* min rtt over the past srtt/2 period */
    struct minmax     rtt_standing; //lzj: xqc_win_filter_t -> minmax, minmax_sample
    /* min rtt over last 10s */
    struct minmax     rtt_min; //lzj: xqc_win_filter_t -> minmax, minmax_sample
    /* max rtt over the past four RTTs */
    struct minmax     rtt_max; //lzj: xqc_win_filter_t -> minmax, minmax_sample
    /* velocity */
    double               v;
    /* direction related states */
    copa_direction_t curr_dir, prev_dir;
    uint32_t             same_dir_cnt;
    /* copa mode */
    copa_mode_t      mode;
    /* when observed a low queuing delay over the past five RTTs */
    lsquic_time_t           t_last_delay_min; //lzj: xqc_usec_t -> lsquic_time_t
    /* in slow start */
    uint8_t           in_slow_start; //lzj: xqc_bool_t -> uint8_t
    /* loss recovery start time */
    lsquic_time_t           recovery_start_time; //lzj: xqc_usec_t -> lsquic_time_t
    /* for packet-timed round trip counting */
    uint32_t             round_cnt;
    uint64_t             next_round_delivered;
    uint8_t           round_start; //lzj: xqc_bool_t -> uint8_t
    int64_t              cwnd_adjustment_accumulated;

    /* connection/path context */
    //xqc_send_ctl_t      *ctl_ctx;
    const struct lsquic_rtt_stats          *copa_rtt_stats;

    /* LZJ: Buffer Probe */
    int loss_flag;
    lsquic_time_t loss_srtt;
};

//extern const xqc_cong_ctrl_callback_t xqc_copa_cb;
extern const struct cong_ctl_if lsquic_cong_copa_if;

#endif
