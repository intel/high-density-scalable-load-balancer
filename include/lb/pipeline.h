/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_PIPELINE_H__
#define __LB_PIPELINE_H__

#include "common.h"
#include "dpdk.h"
#include "lb/core.h"

enum lb_pl_next {
    LB_PL_NEXT_LOOKUP = 0,
    LB_PL_NEXT_IN_NEW = 1,
    LB_PL_NEXT_NEW = 2,
    LB_PL_NEXT_NEW_FNAT = 3,
    LB_PL_NEXT_OUT = 4,
};

enum lb_pl_stage {
    LB_PL_STAGE_INVALID = 0xFF,
    LB_PL_STAGE0 = 0,
    LB_PL_STAGE1 = 1,
    LB_PL_STAGE2 = 2,
    LB_PL_STAGE3 = 3,
    LB_PL_STAGE_IN_MAX  = 4,
    LB_PL_STAGE_OUT_MAX = 4,
    LB_PL_STAGE_MAX = 4,
};

struct lb_service;
struct lb_pl_cache;
typedef void (*lb_pl_cb_t)(struct lb_pl_cache *cache, struct lb_service *lbs);

struct lb_pl_cache {
    struct rte_mbuf *mbuf;
    union {
        void    *v1;
        uint32_t v1d;
    };
    union {
        void    *v2;
        uint32_t v2d;
    };
    union {
        void    *v3;
        uint32_t v3d;
    };
    union {
        void    *v4;
        uint32_t v4d;
        struct {
            uint16_t v4d_sport;
            uint16_t v4d_dport;
        };
    };
    struct lb_service *lbs;
    lb_pl_cb_t *pipe_cbs;
    uint8_t markid;
    uint8_t new_conn_bit_map_index;
    uint8_t nstages;
    uint8_t stage;
    uint8_t next;
    uint8_t tmp_value;
} __rte_cache_aligned;

#define LB_CACHE_DEPTH 2
struct lb_pipeline {
    //uint8_t curr_id;
	struct lb_pl_cache cache[LB_CACHE_DEPTH];
} __rte_cache_aligned;

typedef void (*lb_flow_cb_t)(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);

void lb_flow_pipeline_run(lb_pl_cb_t *pipe_cbs, uint32_t nstages,
            struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);

static inline void lb_cache_invalid(struct rte_mbuf *mbuf, struct lb_pl_cache *cache, char *msg)
{
    RTE_LOG(ERR, LB_RUNNING, "Drop invalid packet: %s\n", msg);
    rte_pktmbuf_free(mbuf);
    cache->stage = LB_PL_STAGE_INVALID;
}

int lb_init_pipe(void);

#endif
