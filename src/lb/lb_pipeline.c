/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include "common.h"
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "lb/service.h"
#include "lb/dest.h"

#include "lb/pipeline.h"

#define this_pipeline     (RTE_PER_LCORE(pipeline))
static RTE_DEFINE_PER_LCORE(struct lb_pipeline, pipeline);

#define this_curr_id     (RTE_PER_LCORE(curr_id))
static RTE_DEFINE_PER_LCORE(uint32_t, curr_id);


static inline uint32_t lb_next_index(uint32_t v, uint32_t max)
{
    v += 1;
    return v != max ? v : 0;
}


static inline void 
lb_flow_cache_handler(lb_pl_cb_t *pipe_cbs, uint32_t nstages, 
                        struct lb_pl_cache *cache, uint8_t stage, struct lb_service *lbs)
{
    if (likely(stage < nstages)) {
        pipe_cbs[stage](cache, lbs);
    } else {
        lb_cache_invalid(cache->mbuf, cache, "Invalid stage");
    }
}

void lb_flow_pipeline_run(lb_pl_cb_t *pipe_cbs, uint32_t nstages,
            struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    struct lb_pl_cache *cache = &this_pipeline.cache[this_curr_id];
    uint8_t i, first;

    if (unlikely(!mbuf)) {
        for (i=LB_PL_STAGE0; i < LB_PL_STAGE_MAX; i++) {
            first = this_curr_id;
            cache = &this_pipeline.cache[this_curr_id];
            if (cache->stage != LB_PL_STAGE_INVALID) {
                lb_flow_cache_handler(cache->pipe_cbs, cache->nstages, cache, cache->stage, cache->lbs);
            }

            this_curr_id = lb_next_index(this_curr_id, LB_CACHE_DEPTH);

            while (first != this_curr_id) {
                cache = &this_pipeline.cache[this_curr_id];
                if (cache->stage != LB_PL_STAGE_INVALID) {
                    lb_flow_cache_handler(cache->pipe_cbs, cache->nstages, cache, cache->stage, cache->lbs);
                }

                this_curr_id = lb_next_index(this_curr_id, LB_CACHE_DEPTH);
            }
        }

        return;
    }

    cache->mbuf = mbuf;
    cache->markid = markid;
    cache->lbs = lbs;
    cache->pipe_cbs = pipe_cbs;
    cache->nstages = nstages;
    cache->stage = LB_PL_STAGE0;
    while (true) {
        if (cache->stage != LB_PL_STAGE_INVALID) {
            lb_flow_cache_handler(cache->pipe_cbs, cache->nstages, cache, cache->stage, cache->lbs);
            if (cache->stage == LB_PL_STAGE_INVALID)
                return;
        } else {
            return;
        }

        this_curr_id = lb_next_index(this_curr_id, LB_CACHE_DEPTH);
        cache = &this_pipeline.cache[this_curr_id];
    }
}

static int lb_init_pipe_lcore(void* arg)
{
    uint32_t i;

    this_curr_id = 0;
    memset(&this_pipeline, 0, sizeof(struct lb_pipeline));
    for (i = 0; i < LB_CACHE_DEPTH; i++)
        this_pipeline.cache[i].stage = LB_PL_STAGE_INVALID;

    return 0;
}

int lb_init_pipe(void)
{
    lcoreid_t lcore;
    int err = EDPVS_OK;

    rte_eal_mp_remote_launch(lb_init_pipe_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                __func__, lcore, dpvs_strerror(err));
            return err;
        }
    }

    return err;
}
