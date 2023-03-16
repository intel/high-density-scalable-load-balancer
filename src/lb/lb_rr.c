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
#include "ipvs/blklst.h"
#include "lb/service.h"
#include "lb/dest.h"
#include "lb/sched.h"
#include "lb/rr.h"

struct lb_rr_mark {
    struct list_head *current;   /* current list head */
    uint32_t skip_cnt;
};

static int lb_rr_init_lbs(struct lb_service *lbs)
{
    struct lb_rr_mark *mark;

    /*
     *    Allocate the mark variable for WRR scheduling
     */
    mark = rte_zmalloc("rr_mark", sizeof(struct lb_rr_mark), RTE_CACHE_LINE_SIZE);
    if (mark == NULL) {
        return EDPVS_NOMEM;
    }
    mark->current = &lbs->dests;
    mark->skip_cnt = 0;
    lbs->sched_data = mark;

    return EDPVS_OK;
}

static int lb_rr_update_lbs(struct lb_service *lbs,
        struct lb_dest *dest __rte_unused)
{
    struct lb_rr_mark *mark = lbs->sched_data;

    mark->current = &lbs->dests;
    mark->skip_cnt = 0;

    return EDPVS_OK;
}

/*
 * Round-Robin Scheduling
 */
static void lb_rr_schedule_next(struct lb_service *lbs,
                                            const struct rte_mbuf *mbuf)
{
    struct lb_rr_mark *mark = lbs->sched_data;
    struct list_head *curr = mark->current;

    if (mark->skip_cnt++ < LB_SCHE_SKIP)
        return;

    mark->skip_cnt = 0;
    curr = curr->next;
    /* skip list head */
    if (curr == &lbs->dests) {
        curr = lbs->dests.next;
    }

    mark->current = curr;
}

static struct lb_dest *lb_rr_schedule_prefetch(struct lb_service *lbs,
                                            const struct rte_mbuf *mbuf)
{
    struct lb_rr_mark *mark = lbs->sched_data;
    struct list_head *curr = mark->current;

    if (likely(curr != &lbs->dests)) {
        return list_entry(curr, struct lb_dest, n_list);
    } else {
        curr = curr->next;
        mark->current = curr;
        if (curr != &lbs->dests)
            return list_entry(curr, struct lb_dest, n_list);
        return NULL;
    }
}


static struct lb_scheduler lb_rr_scheduler = {
    .name = "rr",       /* name */
    .type = LB_SCHED_RR,
    .n_list = LIST_HEAD_INIT(lb_rr_scheduler.n_list),
    .init_service = lb_rr_init_lbs,
    .update_service = lb_rr_update_lbs,
    .schedule_prefetch = lb_rr_schedule_prefetch,
    .schedule_next = lb_rr_schedule_next,
};

int lb_rr_init(void)
{
    return register_lb_scheduler(&lb_rr_scheduler);
}

int lb_rr_term(void)
{
    return unregister_lb_scheduler(&lb_rr_scheduler);
}

