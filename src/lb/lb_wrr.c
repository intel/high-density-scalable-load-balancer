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
#include "lb/wrr.h"

/*
 * current destination pointer for weighted round-robin scheduling
 */
struct lb_wrr_mark {
    struct list_head *cl;   /* current list head */
    int cw;         /* current weight */
    int mw;         /* maximum weight */
    int di;         /* decreasing interval */
    uint32_t skip_cnt;
};

/*
 *    Get the gcd of server weights
 */
static int gcd(int a, int b)
{
    int c;

    while ((c = a % b)) {
        a = b;
        b = c;
    }
    return b;
}

static int lb_wrr_gcd_weight(struct lb_service *lbs)
{
    struct lb_dest *dest;
    int weight;
    int g = 0;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        weight = dest->weight;
        if (weight > 0) {
            if (g > 0)
                g = gcd(weight, g);
            else
                g = weight;
        }
    }
    return g ? g : 1;
}

/*
 *    Get the maximum weight of the service destinations.
 */
static int lb_wrr_max_weight(struct lb_service *lbs)
{
    struct lb_dest *dest;
    int new_weight, weight = 0;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        new_weight = dest->weight;
        if (new_weight > weight)
            weight = new_weight;
    }

    return weight;
}

static int lb_wrr_init_svc(struct lb_service *lbs)
{
    struct lb_wrr_mark *mark;

    /*
     *    Allocate the mark variable for WRR scheduling
     */
    mark = rte_zmalloc("wrr_mark", sizeof(struct lb_wrr_mark), RTE_CACHE_LINE_SIZE);
    if (mark == NULL) {
        return EDPVS_NOMEM;
    }
    mark->cl = &lbs->dests;
    mark->cw = 0;
    mark->mw = lb_wrr_max_weight(lbs);
    mark->di = lb_wrr_gcd_weight(lbs);
    lbs->sched_data = mark;
    mark->skip_cnt = 0;

    return EDPVS_OK;
}

static int lb_wrr_done_svc(struct lb_service *lbs)
{
    /*
     *    Release the mark variable
     */
    rte_free(lbs->sched_data);

    return EDPVS_OK;
}

static int lb_wrr_update_svc(struct lb_service *lbs,
        struct lb_dest *dest __rte_unused)
{
    struct lb_wrr_mark *mark = lbs->sched_data;

    mark->skip_cnt = 0;
    mark->cl = &lbs->dests;
    mark->mw = lb_wrr_max_weight(lbs);
    mark->di = lb_wrr_gcd_weight(lbs);
    if (mark->cw > mark->mw)
        mark->cw = 0;
    return 0;
}

/*
 * Weighted Round-Robin Scheduling
 */
static void lb_wrr_schedule_next(struct lb_service *lbs,
                                             const struct rte_mbuf *mbuf)
{
    struct lb_dest *dest;
    struct lb_wrr_mark *mark = lbs->sched_data;
    struct list_head *p;

    if (mark->skip_cnt++ < LB_SCHE_SKIP) {
        return;
    }
    mark->skip_cnt = 0;

    /*
     * This loop will always terminate, because mark->cw in (0, max_weight]
     * and at least one server has its weight equal to max_weight.
     */
    p = mark->cl;
    while (true) {
        if (unlikely(mark->cl == &lbs->dests)) {
            /* it is at the head of the destination list */

            if (mark->cl == mark->cl->next) {
                /* no dest entry */
                mark->cl = NULL;
                return;
            }

            mark->cl = lbs->dests.next;
            mark->cw -= mark->di;
            if (mark->cw <= 0) {
                mark->cw = mark->mw;
                /*
                 * Still zero, which means no available servers.
                 */
                if (unlikely(mark->cw == 0)) {
                    mark->cl = &lbs->dests;
                    mark->cl = NULL;
                    return;
                }
            }
        } else
            mark->cl = mark->cl->next;

        if (mark->cl != &lbs->dests) {
            /* not at the head of the list */
            dest = list_entry(mark->cl, struct lb_dest, n_list);
            if (lb_dest_is_valid(dest) && dest->weight >= mark->cw) {
                /* got it */
                return;
            }
        }

        if (mark->cl == p && mark->cw == mark->di) {
            /* back to the start, and no dest is found.
               It is only possible when all dests are OVERLOADED */
            mark->cl = NULL;
            return;
        }
    }
}

static struct lb_dest *lb_wrr_schedule_prefetch(struct lb_service *lbs,
                                            const struct rte_mbuf *mbuf)
{
    struct lb_wrr_mark *mark = lbs->sched_data;
    struct list_head *curr = mark->cl;

    if (likely(curr != &lbs->dests)) {
        return list_entry(curr, struct lb_dest, n_list);
    } else {
        return NULL;
    }
}

static struct lb_scheduler lb_wrr_scheduler = {
    .name = "wrr",
    .type = LB_SCHED_WRR,
    .n_list = LIST_HEAD_INIT(lb_wrr_scheduler.n_list),
    .init_service = lb_wrr_init_svc,
    .exit_service = lb_wrr_done_svc,
    .update_service = lb_wrr_update_svc,
    .schedule_prefetch = lb_wrr_schedule_prefetch,
    .schedule_next = lb_wrr_schedule_next,
};

int  lb_wrr_init(void)
{
    return register_lb_scheduler(&lb_wrr_scheduler);
}

int  lb_wrr_term(void)
{
    return unregister_lb_scheduler(&lb_wrr_scheduler);
}
