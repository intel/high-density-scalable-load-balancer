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
#include "lb/wlc.h"

/* 
 * If the conn of DeST exceeds this value, the algorithm will be enabled.
 * Otherwise, it will be allocated directly.
 */
#define WLC_ENABLE_THRESHOLD    1000       // It cannot be 0


struct lb_wlc_mark {
    struct list_head *next;   /* current list head */
    uint32_t skip_cnt;
};

static int lb_wlc_init_lbs(struct lb_service *lbs)
{
    struct lb_wlc_mark *mark;

    /*
     *    Allocate the mark variable for WRR scheduling
     */
    mark = rte_zmalloc("wlc_mark", sizeof(struct lb_wlc_mark), RTE_CACHE_LINE_SIZE);
    if (mark == NULL) {
        return EDPVS_NOMEM;
    }
    mark->next = &lbs->dests;
    mark->skip_cnt = 0;
    lbs->sched_data = mark;

    return EDPVS_OK;
}

static struct lb_dest *lb_wlc_schedule_prefetch(struct lb_service *lbs,
                                             const struct rte_mbuf *mbuf)
{
    struct lb_wlc_mark *mark = lbs->sched_data;
    struct list_head *next = mark->next;

    if (likely(next != &lbs->dests)) {
        return list_entry(next, struct lb_dest, n_list);
    } else {
        return NULL;
    }
}

static inline bool lb_wlc_valid_threshold_dest(struct lb_dest *dest)
{
    if (lb_dest_is_valid(dest) && dest->stats.conns < (WLC_ENABLE_THRESHOLD*dest->weight))
        return true;

    return false;
}

static void lb_wlc_schedule_next(struct lb_service *lbs,
                                             const struct rte_mbuf *mbuf)
{
    struct lb_dest *dest, *least = NULL;
    unsigned int loh, doh;
    struct lb_wlc_mark *mark = lbs->sched_data;
    struct list_head *first, *next = mark->next;

    if ((mark->skip_cnt++ < LB_SCHE_SKIP) && next)
        return;

    mark->skip_cnt = 0;

    /* Within the threshold, use RR to select dest */
    if (unlikely(!next))
        next = lbs->dests.next;
    else
        next = next->next;

    first = next;
    do {
        if (unlikely(next == &lbs->dests)) {
            next = lbs->dests.next;
            if (next == &lbs->dests) { /* Empty list */
                mark->next = NULL;
                return;
            }
            continue;
        }

        dest = list_entry(next, struct lb_dest, n_list);
        if (lb_wlc_valid_threshold_dest(dest)) {
            mark->next = next; // got it
            return;
        }

        next = next->next;
    } while (first != next);

    /*
     * We calculate the load of each dest server as follows:
     *                (dest overhead) / dest->weight
     *
     * The server with weight=0 is quiesced and will not receive any
     * new connections.
     */

    list_for_each_entry(dest, &lbs->dests, n_list) {
        if (lb_dest_is_valid(dest)) {
            least = dest;
            loh = least->stats.conns;
            goto nextstage;
        }
    }
    mark->next = NULL;
    return;

    /*
     *    Find the destination with the least load.
     */
nextstage:
    list_for_each_entry_continue(dest, &lbs->dests, n_list) {
        if (dest->flags & DPVS_DEST_F_OVERLOAD)
            continue;
        doh = dest->stats.conns;
        if (loh * dest->weight > doh * least->weight) {
            least = dest;
            loh = doh;
        }
    }

    mark->next = &least->n_list; // got it
}

static struct lb_scheduler lb_wlc_scheduler = {
    .type = LB_SCHED_WLC,
    .name = "wlc",
    .n_list = LIST_HEAD_INIT(lb_wlc_scheduler.n_list),
    .init_service = lb_wlc_init_lbs,
    .schedule_prefetch = lb_wlc_schedule_prefetch,
    .schedule_next = lb_wlc_schedule_next,
};

int lb_wlc_init(void)
{
    return register_lb_scheduler(&lb_wlc_scheduler);
}

int lb_wlc_term(void)
{
    return unregister_lb_scheduler(&lb_wlc_scheduler);
}
