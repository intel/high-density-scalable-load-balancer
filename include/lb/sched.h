/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_SCHEDULER_H__
#define __LB_SCHEDULER_H__

#include "list.h"
#include "dpdk.h"
#include "common.h"
#include "ctrl.h"
#include "lb/service.h"

enum lb_sched_type {
    LB_SCHED_RR,
    LB_SCHED_WRR,
    LB_SCHED_WLC,
    LB_SCHED_CONHASH,
};

struct lb_scheduler {
    struct list_head    n_list;
    char                *name;
    enum lb_sched_type   type;

    struct lb_dest *
        (*schedule_prefetch)(struct lb_service *lbs,
                    const struct rte_mbuf *mbuf);
    void (*schedule_next)(struct lb_service *lbs,
                    const struct rte_mbuf *mbuf);

    int (*init_service)(struct lb_service *lbs);
    int (*exit_service)(struct lb_service *lbs);
    int (*update_service)(struct lb_service *lbs, struct lb_dest *dest);
} __rte_cache_aligned;

int lb_sched_init(void);
int lb_sched_term(void);

struct lb_scheduler *
lb_scheduler_get(const char *name);
int lb_bind_scheduler(struct lb_service *lbs,
                     struct lb_scheduler *scheduler);
int lb_unbind_scheduler(struct lb_service *lbs);
void lb_scheduler_put(struct lb_scheduler *scheduler);
int register_lb_scheduler(struct lb_scheduler *scheduler);
struct lb_dest *lb_scheduler_next(struct lb_dest *dest, struct lb_service *lbs,
                const struct rte_mbuf *mbuf);
int unregister_lb_scheduler(struct lb_scheduler *scheduler);

#endif
