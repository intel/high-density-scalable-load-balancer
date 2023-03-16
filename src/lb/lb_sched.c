/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include "list.h"
#include "ipvs/sched.h"
#include "ipvs/rr.h"
#include "ipvs/wrr.h"
#include "ipvs/wlc.h"
#include "ipvs/conhash.h"
#include "lb/sched.h"
#include "lb/rr.h"
#include "lb/wrr.h"
#include "lb/wlc.h"
#include "lb/conhash.h"
#include "lb/dest.h"

static struct list_head lb_schedulers;

/*
 *  Bind a service with a scheduler
 */
int lb_bind_scheduler(struct lb_service *lbs,
                         struct lb_scheduler *scheduler)
{
    int ret;

    if (lbs == NULL) {
        return EDPVS_INVAL;
    }
    if (scheduler == NULL) {
        return EDPVS_INVAL;
    }

    lbs->scheduler = scheduler;

    if (scheduler->init_service) {
        ret = scheduler->init_service(lbs);
        if (ret) {
            return ret;
        }
    }

    return EDPVS_OK;
}

/*
 *  Unbind a service with its scheduler
 */
int lb_unbind_scheduler(struct lb_service *lbs)
{
    struct lb_scheduler *sched;

    if (lbs == NULL) {
        return EDPVS_INVAL;;
    }

    sched = lbs->scheduler;
    if (sched == NULL) {
        return EDPVS_INVAL;
    }

    if (sched->exit_service) {
        if (sched->exit_service(lbs) != 0) {
            return EDPVS_INVAL;
        }
    }

    lbs->scheduler = NULL;
    return EDPVS_OK;
}

/*
 *  Lookup scheduler and try to load it if it doesn't exist
 */
struct lb_scheduler *lb_scheduler_get(const char *sched_name)
{
    struct lb_scheduler *sched;


    list_for_each_entry(sched, &lb_schedulers, n_list) {
        if (strcmp(sched_name, sched->name) == 0) {
            /* HIT */
            return sched;
        }
    }

    return NULL;
}

struct lb_dest *lb_scheduler_next(struct lb_dest *dest, struct lb_service *lbs,
                const struct rte_mbuf *mbuf)
{
    struct lb_dest *next = NULL;

    if (unlikely(list_empty(&lbs->dests)))
        return NULL;

    if (!dest)
        dest = list_entry(lbs->dests.next, struct lb_dest, n_list);

    do {
        lbs->scheduler->schedule_next(lbs, mbuf);
        next = lbs->scheduler->schedule_prefetch(lbs, mbuf);
        if (lb_dest_is_valid(next))
            return next;
    } while (next != dest);

    return NULL;
}

/*
 *  Register a scheduler in the scheduler list
 */
int register_lb_scheduler(struct lb_scheduler *scheduler)
{
    struct lb_scheduler *sched;

    if (!scheduler) {
        return EDPVS_INVAL;
    }

    if (!scheduler->name) {
        return EDPVS_INVAL;
    }

    if (!list_empty(&scheduler->n_list)) {
        return EDPVS_EXIST;
    }

    /*
     *  Make sure that the scheduler with this name doesn't exist
     *  in the scheduler list.
     */
    list_for_each_entry(sched, &lb_schedulers, n_list) {
        if (sched == scheduler || sched->type == scheduler->type)
            return EDPVS_EXIST;
    }

    list_add(&scheduler->n_list, &lb_schedulers);

    return EDPVS_OK;
}

/*
 *  Unregister a scheduler from the scheduler list
 */
int unregister_lb_scheduler(struct lb_scheduler *scheduler)
{
    if (!scheduler) {
        return EDPVS_INVAL;
    }

    if (list_empty(&scheduler->n_list)) {
        return EDPVS_NOTEXIST;
    }

    /*
     *      Remove it from the d-linked scheduler list
     */
    list_del(&scheduler->n_list);

    return EDPVS_OK;
}

int lb_sched_init(void)
{
    INIT_LIST_HEAD(&lb_schedulers);
    lb_rr_init();
    lb_wrr_init();
    lb_wlc_init();
    lb_conhash_init();
    //dp_vs_fo_init();

    return EDPVS_OK;
}

int lb_sched_term(void)
{
    lb_rr_term();
    lb_wrr_term();
    lb_wlc_term();
    lb_conhash_term();    
    //dp_vs_fo_term();

    return EDPVS_OK;
}

