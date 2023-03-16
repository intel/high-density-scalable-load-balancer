/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_TIMER_H__
#define __LB_TIMER_H__

#include "common.h"
#include "dpdk.h"
#include "list.h"
#include <sys/time.h>
#include "netif.h"


#ifndef LB_TIMER
#define LB_TIMER
#define RTE_LOGTYPE_LB_TIMER    RTE_LOGTYPE_USER1
#endif

typedef uint64_t lb_tick_t;
typedef uint64_t lb_cycle_t;



#define LB_TIMER_LEVEL_0    0
#define LB_TIMER_LEVEL_1    1
#define LB_TIMER_LEVEL_2    2
#define LB_TIMER_MAX_LEVEL  3

#define LB_HZ_BITS          10
#define LB_L0_BITS          (LB_HZ_BITS+10)
#define LB_L1_BITS          10
#define LB_L2_BITS          10
#define LB_L1_OFFSET        (LB_L0_BITS)
#define LB_L2_OFFSET        (LB_L0_BITS+LB_L1_BITS)

#define LB_HZ               (1UL<<LB_HZ_BITS)
#define LB_L0_SIZE          (1UL<<LB_L0_BITS)
#define LB_L1_SIZE          (1UL<<LB_L1_BITS)
#define LB_L2_SIZE          (1UL<<LB_L2_BITS)
#define LB_MAX_TIME         (1UL<<(LB_L2_OFFSET+LB_L2_BITS))

#define LB_L0_MASK          (LB_L0_SIZE-1)
#define LB_L1_MASK          ((LB_L1_SIZE-1) << LB_L1_OFFSET)
#define LB_L2_MASK          ((LB_L2_SIZE-1) << (LB_L2_OFFSET))

#define LB_L0_HANDS(hands)         (hands & LB_L0_MASK)
#define LB_L1_HANDS(hands)         ((hands & LB_L1_MASK) >> LB_L1_OFFSET)
#define LB_L2_HANDS(hands)         ((hands & LB_L2_MASK) >> LB_L2_OFFSET)


#define LB_CREDIT_IDLE_BITS     2   /* cpu: 1/4 */
#define LB_CREDIT_LOW_BITS      3   /* cpu: 1/8 */
#define LB_CREDIT_HIGH_BITS     4   /* cpu: 1/16 */
#define LB_CREDIT_FULL_BITS     5   /* cpu: 1/32 */

#define LB_CREDIT_TODO_BITS     1   /* cpu: 1/8 ~ 1/64 */


#define LB_TIMER_STAT_UNKNOWN   0
#define LB_TIMER_STAT_INITED    1

#define LB_TIMER_UPDATE_RATIO   3   /* 1/8 */
#define LB_TIMER_UPDATE_MASK    ((1UL<<LB_TIMER_UPDATE_RATIO)-1)

enum lb_tpl_stage {
    LB_TPL_STAGE_INVALID = 0xFF,
    LB_TPL_STAGE0 = 0,
    LB_TPL_STAGE1 = 1,
    LB_TPL_STAGE2 = 2,
    LB_TPL_STAGE3 = 3,
    LB_TPL_STAGE_TIMER  = 3,
};

#define LB_TPIPE_DEPTH      2
struct lb_tcache {
    void *curr;
    void *new;
    uint32_t offset;
    uint8_t stage;
    uint8_t level;
};

struct lb_tpipeline {
    struct lb_tcache cache[LB_TPIPE_DEPTH];
} __rte_cache_aligned;

typedef void (*lb_tpl_cb_t)(struct lb_tcache *cache, lb_tick_t tick);


typedef void (*lb_timer_cb_t)(void *arg);

struct lb_timer {
    struct list_head list;
    lb_timer_cb_t    handler;
    lb_tick_t        hands;     // lb unit time
    lb_tick_t        delay;     // lb unit time
};

struct lb_timer_pos {
    struct list_head head;
};

struct lb_timer_scheduler {
    struct lb_tpipeline tpipe;
    struct lb_timer_pos *levels[LB_TIMER_MAX_LEVEL];
    struct list_head    todo_head;
    lb_cycle_t          cycle_dynamic[NETIF_PRINCIPAL_STAT_MAX];
    lb_cycle_t          cycle_init;                     /* cpu cycle, system init time */
    lb_cycle_t          cycle_last;                     /* cpu cycle, next shedule time */
    lb_cycle_t          precision;                      /* Used to determine the accuracy of HZ */
    lb_tick_t           cursor;                         /* lb unit time, relative hand */
    uint64_t            total;
    uint32_t            stat;
} __rte_cache_aligned;

void lb_lcore_timer_manage(lb_cycle_t start, enum netif_principal_status high_stat);
void *lb_lcore_add_timer_pre(struct lb_timer *timer);
void lb_lcore_update_timer(struct lb_timer *timer);
void lb_lcore_update_timer_delay(struct lb_timer *timer, lb_tick_t delay);
void lb_lcore_del_timer(struct lb_timer *timer);
uint64_t lb_lcore_timer_count(void);
lb_tick_t lb_timeval_to_ticks(const struct timeval *tv);
void lb_ticks_to_timeval(const lb_tick_t ticks, struct timeval *tv);
void lb_lcore_timer_dump_info(lb_tick_t delay);
lb_cycle_t lcore_timer_hz_cycle(void);
int lb_timer_init(void);


static inline int lb_lcore_init_timer(struct lb_timer *timer, lb_tick_t delay, lb_timer_cb_t handler)
{
    if (!delay && delay > LB_MAX_TIME)
        return EDPVS_INVAL;

    timer->delay = delay;
    timer->handler = handler;
    INIT_LIST_HEAD(&timer->list);
    timer->hands = 0;

    return EDPVS_OK;
}

static inline void lb_lcore_add_timer_bottom(struct lb_timer *timer, struct lb_timer_pos *pos)
{
    list_add_tail(&timer->list, &pos->head); // One more prefetch
}

static inline int lb_lcore_add_timer(struct lb_timer *timer)
{
    struct lb_timer_pos *pos = lb_lcore_add_timer_pre(timer);

    if (!pos)
        return EDPVS_INVAL;

    list_add_tail(&timer->list, &pos->head);

    return EDPVS_OK;
}

static inline int lb_lcore_timer_sched(struct lb_timer *timer, lb_tick_t delay, lb_timer_cb_t handler)
{
    int err;

    err = lb_lcore_init_timer(timer, delay, handler);
    if (err)
        return err;

    return lb_lcore_add_timer(timer);
}

static inline bool lb_timer_pending(const struct lb_timer *timer)
{
    return (timer->list.prev != LIST_POISON2
            && timer->list.prev != NULL
            && timer->list.prev != &timer->list);
}

#endif
