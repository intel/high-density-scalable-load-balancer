/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <assert.h>
#include "netif.h"
#include "lb/timer.h"

#define this_timer               (RTE_PER_LCORE(lb_timer_sche))
static RTE_DEFINE_PER_LCORE(struct lb_timer_scheduler, lb_timer_sche);

lb_cycle_t lcore_timer_hz_cycle(void)
{
    return this_timer.precision;
}

static int lcore_timer_malloc_scheduler(void)
{
    int i;
    struct lb_timer_pos *level;

    this_timer.levels[LB_TIMER_LEVEL_0] = rte_malloc_socket(NULL,
                            sizeof(struct lb_timer_pos) * LB_L0_SIZE,
                            RTE_CACHE_LINE_SIZE, rte_socket_id());
    this_timer.levels[LB_TIMER_LEVEL_1] = rte_malloc_socket(NULL,
                            sizeof(struct lb_timer_pos) * LB_L1_SIZE,
                            RTE_CACHE_LINE_SIZE, rte_socket_id());
    this_timer.levels[LB_TIMER_LEVEL_2] = rte_malloc_socket(NULL,
                            sizeof(struct lb_timer_pos) * LB_L2_SIZE,
                            RTE_CACHE_LINE_SIZE, rte_socket_id());

    if (!this_timer.levels[LB_TIMER_LEVEL_0] ||
            !this_timer.levels[LB_TIMER_LEVEL_1] ||
            !this_timer.levels[LB_TIMER_LEVEL_2]) {
        RTE_LOG(WARNING, LB_TIMER, "%s: lcore%d no free memory for timer scheduler\n",
                    __func__, rte_lcore_id());
        return EDPVS_NOMEM;
    }

    level = this_timer.levels[LB_TIMER_LEVEL_0];
    for (i=0; i<LB_L0_SIZE; i++) {
        INIT_LIST_HEAD(&level[i].head);
    }

    level = this_timer.levels[LB_TIMER_LEVEL_1];
    for (i=0; i<LB_L1_SIZE; i++) {
        INIT_LIST_HEAD(&level[i].head);
    }

    level = this_timer.levels[LB_TIMER_LEVEL_2];
    for (i=0; i<LB_L2_SIZE; i++) {
        INIT_LIST_HEAD(&level[i].head);
    }

    return EDPVS_OK;

}

static void lcore_timer_free_scheduler(void)
{
    if (this_timer.levels[LB_TIMER_LEVEL_0])
        rte_free(this_timer.levels[LB_TIMER_LEVEL_0]);

    if (this_timer.levels[LB_TIMER_LEVEL_1])
        rte_free(this_timer.levels[LB_TIMER_LEVEL_1]);

    if (this_timer.levels[LB_TIMER_LEVEL_2])
        rte_free(this_timer.levels[LB_TIMER_LEVEL_2]);
}

static int timer_init_lcore(void *arg)
{
    int i, cid = rte_lcore_id();
    struct lb_timer_scheduler *this = &this_timer;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    /* Delete below 2 line if you want to test lb timer */
    if (netif_lcore_is_idle(cid))
        return EDPVS_IDLE;

    RTE_LOG(INFO, LB_TIMER, "Init lcore %d timer...\n", cid);
    if (lcore_timer_malloc_scheduler()) {
        lcore_timer_free_scheduler();
        return EDPVS_NOMEM;
    }

    for (i = 0; i < LB_TIMER_MAX_LEVEL; i++) {
        this->cursor = 0;
    }

    for (i=0; i<LB_TPIPE_DEPTH; i++)
        this->tpipe.cache[i].stage = LB_TPL_STAGE_INVALID;

    INIT_LIST_HEAD(&this->todo_head);

    this->precision = rte_get_tsc_hz() / LB_HZ;
    this->cycle_init = rte_rdtsc();
    this->cycle_last = rte_rdtsc() + this->precision;
    this->total = 0;
    this->cycle_dynamic[NETIF_PRINCIPAL_STAT_IDLE] = this->precision >> LB_CREDIT_IDLE_BITS;
    this->cycle_dynamic[NETIF_PRINCIPAL_STAT_LOW] = this->precision >> LB_CREDIT_LOW_BITS;
    this->cycle_dynamic[NETIF_PRINCIPAL_STAT_HIGH] = this->precision >> LB_CREDIT_HIGH_BITS;
    this->cycle_dynamic[NETIF_PRINCIPAL_STAT_FULL] = this->precision >> LB_CREDIT_FULL_BITS;

    return EDPVS_OK;
}

/*
 * Convert the CPU cycle to the unit time of LB.
 */
static inline lb_tick_t lb_lcore_relative_tick(lb_cycle_t now)
{
    struct lb_timer_scheduler *this = &this_timer;
    lb_cycle_t cycle_offset = now - this->cycle_init;

    assert(now > this->cycle_init);

    return cycle_offset / this->precision;
}

static inline uint32_t lb_next_index(uint32_t v, uint32_t max)
{
    v += 1;
    return v != max ? v : 0;
}

static inline void lb_tcache_invalid(struct lb_timer *timer, struct lb_tcache *cache, char *msg)
{
    RTE_LOG(ERR, LB_TIMER, "Destroy invalid timer: %s\n", msg);
    // delete timer ?
    cache->stage = LB_TPL_STAGE_INVALID;
}


/*
 * @hands: Time triggered
 * @delay: Time remaining to trigger timer
 */
static inline struct lb_timer_pos *
lb_timer_delay_pos(lb_tick_t hands, lb_tick_t delay)
{
    struct lb_timer_scheduler *this = &this_timer;

    if (likely(delay < LB_L0_SIZE)) {
        return &this->levels[LB_TIMER_LEVEL_0][LB_L0_HANDS(hands)];
    }

    delay = delay >> LB_L0_BITS;
    if (delay < LB_L1_SIZE) {
        return &this->levels[LB_TIMER_LEVEL_1][LB_L1_HANDS(hands)];
    }

    delay = delay >> LB_L1_BITS;
    if (delay < LB_L2_SIZE) {
        return &this->levels[LB_TIMER_LEVEL_2][LB_L2_HANDS(hands)];
    }

    /* Don't let me return NULL */
    return NULL;
}

static void lb_pl_timer0(struct lb_tcache *cache, lb_tick_t tick)
{
    struct lb_timer *timer = cache->curr;
    lb_tick_t delay;

    if (timer->hands <= tick) {
        cache->stage = LB_TPL_STAGE1;
    } else {
        delay = timer->hands - tick;
        cache->new = lb_timer_delay_pos(timer->hands, delay);
        assert(cache->new);
        rte_prefetch0(cache->new);
        cache->stage = LB_TPL_STAGE2;
    }
}

// do handler, must delete timer
static void lb_pl_timer1(struct lb_tcache *cache, lb_tick_t tick __rte_unused)
{
    struct lb_timer *timer = cache->curr;
    struct lb_timer_scheduler *this = &this_timer;

    list_del(&timer->list);
    timer->handler(timer);
    this->total--;
    cache->stage = LB_TPL_STAGE_INVALID;
}

// replace timer
static void lb_pl_timer2(struct lb_tcache *cache, lb_tick_t tick __rte_unused)
{
    struct lb_timer_pos *pos = cache->new;
    struct lb_timer *timer = cache->curr;

    list_del(&timer->list);
    list_add_tail(&timer->list, &pos->head);
    cache->stage = LB_TPL_STAGE_INVALID;
}

static lb_tpl_cb_t lb_timer_cb[LB_TPL_STAGE_TIMER] = {
    lb_pl_timer0,
    lb_pl_timer1,
    lb_pl_timer2,
};

static inline void
lb_timer_cache_handler(struct lb_tcache *cache, uint8_t stage, lb_tick_t tick)
{
    if (likely(stage < LB_TPL_STAGE_TIMER)) {
        lb_timer_cb[stage](cache, tick);
    } else {
        lb_tcache_invalid(cache->curr, cache, "Invalid stage");
    }
}

static void lb_timer_pipeline_run(struct lb_timer *timer,
                            struct lb_tpipeline *pipe, uint32_t *pos, lb_tick_t tick)
{
    struct lb_tcache *cache = &pipe->cache[*pos];

    cache->curr = timer;
    cache->stage = LB_TPL_STAGE0;
    while (true) {
        cache = &pipe->cache[*pos];
        if (cache->stage != LB_TPL_STAGE_INVALID) {
            lb_timer_cache_handler(cache, cache->stage, tick);
            if (cache->stage == LB_TPL_STAGE_INVALID)
                return;
        } else {
            return;
        }

        *pos = lb_next_index(*pos, LB_TPIPE_DEPTH);
    }
}

static void lb_timer_pipeline_end(struct lb_tpipeline *pipe,
                                        uint32_t *pos, lb_tick_t tick)
{
    uint32_t i, first;
    struct lb_tcache *cache;

    for (i=LB_TPL_STAGE0; i<LB_TPL_STAGE_TIMER; i++) {
        first = *pos;
        cache = &pipe->cache[*pos];
        if (cache->stage != LB_TPL_STAGE_INVALID) {
            lb_timer_cache_handler(cache, cache->stage, tick);
        }

        *pos = lb_next_index(*pos, LB_TPIPE_DEPTH);;

        while (first != *pos) {
            cache = &pipe->cache[*pos];
            if (cache->stage != LB_TPL_STAGE_INVALID) {
                lb_timer_cache_handler(cache, cache->stage, tick);
            }

            *pos = lb_next_index(*pos, LB_TPIPE_DEPTH);
        }
    }

    return;
}

/*
 * Return Ture: There are remaining credits.
 */
static inline bool
lb_timer_burst_credit(struct list_head *head, lb_cycle_t start, lb_tick_t tick, lb_cycle_t deadline)
{
    lb_cycle_t now = rte_rdtsc();
    struct lb_timer_scheduler *this = &this_timer;
    uint32_t offset = 0;
    struct lb_timer *timer, *next;

    list_for_each_entry_safe(timer, next, head, list) {
        now = rte_rdtsc();
        if (now > deadline)
            break;

        rte_prefetch0(next);
        lb_timer_pipeline_run(timer, &this->tpipe, &offset, tick);
    }
    lb_timer_pipeline_end(&this->tpipe, &offset, tick);

    return now < deadline;
}

static inline void
lb_timer_burst_todo(lb_cycle_t start, lb_tick_t tick, lb_cycle_t deadline)
{
    struct lb_timer_scheduler *this = &this_timer;
    lb_timer_burst_credit(&this->todo_head, start, tick, deadline);
}

static inline void
lb_timer_burst_level0(lb_cycle_t start, lb_tick_t tick, lb_cycle_t deadline)
{
    struct lb_timer_scheduler *this = &this_timer;
    struct lb_timer_pos *pos;
    uint32_t offset;
    bool credit = true;

    while (this->cycle_last < start) {
        this->cursor++;
        offset = this->cursor & LB_L0_MASK;
        pos = &this->levels[LB_TIMER_LEVEL_0][offset];

        if (credit && !list_empty(&pos->head)) {
            credit = lb_timer_burst_credit(&pos->head, start, tick, deadline);
        }

        if (!credit && !list_empty(&pos->head)) {
            list_splice_init(&pos->head, &this->todo_head);
        }

        this->cycle_last += this->precision;
    }
}

/* Note: Unit time that will be blocked for more than one level 1 is not considered. */
static inline void
lb_timer_burst_level_high(lb_cycle_t start, lb_tick_t tick, lb_cycle_t deadline,
                                            uint64_t mask, uint8_t bits, uint8_t level)
{
    struct lb_timer_scheduler *this = &this_timer;
    struct lb_timer_pos *pos;
    uint32_t offset;
    bool credit = true;

    offset = (this->cursor & mask) >> bits;
    if (!offset)
        return;
    pos = &this->levels[level][offset];

    if (!list_empty(&pos->head)) {
        credit = lb_timer_burst_credit(&pos->head, start, tick, deadline);
        if (credit && !list_empty(&pos->head)) {
            list_splice_init(&pos->head, &this->todo_head);
        }
    }
}

void lb_lcore_timer_dump_info(lb_tick_t delay)
{
    struct lb_timer_scheduler *this = &this_timer;
    uint32_t i, ok = 0, error_pos = 0, error_hands = 0, s, ms, offset, level_cursor;
    struct lb_timer_pos *pos;
    struct lb_timer *timer;

    RTE_LOG(INFO, LB_TIMER, "Total remain timer:%lu, second: %ld, L2 hand: %ld, L1 hand: %ld, L0 hand: %ld\n", 
                        lb_lcore_timer_count(), this->cursor >> LB_HZ_BITS,
                        (this->cursor & LB_L2_MASK) >> LB_L1_BITS, 
                        (this->cursor & LB_L1_MASK) >> LB_L0_BITS,
                        this->cursor & LB_L0_MASK);

    for (i=0; i<LB_L0_SIZE; i++) {
        level_cursor = this->cursor & LB_L0_MASK;
        pos = &this->levels[LB_TIMER_LEVEL_0][i];
        list_for_each_entry(timer, &pos->head, list) {
            if (i > level_cursor)
                offset = i - level_cursor;
            else
                offset = i + LB_L0_SIZE - level_cursor;

            if (offset > delay) {
                s = offset >> LB_HZ_BITS;
                ms = (offset % LB_HZ_BITS) * 1000 / LB_HZ_BITS;
                RTE_LOG(INFO, LB_TIMER, "L0 Pos offset[%u] i[%lu] cursor[%lu] error remain time: %u.%us\n", offset, i, level_cursor, s, ms);
                error_pos++;
                continue;
            }

            if ((timer->hands < this->cursor) || (timer->hands > (this->cursor+delay))) {
                RTE_LOG(INFO, LB_TIMER, "L0 hands[%lus] error, cursor[%lus]\n", timer->hands>>LB_HZ_BITS, this->cursor>>LB_HZ_BITS);
                error_hands++;
                continue;
            }

            ok++;
        }
    }

    RTE_LOG(INFO, LB_TIMER, "Level0 remain timer ok count: %u, pos error: %u, hands error: %u\n", ok, error_pos, error_hands);
    ok = 0;
    error_pos = 0;
    error_hands = 0;

    if (delay > LB_L0_SIZE)
        delay = delay >> LB_L0_BITS;
    else
        delay = 0;

    for (i=0; i<LB_L1_SIZE; i++) {
        pos = &this->levels[LB_TIMER_LEVEL_1][i];
        level_cursor = (this->cursor & LB_L1_MASK) >> LB_L0_BITS;
        list_for_each_entry(timer, &pos->head, list) {
            if (i > level_cursor)
                offset = i - level_cursor;
            else
                offset = i + LB_L1_SIZE - level_cursor;

            if (offset > delay) {
                s = offset << (LB_L0_BITS - LB_HZ_BITS);
                RTE_LOG(INFO, LB_TIMER, "L1 Pos offset[%u] error remain time: %us\n", offset, s);
                error_pos++;
                continue;
            }

            if ((timer->hands < this->cursor) || (timer->hands > (this->cursor+delay))) {
                RTE_LOG(INFO, LB_TIMER, "L1 hands[%lus] error, cursor[%lus]\n", timer->hands>>LB_HZ_BITS, this->cursor>>LB_HZ_BITS);
                error_hands++;
                continue;
            }

            ok++;
        }
    }
    RTE_LOG(INFO, LB_TIMER, "Level1 remain timer ok count: %u, pos error: %u, hands error: %u\n", ok, error_pos, error_hands);
    ok = 0;
    error_pos = 0;
    error_hands = 0;

    if (delay > LB_L1_SIZE)
        delay = delay >> LB_L1_BITS;
    else
        delay = 0;

    for (i=0; i<LB_L2_SIZE; i++) {
        pos = &this->levels[LB_TIMER_LEVEL_2][i];
        level_cursor = (this->cursor & LB_L2_MASK) >> LB_L1_BITS;
        list_for_each_entry(timer, &pos->head, list) {
            if (i > level_cursor)
                offset = i - level_cursor;
            else
                offset = i + LB_L2_SIZE - level_cursor;

            if (offset > delay) {
                s = offset << (LB_L2_BITS + LB_L1_BITS - LB_HZ_BITS);
                RTE_LOG(INFO, LB_TIMER, "L2 Pos offset[%u] error remain time: %us\n", offset, s);
                error_pos++;
                continue;
            }

            if ((timer->hands < this->cursor) || (timer->hands > (this->cursor+delay))) {
                RTE_LOG(INFO, LB_TIMER, "L2 hands[%lus] error, cursor[%lus]\n", timer->hands>>LB_HZ_BITS, this->cursor>>LB_HZ_BITS);
                error_hands++;
                continue;
            }

            ok++;
        }
    }
    RTE_LOG(INFO, LB_TIMER, "Level2 remain timer ok count: %u, pos error: %u, hands error: %u\n", ok, error_pos, error_hands);
    ok = 0;
    error_pos = 0;
    error_hands = 0;

    list_for_each_entry(timer, &this->todo_head, list) {
        if ((timer->hands < this->cursor) || (timer->hands > (this->cursor+delay))) {
            RTE_LOG(INFO, LB_TIMER, "TODO hands[%lus] error, cursor[%lus]\n", timer->hands>>LB_HZ_BITS, this->cursor>>LB_HZ_BITS);
            error_hands++;
            continue;
        }

        ok++;
    }
    RTE_LOG(INFO, LB_TIMER, "Todo remain timer ok count: %u, hands error: %u\n", ok, error_hands);
}

void lb_lcore_timer_manage(lb_cycle_t start, enum netif_principal_status high_stat)
{
    struct lb_timer_scheduler *this = &this_timer;
    lb_tick_t org_cursor;
    lb_tick_t tick = 0;
    lb_cycle_t deadline;

    // Todo list process
    if (unlikely(!list_empty(&this->todo_head))) {
        deadline = start + (this->cycle_dynamic[high_stat] >> LB_CREDIT_TODO_BITS);
        tick = lb_lcore_relative_tick(start);
        lb_timer_burst_todo(start, tick, deadline);
    }

    if (unlikely(this->cycle_last > start)) {
        return;
    }

    if (!tick)
        tick = lb_lcore_relative_tick(start);

    deadline = start + (this->cycle_dynamic[high_stat]);
    org_cursor = this->cursor;
    lb_timer_burst_level0(start, tick, deadline);
    if (unlikely((org_cursor & LB_L1_MASK) != (this->cursor & LB_L1_MASK))) {
        lb_timer_burst_level_high(start, tick, deadline, LB_L1_MASK, LB_L1_OFFSET, LB_TIMER_LEVEL_1);
        if (unlikely((org_cursor & LB_L2_MASK) != (this->cursor & LB_L2_MASK))) {
            lb_timer_burst_level_high(start, tick, deadline, LB_L2_MASK, LB_L2_OFFSET, LB_TIMER_LEVEL_2);
            assert(this->cursor < (LB_MAX_TIME<<LB_L0_BITS));
        }
    }
}

void *lb_lcore_add_timer_pre(struct lb_timer *timer)
{
    struct lb_timer_scheduler *this = &this_timer;
    struct lb_timer_pos *pos;

    timer->hands = this->cursor + timer->delay;
    pos = lb_timer_delay_pos(timer->hands, timer->delay);
    this->total++;

    assert(pos);
    return pos;
}

static inline void __lb_lcore_update_timer(struct lb_timer *timer)
{
    struct lb_timer_scheduler *this = &this_timer;
    lb_tick_t delay = timer->hands - this->cursor;
    struct lb_timer_pos *pos = lb_timer_delay_pos(timer->hands, delay);

    assert(pos);

    list_del(&timer->list);
    list_add_tail(&timer->list, &pos->head);
}

void lb_lcore_update_timer(struct lb_timer *timer)
{
    struct lb_timer_scheduler *this = &this_timer;
    lb_tick_t timeout;

    if (timer->hands > this->cursor)
        timeout = timer->hands - this->cursor;
    else
        timeout = timer->hands + LB_L0_SIZE - this->cursor;

    timer->hands = this->cursor + timer->delay;
    /* timeout 50% and only a certain probability will be updated */
    if (timeout < (timer->delay >> 1) && !(rte_rdtsc() & LB_TIMER_UPDATE_MASK)) {
        __lb_lcore_update_timer(timer);
    }
}

void lb_lcore_update_timer_delay(struct lb_timer *timer, lb_tick_t delay)
{
    struct lb_timer_scheduler *this = &this_timer;

    timer->delay = delay;
    timer->hands = this->cursor + timer->delay;
    __lb_lcore_update_timer(timer);
}


void lb_lcore_del_timer(struct lb_timer *timer)
{
    struct lb_timer_scheduler *this = &this_timer;

    list_del(&timer->list);
    this->total--;
}

lb_tick_t lb_timeval_to_ticks(const struct timeval *tv)
{
    lb_tick_t ticks;

    ticks = tv->tv_sec * LB_HZ + \
            tv->tv_usec * LB_HZ / 1000000;

    if (unlikely(ticks >= LB_MAX_TIME))
        return LB_MAX_TIME;

    return ticks;
}

void lb_ticks_to_timeval(const lb_tick_t ticks, struct timeval *tv)
{
    tv->tv_sec = ticks / LB_HZ;
    tv->tv_usec = ticks % LB_HZ * 1000000 / LB_HZ;
}


uint64_t lb_lcore_timer_count(void)
{
    return this_timer.total;
}

int lb_timer_init(void)
{
    int err;
    lcoreid_t lcore;

    assert((LB_L2_OFFSET+LB_L2_BITS) < 64); /* avoid overflow */
    rte_eal_mp_remote_launch(timer_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, LB_TIMER, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}

