/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <unistd.h>
#include "dpdk.h"
#include "cfgfile.h"
#include "timer.h"
#include "lb/timer.h"

#define RTE_TIMER_INT  1     /* us */
#define DELAY_BITS     4    /* 16s */
#define MAX_DELAY     (1<<DELAY_BITS)
#define MAX_TIMERS    (1<<24)   /* 1600W */

static struct timeval g_start_time;
static uint64_t g_start_cycle;

struct test_data {
    struct lb_timer tm;
    uint64_t tick;
    uint64_t id;
};

static void timeup_perf(void *arg)
{
    uint64_t now;
    struct test_data *timer = list_entry(arg, struct test_data, tm);
    static int s = 0;

    now = rte_rdtsc();
    if ((now - g_start_cycle) > rte_get_timer_hz()) {
            g_start_cycle = now;
            s++;
            printf("%s, id: %ld, tick: %ld, remain: %ld, %ds\n", __func__, timer->id, timer->tick, lb_lcore_timer_count(), s);
    }
}

static int lcore_loop(void *arg)
{
    int i, j, err, cid = rte_lcore_id();
    struct test_data *timer;
    uint64_t start, end;
    lb_tick_t tick;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    if (cid != 1)
        return EDPVS_OK;

    timer = rte_zmalloc("timer", sizeof(struct lb_timer)*MAX_TIMERS, 0);
    if (!timer) {
        fprintf(stderr, "no memory for timer\n");
        return 1;
    }

    fprintf(stdout, "LCORE 1 loop init...\n");
    start = rte_rdtsc();
    fprintf(stdout, "Add start: %lu\n", start);

    for (i=1; i < MAX_TIMERS+1; i++) {
        j = i % MAX_DELAY;
        tick = (j << LB_HZ_BITS) + (i % LB_HZ_BITS);
        timer->id = i;
        timer->tick = tick;
        err = lb_lcore_init_timer(&timer->tm, tick, timeup_perf);
        if (err) {
            fprintf(stderr, "lb_lcore_init_timer failed\n");
            return 1;
        }
        lb_lcore_add_timer(&timer->tm);
    }
    end = rte_rdtsc();
    fprintf(stdout, "Add end: %lu\n", (end - start)/rte_get_timer_hz());

    g_start_cycle = rte_rdtsc();
    while (1) {
        lb_lcore_timer_manage(rte_rdtsc(), NETIF_PRINCIPAL_STAT_IDLE);
    }

    return EDPVS_OK;
}

int main(int argc, char *argv[])
{
    int err;

    /* init */
    err = rte_eal_init(argc, argv);
    if (err < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return 1;
    }
    rte_timer_subsystem_init();

    err = cfgfile_init();
    if (err) {
        fprintf(stderr, "cfgfile_init failed\n");
        return 1;
    }

    err = lb_timer_init();
    if (err) {
        fprintf(stderr, "lb_timer_init failed\n");
        return 1;
    }

    rte_eal_mp_remote_launch(lcore_loop, NULL, SKIP_MASTER);

    /* start timer */
    gettimeofday(&g_start_time, NULL);

    /* wait for timeout */
    while (1) {
        //rte_timer_manage();
        usleep(RTE_TIMER_INT);
    }

    return 0;
}
