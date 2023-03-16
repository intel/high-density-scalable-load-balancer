/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <unistd.h>
#include "dpdk.h"
#include "cfgfile.h"
#include "timer.h"
#include "lb/timer.h"

#define RTE_TIMER_INT 50     /* us */
#define MAX_DELAY     31     /* s */

static struct timeval g_start_time;

struct test_data {
    struct lb_timer tm;
    int id;
};

static void timeup(void *arg)
{
    struct timeval now, elapsed;
    struct test_data *timer = arg;
    struct lb_timer *tm = &timer->tm;

    gettimeofday(&now, NULL);
    timersub(&now, &g_start_time, &elapsed);

    fprintf(stdout, "*** timer %d timeout: %lu, elapsed time: %lu.%06lu\n", timer->id,
            tm->delay, elapsed.tv_sec, elapsed.tv_usec);

    rte_free(tm);
}

static volatile rte_atomic32_t once = RTE_ATOMIC32_INIT(0);
static int lcore_loop(void *arg)
{
    int i, err;
    unsigned cid = rte_lcore_id();
    struct test_data *timer;
    struct timeval tv;

    if (!rte_atomic32_cmpset(&once, 0, 1))
        return EDPVS_OK;

    //if (!rte_lcore_is_enabled(cid))
        //return EDPVS_DISABLED;

    fprintf(stdout, "LCORE %u loop init...\n", cid);

    for (i = 1; i < MAX_DELAY; i++) {
        timer = rte_zmalloc("timer", sizeof(struct lb_timer), 0);
        if (!timer) {
            fprintf(stderr, "no memory for timer\n");
            return 1;
        }
        memset(timer, 0, sizeof(*timer));
        tv.tv_sec = i;
        tv.tv_usec = i % 4;

        timer->id = i;
        err = lb_lcore_init_timer(&timer->tm, lb_timeval_to_ticks(&tv), timeup);
        if (err) {
            fprintf(stderr, "lb_lcore_init_timer failed\n");
            return 1;
        }
        lb_lcore_add_timer(&timer->tm);
    }
    fprintf(stdout, "LCORE %u loop start...\n", cid);

    while (1) {
        lb_lcore_timer_manage(rte_rdtsc(), NETIF_PRINCIPAL_STAT_IDLE);
        usleep(1);
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
