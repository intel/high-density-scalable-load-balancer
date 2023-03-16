/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_CORE_H__
#define __LB_CORE_H__

#define LB_DEBUG_CMD_TIMER  0
#define LB_DEBUG_CMD_LOOP_CYCLE 1
#define LB_DEBUG_CMD_SNAT_POOL  2
#define LB_DEBUG_CMD_MEMPOOL    3
#define LB_DEBUG_CMD_NETIF_STAT 4

#ifndef LB_INIT
#define LB_INIT
#define RTE_LOGTYPE_LB_INIT    RTE_LOGTYPE_USER1
#endif

#ifndef LB_RUNNING
#define LB_RUNNING
#define RTE_LOGTYPE_LB_RUNNING    RTE_LOGTYPE_USER1
#endif


struct lb_debug_timer_arg {
    uint64_t delay;
};

struct lb_debug_loop_record {
    uint32_t percision;
    uint8_t  clean;
};

struct lb_debug_arg {
    uint8_t cmd;
    uint8_t cid;
    union {
        struct lb_debug_timer_arg timer_arg;
        struct lb_debug_loop_record loop_record_arg;
    };
};


int lb_core_init(void);
void lb_core_uninit(void);
void lb_debug_handler(const void *user, size_t len, void **out, size_t *outlen);


#endif
