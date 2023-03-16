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
#include "lb/laddr.h"
#include "lb/sched.h"
#include "lb/core.h"
#include "lb/timer.h"
#include "lb/snat_pool.h"
#include "lb/sync.h"
#include "lb/redirect.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "dpdk.h"

static int lcore_debug_msg_cb(struct dpvs_msg *msg)
{
    struct lb_debug_arg *arg = (struct lb_debug_arg *)(msg->data);

    if (!msg || !msg->len || msg->mode != DPVS_MSG_UNICAST || !arg)
        return EDPVS_INVAL;

    if (arg->cmd == LB_DEBUG_CMD_TIMER) {
        RTE_LOG(INFO, LB_TIMER, "timer debug on core: %d\n", rte_lcore_id());
        lb_lcore_timer_dump_info(arg->timer_arg.delay << LB_HZ_BITS);
    }
#ifdef CONFIG_RECORD_LOOP_CYCLE
    else if (arg->cmd == LB_DEBUG_CMD_LOOP_CYCLE) {
        extern bool g_netif_cycle_dump[DPVS_MAX_LCORE];
        extern uint32_t g_netif_cycle_precision[DPVS_MAX_LCORE];
        extern uint8_t g_netif_cycle_clean[DPVS_MAX_LCORE];

        RTE_LOG(INFO, LB_TIMER, "record loop cycle debug on core: %d\n", rte_lcore_id());
        g_netif_cycle_dump[rte_lcore_id()] = true;
        g_netif_cycle_precision[rte_lcore_id()] = arg->loop_record_arg.percision;
        g_netif_cycle_clean[rte_lcore_id()] = arg->loop_record_arg.clean;
    }
#endif
    else if (arg->cmd == LB_DEBUG_CMD_SNAT_POOL) {
        lb_snat_pool_debug();
    } else {
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static inline int lb_lcore_debug_msg_init(void)
{
    int ii, err;
    struct dpvs_msg_type lb_msg_type = {
        .type = MSG_TYPE_LB_DEBUG,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_debug_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (ii == rte_get_master_lcore() || !rte_lcore_is_enabled(ii) || netif_lcore_is_idle(ii))
            continue;

        lb_msg_type.cid = ii;
        err = msg_type_register(&lb_msg_type);
        if (EDPVS_OK != err) {
            RTE_LOG(DEBUG, LB_INIT, "[%s] fail to register MSG_TYPE_LB_DEBUG msg-type "
                    "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
            return err;
        }
    }

    return EDPVS_OK;
}

static inline int lb_lcore_debug_msg_term(void)
{
    int ii, err;
    struct dpvs_msg_type lb_msg_type = {
        .type = MSG_TYPE_LB_DEBUG,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_debug_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (ii == rte_get_master_lcore() || !rte_lcore_is_enabled(ii) || netif_lcore_is_idle(ii))
            continue;

        lb_msg_type.cid = ii;
        err = msg_type_unregister(&lb_msg_type);
        if (EDPVS_OK != err) {
            RTE_LOG(WARNING, LB_INIT, "[%s] fail to unregister MSG_TYPE_LB_DEBUG msg-type "
                    "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
            return err;
        }
    }

    return EDPVS_OK;
}

static int lb_debug_init(void)
{
    return lb_lcore_debug_msg_init();
}

static void lb_debug_uninit(void)
{
    lb_lcore_debug_msg_term();
}

static int __lb_debug_handler(lcoreid_t cid, const void *user, size_t len, void **out, size_t *outlen)
{
    assert(out && outlen);
    int err;
    struct dpvs_msg *pmsg;
    struct dpvs_msg_reply *reply;

    pmsg = msg_make(MSG_TYPE_LB_DEBUG, 0, DPVS_MSG_UNICAST, cid, len, user);
    if (unlikely(!pmsg)) {
        return EDPVS_NOMEM;
    }

    err = msg_send(pmsg, cid, 0, &reply);
    if (EDPVS_OK != err) {
        msg_destroy(&pmsg);
        return err;
    }

    msg_destroy(&pmsg);

    return EDPVS_OK;
}


void lb_debug_handler(const void *user, size_t len, void **out, size_t *outlen)
{
    struct lb_debug_arg *arg = (struct lb_debug_arg *)user;

    if (!user)
        return;

    if (arg->cmd == LB_DEBUG_CMD_MEMPOOL) {
        rte_mempool_list_dump(stdout);
        return;
    }

    if (arg->cmd == LB_DEBUG_CMD_NETIF_STAT) {
        netif_show_stats(arg->cid);
        return;
    }

    __lb_debug_handler(arg->cid, user, len, out, outlen);
}

int lb_core_init(void)
{
    int ret;

    ret = lb_service_init();
    if (ret)
        return ret;;

    ret = lb_sched_init();
    if (ret)
        goto err_sched;

    ret = lb_dest_init();
    if (ret)
        goto err_dest;

    ret = lb_laddr_init();
    if (ret)
        goto err_laddr;

    lb_timer_init();
    lb_debug_init();
    lb_snat_pool_init();
    ret = lb_conn_init();
    if (ret) {
        return ret;
    }
    lb_sync_init();
    lb_init_pipe();
    ret = lb_redirect_init();
    if (ret)
        goto err_redirect;

    return ret;

err_sched:
    lb_service_uninit();
err_dest:
    lb_sched_term();
err_laddr:
    lb_dest_uninit();
err_redirect:
    lb_redirect_term();

    return ret;
}

void lb_core_uninit(void)
{
    lb_sync_term();
    lb_debug_uninit();
    lb_service_uninit();
    lb_sched_term();
    lb_dest_uninit();
    lb_laddr_uninit();
}

