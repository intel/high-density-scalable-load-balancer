/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include "dpdk.h"
#include "list.h"
#include "common.h"
#include "netif.h"
#include "route.h"
#include "inet.h"
#include "ctrl.h"
#include "ipvs/ipvs.h"
#include "ipvs/service.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/laddr.h"
#include "conf/laddr.h"
#include "lb/core.h"
#include "lb/service.h"
#include "lb/laddr.h"
#include "lb/conn.h"
#include "lb/snat_pool.h"

#define LADDR_IPV4_MASK       0xFFFFFF00

static int
lcore_laddr_add(struct dpvs_laddr_arg     *arg)
{
    struct lb_service *lbs;

    lbs = lb_lcore_lookup_service(arg->svc);
    if (lbs == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: no lb service.\n", __func__);
        return EDPVS_NOTEXIST;
    }


    if (lbs->fwdmod == DPVS_FWD_MODE_FNAT) {
        if (lbs->snat_pool)
            return EDPVS_EXIST;

        lbs->snat_pool = lb_snat_pool_association_multiply(arg->af, arg->iface, arg->addr, lbs->proto, rte_lcore_id());
        if (!lbs->snat_pool) {
            RTE_LOG(ERR, LB_RUNNING, "%s: snat_pool is NULL.\n", __func__);
            return EDPVS_NOTEXIST;
        }
        lbs->conn_cache_out = lb_get_fnat_conn_hash_cache_out_use_addr(arg->addr);
        if (!lbs->conn_cache_out) {
            RTE_LOG(ERR, LB_RUNNING, "%s: conn_cache_out is NULL.\n", __func__);
            return EDPVS_NOTEXIST;
        }
    } else if (lbs->fwdmod == DPVS_FWD_MODE_SNAT) {
        
    }

    return !lbs->snat_pool;
}

static int
lcore_laddr_del(struct dpvs_laddr_arg       *arg)
{
    struct lb_service *lbs;

    lbs = lb_lcore_lookup_service(arg->svc);
    if (lbs == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: no lb service.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    if (lbs->fwdmod == DPVS_FWD_MODE_FNAT) {
        lb_snat_pool_deassociation_multiply(lbs->snat_pool, arg->iface);
        lbs->snat_pool = NULL;
    } else if (lbs->fwdmod == DPVS_FWD_MODE_SNAT) {
        
    }

    return EDPVS_OK;
}

static int laddr_add_msg_cb(struct dpvs_msg *msg)
{
    return lcore_laddr_add((struct dpvs_laddr_arg *)msg->data);
}

static int laddr_del_msg_cb(struct dpvs_msg *msg)
{
    return lcore_laddr_del((struct dpvs_laddr_arg *)msg->data);
}

int lb_laddr_init(void)
{
    struct dpvs_msg_type msg_type;
    int err;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = laddr_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = laddr_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    return err;

}

void lb_laddr_uninit(void)
{

}

