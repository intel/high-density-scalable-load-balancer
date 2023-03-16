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
#include "lb/core.h"
#include "lb/service.h"
#include "lb/conn.h"
#include "lb/dest.h"
#include "lb/laddr.h"
#include "lb/sched.h"
#include "lb/ipv4.h"
#include "lb/ipv6.h"
#include "lb/tcp.h"
#include "lb/udp.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"

#define LB_MAX_SERVICE  DP_VS_MAX_SERVER_ID
#define LB_FLOW_ID_BASE DP_VS_FLOW_ID_BASE

#define this_lb_services               (RTE_PER_LCORE(lb_services))
#define this_service_count             (RTE_PER_LCORE(lb_service_count))
#define this_ipv4_hash_table_add_flag  (RTE_PER_LCORE(ipv4_hash_table_add_flag))
#define this_ipv6_hash_table_add_flag  (RTE_PER_LCORE(ipv6_hash_table_add_flag))

static RTE_DEFINE_PER_LCORE(struct lb_service *, lb_services);
static RTE_DEFINE_PER_LCORE(uint32_t, lb_service_count);
static RTE_DEFINE_PER_LCORE(uint32_t, ipv4_hash_table_add_flag);
static RTE_DEFINE_PER_LCORE(uint32_t, ipv6_hash_table_add_flag);


static int service_init_lcore(void *arg)
{
    int i, cid = rte_lcore_id();

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    if (netif_lcore_is_idle(cid))
        return EDPVS_IDLE;

    this_lb_services = rte_malloc_socket(NULL,
                        sizeof(struct lb_service) * LB_MAX_SERVICE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!this_lb_services)
        return EDPVS_NOMEM;

    for (i = 0; i < LB_MAX_SERVICE; i++) {
        this_lb_services[i].status = LB_STATUS_SERVICE_FREE;
        this_lb_services[i].refcount = 0;
    }

    this_service_count = 0;

    return EDPVS_OK;
}

struct lb_service *lb_lcore_lookup_service(struct dp_vs_service *svc)
{
    int i;
    struct lb_service *lbs;

    for (i = 0; i < LB_MAX_SERVICE; i++) {
        lbs = &this_lb_services[i];
        if (lbs->status == LB_STATUS_SERVICE_BUSY &&
                lbs->af == svc->af &&
                lbs->proto == svc->proto &&
                inet_addr_equal(lbs->af, &lbs->addr, &svc->addr) &&
                lbs->port == svc->port) {
            return lbs;
        }
    }

    return NULL;
}

struct lb_service* lb_lcore_lookup_service_by_tup(int af, uint8_t protocol
    , const union inet_addr* vaddr, uint16_t vport)
{
    int i;
    struct lb_service* lbs = NULL;

    for (i = 0; i < LB_MAX_SERVICE; i++) {
        lbs = &this_lb_services[i];
        if (LB_STATUS_SERVICE_BUSY == lbs->status &&
            lbs->af == af &&
            lbs->proto == protocol &&
            inet_addr_equal(lbs->af, &lbs->addr, vaddr) &&
            lbs->port == vport) {
           return lbs;
        }
    }

    return NULL;
}

struct lb_service* lb_lcore_lookup_service_by_markid(uint8_t markid)
{
    int i;
    struct lb_service* lbs = NULL;

    for (i = 0; i < LB_MAX_SERVICE; i++) {
        lbs = &this_lb_services[i];
        if (LB_STATUS_SERVICE_BUSY == lbs->status && lbs->markid == markid) {
            return lbs;
        }
    }

    return NULL;
}

struct lb_service* lb_lcore_get_service(uint32_t start_idx, uint32_t* found_idx)
{
    struct lb_service* lbs = NULL;
    *found_idx = 0;
    if (NULL == this_lb_services) {
        return NULL;
    }
    while (start_idx < LB_MAX_SERVICE) {
        if (LB_STATUS_SERVICE_BUSY == this_lb_services[start_idx].status) {
            *found_idx = start_idx;
            lbs = &this_lb_services[start_idx];
            break;
        }
        start_idx++;
    }

    return lbs;
}

/*
 *  Only add service, No packets in beacuse fdir rule was not created.
 */
static int lcore_service_add(struct dp_vs_service *svc)
{
    struct dp_vs_flowid flow_id;
    uint8_t index;
    struct lb_service *lbs = NULL;
    struct lb_scheduler *sched = NULL;
    int err;

    flow_id.value = svc->markid;
    index = flow_id.id;

    sched = lb_scheduler_get(svc->scheduler->name);
    if(sched == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: scheduler not found.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    if (this_service_count >= LB_MAX_SERVICE) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: %s.\n",
                    __func__, rte_lcore_id, dpvs_strerror(EDPVS_NOROOM));
        return EDPVS_NOROOM;
    }

    lbs = &this_lb_services[index];
    if (lbs->status != LB_STATUS_SERVICE_FREE) {
        RTE_LOG(WARNING, LB_RUNNING, "%s: lcore %d, index: %s.\n",
                    __func__, rte_lcore_id, index, dpvs_strerror(EDPVS_NOROOM));
        return EDPVS_NOROOM;
    }

    // fill lbs
    lbs->af = svc->af;
    lbs->proto = svc->proto;
    memcpy(&lbs->addr, &svc->addr, sizeof(lbs->addr));
    lbs->port = svc->port;
    lbs->weight = svc->weight;
    lbs->markid = svc->markid;
    lbs->flags = svc->flags;
    lbs->refcount = 1;
    lbs->num_dests = 0;
    INIT_LIST_HEAD(&lbs->dests);
    lbs->fwdmod = DPVS_FWD_MODE_UNKNOWN;

    err = lb_bind_scheduler(lbs, sched);
    if (err) {
        goto err;
    }

    if (svc->af == AF_INET) {
        if (IPPROTO_ICMP == lbs->proto) {
            lbs->flow_cb[DP_VS_FLOW_DIR_IN] = lb_flow_nat_icmp_ipv4_in;
        } else {
            lbs->flow_cb[DP_VS_FLOW_DIR_IN] = lb_flow_ipv4_in;
        }
        if (0 == this_ipv4_hash_table_add_flag) {
            if (lb_conn_hash_table_init(svc->af)) {
                goto err;
            }
            this_ipv4_hash_table_add_flag = 1;
        }
    } else {
        if (IPPROTO_ICMPV6 == lbs->proto) {
            lbs->flow_cb[DP_VS_FLOW_DIR_IN] = lb_flow_nat_icmp6_ipv6_in;
        } else {
            lbs->flow_cb[DP_VS_FLOW_DIR_IN] = lb_flow_ipv6_in;
        }
        if (0 == this_ipv6_hash_table_add_flag) {
            if (lb_conn_hash_table_init(svc->af)) {
                goto err;
            }
            this_ipv6_hash_table_add_flag = 1;
        }
    }

    if (IPPROTO_UDP == lbs->proto) {
        lbs->get_transport = get_udp_port;
    } else if (IPPROTO_TCP == lbs->proto) {
        lbs->get_transport = get_tcp_port;
    } else {

    }

    lbs->status = LB_STATUS_SERVICE_BUSY;
    this_service_count++;

    return EDPVS_OK;

err:
    // TODO err handler
    return err;
}


static int lcore_service_del(struct dp_vs_service *svc)
{
    struct lb_service *lbs = NULL;
    struct dp_vs_flowid flow_id;
    struct lb_dest *dest, *t;

    flow_id.value = svc->markid;

    if (flow_id.id >= LB_MAX_SERVICE) {
        RTE_LOG(ERR, LB_RUNNING, "%s: scheduler not found.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    lbs = &this_lb_services[flow_id.id];

    lbs->status = LB_STATUS_SERVICE_INACTIVE;
    list_for_each_entry_safe(dest, t, &lbs->dests, n_list) {
        list_del(&dest->n_list);
        lb_lcore_del_dest(dest);
    }

    return 0;
}

static int service_add_msg_cb(struct dpvs_msg *msg)
{
    return lcore_service_add((struct dp_vs_service *)msg->data);
}

static int service_del_msg_cb(struct dpvs_msg *msg)
{
    return lcore_service_del((struct dp_vs_service *)msg->data);
}

static int service_get_stat_msg_cb(struct dpvs_msg *msg)
{
    struct dp_vs_service *svc = (struct dp_vs_service *)msg->data;
    struct lb_service *lbs;
    struct lb_dest    *dest;
    struct dpvs_lb_stats *lb_stat;

    if (svc == NULL)
        return EDPVS_INVAL;

    lbs = lb_lcore_lookup_service(svc);
    if (lbs == NULL)
        return EDPVS_EXIST;

    lb_stat = msg_reply_alloc(sizeof(*lb_stat));
    if (lb_stat == NULL)
        return EDPVS_NOMEM;

    memset(lb_stat, 0, sizeof(*lb_stat));
    lb_stat->cid = rte_lcore_id();
    lb_stat->rsp_status = DPVS_LB_STAT_OK;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        lb_stat->stats.conns      += dest->stats.conns;
        lb_stat->stats.inpkts     += dest->stats.inpkts;
        lb_stat->stats.inbytes    += dest->stats.inbytes;
        lb_stat->stats.outpkts    += dest->stats.outpkts;
        lb_stat->stats.outbytes   += dest->stats.outbytes;
    }

    msg->reply.len = sizeof(*lb_stat);
    msg->reply.data = lb_stat;

    return EDPVS_OK;
}

static void lb_service_process_null_mbuf(void)
{
    lb_flow_pipeline_run(NULL, 0, NULL, NULL, 0);
}

static void lb_fnat_out_process(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    if (mbuf) {
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        if (RTE_ETHER_TYPE_IPV4 == rte_be_to_cpu_16(eth_hdr->ether_type)) {
            lb_flow_ipv4_out(mbuf, lbs, markid);
        } else {
            lb_flow_ipv6_out(mbuf, lbs, markid);
        }
    } else {
        lb_service_process_null_mbuf();
    }
}

static void lb_nat_out_process(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    if (mbuf) {
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        if (RTE_ETHER_TYPE_IPV4 == rte_be_to_cpu_16(eth_hdr->ether_type)) {
            lb_flow_nat_ipv4_out(mbuf, lbs, markid);
        } else {
            lb_flow_nat_ipv6_out(mbuf, lbs, markid);
        }
    } else {
        lb_service_process_null_mbuf();
    }
}

static void lb_service_process(struct rte_mbuf *mbuf, uint8_t markid)
{
    struct dp_vs_flowid flow_id;
    struct lb_service *lbs;

    flow_id.value = markid;
    if (unlikely(flow_id.id >= LB_MAX_SERVICE)) {
        rte_pktmbuf_free(mbuf);
        return;
    }

    if (DP_VS_FLOW_DIR_IN == flow_id.dir) {
        lbs = &this_lb_services[flow_id.id];
        if (LB_STATUS_SERVICE_BUSY == lbs->status && lbs->flow_cb[flow_id.dir]) {
            lbs->flow_cb[flow_id.dir](mbuf, lbs, flow_id.id);
        }
    } else if (DP_VS_FLOW_DIR_SNAT_OUT == flow_id.dir) {
        lb_fnat_out_process(mbuf, NULL, flow_id.id);
    } else {
        lbs = &this_lb_services[flow_id.id];
        lb_nat_out_process(mbuf, lbs, flow_id.id);
    }
}

int lb_service_init(void)
{
    struct dpvs_msg_type msg_type;
    int err;
    lcoreid_t lcore;

    rte_eal_mp_remote_launch(service_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, LB_INIT, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SERVER_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = service_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SERVER_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = service_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_GET_LB_SERVER_STATS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = service_get_stat_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    netif_set_flow_handler(lb_service_process);

    return EDPVS_OK;
}


void lb_service_uninit(void)
{

}

