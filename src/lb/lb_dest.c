/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include "common.h"
#include "inet.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/conn.h"
#include "lb/dest.h"
#include "lb/service.h"
#include "lb/sched.h"
#include "route.h"
#include "route6.h"
#include "lb/core.h"
#include "lb/ipv4.h"
#include "lb/ipv6.h"
#include "lb/tcp.h"
#include "lb/udp.h"
#include "lb/icmp.h"
#include "lb/xmit.h"
#include "lb/timer.h"
#include "neigh.h"

static struct lb_dest *lb_core_lookup_dest(struct lb_service   *lbs,
                                                    struct dp_vs_dest  *dpvs_dest)
{
    struct lb_dest *dest;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        if (is_same_server(dest->af, &dest->addr, dest->port, dest->proto,
                    dpvs_dest->af, &dpvs_dest->addr, dpvs_dest->port, dpvs_dest->proto))
            return dest;
    }

    return NULL;
}

struct lb_dest* lb_lcore_lookup_dest_by_tup(struct lb_service* lbs,
    int af, uint8_t proto, union inet_addr* daddr, uint16_t dport)
{
    struct lb_dest* dest;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        if (is_same_server(dest->af, &dest->addr, dest->port, dest->proto
            , af, daddr, dport, proto))
            return dest;
    }

    return NULL;
}

struct lb_dest* lb_lcore_get_dest(struct lb_service* lbs, uint32_t idx)
{
    struct lb_dest* dest;
    uint32_t i = 0;

    list_for_each_entry(dest, &lbs->dests, n_list) {
        if (i == idx) {
            return dest;
        } else {
            i++;
        }
    }

    return NULL;
}

static int lb_lcore_dest_bind_xmit(struct lb_service *lbs, struct lb_dest *dest)
{
    if (dest->proto == IPPROTO_UDP) {
        dest->state_trans = lb_udp_state_trans;
    } else if (dest->proto == IPPROTO_TCP) {
        dest->state_trans = lb_tcp_state_trans;
    }

    switch (dest->fwdmode) {
    case DPVS_FWD_MODE_FNAT:
        if (dest->af == AF_INET) {
            if (lbs->af == AF_INET) {
                dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_fnat_xmit4_in;
                dest->xmit_cb[LB_DEST_XMIT_OUT] = lb_dest_fnat_xmit4_out;
                if (dest->proto == IPPROTO_UDP) {
                    dest->transport_in_handler = lb_ipv4_udp_fnat_in_handler;
                    dest->transport_out_handler = lb_ipv4_udp_fnat_out_handler;
                } else if (dest->proto == IPPROTO_TCP) {
                    dest->transport_in_handler = lb_ipv4_tcp_fnat_in_handler;
                    dest->transport_out_handler = lb_ipv4_tcp_fnat_out_handler;
                }
            } else {
                dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_fnat_xmit64_in;
                dest->xmit_cb[LB_DEST_XMIT_OUT] = lb_dest_fnat_xmit46_out;
                if (dest->proto == IPPROTO_UDP) {
                    dest->transport_in_handler = lb_ipv4_udp_fnat_in_handler;
                    dest->transport_out_handler = lb_ipv6_udp_fnat_out_handler;
                } else if (dest->proto == IPPROTO_TCP) {
                    dest->transport_in_handler = lb_ipv4_tcp_fnat_in_handler;
                    dest->transport_out_handler = lb_ipv6_tcp_fnat_out_handler;
                }
            }
        } else {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_fnat_xmit6_in;
            dest->xmit_cb[LB_DEST_XMIT_OUT] = lb_dest_fnat_xmit6_out;
            if (dest->proto == IPPROTO_UDP) {
                dest->transport_in_handler = lb_ipv6_udp_fnat_in_handler;
                dest->transport_out_handler = lb_ipv6_udp_fnat_out_handler;
            } else if (dest->proto == IPPROTO_TCP) {
                dest->transport_in_handler = lb_ipv6_tcp_fnat_in_handler;
                dest->transport_out_handler = lb_ipv6_tcp_fnat_out_handler;
            }
        }
        if (dest->proto == IPPROTO_TCP) {
            dest->transport_conn_expire = lb_tcp_conn_expire;
        }
        break;

    case DPVS_FWD_MODE_NAT:
        if (dest->af == AF_INET) {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_nat_xmit4_in;
            dest->xmit_cb[LB_DEST_XMIT_OUT] = lb_dest_nat_xmit4_out;
            if (dest->proto == IPPROTO_UDP) {
                dest->transport_in_handler = lb_ipv4_udp_nat_in_handler;
                dest->transport_out_handler = lb_ipv4_udp_nat_out_handler;
            } else if (dest->proto == IPPROTO_TCP) {
                dest->transport_in_handler = lb_ipv4_tcp_nat_in_handler;
                dest->transport_out_handler = lb_ipv4_tcp_nat_out_handler;
            } else if (dest->proto == IPPROTO_ICMP) {
                dest->transport_in_handler = lb_ipv4_icmp_nat_in_handler;
                dest->transport_out_handler = lb_ipv4_icmp_nat_out_handler;
            }
        } else {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_nat_xmit6_in;
            dest->xmit_cb[LB_DEST_XMIT_OUT] = lb_dest_nat_xmit6_out;
            if (dest->proto == IPPROTO_UDP) {
                dest->transport_in_handler = lb_ipv6_udp_nat_in_handler;
                dest->transport_out_handler = lb_ipv6_udp_nat_out_handler;
            } else if (dest->proto == IPPROTO_TCP) {
                dest->transport_in_handler = lb_ipv6_tcp_nat_in_handler;
                dest->transport_out_handler = lb_ipv6_tcp_nat_out_handler;
            } else if (dest->proto == IPPROTO_ICMPV6) {
                dest->transport_in_handler = lb_ipv6_icmp6_nat_in_handler;
                dest->transport_out_handler = lb_ipv6_icmp6_nat_out_handler;
            }
        }
        break;

    case DPVS_FWD_MODE_DR:
        if (dest->af == AF_INET) {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_dr_xmit4;
        } else {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_dr_xmit6;
        }
        break;

    case DPVS_FWD_MODE_SNAT:
        break;

    case DPVS_FWD_MODE_TUNNEL:
        if (lbs->af == AF_INET && dest->af == AF_INET) {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_tunnel_xmit4;
        } else if (lbs->af == AF_INET6 && dest->af == AF_INET) {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_tunnel_xmit6o4;
        } else if (lbs->af == AF_INET6 && dest->af == AF_INET6) {
            dest->xmit_cb[LB_DEST_XMIT_IN] = lb_dest_tunnel_xmit6;
        }
        break;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static inline bool
lb_dest_discover_force(int timeout)
{
    uint8_t nlcore;
    uint64_t lcore_mask;
    int pos, i, index, cid = rte_lcore_id();

    netif_get_slave_lcores(&nlcore, &lcore_mask);
    assert(nlcore != 0);
    pos = timeout % nlcore;
    for (i=0; i<pos; i++) {
        index = rte_bsf64(lcore_mask);
        if (i != (pos-1))
            lcore_mask &= ~(0x1 << index);
    }

    index = rte_bsf64(lcore_mask);

    return index == cid;
}

/* The neigh table is updated regularly. The default is 75 seconds */
static void lb_dest_discover_l3l4_cache(void *priv)
{
    struct lb_dest *dest = list_entry(priv, struct lb_dest, cache_timer);
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct flow6 fl6;
    struct route6 *rt6 = NULL;
    struct neighbour_entry *neighbour;
    union inet_addr     in_nexthop;
    struct timeval          tv;

    if (dest->af == AF_INET) {
        // update in cache
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = dest->addr.in;
        rt = route4_output(&fl4);
        if (!rt) {
            goto error;
        }

        dest->in_dev = rt->port;
        if (rt->gw.s_addr == htonl(INADDR_ANY)) {
            in_nexthop.in = dest->addr.in;
        } else {
            in_nexthop.in = rt->gw;
        }
        dest->mtu = rt->mtu;
        route4_put(rt);
    } else if (dest->af == AF_INET6) {
        // update in cache
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &dest->addr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(NULL, &fl6);
        if (!rt6) {
            goto error;
        }

        dest->in_dev = rt6->rt6_dev;
        if (ipv6_addr_any(&rt6->rt6_gateway)) {
            rte_memcpy(&in_nexthop.in6, &dest->addr.in6, sizeof(struct in6_addr));
        } else {
            rte_memcpy(&in_nexthop.in6, &rt6->rt6_gateway, sizeof(struct in6_addr));
        }
        route6_put(rt6);
    } else
        return;

    neighbour = neigh_lookup(dest->af, &in_nexthop, dest->in_dev, lb_dest_discover_force(LB_DEST_CACHE_DURATION-dest->life_time));
    if (!neighbour) {
        RTE_LOG(DEBUG, LB_RUNNING, "%s: * neighbour WAS not found on core:%d\n", __func__, rte_lcore_id());
        goto error;
    }

    rte_ether_addr_copy(&neighbour->eth_addr, &dest->in_dmac);
    rte_ether_addr_copy(&dest->in_dev->addr, &dest->in_smac);
    dest->flags |= DPVS_DEST_F_AVAILABLE;
    RTE_LOG(DEBUG, LB_RUNNING, "%s: # neighbour WAS found on core:%d\n", __func__, rte_lcore_id());

    tv.tv_sec = neigh_aging_eve_timeout();
    tv.tv_usec = 0;
    lb_lcore_timer_sched(&dest->cache_timer, lb_timeval_to_ticks(&tv), lb_dest_discover_l3l4_cache);
    dest->life_time = LB_DEST_CACHE_DURATION;

    return;

error:
    if (dest->life_time-- > 0) {
        tv.tv_sec = LB_DEST_CACHE_INTERVAL;
        tv.tv_usec = 0;
        RTE_LOG(DEBUG, LB_RUNNING, "%s: update timer on core%d, life: %d\n", __func__, rte_lcore_id(), dest->life_time);
        lb_lcore_timer_sched(&dest->cache_timer, lb_timeval_to_ticks(&tv), lb_dest_discover_l3l4_cache);
    }
}

static void
lb_add_dest_cache_timer(struct lb_dest *dest)
{
    struct timeval          tv;

    tv.tv_sec = LB_DEST_CACHE_INTERVAL;
    tv.tv_usec = 0;

    dest->life_time = LB_DEST_CACHE_DURATION;
    dest->flags &= ~DPVS_DEST_F_AVAILABLE;

    lb_lcore_timer_sched(&dest->cache_timer, lb_timeval_to_ticks(&tv), lb_dest_discover_l3l4_cache);
}

static struct lb_dest *
lb_lcore_lookup_dest(struct dp_vs_dest  *dpvs_dest)
{
    struct lb_dest *dest;
    struct lb_service *lbs;

    assert(dpvs_dest->svc != NULL);

    lbs = lb_lcore_lookup_service(dpvs_dest->svc);
    if (lbs == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: no lb service.\n", __func__);
        return NULL;
    }

    list_for_each_entry(dest, &lbs->dests, n_list) {
        if (!memcpy(&dpvs_dest->addr, &dest->addr, sizeof(union inet_addr)) &&
            (dest->af == dpvs_dest->af) && (dest->proto = dpvs_dest->proto) &&
            (dest->port == dpvs_dest->port))
            return dest;
    }

    return NULL;
}

static struct lb_dest *
lb_lcore_new_dest(struct lb_service *lbs, struct dp_vs_dest  *dpvs_dest)
{
    int size;
    struct lb_dest *dest;
    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct lb_dest));
    dest = rte_zmalloc("lb_new_dest", size, 0);
    if(dest == NULL){
        RTE_LOG(ERR, LB_RUNNING, "%s: no memory.\n", __func__);
        return NULL;
    }

    dest->af = dpvs_dest->af;
    dest->proto = dpvs_dest->proto;
    rte_memcpy(&dest->addr, &dpvs_dest->addr, sizeof(dpvs_dest->addr));
    dest->port = dpvs_dest->port;
    dest->flags = dpvs_dest->flags;
    dest->flags &= ~DPVS_DEST_F_AVAILABLE;
    dest->conn_flags = rte_atomic16_read(&dpvs_dest->conn_flags);
    dest->refcount = 1;
    dest->weight = rte_atomic16_read(&dpvs_dest->weight);
    dest->fwdmode = dpvs_dest->fwdmode;
    dest->max_conn = dpvs_dest->max_conn;
    dest->min_conn = dpvs_dest->min_conn;
    dest->vport = dpvs_dest->vport;
    rte_memcpy(&dest->vaddr, &dpvs_dest->vaddr, sizeof(dpvs_dest->vaddr));
    dest->ipv4_id = (uint16_t)random(); /* used by tunnel mode */
    dest->actconns = 0;
    dest->inactconns = 0;
    if (dest->af == AF_INET) {
        struct flow4 fl4;
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = dest->addr.in;
        struct route_entry *rt = route4_output(&fl4);
        if (!rt) {
            RTE_LOG(ERR, LB_RUNNING, "%s: no route.\n", __func__);
            rte_free(dest);
            return NULL;
        }
        dest->mtu = rt->mtu;
    } else {
        struct flow6 fl6;
        memset(&fl6, 0, sizeof(struct flow6));
        fl6.fl6_daddr = dest->addr.in6;
        struct route6 *rt6 = route6_output(NULL, &fl6);
        if (!rt6) { 
            RTE_LOG(ERR, LB_RUNNING, "%s: no route.\n", __func__);
            rte_free(dest);
            return NULL;
        }
        dest->mtu = rt6->rt6_mtu;
    }

    if (lbs->fwdmod != DPVS_FWD_MODE_SNAT) {
        lb_lcore_dest_bind_xmit(lbs, dest);
        lb_add_dest_cache_timer(dest);
    }

    return dest;
}

int lb_lcore_del_dest(struct lb_dest *dest)
{
    if (!dest)
        return EDPVS_INVAL;

    if (lb_timer_pending(&dest->cache_timer))
        lb_lcore_del_timer(&dest->cache_timer);

    dest->flags &= ~DPVS_DEST_F_AVAILABLE;
    lb_dest_put(dest);

    return EDPVS_OK;
}

static int
lcore_dest_add(struct dp_vs_dest       *dpvs_dest)
{
    struct lb_service *lbs;
    struct lb_dest *dest;

    assert(dpvs_dest->svc != NULL);

    lbs = lb_lcore_lookup_service(dpvs_dest->svc);
    if (lbs == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: no lb service.\n", __func__);
        return EDPVS_INVAL;
    }

    if (lbs->fwdmod == DPVS_FWD_MODE_UNKNOWN)
        lbs->fwdmod = dpvs_dest->fwdmode;

    if (lbs->fwdmod != dpvs_dest->fwdmode) {
        RTE_LOG(ERR, LB_RUNNING, "%s: Different forwarding modes are not supported.\n", __func__);
        return EDPVS_INVAL;
    }

    dest = lb_lcore_new_dest(lbs, dpvs_dest);
    if (dest == NULL)
        return EDPVS_NOMEM;

    dest->lbs = lbs;
    list_add(&dest->n_list, &lbs->dests);
    lbs->weight += rte_atomic16_read(&dpvs_dest->weight);
    lbs->num_dests++;

    if (lbs->scheduler->update_service)
        lbs->scheduler->update_service(lbs, dest);

    return EDPVS_OK;
}



static int
lcore_dest_del(struct dp_vs_dest       *dpvs_dest)
{
    struct lb_dest *dest;

    dest = lb_lcore_lookup_dest(dpvs_dest);
    if (dest == NULL) {
        RTE_LOG(ERR, LB_RUNNING, "%s: not find dest.\n", __func__);
        return EDPVS_INVAL;
    }

    return lb_lcore_del_dest(dest);
}

static int dest_add_msg_cb(struct dpvs_msg *msg)
{
    return lcore_dest_add((struct dp_vs_dest *)msg->data);
}

static int dest_del_msg_cb(struct dpvs_msg *msg)
{
    return lcore_dest_del((struct dp_vs_dest *)msg->data);
}

static int dest_get_stat_msg_cb(struct dpvs_msg *msg)
{
    struct dpvs_lb_dest_entry *lb_entry = (struct dpvs_lb_dest_entry *)msg->data;
    struct dp_vs_service *svc = lb_entry->svc;
    struct lb_service *lbs;
    struct lb_dest    *dest;
    struct dpvs_lb_dest_entry *reply;

    if (svc == NULL)
        return EDPVS_INVAL;

    lbs = lb_lcore_lookup_service(svc);
    if (lbs == NULL)
        return EDPVS_EXIST;

    dest = lb_core_lookup_dest(lbs, lb_entry->dest);
    if (dest == NULL)
        return EDPVS_EXIST;

    reply = msg_reply_alloc(sizeof(*reply));
    if (reply == NULL)
        return EDPVS_NOMEM;

    memset(reply, 0, sizeof(*reply));
    reply->cid = rte_lcore_id();

    reply->entry.stats.conns      = dest->stats.conns;
    reply->entry.stats.inpkts     = dest->stats.inpkts;
    reply->entry.stats.inbytes    = dest->stats.inbytes;
    reply->entry.stats.outpkts    = dest->stats.outpkts;
    reply->entry.stats.outbytes   = dest->stats.outbytes;
    reply->entry.actconns         = dest->stats.conns;
    reply->entry.inactconns       = dest->inactconns;

    msg->reply.len = sizeof(*reply);
    msg->reply.data = reply;

    return EDPVS_OK;

}

int lb_dest_init(void)
{
    struct dpvs_msg_type msg_type;
    int err;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_DEST_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dest_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_DEST_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dest_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_GET_LB_DEST_STATS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dest_get_stat_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, LB_INIT, "%s: fail to register msg.\n", __func__);
        return err;
    }

    return err;
}

void lb_dest_uninit(void)
{

}

