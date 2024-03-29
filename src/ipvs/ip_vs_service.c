/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/blklst.h"
#include "lb/core.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "ipset.h"

static int dp_vs_num_services = 0;

/**
 * hash table for svc
 */
#define DP_VS_SVC_TAB_BITS 8
#define DP_VS_SVC_TAB_SIZE (1 << DP_VS_SVC_TAB_BITS)
#define DP_VS_SVC_TAB_MASK (DP_VS_SVC_TAB_SIZE - 1)

static struct list_head dp_vs_svc_table[DP_VS_SVC_TAB_SIZE];

static struct list_head dp_vs_svc_fwm_table[DP_VS_SVC_TAB_SIZE];

static struct list_head dp_vs_svc_match_list;

static uint8_t g_server_id[DP_VS_MAX_SERVER_ID];

static uint8_t dp_vs_alloc_server_id(void)
{
    uint8_t i;
    struct dp_vs_flowid flow_id;

    flow_id.value = 0;
    for (i = 0; i < DP_VS_MAX_SERVER_ID; i++) {
        if (g_server_id[i] == DP_VS_F_SERVER_ID_FREE) {
            flow_id.dir = DP_VS_FLOW_DIR_IN; //server default set in.
            flow_id.id = i;
            if (flow_id.value == NETIF_FLOW_INVALID) {
                return EDPVS_NOROOM;
            }

            g_server_id[i] = DP_VS_F_SERVER_ID_BUSY;
            return flow_id.value;
        }
    }

    return EDPVS_NOROOM;
}

static void dp_vs_free_server_id(uint8_t id)
{
    struct dp_vs_flowid flow_id;

    flow_id.value = id;

    if (id < DP_VS_MAX_SERVER_ID && 
        g_server_id[flow_id.id] == DP_VS_F_SERVER_ID_BUSY)
        g_server_id[flow_id.id] = DP_VS_F_SERVER_ID_FREE;
}


static inline unsigned dp_vs_svc_hashkey(int af, unsigned proto, const union inet_addr *addr)
{
    uint32_t addr_fold;

    addr_fold = inet_addr_fold(af, addr);

    if (!addr_fold) {
        RTE_LOG(DEBUG, SERVICE, "%s: IP proto not support.\n", __func__);
        return 0;
    }

    return (proto ^ rte_be_to_cpu_32(addr_fold)) & DP_VS_SVC_TAB_MASK;
}

static inline unsigned dp_vs_svc_fwm_hashkey(uint32_t fwmark)
{
    return fwmark & DP_VS_SVC_TAB_MASK;
}

static int dp_vs_svc_hash(struct dp_vs_service *svc)
{
    unsigned hash;

    if (svc->flags & DP_VS_SVC_F_HASHED){
        RTE_LOG(DEBUG, SERVICE, "%s: request for already hashed.\n", __func__);
        return EDPVS_EXIST;
    }

    if (svc->fwmark) {
        hash = dp_vs_svc_fwm_hashkey(svc->fwmark);
        list_add(&svc->f_list, &dp_vs_svc_fwm_table[hash]);
    } else if (svc->match) {
        list_add(&svc->m_list, &dp_vs_svc_match_list);
    } else {
        /*
         *  Hash it by <protocol,addr,port> in dp_vs_svc_table
         */
        hash = dp_vs_svc_hashkey(svc->af, svc->proto, &svc->addr);
        list_add(&svc->s_list, &dp_vs_svc_table[hash]);
    }

    svc->flags |= DP_VS_SVC_F_HASHED;
    rte_atomic32_inc(&svc->refcnt);
    return EDPVS_OK;
}

static int dp_vs_svc_unhash(struct dp_vs_service *svc)
{
    if (!(svc->flags & DP_VS_SVC_F_HASHED)) {
        RTE_LOG(DEBUG, SERVICE, "%s: request for unhashed flag.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    if (svc->fwmark)
        list_del(&svc->f_list);
    else if (svc->match)
        list_del(&svc->m_list);
    else
        list_del(&svc->s_list);

    svc->flags &= ~DP_VS_SVC_F_HASHED;
    rte_atomic32_dec(&svc->refcnt);
    return EDPVS_OK;
}

struct dp_vs_service *__dp_vs_service_get(int af, uint16_t protocol,
                                          const union inet_addr *vaddr,
                                          uint16_t vport)
{
    unsigned hash;
    struct dp_vs_service *svc;

    hash = dp_vs_svc_hashkey(af, protocol, vaddr);
    list_for_each_entry(svc, &dp_vs_svc_table[hash], s_list){
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->port == vport)
            && (svc->proto == protocol)) {
                rte_atomic32_inc(&svc->usecnt);
                return svc;
            }
    }

    return NULL;
}

struct dp_vs_service *__dp_vs_svc_fwm_get(int af, uint32_t fwmark)
{
    unsigned hash;
    struct dp_vs_service *svc;

    /* Check for fwmark addressed entries */
    hash = dp_vs_svc_fwm_hashkey(fwmark);

    list_for_each_entry(svc, &dp_vs_svc_fwm_table[hash], f_list) {
        if (svc->fwmark == fwmark && svc->af == af) {
            /* HIT */
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

static inline bool __svc_in_range(int af,
                                  const union inet_addr *addr, __be16 port,
                                  const struct inet_addr_range *range)
{
    if (unlikely((af == AF_INET) &&
        (ntohl(range->min_addr.in.s_addr) > ntohl(range->max_addr.in.s_addr))))
        return false;

    if (unlikely((af == AF_INET6) &&
        ipv6_addr_cmp(&range->min_addr.in6, &range->max_addr.in6) > 0))
        return false;

    if (unlikely(ntohs(range->min_port) > ntohs(range->max_port)))
        return false;

    /* if both min/max are zero, means need not check. */
    if (!inet_is_addr_any(af, &range->max_addr)) {
        if (af == AF_INET) {
            if (ntohl(addr->in.s_addr) < ntohl(range->min_addr.in.s_addr) ||
                ntohl(addr->in.s_addr) > ntohl(range->max_addr.in.s_addr))
                return false;
        } else {
            if (ipv6_addr_cmp(&range->min_addr.in6, &addr->in6) > 0 ||
                ipv6_addr_cmp(&range->max_addr.in6, &addr->in6) < 0)
                return false;
        }
    }

    if (range->max_port != 0) {
        if (ntohs(port) < ntohs(range->min_port) ||
            ntohs(port) > ntohs(range->max_port))
            return false;
    }

    return true;
}

static struct dp_vs_service *
__dp_vs_svc_match_get4(const struct rte_mbuf *mbuf, bool *outwall)
{
    struct route_entry *rt = mbuf->userdata;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf); /* ipv4 only */
    struct dp_vs_service *svc;
    union inet_addr saddr, daddr;
    __be16 _ports[2], *ports;
    portid_t oif = NETIF_PORT_ID_ALL;

    saddr.in.s_addr = iph->src_addr;
    daddr.in.s_addr = iph->dst_addr;
    ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return NULL;

    /* snat is handled at pre-routing to check if oif
     * is match perform route here. */
    if (rt) {
        if ((rt->flag & RTF_KNI) || (rt->flag & RTF_LOCALIN))
            return NULL;
        oif = rt->port->id;
    } else if (outwall != NULL && (NULL != ipset_addr_lookup(AF_INET, &daddr))
                               && (rt = route_gfw_net_lookup(&daddr.in))) {
        char dst[64];	     
        RTE_LOG(DEBUG, IPSET, "%s: IP %s is in the gfwip set, found route in the outwall table.\n", __func__, 
                              inet_ntop(AF_INET, &daddr, dst, sizeof(dst))? dst: "");	    
        oif = rt->port->id;
        route4_put(rt);
        *outwall = true;
    } else {
        rt = route4_input(mbuf, &daddr.in, &saddr.in,
                          iph->type_of_service,
                          netif_port_get(mbuf->port));
        if (!rt)
            return NULL;
        if ((rt->flag & RTF_KNI) || (rt->flag & RTF_LOCALIN)) {
            route4_put(rt);
            return NULL;
        }
        oif = rt->port->id;
        route4_put(rt);
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        if (!strlen(m->oifname))
            oif = NETIF_PORT_ID_ALL;

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        if (svc->af == AF_INET && svc->proto == iph->next_proto_id &&
            __svc_in_range(AF_INET, &saddr, ports[0], &m->srange) &&
            __svc_in_range(AF_INET, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

static struct dp_vs_service *
__dp_vs_svc_match_get6(const struct rte_mbuf *mbuf)
{
    struct route6 *rt = mbuf->userdata;
    struct ip6_hdr *iph = ip6_hdr(mbuf);
    uint8_t ip6nxt = iph->ip6_nxt;
    struct dp_vs_service *svc;
    union inet_addr saddr, daddr;
    __be16 _ports[2], *ports;
    portid_t oif = NETIF_PORT_ID_ALL;

    struct flow6 fl6 = {
        .fl6_iif    = NULL,
        .fl6_daddr  = iph->ip6_dst,
        .fl6_saddr  = iph->ip6_src,
        .fl6_proto  = iph->ip6_nxt,
    };

    saddr.in6 = iph->ip6_src;
    daddr.in6 = iph->ip6_dst;
    ports = mbuf_header_pointer(mbuf, ip6_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return NULL;

    /* snat is handled at pre-routing to check if oif
     * is match perform route here. */
    if (rt) {
        if ((rt->rt6_flags & RTF_KNI) || (rt->rt6_flags & RTF_LOCALIN))
            return NULL;
        oif = rt->rt6_dev->id;
    } else {
        rt = route6_input(mbuf, &fl6);
        if (!rt)
            return NULL;

        /* set mbuf->userdata to @rt as side-effect is not good!
         * although route will done again when out-xmit. */
        if ((rt->rt6_flags & RTF_KNI) || (rt->rt6_flags & RTF_LOCALIN)) {
            route6_put(rt);
            return NULL;
        }
        oif = rt->rt6_dev->id;
        route6_put(rt);
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        if (!strlen(m->oifname))
            oif = NETIF_PORT_ID_ALL;

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);

        if (svc->af == AF_INET6 && svc->proto == ip6nxt &&
            __svc_in_range(AF_INET6, &saddr, ports[0], &m->srange) &&
            __svc_in_range(AF_INET6, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

static struct dp_vs_service *
__dp_vs_svc_match_get(int af, const struct rte_mbuf *mbuf, bool *outwall)
{
    if (af == AF_INET)
        return __dp_vs_svc_match_get4(mbuf, outwall);
    else if (af == AF_INET6)
        return __dp_vs_svc_match_get6(mbuf);
    else
        return NULL;
}

int dp_vs_match_parse(const char *srange, const char *drange,
                      const char *iifname, const char *oifname,
                      struct dp_vs_match *match)
{
    int err;

    memset(match, 0, sizeof(*match));

    if (srange && strlen(srange)) {
        err = inet_addr_range_parse(srange, &match->srange, &match->af);
        if (err != EDPVS_OK)
            return err;
    }

    if (drange && strlen(drange)) {
        err = inet_addr_range_parse(drange, &match->drange, &match->af);
        if (err != EDPVS_OK)
            return err;
    }

    snprintf(match->iifname, IFNAMSIZ, "%s", iifname ? : "");
    snprintf(match->oifname, IFNAMSIZ, "%s", oifname ? : "");

    return EDPVS_OK;
}

static struct dp_vs_service *
__dp_vs_svc_match_find(int af, uint8_t proto, const struct dp_vs_match *match)
{
    struct dp_vs_service *svc;

    if (!match || is_empty_match(match))
        return NULL;

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        assert(svc->match);
        if (af == svc->af && proto == svc->proto &&
            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
        {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

struct dp_vs_service *dp_vs_service_lookup(int af, uint16_t protocol,
                                        const union inet_addr *vaddr,
                                        uint16_t vport, uint32_t fwmark,
                                        const struct rte_mbuf *mbuf,
                                        const struct dp_vs_match *match,
                                        bool *outwall)
{
    struct dp_vs_service *svc = NULL;

    rte_rwlock_read_lock(&__dp_vs_svc_lock);

    if (fwmark && (svc = __dp_vs_svc_fwm_get(af, fwmark)))
        goto out;

    if ((svc = __dp_vs_service_get(af, protocol, vaddr, vport)))
        goto out;

    if (match && !is_empty_match(match))
        if ((svc = __dp_vs_svc_match_find(af, protocol, match)))
            goto out;

    if (mbuf) /* lowest priority */
        svc = __dp_vs_svc_match_get(af, mbuf, outwall);

out:
    rte_rwlock_read_unlock(&__dp_vs_svc_lock);
#ifdef CONFIG_DPVS_MBUF_DEBUG
    if (!svc && mbuf)
        dp_vs_mbuf_dump("found service failed.", af, mbuf);
#endif
    return svc;
}


struct dp_vs_service *dp_vs_lookup_vip(int af, uint16_t protocol,
                                       const union inet_addr *vaddr)
{
    struct dp_vs_service *svc;
    unsigned hash;

    rte_rwlock_read_lock(&__dp_vs_svc_lock);

    hash = dp_vs_svc_hashkey(af, protocol, vaddr);
    list_for_each_entry(svc, &dp_vs_svc_table[hash], s_list) {
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->proto == protocol)) {
            /* HIT */
            rte_rwlock_read_unlock(&__dp_vs_svc_lock);
            return svc;
        }
    }

    rte_rwlock_read_unlock(&__dp_vs_svc_lock);
    return NULL;
}

void
__dp_vs_bind_svc(struct dp_vs_dest *dest, struct dp_vs_service *svc)
{
    rte_atomic32_inc(&svc->refcnt);
    dest->svc = svc;
}

void __dp_vs_unbind_svc(struct dp_vs_dest *dest)
{
    struct dp_vs_service *svc = dest->svc;

    dest->svc = NULL;
    if (rte_atomic32_dec_and_test(&svc->refcnt)) {
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
}

static int dp_vs_add_del_lb_service(bool add, struct dp_vs_service *svc)
{
    struct dpvs_msg* msg = NULL;
    int err;

    if (add)
        msg = msg_make(MSG_TYPE_SERVER_ADD, 0, DPVS_MSG_MULTICAST,
                       rte_lcore_id(), sizeof(struct dp_vs_service), svc);
    else
        msg = msg_make(MSG_TYPE_SERVER_DEL, 0, DPVS_MSG_MULTICAST,
                       rte_lcore_id(), sizeof(struct dp_vs_service), svc);

    err = multicast_msg_send(msg, 0/*DPVS_MSG_F_ASYNC*/, NULL);
    if (err != EDPVS_OK) {
        /* ignore timeout for msg, or keepalived will cause a lot bug.
         * Timeout error is ok because route can still be set,
         * no mem is another possible err, but problem will not just be here */
        RTE_LOG(INFO, IPVS, "[%s] fail to send multicast message, error code = %d\n",
                                                                      __func__, err);
    }
    msg_destroy(&msg);

    return err;
}

int dp_vs_add_service(struct dp_vs_service_conf *u,
                      struct dp_vs_service **svc_p)
{
    int ret = 0, i;
    int size;
    struct dp_vs_scheduler *sched = NULL;
    struct dp_vs_service *svc = NULL;

    if (!u->fwmark && inet_is_addr_any(u->af, &u->addr)
        && !u->port && is_empty_match(&u->match)) {
        RTE_LOG(ERR, SERVICE, "%s: adding empty servive\n", __func__);
        return EDPVS_INVAL;
    }

    sched = dp_vs_scheduler_get(u->sched_name);
    if(sched == NULL) {
        RTE_LOG(ERR, SERVICE, "%s: scheduler not found.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct dp_vs_service));
    svc = rte_zmalloc("dp_vs_service", size, RTE_CACHE_LINE_SIZE);
    if(svc == NULL){
        RTE_LOG(ERR, SERVICE, "%s: no memory.\n", __func__);
        return EDPVS_NOMEM;
    }
    rte_atomic32_set(&svc->usecnt, 1);
    rte_atomic32_set(&svc->refcnt, 1);

    svc->af = u->af;
    svc->proto = u->protocol;
    rte_memcpy(&svc->addr, &u->addr, sizeof(u->addr));
    svc->port = u->port;
    svc->fwmark = u->fwmark;
    svc->flags = u->flags;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;
    svc->netmask = u->netmask;
    if (!is_empty_match(&u->match)) {
        svc->match = rte_zmalloc(NULL, sizeof(struct dp_vs_match),
                                 RTE_CACHE_LINE_SIZE);
        if (!svc->match) {
            ret = EDPVS_NOMEM;
            goto out_err;
        }

        *(svc->match) = u->match;
    }

    for (i=0; i<RTE_MAX_LCORE; i++) {
        rte_rwlock_init(&svc->laddrs[i].laddr_lock);
        INIT_LIST_HEAD(&svc->laddrs[i].laddr_list);
        svc->laddrs[i].num_laddrs = 0;
        svc->laddrs[i].laddr_curr = &svc->laddrs[i].laddr_list;
    }

    INIT_LIST_HEAD(&svc->dests);
    rte_rwlock_init(&svc->sched_lock);

    ret = dp_vs_bind_scheduler(svc, sched);
    if (ret)
        goto out_err;
    sched = NULL;

    ret = dp_vs_new_stats(&(svc->stats));
    if(ret)
        goto out_err;

    svc->markid = dp_vs_alloc_server_id();
    if (svc->markid < 0)
        goto out_err;
    svc->mark_flowid = DP_VS_MARK_FLOW_ID_UNKNOWN;

    dp_vs_num_services++;

    rte_rwlock_write_lock(&__dp_vs_svc_lock);
    dp_vs_svc_hash(svc);
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    if (!dp_vs_add_del_lb_service(true, svc)) {
        svc->flags |= DP_VS_SVC_F_LB_CORE;
    }
    *svc_p = svc;
    return EDPVS_OK;

out_err:
    if(svc != NULL) {
        dp_vs_free_server_id(svc->markid);
        if (svc->scheduler)
            dp_vs_unbind_scheduler(svc);
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
    return ret;
}

int
dp_vs_edit_service(struct dp_vs_service *svc, struct dp_vs_service_conf *u)
{
    struct dp_vs_scheduler *sched, *old_sched;
    int ret = 0;

    /*
     * Lookup the scheduler, by 'u->sched_name'
     */
    sched = dp_vs_scheduler_get(u->sched_name);
    if (sched == NULL) {
        RTE_LOG(ERR, SERVICE, "Scheduler dp_vs_%s not found\n", u->sched_name);
        return EDPVS_NOTEXIST;
    }
    old_sched = sched;

    if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
        ret = EDPVS_INVAL;
        goto out;
    }

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     * Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    /*
     * Set the flags and timeout value
     */
    svc->flags = u->flags | DP_VS_SVC_F_HASHED;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->netmask = u->netmask;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;

    old_sched = svc->scheduler;
    if (sched != old_sched) {
        /*
         * Unbind the old scheduler
         */
        if ((ret = dp_vs_unbind_scheduler(svc))) {
            old_sched = sched;
            goto out_unlock;
        }

        /*
         * Bind the new scheduler
         */
        if ((ret = dp_vs_bind_scheduler(svc, sched))) {
            /*
             * If ip_vs_bind_scheduler fails, restore the old
             * scheduler.
             * The main reason of failure is out of memory.
             *
             * The question is if the old scheduler can be
             * restored all the time. TODO: if it cannot be
             * restored some time, we must delete the service,
             * otherwise the system may crash.
             */
            dp_vs_bind_scheduler(svc, old_sched);
            old_sched = sched;
            goto out_unlock;
        }
    }

out_unlock:
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);
out:
    return ret;
}

static void __dp_vs_del_service(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest, *nxt;

    dp_vs_free_server_id(svc->markid);
    if (svc->mark_flowid != DP_VS_MARK_FLOW_ID_UNKNOWN) {
        dp_vs_server_del_mark_flow(svc);
    }

    dp_vs_add_del_lb_service(false, svc);

    /* Count only IPv4 services for old get/setsockopt interface */
    dp_vs_num_services--;

    /* Unbind scheduler */
    dp_vs_unbind_scheduler(svc);

    dp_vs_laddr_flush(svc);

    dp_vs_blklst_flush(svc);

    /*
     *    Unlink the whole destination list
     */
    list_for_each_entry_safe(dest, nxt, &svc->dests, n_list) {
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);
        __dp_vs_unlink_dest(svc, dest, 0);
        __dp_vs_del_dest(dest);
    }

    /*
     *    Free the service if nobody refers to it
     */
    if (rte_atomic32_dec_and_test(&svc->refcnt)) {
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
}

int dp_vs_del_service(struct dp_vs_service *svc)
{
    if (svc == NULL)
        return EDPVS_NOTEXIST;

    /*
     * Unhash it from the service table
     */
    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    dp_vs_svc_unhash(svc);

    /*
     * Wait until all the svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    __dp_vs_del_service(svc);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

static int
dp_vs_copy_lb_stats(struct dp_vs_stats *dst, struct dp_vs_service *src)
{
    struct dpvs_lb_stats *lb_stat;
    struct dpvs_msg *msg, *rmsg;
    struct dpvs_multicast_queue *mcq;
    int res;

    memset(dst, 0, sizeof(*dst));

    /* per-lcore conns */
    msg = msg_make(MSG_TYPE_GET_LB_SERVER_STATS, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
                                        sizeof(struct dp_vs_service), src);
    if (unlikely(msg == NULL))
        return EDPVS_NOMEM;
    res = multicast_msg_send(msg, 0, &mcq);
    if (res == EDPVS_OK) {
        list_for_each_entry(rmsg, &mcq->mq, mq_node) {
            lb_stat = (struct dpvs_lb_stats *)rmsg->data;
            if (lb_stat->rsp_status == DPVS_LB_STAT_OK) {
                //printf("%s, locre: %d, conns: %lu, inpkts: %lu\n", __func__, lb_stat->cid, lb_stat->stats.conns, lb_stat->stats.inpkts);
                dst->conns += lb_stat->stats.conns;
                dst->inpkts += lb_stat->stats.inpkts;
                dst->inbytes += lb_stat->stats.inbytes;
                dst->outpkts += lb_stat->stats.outpkts;
                dst->outbytes += lb_stat->stats.outbytes;
            }
        }
    } else
        return EDPVS_NOTEXIST;

    msg_destroy(&msg);

    return EDPVS_OK;
}


static int
dp_vs_copy_service(struct dp_vs_service_entry *dst, struct dp_vs_service *src)
{
    int err = 0;
    struct dp_vs_match *m;

    memset(dst, 0, sizeof(*dst));
    dst->af = src->af;
    dst->proto = src->proto;
    dst->addr = src->addr;
    dst->port = src->port;
    dst->fwmark = src->fwmark;
    snprintf(dst->sched_name, sizeof(dst->sched_name),
             "%s", src->scheduler->name);
    dst->flags = src->flags;
    dst->timeout = src->timeout;
    dst->conn_timeout = src->conn_timeout;
    dst->netmask = src->netmask;
    dst->num_dests = src->num_dests;
    //dst->num_laddrs = src->num_laddrs; //TODO: fix me

    if (src->flags & DP_VS_SVC_F_LB_CORE) {
        err = dp_vs_copy_lb_stats(&dst->stats, src);
    } else {
        err = dp_vs_copy_stats(&dst->stats, src->stats);
    }

    m = src->match;
    if (!m)
        return err;

    inet_addr_range_dump(m->af, &m->srange, dst->srange, sizeof(dst->srange));
    inet_addr_range_dump(m->af, &m->drange, dst->drange, sizeof(dst->drange));

    snprintf(dst->iifname, sizeof(dst->iifname), "%s", m->iifname);
    snprintf(dst->oifname, sizeof(dst->oifname), "%s", m->oifname);

    return err;
}

int dp_vs_get_service_entries(const struct dp_vs_get_services *get,
                              struct dp_vs_get_services *uptr)
{
    int idx, count = 0;
    struct dp_vs_service *svc;
    int ret = 0;

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[idx], s_list){
            if (count >= get->num_services)
                goto out;
            ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[idx], f_list) {
            if (count >= get->num_services)
                goto out;
            ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        if (count >= get->num_services)
            goto out;
        ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
        if (ret != EDPVS_OK)
            goto out;
        count++;
    }

out:
    return ret;
}


unsigned dp_vs_get_conn_timeout(struct dp_vs_conn *conn)
{
    unsigned conn_timeout;
    if (conn->dest) {
        conn_timeout = conn->dest->conn_timeout;
        return conn_timeout;
    }
    return 90;
}

int dp_vs_flush(void)
{
    int idx;
    struct dp_vs_service *svc, *nxt;

    /*
     * Flush the service table hashed by <protocol,addr,port>
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt, &dp_vs_svc_table[idx],
                     s_list) {
            rte_rwlock_write_lock(&__dp_vs_svc_lock);
            dp_vs_svc_unhash(svc);
            /*
             * Wait until all the svc users go away.
             */
            DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
            __dp_vs_del_service(svc);
            rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        }
    }

    /*
     * Flush the service table hashed by fwmark
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt,
                     &dp_vs_svc_fwm_table[idx], f_list) {
            rte_rwlock_write_lock(&__dp_vs_svc_lock);
            dp_vs_svc_unhash(svc);
            /*
             * Wait until all the svc users go away.
             */
            DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
            __dp_vs_del_service(svc);
            rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        }
    }

    list_for_each_entry_safe(svc, nxt,
                    &dp_vs_svc_match_list, m_list) {
        rte_rwlock_write_lock(&__dp_vs_svc_lock);
        dp_vs_svc_unhash(svc);
        /*
         * Wait until all the svc users go away.
         */
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
        __dp_vs_del_service(svc);
        rte_rwlock_write_unlock(&__dp_vs_svc_lock);
    }

    return EDPVS_OK;
}

int dp_vs_zero_service(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    list_for_each_entry(dest, &svc->dests, n_list) {
        dp_svc_stats_clear(dest->stats);
    }
    dp_svc_stats_clear(svc->stats);
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);
    return EDPVS_OK;
}

int dp_vs_zero_all(void)
{
    int idx;
    struct dp_vs_service *svc;

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[idx], s_list) {
            dp_vs_zero_service(svc);
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[idx], f_list) {
            dp_vs_zero_service(svc);
        }
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        dp_vs_zero_service(svc);
    }

    dp_vs_stats_clear();
    return EDPVS_OK;
}


/*CONTROL PLANE*/
static int dp_vs_copy_usvc_compat(struct dp_vs_service_conf *conf,
                                   struct dp_vs_service_user *user)
{
    int err;
    conf->af = user->af;
    conf->protocol = user->proto;
    conf->addr = user->addr;
    conf->port = user->port;
    conf->fwmark = user->fwmark;

    /* Deep copy of sched_name is not needed here */
    conf->sched_name = user->sched_name;

    conf->flags = user->flags;
    conf->timeout = user->timeout;
    conf->conn_timeout = user->conn_timeout;
    conf->netmask = user->netmask;
    conf->bps = user->bps;
    conf->limit_proportion = user->limit_proportion;

    err = dp_vs_match_parse(user->srange, user->drange,
                            user->iifname, user->oifname, &conf->match);
    if (conf->match.af)
        conf->af = conf->match.af;

    return err;
}

static void dp_vs_copy_udest_compat(struct dp_vs_dest_conf *udest,
                                    struct dp_vs_dest_user *udest_compat)
{
    udest->af         = udest_compat->af;
    udest->addr       = udest_compat->addr;
    udest->port       = udest_compat->port;
    udest->fwdmode    = udest_compat->conn_flags;//make sure fwdmode and conn_flags are the same
    udest->conn_flags = udest_compat->conn_flags;
    udest->weight     = udest_compat->weight;
    udest->max_conn   = udest_compat->max_conn;
    udest->min_conn   = udest_compat->min_conn;
}

static int gratuitous_arp_send_vip(struct in_addr *vip)
{
    struct route_entry *local_route;

    local_route = route_out_local_lookup(vip->s_addr);
    if(local_route){
        neigh_gratuitous_arp(&local_route->dest, local_route->port);
        route4_put(local_route);
        return EDPVS_OK;
    }
    return EDPVS_NOTEXIST;
}

static int dp_vs_set_svc(sockoptid_t opt, const void *user, size_t len)
{
    int ret;
    unsigned char arg[MAX_ARG_LEN];
    struct dp_vs_service_user *usvc_compat;
    struct dp_vs_service_conf usvc;
    struct dp_vs_service *svc = NULL;
    struct dp_vs_dest_user *udest_compat;
    struct dp_vs_dest_conf udest;
    struct in_addr *vip;

    if (opt == DPVS_SO_SET_GRATARP){
        vip = (struct in_addr *)user;
        return gratuitous_arp_send_vip(vip);
    }
    if (opt == DPVS_SO_SET_FLUSH)
        return dp_vs_flush();

    memcpy(arg, user, len);
    usvc_compat = (struct dp_vs_service_user *)arg;
    udest_compat = (struct dp_vs_dest_user *)(usvc_compat + 1);

    ret = dp_vs_copy_usvc_compat(&usvc, usvc_compat);
    if (ret != EDPVS_OK)
        return ret;

    if (opt == DPVS_SO_SET_ZERO) {
        if(!inet_is_addr_any(usvc.af, &usvc.addr) &&
           !usvc.fwmark && !usvc.port &&
           is_empty_match(&usvc.match)
          ) {
            return dp_vs_zero_all();
        }
    }

    if (usvc.protocol != IPPROTO_TCP && usvc.protocol != IPPROTO_UDP &&
        usvc.protocol != IPPROTO_ICMP && usvc.protocol != IPPROTO_ICMPV6) {
        RTE_LOG(ERR, SERVICE, "%s: protocol not support.\n", __func__);
        return EDPVS_INVAL;
    }

    if (!inet_is_addr_any(usvc.af, &usvc.addr) || usvc.port)
        svc = __dp_vs_service_get(usvc.af, usvc.protocol,
                                  &usvc.addr, usvc.port);
    else if (usvc.fwmark)
        svc = __dp_vs_svc_fwm_get(usvc.af, usvc.fwmark);
    else if (!is_empty_match(&usvc.match))
        svc = __dp_vs_svc_match_find(usvc.af, usvc.protocol, &usvc.match);
    else {
        RTE_LOG(ERR, SERVICE, "%s: empty service.\n", __func__);
        return EDPVS_INVAL;
    }

    if(opt != DPVS_SO_SET_ADD &&
            (svc == NULL || svc->proto != usvc.protocol)){
        if (svc)
            dp_vs_service_put(svc);
        return EDPVS_INVAL;
    }

    switch(opt){
        case DPVS_SO_SET_ADD:
            if(svc != NULL)
                ret = EDPVS_EXIST;
            else
                ret = dp_vs_add_service(&usvc, &svc);
            break;
        case DPVS_SO_SET_EDIT:
            ret = dp_vs_edit_service(svc, &usvc);
            break;
        case DPVS_SO_SET_DEL:
            ret = dp_vs_del_service(svc);
            // reset svc to avoid use after free
            svc = NULL;
            break;
        case DPVS_SO_SET_ZERO:
            ret = dp_vs_zero_service(svc);
            break;
        case DPVS_SO_SET_ADDDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_add_dest(svc, &udest);
            break;
        case DPVS_SO_SET_EDITDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_edit_dest(svc, &udest);
            break;
        case DPVS_SO_SET_DELDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_del_dest(svc, &udest);
            break;
        default:
            ret = EDPVS_INVAL;
    }

    if(svc)
        dp_vs_service_put(svc);
    return ret;
}

static int dp_vs_get_svc(sockoptid_t opt, const void *user, size_t len, void **out, size_t *outlen)
{
    int ret = 0;
    switch (opt){
        case DPVS_SO_GET_LB_DEBUG:
            lb_debug_handler(user, len, out, outlen);
            break;

        case DPVS_SO_GET_VERSION:
            {
                char *buf = rte_zmalloc("info",64,0);
                if (unlikely(NULL == buf))
                    return EDPVS_NOMEM;
                sprintf(buf,"DPDK-FULLNAT Server version 1.1.4 (size=0)");
                *out = buf;
                *outlen = 64;
                break;
            }
        case DPVS_SO_GET_INFO:
            {
                struct dp_vs_getinfo *info;
                info = rte_zmalloc("info", sizeof(struct dp_vs_getinfo), 0);
                if (unlikely(NULL == info))
                    return EDPVS_NOMEM;
                info->version = 0;
                info->size = 0;
                info->num_services = dp_vs_num_services;
                *out = info;
                *outlen = sizeof(struct dp_vs_getinfo);
                break;
            }
        case DPVS_SO_GET_SERVICES:
            {
                struct dp_vs_get_services *get, *output;
                int size;
                get = (struct dp_vs_get_services *)user;
                size = sizeof(*get) + \
                       sizeof(struct dp_vs_service_entry) * (get->num_services);
                if(len != sizeof(*get)){
                    *outlen = 0;
                    return EDPVS_INVAL;
                }
                output = rte_zmalloc("get_services", size, 0);
                if (unlikely(NULL == output))
                    return EDPVS_NOMEM;
                memcpy(output, get, sizeof(*get));
                ret = dp_vs_get_service_entries(get, output);
                *out = output;
                *outlen = size;
            }
            break;
        case DPVS_SO_GET_SERVICE:
            {
                struct dp_vs_service_entry *entry, *output;
                struct dp_vs_service *svc = NULL;
                union inet_addr addr;

                entry = (struct dp_vs_service_entry *)user;
                addr = entry->addr;
                if(entry->fwmark)
                    svc = __dp_vs_svc_fwm_get(AF_INET, entry->fwmark);
                else if (!inet_is_addr_any(entry->af, &entry->addr) || entry->port)
                    svc = __dp_vs_service_get(entry->af, entry->proto,
                                              &addr, entry->port);
                else {
                    struct dp_vs_match match;

                    ret = dp_vs_match_parse(entry->srange, entry->drange,
                                            entry->iifname, entry->oifname,
                                            &match);
                    if (ret != EDPVS_OK)
                        return ret;

                    if (!is_empty_match(&match)) {
                        svc = __dp_vs_svc_match_find(match.af, entry->proto,
                                                     &match);
                    }
                }

                if (!svc) {
                    *outlen = 0;
                    return EDPVS_NOTEXIST;
                }

                output = rte_zmalloc("get_service",
                                     sizeof(struct dp_vs_service_entry), 0);
                if (unlikely(NULL == output)) {
                    dp_vs_service_put(svc);
                    return EDPVS_NOMEM;
                }
                memcpy(output, entry, sizeof(struct dp_vs_service_entry));
                ret = dp_vs_copy_service(output, svc);
                dp_vs_service_put(svc);
                *out = output;
                *outlen = sizeof(struct dp_vs_service_entry);
            }
            break;
        case DPVS_SO_GET_DESTS:
            {
                struct dp_vs_service *svc = NULL;
                union inet_addr addr;
                struct dp_vs_get_dests *get, *output;
                int size;
                get = (struct dp_vs_get_dests *)user;
                size = sizeof(*get) + sizeof(struct dp_vs_dest_entry) * get->num_dests;
                if(len != sizeof(*get)){
                    *outlen = 0;
                    return EDPVS_INVAL;
                }
                addr = get->addr;
                output = rte_zmalloc("get_services", size, 0);
                if (unlikely(NULL == output))
                    return EDPVS_NOMEM;
                memcpy(output, get, sizeof(*get));

                if(get->fwmark)
                    svc = __dp_vs_svc_fwm_get(get->af, get->fwmark);
                else if (!inet_is_addr_any(get->af, &addr) || get->port)
                    svc = __dp_vs_service_get(get->af, get->proto, &addr,
                                              get->port);
                else {
                    struct dp_vs_match match;

                    ret = dp_vs_match_parse(get->srange, get->drange,
                                            get->iifname, get->oifname,
                                            &match);
                    if (ret != EDPVS_OK) {
                        rte_free(output);
                        return ret;
                    }

                    if (!is_empty_match(&match)) {
                        svc = __dp_vs_svc_match_find(match.af, get->proto,
                                                     &match);
                    }
                }

                if (!svc)
                    ret = EDPVS_NOTEXIST;
                else {
                    ret = dp_vs_get_dest_entries(svc, get, output);
                    dp_vs_service_put(svc);
                }
                *out = output;
                *outlen = size;
            }
            break;
        default:
            return EDPVS_INVAL;
    }
    
    if (ret != EDPVS_OK) {
        if (*out)
            rte_free(*out);
    }

    return ret; 
}

struct dpvs_sockopts sockopts_svc = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SVC_BASE,
    .set_opt_max    = SOCKOPT_SVC_SET_CMD_MAX,
    .set            = dp_vs_set_svc,
    .get_opt_min    = SOCKOPT_SVC_BASE,
    .get_opt_max    = SOCKOPT_SVC_GET_CMD_MAX,
    .get            = dp_vs_get_svc,
};

int dp_vs_service_init(void)
{
    int idx;
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        INIT_LIST_HEAD(&dp_vs_svc_table[idx]);
        INIT_LIST_HEAD(&dp_vs_svc_fwm_table[idx]);
    }
    INIT_LIST_HEAD(&dp_vs_svc_match_list);
    rte_rwlock_init(&__dp_vs_svc_lock);
    dp_vs_dest_init();
    sockopt_register(&sockopts_svc);
    return EDPVS_OK;
}

int dp_vs_service_term(void)
{
    dp_vs_flush();
    dp_vs_dest_term();
    return EDPVS_OK;
}
