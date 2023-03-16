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
#include <assert.h>
#include "inet.h"
#include "route.h"
#include "route6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/conn.h"

/*
 * Trash for destinations
 */

struct list_head dp_vs_dest_trash = LIST_HEAD_INIT(dp_vs_dest_trash);

struct dp_vs_dest *dp_vs_lookup_dest(int af,
                                     struct dp_vs_service *svc,
                                     const union inet_addr *daddr,
                                     uint16_t dport)
{
    struct dp_vs_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list){
        if ((dest->af == af)
            && inet_addr_equal(af, &dest->addr, daddr)
            && (dest->port == dport))
            return dest;
    }
    return NULL;
}

static int dp_vs_add_del_lb_dest(bool add, struct dp_vs_dest *dest)
{
    struct dpvs_msg* msg = NULL;
    int err;

    if (add)
        msg = msg_make(MSG_TYPE_DEST_ADD, 0, DPVS_MSG_MULTICAST,
                    rte_lcore_id(), sizeof(struct dp_vs_dest), dest);
    else
        msg = msg_make(MSG_TYPE_DEST_DEL, 0, DPVS_MSG_MULTICAST,
                    rte_lcore_id(), sizeof(struct dp_vs_dest), dest);

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


/*
 *  Lookup dest by {svc,addr,port} in the destination trash.
 *  The destination trash is used to hold the destinations that are removed
 *  from the service table but are still referenced by some conn entries.
 *  The reason to add the destination trash is when the dest is temporary
 *  down (either by administrator or by monitor program), the dest can be
 *  picked back from the trash, the remaining connections to the dest can
 *  continue, and the counting information of the dest is also useful for
 *  scheduling.
 */
struct dp_vs_dest *dp_vs_trash_get_dest(struct dp_vs_service *svc,
                                        const union inet_addr *daddr,
                                        uint16_t dport)
{
    struct dp_vs_dest *dest, *nxt;

    list_for_each_entry_safe(dest, nxt, &dp_vs_dest_trash, n_list) {
        RTE_LOG(DEBUG, SERVICE, "%s: Destination still in trash.\n", __func__);
        if (dest->af == svc->af &&
            inet_addr_equal(svc->af, &dest->addr, daddr) &&
            dest->port == dport &&
            dest->vfwmark == svc->fwmark &&
            dest->proto == svc->proto &&
            (svc->fwmark ||
             (inet_addr_equal(svc->af, &dest->vaddr, &svc->addr) &&
              dest->vport == svc->port))) {
             /*since svc may be edit, variables should be coverd*/
             dest->conn_timeout = svc->conn_timeout;
             dest->limit_proportion = svc->limit_proportion;
             return dest;
            }
        if (rte_atomic32_read(&dest->refcnt) == 1) {
            RTE_LOG(DEBUG, SERVICE, "%s: Removing destination from trash.\n", __func__);
            list_del(&dest->n_list);
            //dp_vs_dst_reset(dest);//to be finished
            __dp_vs_unbind_svc(dest);

            dp_vs_del_stats(dest->stats);
            rte_free(dest);
        }
    }
    return NULL;
}

void dp_vs_trash_cleanup(void)
{
    struct dp_vs_dest *dest, *nxt;

    list_for_each_entry_safe(dest, nxt, &dp_vs_dest_trash, n_list) {
        list_del(&dest->n_list);
        //dp_vs_dst_reset(dest);
        __dp_vs_unbind_svc(dest);

        dp_vs_del_stats(dest->stats);
        rte_free(dest);
    }
}

static void __dp_vs_update_dest(struct dp_vs_service *svc,
                                struct dp_vs_dest *dest,
                                struct dp_vs_dest_conf *udest)
{
    int conn_flags;

    rte_atomic16_set(&dest->weight, udest->weight);
    conn_flags = udest->conn_flags | DPVS_CONN_F_INACTIVE;

    rte_atomic16_set(&dest->conn_flags, conn_flags);

    /* bind the service */
    if (!dest->svc) {
        __dp_vs_bind_svc(dest, svc);
    } else {
        if (dest->svc != svc) {
            __dp_vs_unbind_svc(dest);

            dp_svc_stats_clear(dest->stats);

            __dp_vs_bind_svc(dest, svc);
        }
    }

    dest->flags |= DPVS_DEST_F_AVAILABLE;

    if (udest->max_conn == 0 || udest->max_conn > dest->max_conn)
        dest->flags &= ~DPVS_DEST_F_OVERLOAD;
    dest->max_conn = udest->max_conn;
    dest->min_conn = udest->min_conn;
}

int dp_vs_new_dest(struct dp_vs_service *svc,
                   struct dp_vs_dest_conf *udest,
                   struct dp_vs_dest **dest_p)
{
    int size;
    struct dp_vs_dest *dest;
    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct dp_vs_dest));
    dest = rte_zmalloc("dpvs_new_dest", size, 0);
    if(dest == NULL){
        RTE_LOG(DEBUG, SERVICE, "%s: no memory.\n", __func__);
        return EDPVS_NOMEM;
    }
    assert(dest->svc == NULL);

    dest->af = udest->af;
    dest->proto = svc->proto;
    dest->vaddr = svc->addr;
    dest->vport = svc->port;
    dest->conn_timeout = svc->conn_timeout;
    dest->limit_proportion = svc->limit_proportion;
    dest->vfwmark = svc->fwmark;
    dest->addr = udest->addr;
    dest->port = udest->port;
    dest->fwdmode = udest->fwdmode;
    dest->markid = svc->markid;
    rte_atomic32_set(&dest->actconns, 0);
    rte_atomic32_set(&dest->inactconns, 0);
    rte_atomic32_set(&dest->persistconns, 0);
    rte_atomic32_set(&dest->refcnt, 0);

    if (dp_vs_new_stats(&(dest->stats)) != EDPVS_OK) {
        rte_free(dest);
        return EDPVS_NOMEM;
    }

    __dp_vs_update_dest(svc, dest, udest);

    *dest_p = dest;
    return EDPVS_OK;
}

static int dp_vs_set_nat_rss_hash(struct dp_vs_service *svc, struct dp_vs_dest *dest)
{
    struct netif_port *indev = NULL;   // src-ip, src-port
    struct netif_port *outdev = NULL;  // dst-ip, dst-port
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct flow6 fl6;
    struct route6 *rt6 = NULL;

    indev = inet_lookup_dev_by_addr(svc->af, &svc->addr);
    if (!indev) {
        RTE_LOG(ERR, SERVICE, "%s: Can't find netif device.\n", __func__);
        return EDPVS_NODEV;
    }

    if (dest->af == AF_INET) {
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = dest->addr.in;
        rt = route4_output(&fl4);
        if (!rt) {
            RTE_LOG(ERR, SERVICE, "%s: Can't find netif device.\n", __func__);
            return EDPVS_NOROUTE;
        }
    
        outdev = rt->port;
    } else {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &dest->addr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(NULL, &fl6);
        if (!rt6) {
            RTE_LOG(ERR, SERVICE, "%s: Can't find netif device.\n", __func__);
            return EDPVS_NOROUTE;
        }

        outdev = rt6->rt6_dev;
    }

    if (!indev || !outdev)
        return EDPVS_NODEV;

    return netif_set_nat_rss_hash(indev, outdev);
}

static inline int
dp_vs_dest_add_mark_flow(struct dp_vs_dest *dest)
{
    struct netif_port *dev;
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct flow6 fl6;
    struct route6 *rt6 = NULL;
    int flow_id;
    struct dp_vs_flowid flow_markid;

    if (dest->af == AF_INET) {
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = dest->addr.in;
        rt = route4_output(&fl4);
        if (!rt) {
            RTE_LOG(WARNING, SERVICE, "%s: Can't find netif device.\n", __func__);
            return DP_VS_MARK_FLOW_ID_UNKNOWN;
        }
    
        dev = rt->port;
    } else {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &dest->addr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(NULL, &fl6);
        if (!rt6) {
            RTE_LOG(WARNING, SERVICE, "%s: Can't find netif device.\n", __func__);
            return DP_VS_MARK_FLOW_ID_UNKNOWN;
        }
    
        dev = rt6->rt6_dev;
    }

    flow_markid.value = dest->markid;
    flow_markid.dir = DP_VS_FLOW_DIR_NAT_OUT;

    flow_id = netif_flow_src_mark(dest->af, dest->proto, dest->port, flow_markid.value, &dest->addr, dev);
    if (flow_id < 0) {
        RTE_LOG(ERR, SERVICE, "%s: Can't add netif flow rule.\n", __func__);
        return DP_VS_MARK_FLOW_ID_UNKNOWN;
    }

    return flow_id;
}

static inline int
dp_vs_dest_del_mark_flow(struct dp_vs_dest *dest)
{
    struct netif_port *dev;
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct flow6 fl6;
    struct route6 *rt6 = NULL;

    if (dest->af == AF_INET) {
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = dest->addr.in;
        rt = route4_output(&fl4);
        if (!rt) {
            RTE_LOG(WARNING, SERVICE, "%s: Can't find netif device.\n", __func__);
            return DP_VS_MARK_FLOW_ID_UNKNOWN;
        }
    
        dev = rt->port;
    } else {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &dest->addr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(NULL, &fl6);
        if (!rt6) {
            RTE_LOG(WARNING, SERVICE, "%s: Can't find netif device.\n", __func__);
            return DP_VS_MARK_FLOW_ID_UNKNOWN;
        }
    
        dev = rt6->rt6_dev;
    }

    return netif_flow_destroy(dev, dest->mark_flowid);
}

int
dp_vs_add_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    struct dp_vs_dest *new_dest;
    union inet_addr daddr;
    uint16_t dport = udest->port;
    enum dpvs_fwd_mode  fwdmode;
    int ret;

    if (udest->weight < 0) {
        RTE_LOG(DEBUG, SERVICE, "%s: server weight less than zero.\n", __func__);
        return EDPVS_NOTSUPP;
    }

    if (udest->min_conn > udest->max_conn) {
        RTE_LOG(DEBUG, SERVICE, "%s: lower threshold is higher than upper threshold\n",
               __func__);
        return EDPVS_NOTSUPP;
    }

    daddr = udest->addr;

    /*
     * Check if the dest already exists in the list
     */
    dest = dp_vs_lookup_dest(udest->af, svc, &daddr, dport);

    if (dest != NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: dest already exists.\n", __func__);
        return EDPVS_EXIST;
    }

    /*
     * Check if the dest already exists in the trash and
     * is from the same service
     */
    dest = dp_vs_trash_get_dest(svc, &daddr, dport);

    if (dest != NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: get dest from trash.\n", __func__);

        __dp_vs_update_dest(svc, dest, udest);

        /*
         * Get the destination from the trash
         */
        list_del(&dest->n_list);
        /* Reset the statistic value */
        dp_svc_stats_clear(dest->stats);

        rte_rwlock_write_lock(&__dp_vs_svc_lock);

        /*
         * Wait until all other svc users go away.
         */
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

        list_add(&dest->n_list, &svc->dests);
        svc->weight += udest->weight;
        svc->num_dests++;

        /* call the update_service function of its scheduler */
        if (svc->scheduler->update_service)
            svc->scheduler->update_service(svc, dest, DPVS_SO_SET_ADDDEST);

        rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        return EDPVS_OK;
    }

    /*
     * Allocate and initialize the dest structure
     */
    ret = dp_vs_new_dest(svc, udest, &dest);
    if (ret) {
        return ret;
    }
    new_dest = dest;

    /*
     * Add the dest entry into the list
     */
    rte_atomic32_inc(&dest->refcnt);

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     * Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    dp_vs_add_del_lb_dest(true, dest);
    list_add(&dest->n_list, &svc->dests);
    svc->weight += udest->weight;
    svc->num_dests++;

    /* call the update_service function of its scheduler */
    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_ADDDEST);

    fwdmode = DPVS_FWD_MODE_UNKNOWN;
    list_for_each_entry(dest, &svc->dests, n_list) {
        if (fwdmode == DPVS_FWD_MODE_UNKNOWN) {
            fwdmode = dest->fwdmode;
        }

        if (fwdmode != dest->fwdmode) {
            if (svc->mark_flowid != DP_VS_MARK_FLOW_ID_UNKNOWN) {
                dp_vs_server_del_mark_flow(svc);
                svc->mark_flowid = DP_VS_MARK_FLOW_ID_UNKNOWN;
            }
            goto out;
        }
    }

    
    if (DPVS_FWD_MODE_NAT == fwdmode) {
#ifndef CONFIG_LB_REDIRECT
        if (svc->mark_flowid == DP_VS_MARK_FLOW_ID_UNKNOWN) {
            // Only once
            if (dp_vs_set_nat_rss_hash(svc, new_dest)) {
                RTE_LOG(ERR, SERVICE,"%s(): set rss hash for NAT fail\n", __func__);
                goto out;
            }
        }
#endif
        new_dest->mark_flowid = dp_vs_dest_add_mark_flow(new_dest);
    }

    if (fwdmode != DPVS_FWD_MODE_SNAT) {
        if (svc->mark_flowid == DP_VS_MARK_FLOW_ID_UNKNOWN) {
            // TODO free server id
            svc->mark_flowid = dp_vs_server_add_mark_flow(svc);
        }
    } else if (svc->flags & DP_VS_SVC_F_LB_CORE) {
        svc->flags &= ~DP_VS_SVC_F_LB_CORE;
    }

out:
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

int
dp_vs_edit_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    union inet_addr daddr;
    uint16_t dport = udest->port;
    uint32_t old_weight;

    if (udest->weight < 0) {
        RTE_LOG(DEBUG, SERVICE,"%s(): server weight less than zero\n", __func__);
        return EDPVS_INVAL;
    }

    if (udest->min_conn > udest->max_conn) {
        RTE_LOG(DEBUG, SERVICE,"%s(): lower threshold is higher than upper threshold\n",
               __func__);
        return EDPVS_INVAL;
    }

    daddr = udest->addr;

    /*
     *  Lookup the destination list
     */
    dest = dp_vs_lookup_dest(udest->af, svc, &daddr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): dest doesn't exist\n", __func__);
        return EDPVS_NOTEXIST;
    }

    /* Save old weight */
    old_weight = rte_atomic16_read(&dest->weight);

    __dp_vs_update_dest(svc, dest, udest);

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /* Wait until all other svc users go away */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    /* Update service weight */
    svc->weight = svc->weight - old_weight + udest->weight;
    if (svc->weight < 0) {
        struct dp_vs_dest *tdest;
        svc->weight = 0;
        list_for_each_entry(tdest, &svc->dests, n_list) {
            svc->weight += rte_atomic16_read(&tdest->weight);
        }
        RTE_LOG(ERR, SERVICE, "%s(): vs weight < 0\n", __func__);
    }

    /* call the update_service, because server weight may be changed */
    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_EDITDEST);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

/*
 *  Delete a destination (must be already unlinked from the service)
 */
void __dp_vs_del_dest(struct dp_vs_dest *dest)
{
    /*
     *  Decrease the refcnt of the dest, and free the dest
     *  if nobody refers to it (refcnt=0). Otherwise, throw
     *  the destination into the trash.
     */
    if (dest->mark_flowid != DP_VS_MARK_FLOW_ID_UNKNOWN) {
        dp_vs_dest_del_mark_flow(dest);
    }

    if (rte_atomic32_dec_and_test(&dest->refcnt)) {
     //   dp_vs_dst_reset(dest);
        /* simply decrease svc->refcnt here, let the caller check
           and release the service if nobody refers to it.
           Only user context can release destination and service,
           and only one user context can update virtual service at a
           time, so the operation here is OK */
        __dp_vs_unbind_svc(dest);
        dp_vs_del_stats(dest->stats);
        rte_free(dest);
    } else {
        RTE_LOG(DEBUG, SERVICE,"%s moving dest into trash\n", __func__);
        list_add(&dest->n_list, &dp_vs_dest_trash);
        rte_atomic32_inc(&dest->refcnt);
    }
}

/*
 *  Unlink a destination from the given service
 */
void __dp_vs_unlink_dest(struct dp_vs_service *svc,
                struct dp_vs_dest *dest, int svcupd)
{
    dest->flags &= ~DPVS_DEST_F_AVAILABLE;

    /*
     *  Remove it from the d-linked destination list.
     */
    list_del(&dest->n_list);
    svc->num_dests--;

    svc->weight -= rte_atomic16_read(&dest->weight);
    if (svc->weight < 0) {
        struct dp_vs_dest *tdest;
        svc->weight = 0;
        list_for_each_entry(tdest, &svc->dests, n_list) {
            svc->weight += rte_atomic16_read(&tdest->weight);
        }
        RTE_LOG(ERR, SERVICE, "%s(): vs weight < 0\n", __func__);
    }

    /*
     *  Call the update_service function of its scheduler
     */
    if (svcupd && svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_DELDEST);
}

int
dp_vs_del_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    uint16_t dport = udest->port;

    dest = dp_vs_lookup_dest(udest->af, svc, &udest->addr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): destination not found!\n", __func__);
        return EDPVS_NOTEXIST;
    }

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     *      Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    /*
     *      Unlink dest from the service
     */
    __dp_vs_unlink_dest(svc, dest, 1);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    /*
     *      Delete the destination
     */
    __dp_vs_del_dest(dest);

    return EDPVS_OK;
}

static int __dp_vs_get_dest_entries(const struct dp_vs_service *svc,
                           const struct dp_vs_get_dests *get,
                           struct dp_vs_get_dests *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dp_vs_dest_entry entry;

    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= get->num_dests)
            break;
        memset(&entry, 0, sizeof(entry));
        entry.af   = dest->af;
        entry.addr = dest->addr;
        entry.port = dest->port;
        entry.conn_flags = dest->fwdmode;
        entry.weight = rte_atomic16_read(&dest->weight);
        entry.max_conn = dest->max_conn;
        entry.min_conn = dest->min_conn;
        entry.actconns = rte_atomic32_read(&dest->actconns);
        entry.inactconns = rte_atomic32_read(&dest->inactconns);
        entry.persistconns = rte_atomic32_read(&dest->persistconns);
        ret = dp_vs_copy_stats(&(entry.stats), dest->stats);

        memcpy(&uptr->entrytable[count], &entry, sizeof(entry));
        count++;
    }

    return ret;
}

static int __dpvs_get_lb_dest_entries(struct dpvs_lb_dest_entry *lb_entry)
{
    struct dpvs_msg *msg;
    struct dpvs_multicast_queue *reply=NULL;
    struct dpvs_msg *cur;
    struct dpvs_lb_dest_entry *per_stats;
    struct dp_vs_dest_entry *entry = &lb_entry->entry;
    int err;

    if (!lb_entry)
        return EDPVS_INVAL;

    msg = msg_make(MSG_TYPE_GET_LB_DEST_STATS, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
            sizeof(*lb_entry), lb_entry);
    if (!msg) {
        return EDPVS_NOMEM;
    }
    err = multicast_msg_send(msg, 0, &reply);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
        return err;
    }
    list_for_each_entry(cur, &reply->mq, mq_node) {
        per_stats = (struct dpvs_lb_dest_entry *)(cur->data);
        entry->actconns += per_stats->entry.actconns;
        entry->inactconns += per_stats->entry.inactconns;
        entry->stats.conns += per_stats->entry.stats.conns;
        entry->stats.inpkts += per_stats->entry.stats.inpkts;
        entry->stats.inbytes += per_stats->entry.stats.inbytes;
        entry->stats.outbytes += per_stats->entry.stats.outbytes;
        entry->stats.outpkts += per_stats->entry.stats.outpkts;
    }

    entry->af   = lb_entry->dest->af;
    entry->addr = lb_entry->dest->addr;
    entry->port = lb_entry->dest->port;
    entry->conn_flags = lb_entry->dest->fwdmode;
    entry->max_conn = lb_entry->dest->max_conn;
    entry->min_conn = lb_entry->dest->min_conn;
    entry->weight = rte_atomic16_read(&lb_entry->dest->weight);
    //printf("%s, lcore: %d, action: %d, inaction: %d conn: %ld\n", __func__, per_stats->cid,
    //               entry->actconns, entry->inactconns, entry->stats.conns);

    msg_destroy(&msg);
    return EDPVS_OK;
}

static int dpvs_get_lb_dest_entries(const struct dp_vs_service *svc,
                          const struct dp_vs_get_dests *get,
                          struct dp_vs_get_dests *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dpvs_lb_dest_entry lb_entry;
    struct dp_vs_dest_entry *entry = &lb_entry.entry;

    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= get->num_dests)
            break;
        memset(&lb_entry, 0, sizeof(lb_entry));
        lb_entry.svc = (struct dp_vs_service*)svc;
        lb_entry.dest = dest;
        ret = __dpvs_get_lb_dest_entries(&lb_entry);

        memcpy(&uptr->entrytable[count], entry, sizeof(*entry));
        count++;
    }

    return ret;
}

int dp_vs_get_dest_entries(const struct dp_vs_service *svc,
                          const struct dp_vs_get_dests *get,
                          struct dp_vs_get_dests *uptr)
{
    if (svc->flags & DP_VS_SVC_F_LB_CORE)
        return dpvs_get_lb_dest_entries(svc, get, uptr);

    return __dp_vs_get_dest_entries(svc, get, uptr);
}


int dp_vs_dest_init(void)
{
    return EDPVS_OK;
}

int dp_vs_dest_term(void)
{
    dp_vs_trash_cleanup();
    return EDPVS_OK;
}
