/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip_vs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "common.h"
#include "linux_ipv6.h"
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
#include "lb/conn.h"
#include "lb/redirect_conn_hash_table.h"
#include "lb/ipv4.h"
#include "lb/xmit.h"
#include "lb/snat_pool.h"
#include "lb/tcp.h"
#include "lb/udp.h"
#include "lb/icmp.h"
#include "lb/redirect.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "uoa.h"
#include "lb/ipv6.h"
#include "lb/sync.h"


static void ipv6_conn_expire(void *priv)
{
    struct lb_conn* conn = list_entry(priv, struct lb_conn, timer);
    struct lb_dest* dest = conn->dest;

    if (dest->transport_conn_expire) {
        dest->transport_conn_expire(conn);
    }

    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        lb_snat_multiply_release(AF_INET6, dest->lbs->snat_pool, &conn->laddr, conn->lport);
    }

#ifdef CONFIG_LB_REDIRECT
    if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
        lb_redirect_conn_hash_free(conn);
    }
#endif

    conn->dest->stats.conns--;
    lb_conn_free(conn);
    lb_dest_put(dest);
}

void ipv6_conn_expire_sync_conn(struct lb_conn *conn)
{
    struct lb_dest* dest;

    if (NULL == conn) {
        return;
    }

    dest = conn->dest;
    /* do not send tcp rst */

    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        lb_snat_multiply_release(AF_INET6, dest->lbs->snat_pool, &conn->laddr, conn->lport);
    }

    conn->dest->stats.conns--;
    lb_conn_free(conn);
    lb_dest_put(dest);
    lbs_put(dest->lbs);
}

static void lb_ipv6_in0(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    union inet_addr *saddr;
    union inet_addr *daddr;
    uint16_t sport, dport;
    int iphdrlen;

    rte_pktmbuf_adj(cache->mbuf, sizeof(struct rte_ether_hdr));
    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    saddr = (union inet_addr *)ip6h->src_addr;
    daddr = (union inet_addr *)ip6h->dst_addr;

    iphdrlen = ip6_hdrlen(cache->mbuf);
    lbs->get_transport(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    cache->v3 = lb_get_blklst_table_head(ip6h->proto, daddr, dport, saddr);
    rte_prefetch0(cache->v3);
    cache->v1 = lb_conn_cache_get(lbs->af, saddr, sport);
    rte_prefetch0(cache->v1);
    cache->v4d_dport = dport;
    cache->v4d_sport = sport;
    cache->stage = LB_PL_STAGE1;
    cache->next = LB_PL_NEXT_LOOKUP;

    return;
}

// lookup session or allocat session memory
static void lb_ipv6_in1(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *hash_elem = NULL;
    struct lb_conn *conn = NULL;
    struct lb_dest *dest = NULL;
    union inet_addr *saddr;
    union inet_addr *daddr;
    uint16_t sport = cache->v4d_sport, dport = cache->v4d_dport;
    struct lb_conn_hash_elem_free hash_elem_free;

    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    saddr = (union inet_addr *)ip6h->src_addr;
    daddr = (union inet_addr *)ip6h->dst_addr;

    hash_elem_free.conn_page_head = NULL;

    if (lb_blklst_lookup(cache->v3, ip6h->proto, daddr, dport, saddr)) {
        lb_cache_invalid(cache->mbuf, cache, "block list");
        return;
    }

    hash_elem = (struct lb_conn_hash_elem *)cache->v1;
    conn = lb_conn_get(hash_elem, lbs->af, saddr, sport, cache->markid, &hash_elem_free);
    if (conn) {
        cache->v2 = conn;
        rte_prefetch0(cache->v2);
        rte_prefetch0(cache->v2+RTE_CACHE_LINE_SIZE);
        cache->stage = LB_PL_STAGE3;
        cache->next = LB_PL_NEXT_OUT;
    } else {
        if (!hash_elem_free.conn_page_head) {
            lb_cache_invalid(cache->mbuf, cache, "No memory for new connection hash");
            return;
        }
        cache->v1 = hash_elem_free.conn_page_head;
        cache->v2 = (void *)lb_conn_alloc();
        if (!cache->v2) {
            lb_cache_invalid(cache->mbuf, cache, "No memory for new connection");
            return;
        }
        rte_prefetch0(cache->v2);
        rte_prefetch0(cache->v2+RTE_CACHE_LINE_SIZE);
        if (unlikely(hash_elem_free.bit_map_index >= 2)) {
            rte_prefetch0(hash_elem_free.free_hash_elem);
        }
        dest = lbs->scheduler->schedule_prefetch(lbs, cache->mbuf);
        if (unlikely(!lb_dest_is_valid(dest))) {
            dest = lb_scheduler_next(dest, lbs, cache->mbuf);
            if (!dest) {
                lb_cache_invalid(cache->mbuf, cache, "No valid dest");
                lb_conn_put((struct lb_conn *)cache->v2);
                return;
            }
        }
        rte_prefetch0(dest);
        cache->v3 = dest;
        cache->new_conn_bit_map_index = hash_elem_free.bit_map_index;
        cache->stage = LB_PL_STAGE2;
        cache->next = LB_PL_NEXT_NEW;
        lb_conn_hold_free_tuple(&hash_elem_free, lbs->af, cache->v2, saddr, sport, cache->markid);
    }

    return;
}

// new session and find out dst and laddr
#ifdef CONFIG_LB_REDIRECT
static void lb_ipv6_in2(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *conn_page_head = cache->v1;
    struct lb_conn *new = cache->v2;
    struct lb_dest *dest = cache->v3;
    uint16_t sport = cache->v4d_sport;
    int err;
    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    struct flow6 fl6;
    struct route6 *rt6 = NULL;
    struct lb_conn_hash_elem *nat_hash_elem = NULL;
    struct lb_conn_hash_elem_free nat_hash_elem_free;
    uint32_t nat_hash = 0;

    assert(cache->stage == LB_PL_STAGE2);
    assert(cache->next == LB_PL_NEXT_NEW);

    new->flags = LB_CONN_F_NEW;

    if (unlikely(!lb_dest_is_valid(dest))) {
        dest = lb_scheduler_next(dest, lbs, cache->mbuf);
        if (!dest) {
            lb_cache_invalid(cache->mbuf, cache, "No valid dest");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
    }

    lbs->scheduler->schedule_next(lbs, cache->mbuf);

    rte_memcpy(&new->caddr.in6, ip6h->src_addr, sizeof(struct in6_addr));
    new->cport              = sport;
    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &new->caddr.in6, sizeof(struct in6_addr));
        rte_memcpy(&fl6.fl6_saddr, &dest->vaddr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(cache->mbuf, &fl6);
        if (!rt6) {
            route6_put(rt6);
            lb_cache_invalid(cache->mbuf, cache, "No SNAT route entry");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }

        new->out_dev = rt6->rt6_dev;
        route6_put(rt6);
        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(cache->mbuf, char *) -sizeof(struct rte_ether_hdr));
        rte_ether_addr_copy(&eth_hdr->d_addr, &new->out_smac);
        rte_ether_addr_copy(&eth_hdr->s_addr, &new->out_dmac);

        new->out_af = AF_INET6;

        err = lb_snat_multiply_fetch(AF_INET6, lbs->snat_pool, &new->laddr, &new->lport);
        if (unlikely(err)) {
            char msg[128];
            snprintf(msg, 127, "No SNAT resource entry for FNAT: %s", dpvs_strerror(err));
            lb_cache_invalid(cache->mbuf, cache, msg);
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
        cache->next = LB_PL_NEXT_NEW;
    } else if (dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        cache->next = LB_PL_NEXT_NEW;
    } else {
        if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
            nat_hash_elem = lb_redirect_conn_cache_get(lbs->af, &new->caddr, sport, &nat_hash);
            rte_prefetch0(nat_hash_elem);
            memset(&fl6, 0, sizeof(struct flow6));
            rte_memcpy(&fl6.fl6_daddr, &new->caddr.in6, sizeof(struct in6_addr));
            rte_memcpy(&fl6.fl6_saddr, &dest->vaddr.in6, sizeof(struct in6_addr));
            rt6 = route6_output(cache->mbuf, &fl6);
            if (!rt6) {
                route6_put(rt6);
                lb_cache_invalid(cache->mbuf, cache, "No NAT route entry");
                lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
                return;
            }

            new->out_dev = rt6->rt6_dev;
            route6_put(rt6);
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(cache->mbuf, char *) -sizeof(struct rte_ether_hdr));
            rte_ether_addr_copy(&eth_hdr->d_addr, &new->out_smac);
            rte_ether_addr_copy(&eth_hdr->s_addr, &new->out_dmac);
        }
        rte_memcpy(&new->laddr.in6, ip6h->src_addr, sizeof(struct in6_addr));
        new->lport  = sport;
        cache->next = LB_PL_NEXT_NEW;
        if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
            nat_hash_elem_free.conn_page_head = NULL;
            lb_redirect_conn_get_free(AF_INET6, nat_hash_elem, &nat_hash_elem_free, nat_hash);
            if (!nat_hash_elem_free.conn_page_head) {
                lb_cache_invalid(cache->mbuf, cache, " lb_ipv6_in2 No memory for new nat connection hash");
                lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
                return;
            }
            if (unlikely(nat_hash_elem_free.bit_map_index >= 2)) {
                rte_prefetch0(nat_hash_elem_free.free_hash_elem);
            }
        }
    }

    lb_conn_use_free_tuple(conn_page_head, cache->new_conn_bit_map_index, new);
    
    if (lb_lcore_init_timer(&new->timer, lb_get_conn_init_timeout(), ipv6_conn_expire)) {
        lb_cache_invalid(cache->mbuf, cache, "lb_ipv6_in2 init timer failed");
        lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
        return;
    }
    cache->v4 = lb_lcore_add_timer_pre(&new->timer);
    rte_prefetch0(cache->v4);

    if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
        lb_redirect_conn_hold_free_tuple(&nat_hash_elem_free, rte_lcore_id(), lbs->af, &new->caddr, sport, cache->markid);
        lb_redirect_conn_use_free_tuple(nat_hash_elem_free.conn_page_head, nat_hash_elem_free.bit_map_index, new);
        new->cid = rte_lcore_id();
    }

    cache->stage = LB_PL_STAGE3;
}
#else
static void lb_ipv6_in2(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *conn_page_head = cache->v1;
    struct lb_conn *new = cache->v2;
    struct lb_dest *dest = cache->v3;
    uint16_t sport = cache->v4d_sport;
    int err;
    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    struct flow6 fl6;
    struct route6 *rt6 = NULL;

    assert(cache->stage == LB_PL_STAGE2);
    assert(cache->next == LB_PL_NEXT_NEW);

    new->flags = LB_CONN_F_NEW;

    if (unlikely(!lb_dest_is_valid(dest))) {
        dest = lb_scheduler_next(dest, lbs, cache->mbuf);
        if (!dest) {
            lb_cache_invalid(cache->mbuf, cache, "No valid dest");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
    }

    lbs->scheduler->schedule_next(lbs, cache->mbuf);

    rte_memcpy(&new->caddr.in6, ip6h->src_addr, sizeof(struct in6_addr));
    new->cport              = sport;
    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        new->out_af = AF_INET6;
        err = lb_snat_multiply_fetch(AF_INET6, lbs->snat_pool, &new->laddr, &new->lport);
        if (unlikely(err)) {
            char msg[128];
            snprintf(msg, 127, "No SNAT resource entry for FNAT: %s", dpvs_strerror(err));
            lb_cache_invalid(cache->mbuf, cache, msg);
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
        cache->next = LB_PL_NEXT_NEW;
    } else if (dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        cache->next = LB_PL_NEXT_NEW;
    } else {
        rte_memcpy(&new->laddr.in6, ip6h->src_addr, sizeof(struct in6_addr));
        new->lport  = sport;
        cache->next = LB_PL_NEXT_NEW;
    }

    if (dest->fwdmode == DPVS_FWD_MODE_FNAT || dest->fwdmode == DPVS_FWD_MODE_NAT) {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &new->caddr.in6, sizeof(struct in6_addr));
        rte_memcpy(&fl6.fl6_saddr, &dest->vaddr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(cache->mbuf, &fl6);
        if (!rt6) {
            route6_put(rt6);
            lb_cache_invalid(cache->mbuf, cache, "No SNAT route entry");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }

        new->out_dev = rt6->rt6_dev;
        route6_put(rt6);
        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(cache->mbuf, char *) -sizeof(struct rte_ether_hdr));
        rte_ether_addr_copy(&eth_hdr->d_addr, &new->out_smac);
        rte_ether_addr_copy(&eth_hdr->s_addr, &new->out_dmac);
    }

    lb_conn_use_free_tuple(conn_page_head, cache->new_conn_bit_map_index, new);
    
    if (lb_lcore_init_timer(&new->timer, lb_get_conn_init_timeout(), ipv6_conn_expire)) {
        lb_cache_invalid(cache->mbuf, cache, "lb_ipv6_in2 init timer failed");
        lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
        return;
    }
    cache->v4 = lb_lcore_add_timer_pre(&new->timer);
    rte_prefetch0(cache->v4);

    cache->stage = LB_PL_STAGE3;
}
#endif

static void lb_ipv6_in3(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;
    struct lb_dest *dest;
    uint16_t lport = 0, offset;
    void **out_cache_conn = NULL;
#ifdef CONFIG_SYNC_DEBUG
    char buf[64];
#endif

    if (unlikely(cache->next == LB_PL_NEXT_NEW)) {
        dest = cache->v3;
        conn->dest = dest;
        conn->in_af = (uint8_t)dest->af;
        conn->l4_proto = dest->proto;
        if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
            lport = conn->lport;
            offset = lb_snat_multiply_offset(AF_INET6, lbs->snat_pool, &conn->laddr);
            assert(offset < DPVS_MAX_LADDR_PERCORE);
            out_cache_conn = &(lbs->conn_cache_out->out[offset][rte_be_to_cpu_16(lport)-DEF_MIN_PORT].conn);
            rte_prefetch0(out_cache_conn);
        }

        dest->stats.conns++;
        conn->flags &= ~LB_CONN_F_NEW;
    }

    if (unlikely(conn->flags & LB_CONN_F_NEW || conn->flags & LB_CONN_F_DROP)) {
        if (likely(conn->flags & LB_CONN_F_NEW)) {
            return;
        } else {
            lb_cache_invalid(cache->mbuf, cache, "LB_CONN_F_DROP.");
            lb_conn_put(conn);
            return;
        }
    }

    dest = conn->dest;

    if (unlikely(conn->flags & LB_CONN_F_SYNC)) {
        conn->flags &= ~LB_CONN_F_SYNC;
        /* set this flag to prevent sync this conn as a new one */
        conn->flags |= LB_CONN_F_SYNC_SENT;
        if (lb_lcore_timer_sched(&conn->timer, lb_get_conn_init_timeout(), ipv6_conn_expire)) {
            lb_cache_invalid(cache->mbuf, cache, "lb_ipv6_in3 init timer failed");
            lb_conn_free(conn);
            return;
        }
    }

    lb_xmit_inbound(conn, cache->mbuf);
    if (unlikely(cache->next == LB_PL_NEXT_NEW)) {
        lb_lcore_add_timer_bottom(&conn->timer, cache->v4);
        if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
            if (unlikely(!out_cache_conn)) {
                lb_cache_invalid(cache->mbuf, cache, "out connection cache invalid");
                lb_conn_free(conn);
                return;
            }
            lb_conn_set_out_value(out_cache_conn, conn);
        }
        lb_dest_get(dest);
        lbs_get(lbs);
    } else {
        lb_lcore_update_timer(&conn->timer);
    }

    cache->stage = LB_PL_STAGE_INVALID;

    if (lb_sync_lcore_is_active() && lb_sync_conn_needed(conn))
    {
#ifdef CONFIG_SYNC_DEBUG
        RTE_LOG(INFO, LB_RUNNING, "%s: new session sync packet: caddr[cport]:%s[%u] is sent from lcore_id:%u.\n", __func__, inet_ntop(lbs->af, &conn->caddr, buf, sizeof(buf)), ntohs(conn->cport), rte_lcore_id());
#endif
        lb_sync_send_message(conn, lbs, true);
    }
}

static lb_pl_cb_t lb_ipv6_in_cb[LB_PL_STAGE_IN_MAX] = {
    lb_ipv6_in0,
    lb_ipv6_in1,
    lb_ipv6_in2,
    lb_ipv6_in3,
};

static void lb_ipv6_out0(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    uint16_t sport, dport, offset;
    struct in6_addr *daddr;
    int iphdrlen;
    struct lb_conn_out *conn_cache_out;
    struct snat_multiply_pool *snat_pool;
    union inet_addr laddr;

    rte_pktmbuf_adj(cache->mbuf, sizeof(struct rte_ether_hdr));
    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    daddr = (struct in6_addr *)ip6h->dst_addr;

    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (ip6h->proto == IPPROTO_TCP) {
        get_tcp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_UDP) {
        get_udp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else {
        lb_cache_invalid(cache->mbuf, cache, "lb_ipv6_out0 protocol not supported.");
        return;
    }

    rte_memcpy(&laddr.in6, daddr->s6_addr, sizeof(struct in6_addr));
    snat_pool = lb_get_snat_pool(cache->markid);
    offset = lb_snat_multiply_offset(AF_INET, snat_pool, &laddr);
    assert(offset < DPVS_MAX_LADDR_PERCORE);

    conn_cache_out = lb_get_fnat_conn_hash_cache_out_use_markid(cache->markid);
    cache->v2 = &(conn_cache_out->out[offset][rte_be_to_cpu_16(dport)-DEF_MIN_PORT].conn);

    rte_prefetch0(cache->v2);
    cache->v1d = daddr->s6_addr16[7];
    cache->v3d = dport;
    cache->stage = LB_PL_STAGE1;
}

static void lb_ipv6_out1(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    void **out_cache = cache->v2;
    struct lb_conn *conn = *out_cache;

    if (!conn) {
        lb_cache_invalid(cache->mbuf, cache, "IPv6 No out connection");
        return;
    }

    cache->v2 = conn;

    rte_prefetch0(cache->v2);
    cache->stage = LB_PL_STAGE2;
}

static void lb_ipv6_out2(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;
    rte_be32_t dst_addr = cache->v1d;
    rte_be16_t dst_port = cache->v3d;

    if (conn->laddr.in6.s6_addr16[7] != dst_addr || conn->lport != dst_port) {
        lb_cache_invalid(cache->mbuf, cache, "Out addr check fail");
        return;
    }

    rte_prefetch0(conn->dest);
    cache->stage = LB_PL_STAGE3;
}

static void lb_ipv6_out3(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;

    lb_xmit_outbound(conn, cache->mbuf);
    lb_lcore_update_timer(&conn->timer);
    cache->stage = LB_PL_STAGE_INVALID;
}

static lb_pl_cb_t lb_ipv6_out_cb[LB_PL_STAGE_OUT_MAX] = {
    lb_ipv6_out0,
    lb_ipv6_out1,
    lb_ipv6_out2,
    lb_ipv6_out3,
};

static void lb_nat_ipv6_out0(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    union inet_addr saddr, daddr;
    uint16_t sport, dport;
    int iphdrlen;
    int icmp_type = 0;

    rte_pktmbuf_adj(cache->mbuf, sizeof(struct rte_ether_hdr));
    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    
    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (ip6h->proto == IPPROTO_TCP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_tcp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_UDP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_udp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_ICMPV6)  {
        if (get_ipv6_icmp6_addr_port(cache->mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
            lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out0 get_ipv6_icmp6_addr_port fail.");
            return;
        }
    } else {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out0 protocol not supported.");
        return;
    }
    
    cache->v1 = lb_conn_cache_get(lbs->af, &daddr, dport);
    rte_prefetch0(cache->v1);
    cache->stage = LB_PL_STAGE1;
    cache->next = LB_PL_NEXT_LOOKUP;

    return;
}

static void lb_nat_ipv6_out1(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *hash_elem = NULL;
    struct lb_conn *conn = NULL;
    union inet_addr saddr, daddr;
    uint16_t sport, dport;
    int icmp_type = 0;
    struct rte_mbuf *mbuf = cache->mbuf;
    int iphdrlen;
#ifdef CONFIG_LB_REDIRECT
    struct lb_conn_hash_elem *nat_hash_elem = NULL;
    uint32_t nat_hash = 0;
#endif

    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    
    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (ip6h->proto == IPPROTO_TCP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_tcp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_UDP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_udp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_ICMPV6)  {
        if (get_ipv6_icmp6_addr_port(cache->mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
            lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out0 get_ipv6_icmp6_addr_port fail.");
            return;
        }
    } else {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out0 protocol not supported.");
        return;
    }

    rte_prefetch0(mbuf->cacheline1);
    hash_elem = (struct lb_conn_hash_elem *)cache->v1;
    conn = lb_conn_get(hash_elem, AF_INET6, &daddr, dport, cache->markid, NULL);
    if (conn) {
        cache->v2 = conn;
        rte_prefetch0(cache->v2);
        cache->stage = LB_PL_STAGE3;
        cache->next = LB_PL_NEXT_OUT;
    } else {
#ifdef CONFIG_LB_REDIRECT
        cache->v2 = (void *)lb_conn_alloc();
        if (!cache->v2) {
            lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out1 lb_conn_alloc is NULL.");
            return;
        }
        rte_prefetch0(cache->v2);
        nat_hash_elem = lb_redirect_conn_cache_get(AF_INET6, &daddr, dport, &nat_hash);
        cache->v3d = nat_hash;
        cache->v4 = nat_hash_elem;
        rte_prefetch0(cache->v4);
        cache->stage = LB_PL_STAGE2;
        cache->next = LB_PL_NEXT_LOOKUP;
#else
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out1 no connection");
#endif
    }

    return;
}

static void lb_nat_ipv6_out2(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    union inet_addr saddr, daddr;
    uint16_t sport, dport;
    int icmp_type = 0;
    struct lb_conn_hash_elem *nat_hash_elem = NULL;
    int64_t cid = -1;
    struct lb_conn_hash_elem_free nat_hash_elem_free;
    void *value = NULL;
    int iphdrlen;
    struct lb_conn *conn = cache->v2;

    if (lb_lcore_init_timer(&conn->timer, lb_get_conn_init_timeout(), lb_redirect_conn_expire)) {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv4_out2 init timer failed");
        return;
    }
    value = lb_lcore_add_timer_pre(&conn->timer);
    rte_prefetch0(value);

    struct rte_ipv6_hdr *ip6h = rte_pktmbuf_mtod(cache->mbuf, struct rte_ipv6_hdr *);
    
    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (ip6h->proto == IPPROTO_TCP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_tcp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_UDP) {
        rte_memcpy(&daddr.in6, ip6h->dst_addr, sizeof(struct in6_addr));
        get_udp_port(rte_pktmbuf_mtod_offset(cache->mbuf, void *, iphdrlen), &sport, &dport);
    } else if (ip6h->proto == IPPROTO_ICMPV6)  {
        if (get_ipv6_icmp6_addr_port(cache->mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
            lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out0 get_ipv6_icmp6_addr_port fail.");
        }
    } else {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_ipv6_out2 protocol not supported.");
        return;
    }

    nat_hash_elem = (struct lb_conn_hash_elem *)cache->v4;
    cid = lb_redirect_conn_get_cid(nat_hash_elem, AF_INET6, &daddr, dport, cache->markid, cache->v3d);
    if (cid > 0) {
        nat_hash_elem_free.conn_page_head = NULL;
        lb_conn_get_free(AF_INET6, cache->v1, &nat_hash_elem_free);
        if (!nat_hash_elem_free.conn_page_head) {
            lb_cache_invalid(cache->mbuf, cache, "No memory for new nat connection hash lb_nat_ipv4_out2");
            return;
        }
        if (unlikely(nat_hash_elem_free.bit_map_index >= 2)) {
            rte_prefetch0(nat_hash_elem_free.free_hash_elem);
        }
        (void)rte_pktmbuf_prepend(cache->mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
        (void)lb_redirect_pkt(cache->mbuf, cid);
        lb_conn_hold_free_tuple(&nat_hash_elem_free, AF_INET6, conn, &daddr, dport, cache->markid);
        conn->in_hash_elem_head = NULL;
        conn->cid = cid;
        lb_conn_use_free_tuple(nat_hash_elem_free.conn_page_head, nat_hash_elem_free.bit_map_index, conn);
        lb_lcore_add_timer_bottom(&conn->timer, value);
    } else {
        lb_conn_put(conn);
    }

    cache->stage = LB_PL_STAGE_INVALID;
}

#ifdef CONFIG_LB_REDIRECT
static void lb_nat_ipv6_out3(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;

    if (conn->cid == rte_lcore_id()) {
        lb_xmit_outbound(conn, cache->mbuf);
        lb_lcore_update_timer(&conn->timer);
    } else {
        (void)rte_pktmbuf_prepend(cache->mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
        (void)lb_redirect_pkt(cache->mbuf, conn->cid);
    }
    cache->stage = LB_PL_STAGE_INVALID;
}
#else
static void lb_nat_ipv6_out3(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;

    lb_xmit_outbound(conn, cache->mbuf);
    lb_lcore_update_timer(&conn->timer);

    cache->stage = LB_PL_STAGE_INVALID;
}
#endif

static lb_pl_cb_t lb_nat_ipv6_out_cb[LB_PL_STAGE_OUT_MAX] = {
    lb_nat_ipv6_out0,
    lb_nat_ipv6_out1,
    lb_nat_ipv6_out2,
    lb_nat_ipv6_out3,
};

static void lb_nat_icmp6_ipv6_in0(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t sport, dport;
    int icmp_type = 0;
    int iphdrlen;

    rte_pktmbuf_adj(cache->mbuf, sizeof(struct rte_ether_hdr));
    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (get_ipv6_icmp6_addr_port(cache->mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_icmp6_ipv6_in0 get_ipv6_icmp6_addr_port fail.");
        return;
    }

    cache->v1 = lb_conn_cache_get(lbs->af, &saddr, sport);
    rte_prefetch0(cache->v1);
    cache->stage = LB_PL_STAGE1;
    cache->next = LB_PL_NEXT_LOOKUP;

    return;
}

// lookup session or allocat session memory
static void lb_nat_icmp6_ipv6_in1(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *hash_elem = NULL;
    struct lb_conn *conn = NULL;
    struct lb_dest *dest = NULL;
    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t sport, dport;
    struct lb_conn_hash_elem_free hash_elem_free;
    int iphdrlen;
    struct rte_mbuf *mbuf = cache->mbuf;
    int icmp_type = 0;

    iphdrlen = ip6_hdrlen(mbuf);
    if (get_ipv6_icmp6_addr_port(mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
        lb_cache_invalid(mbuf, cache, "lb_nat_icmp6_ipv6_in1 get_ipv6_icmp6_addr_port fail.");
        return;
    }

    rte_prefetch0(mbuf->cacheline1);
    hash_elem_free.conn_page_head = NULL;
    hash_elem = (struct lb_conn_hash_elem *)cache->v1;
    conn = lb_conn_get(hash_elem, lbs->af, &saddr, sport, cache->markid, &hash_elem_free);
    if (conn) {
        cache->v2 = conn;
        rte_prefetch0(cache->v2);
        cache->stage = LB_PL_STAGE3;
        cache->next = LB_PL_NEXT_OUT;
    } else {
        if (!hash_elem_free.conn_page_head) {
            lb_cache_invalid(mbuf, cache, "No memory for new connection hash");
            return;
        }
        cache->v1 = hash_elem_free.conn_page_head;
        cache->v2 = (void *)lb_conn_alloc();
        if (!cache->v2) {
            lb_cache_invalid(mbuf, cache, "No memory for new connection");
            return;
        }
        rte_prefetch0(cache->v2);
        if (unlikely(hash_elem_free.bit_map_index >= 2)) {
            rte_prefetch0(hash_elem_free.free_hash_elem);
        }
        if (icmp_type) {
            dest = lbs->scheduler->schedule_prefetch(lbs, mbuf);
            if (unlikely(!lb_dest_is_valid(dest))) {
                dest = lb_scheduler_next(dest, lbs, mbuf);
                if (!dest) {
                    lb_cache_invalid(mbuf, cache, "No valid dest");
                    lb_conn_put((struct lb_conn *)cache->v2);
                    return;
                }
            }
            rte_prefetch0(dest);
            cache->v3 = dest;
        }
        cache->new_conn_bit_map_index = hash_elem_free.bit_map_index;
        cache->stage = LB_PL_STAGE2;
        cache->next = LB_PL_NEXT_NEW;
        lb_conn_hold_free_tuple(&hash_elem_free, lbs->af, cache->v2, &saddr, sport, cache->markid);
    }

    return;
}

// new session and find out dst and laddr
static void lb_nat_icmp6_ipv6_in2(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn_hash_elem *conn_page_head = cache->v1;
    struct lb_conn *new = cache->v2;
    struct lb_dest *dest = cache->v3;
    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t sport, dport;
    int iphdrlen, err;
    struct flow6 fl6;
    struct route6 *rt6 = NULL;
    struct lb_conn_hash_elem *nat_hash_elem = NULL;
    struct lb_conn_hash_elem_free nat_hash_elem_free;
    int icmp_type = 0;
    uint32_t nat_hash = 0;

    iphdrlen = ip6_hdrlen(cache->mbuf);
    if (get_ipv6_icmp6_addr_port(cache->mbuf, iphdrlen, &saddr, &daddr, &sport, &dport, &icmp_type)) {
        lb_cache_invalid(cache->mbuf, cache, "lb_nat_icmp6_ipv6_in1 get_ipv6_icmp6_addr_port fail.");
        lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
        return;
    }

    assert(cache->stage == LB_PL_STAGE2);
    assert(cache->next == LB_PL_NEXT_NEW);

    new->flags = LB_CONN_F_NEW;
    
    if (0 == icmp_type) {
        goto tag;
    }

    lbs->scheduler->schedule_next(lbs, cache->mbuf);

    rte_memcpy(&new->caddr.in6, &saddr.in6, sizeof(struct in6_addr));
    new->cport              = sport;
    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        memset(&fl6, 0, sizeof(struct flow6));
        rte_memcpy(&fl6.fl6_daddr, &new->caddr.in6, sizeof(struct in6_addr));
        rte_memcpy(&fl6.fl6_saddr, &dest->vaddr.in6, sizeof(struct in6_addr));
        rt6 = route6_output(cache->mbuf, &fl6);
        if (!rt6) {
            route6_put(rt6);
            lb_cache_invalid(cache->mbuf, cache, "No route entry");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }

        new->out_dev = rt6->rt6_dev;
        route6_put(rt6);
        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(cache->mbuf, char *) -sizeof(struct rte_ether_hdr));
        rte_ether_addr_copy(&eth_hdr->d_addr, &new->out_smac);
        rte_ether_addr_copy(&eth_hdr->s_addr, &new->out_dmac);

        new->out_af = AF_INET6;

        err = lb_snat_multiply_fetch(AF_INET6, lbs->snat_pool, &new->laddr, &new->lport);
        if (unlikely(err)) {
            char msg[128];
            snprintf(msg, 127, "No SNAT resource entry for FNAT: %s", dpvs_strerror(err));
            lb_cache_invalid(cache->mbuf, cache, msg);
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
        cache->next = LB_PL_NEXT_NEW;
    } else if (dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        cache->next = LB_PL_NEXT_NEW;
    } else {
        if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
            nat_hash_elem = lb_redirect_conn_cache_get(AF_INET6, &new->caddr, sport, &nat_hash);
            rte_prefetch0(nat_hash_elem);
            memset(&fl6, 0, sizeof(struct flow6));
            rte_memcpy(&fl6.fl6_daddr, &new->caddr.in6, sizeof(struct in6_addr));
            rte_memcpy(&fl6.fl6_saddr, &dest->vaddr.in6, sizeof(struct in6_addr));
            rt6 = route6_output(cache->mbuf, &fl6);
            if (!rt6) {
                route6_put(rt6);
                lb_cache_invalid(cache->mbuf, cache, "No route entry");
                lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
                return;
            }

            new->out_dev = rt6->rt6_dev;
            route6_put(rt6);
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(cache->mbuf, char *) -sizeof(struct rte_ether_hdr));
            rte_ether_addr_copy(&eth_hdr->d_addr, &new->out_smac);
            rte_ether_addr_copy(&eth_hdr->s_addr, &new->out_dmac);
        }
        rte_memcpy(&new->laddr.in6, &saddr.in6, sizeof(struct in6_addr));
        new->lport  = sport;
        cache->next = LB_PL_NEXT_NEW;
        if (dest->fwdmode == DPVS_FWD_MODE_NAT) {
            nat_hash_elem_free.conn_page_head = NULL;
            lb_redirect_conn_get_free(AF_INET6, nat_hash_elem, &nat_hash_elem_free, nat_hash);
            if (!nat_hash_elem_free.conn_page_head) {
                lb_cache_invalid(cache->mbuf, cache, "No memory for new nat connection hash");
                lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
                return;
            }
            if (unlikely(nat_hash_elem_free.bit_map_index >= 2)) {
                rte_prefetch0(nat_hash_elem_free.free_hash_elem);
            }
        }
    }

tag:
    lb_conn_use_free_tuple(conn_page_head, cache->new_conn_bit_map_index, new);

    if (icmp_type) {
        if (lb_lcore_init_timer(&new->timer, lb_get_conn_init_timeout(), ipv6_conn_expire)) {
            lb_cache_invalid(cache->mbuf, cache, "init timer failed");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
    } else {
        if (lb_lcore_init_timer(&new->timer, lb_get_conn_init_timeout(), lb_redirect_conn_expire)) {
            lb_cache_invalid(cache->mbuf, cache, "init timer failed");
            lb_conn_release_free_tuple(new, conn_page_head, cache->new_conn_bit_map_index);
            return;
        }
    }
    cache->v4 = lb_lcore_add_timer_pre(&new->timer);
    rte_prefetch0(cache->v4);

    if (dest->fwdmode == DPVS_FWD_MODE_NAT && icmp_type) {
        lb_redirect_conn_hold_free_tuple(&nat_hash_elem_free, rte_lcore_id(), lbs->af, &new->caddr, sport, cache->markid);
        lb_redirect_conn_use_free_tuple(nat_hash_elem_free.conn_page_head, nat_hash_elem_free.bit_map_index, new);
        new->cid = rte_lcore_id();
    }

    cache->tmp_value = icmp_type;

    cache->stage = LB_PL_STAGE3;
}

static void lb_nat_icmp6_ipv6_in3(struct lb_pl_cache *cache, struct lb_service *lbs)
{
    struct lb_conn *conn = cache->v2;
    struct lb_dest *dest = NULL;
    uint16_t lport = 0, offset;
    void **out_cache_conn = NULL;
    int icmp_type = cache->tmp_value;

    if (unlikely(icmp_type && (cache->next == LB_PL_NEXT_NEW))) {
        dest = cache->v3;
        conn->dest = dest;
        conn->in_af = (uint8_t)dest->af;
        if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
            lport = conn->lport;
            offset = lb_snat_multiply_offset(AF_INET6, lbs->snat_pool, &conn->laddr);
            assert(offset < DPVS_MAX_LADDR_PERCORE);
            out_cache_conn = &(lbs->conn_cache_out->out[offset][rte_be_to_cpu_16(lport)-DEF_MIN_PORT].conn);
            rte_prefetch0(out_cache_conn);
        }

        dest->stats.conns++;
        conn->flags &= ~LB_CONN_F_NEW;
    }

    if (unlikely(conn->flags & LB_CONN_F_NEW || conn->flags & LB_CONN_F_DROP)) {
        if (likely(conn->flags & LB_CONN_F_NEW)) {
            return;
        } else {
            cache->stage = LB_PL_STAGE_INVALID;
            return;
        }
    }

    if (icmp_type) {
        dest = conn->dest;

        if (unlikely(conn->flags & IP_VS_CONN_F_SYNC)) {
            conn->flags &= ~IP_VS_CONN_F_SYNC;
            /* set this flag to prevent sync this conn as a new one */
            conn->flags |= LB_CONN_F_SYNC_SENT;
            if (lb_lcore_timer_sched(&conn->timer, lb_get_conn_init_timeout(), ipv6_conn_expire)) {
                lb_cache_invalid(cache->mbuf, cache, "init timer failed");
                lb_conn_free(conn);
                return;
            }
        }
    }

    if (conn->cid == rte_lcore_id()) {
        lb_xmit_inbound(conn, cache->mbuf);
    } else {
        (void)rte_pktmbuf_prepend(cache->mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
        (void)lb_redirect_pkt(cache->mbuf, conn->cid);
    }
    if (unlikely(cache->next == LB_PL_NEXT_NEW)) {
        lb_lcore_add_timer_bottom(&conn->timer, cache->v4);
        if (icmp_type) {
            if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
                if (unlikely(!out_cache_conn)) {
                    lb_cache_invalid(cache->mbuf, cache, "out connection cache invalid");
                    lb_conn_free(conn);
                    return;
                }
                lb_conn_set_out_value(out_cache_conn, conn);
            }
            lb_dest_get(dest);
            lbs_get(lbs);
        }
    } else {
        lb_lcore_update_timer(&conn->timer);
    }

    cache->stage = LB_PL_STAGE_INVALID;

    if (icmp_type && lb_sync_lcore_is_active() && lb_sync_conn_needed(conn))
    {
        lb_sync_send_message(conn, lbs, true);
    }
}

static lb_pl_cb_t lb_nat_icmp6_ipv6_in_cb[LB_PL_STAGE_IN_MAX] = {
    lb_nat_icmp6_ipv6_in0,
    lb_nat_icmp6_ipv6_in1,
    lb_nat_icmp6_ipv6_in2,
    lb_nat_icmp6_ipv6_in3,
};

void lb_flow_ipv6_in(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    lb_flow_pipeline_run(lb_ipv6_in_cb, LB_PL_STAGE_IN_MAX, mbuf, lbs, markid);
}

void lb_flow_nat_icmp6_ipv6_in(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    lb_flow_pipeline_run(lb_nat_icmp6_ipv6_in_cb, LB_PL_STAGE_IN_MAX, mbuf, lbs, markid);
}

void lb_flow_ipv6_out(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    lb_flow_pipeline_run(lb_ipv6_out_cb, LB_PL_STAGE_OUT_MAX, mbuf, lbs, markid);
}

void lb_flow_nat_ipv6_out(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid)
{
    lb_flow_pipeline_run(lb_nat_ipv6_out_cb, LB_PL_STAGE_OUT_MAX, mbuf, lbs, markid);
}
