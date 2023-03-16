/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_DEST_H__
#define __LB_DEST_H__

#include "common.h"
#include "list.h"
#include "dpdk.h"
#include "lb/conn.h"

#define LB_DEST_XMIT_OUT    0
#define LB_DEST_XMIT_IN     1
#define LB_DEST_XMIT_MAX    2

#define LB_DEST_CACHE_INTERVAL    1       // 1s
#define LB_DEST_CACHE_DURATION    600     // 600s


struct lb_dest;
typedef void (*lb_dest_xmit_t)(void *conn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest);

struct lb_dest {
    /* cache line0 */
    int (*transport_in_handler)(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
    int (*transport_out_handler)(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
    int (*state_trans)(struct lb_conn *conn, struct rte_mbuf *mbuf, int iphdrlen, int dir);
    lb_dest_xmit_t          xmit_cb[LB_DEST_XMIT_MAX];
    struct netif_port       *in_dev;     /* inside to rs*/
    struct rte_ether_addr   in_smac;
    struct rte_ether_addr   in_dmac;
    uint16_t                flags;      /* dest status flags */
    uint16_t                conn_flags; /* flags to copy to conn */

    /* cache line1 */
    struct dp_vs_stats      stats;     /* Use per-cpu statistics for destination server */
    uint32_t                refcount;


    /* cache line2 */
    union inet_addr         addr;       /* IP address of the real server */
    union inet_addr         vaddr;      /* virtual IP address */
    int (*transport_conn_expire)(struct lb_conn *conn);
    rte_be16_t              port;       /* port number of the real server */
    rte_be16_t              vport;      /* virtual port number */
    uint16_t                af;         /* address family */
    uint16_t                fwdmode;
    struct list_head        n_list;     /* for the dests in the service */

    /* cache line3 */
    uint32_t            actconns;   /* active connections */
    uint32_t            inactconns; /* inactive connections */
    uint32_t            max_conn;   /* upper threshold */
    uint32_t            min_conn;   /* lower threshold */
    uint16_t            mtu;
    uint16_t                weight;     /* server weight */
    uint16_t            ipv4_id;    /* tunnel id */
    uint16_t            proto;      /* which protocol (TCP/UDP) */
    struct lb_service   *lbs;      /* service it belongs to */
    unsigned            conn_timeout; /* conn timeout copied from svc*/
    unsigned            limit_proportion; /* limit copied from svc*/

    /* for L2, L3 cache manage */
    struct lb_timer     cache_timer;
    int                 life_time;
} __rte_cache_aligned;

static inline void
lb_dest_get(struct lb_dest *dest)
{
    dest->refcount++;
}

static inline void
lb_dest_put(struct lb_dest *dest)
{
    dest->refcount--;
    if (unlikely(!dest->refcount))
        rte_free(dest);
}

static inline bool
lb_dest_is_avail(struct lb_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_AVAILABLE) ? true : false;
}

static inline bool
lb_dest_is_overload(struct lb_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_OVERLOAD) ? true : false;
}

static inline bool
lb_dest_is_valid(struct lb_dest *dest)
{
    return (dest
            && lb_dest_is_avail(dest)
            && !lb_dest_is_overload(dest)
            && dest->weight > 0) ? true : false;;
}

int lb_dest_init(void);
void lb_dest_uninit(void);
struct lb_dest* lb_lcore_lookup_dest_by_tup(struct lb_service* lbs
    , int af, uint8_t proto, union inet_addr* daddr, uint16_t dport);
struct lb_dest* lb_lcore_get_dest(struct lb_service* lbs, uint32_t idx);
int lb_lcore_del_dest(struct lb_dest *dest);


#endif
