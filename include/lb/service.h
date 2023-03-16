/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_SERVICE_H__
#define __LB_SERVICE_H__
#include "lb/pipeline.h"

#define LB_STATUS_SERVICE_FREE   0
#define LB_STATUS_SERVICE_BUSY   1
#define LB_STATUS_SERVICE_ACTIVE 2
#define LB_STATUS_SERVICE_INACTIVE 3


#define LB_SCHE_SKIP      3   // Must be greater than LB_CACHE_DEPTH
struct lb_fnat_laddr {
    struct list_head    laddr_list; /* local address (LIP) pool */
    struct list_head    *laddr_curr;
    uint32_t            num_laddrs;
    uint32_t            skip_cnt;
};

/* virtual service */
struct lb_service {
    /* cache line0,1 */
    //struct lb_pipeline  pipe;   /* 96B */
    void (*get_transport)(void *trans_head, uint16_t *sport, uint16_t *dport);
    /* cache line3 */
    lb_flow_cb_t        flow_cb[DP_VS_MAX_DIRECTION];

    struct lb_conn_out  *conn_cache_out;
    struct netif_port      *out_dev;   /* outside to client*/

    struct lb_conn_hash_elem *conn_hash_tbl;
    struct rte_mempool   *conn_hash_cache_in;
    struct rte_mempool  *conn_pool;

    uint32_t            refcount;
    uint32_t            af;
    uint16_t            port;
    uint8_t             proto;      /* TCP/UDP/... */
    uint8_t             markid;

    /* cache line4 */
    struct lb_scheduler  *scheduler;
    void                *sched_data;
    void                *snat_pool; // FNAT or SNAT

    struct list_head    dests;      /* real services (dp_vs_dest{}) */
    enum dpvs_fwd_mode  fwdmod;
    uint32_t            num_dests;
    long                weight;     /* sum of servers weight */

    struct dp_vs_stats  stats;

    union inet_addr     addr;       /* virtual IP address */
    /* ... flags, timer ... */
    unsigned           flags;
    uint16_t            status;
    unsigned            timeout;
    unsigned            conn_timeout;
} __rte_cache_aligned;


static inline void
lbs_get(struct lb_service *lbs)
{
    lbs->refcount++;
}

static inline void
lbs_put(struct lb_service *lbs)
{
    lbs->refcount--;
    if (unlikely(!lbs->refcount))
        free(lbs);
}

static inline bool is_same_server(int af1, union inet_addr *addr1, uint16_t port1, uint8_t proto1,
                                        int af2, union inet_addr *addr2, uint16_t port2, uint8_t proto2)
{
    return af1 == af2 && inet_addr_equal(af1, addr1, addr2) && port1 == port2 && proto1 == proto2;
}

int lb_service_init(void);
void lb_service_uninit(void);
struct lb_service *lb_lcore_lookup_service(struct dp_vs_service *svc);
struct lb_service* lb_lcore_lookup_service_by_tup(int af, uint8_t protocol
    , const union inet_addr* vaddr, uint16_t vport);
struct lb_service* lb_lcore_lookup_service_by_markid(uint8_t markid);
/*
 * Get lb service by service index
 *
 * @param start_idx
 *   search start at this index
 * @param found_idx
 *   if service found, output the index of found service
 * @return
 *   NULL if service is not found.
  */
struct lb_service* lb_lcore_get_service(uint32_t start_idx, uint32_t* found_idx);


#endif
