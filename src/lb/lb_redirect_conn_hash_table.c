/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include "common.h"
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/blklst.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/proto_udp.h"
#include "lb/service.h"
#include "lb/dest.h"
#include "lb/laddr.h"
#include "lb/sched.h"
#include "lb/ipv4.h"
#include "lb/udp.h"
#include "lb/tcp.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "sa_pool.h"
#include "inet.h"
#include "lb/conn.h"
#include "lb/redirect_conn_hash_table.h"
#include "dpdk.h"


#define LB_REDIRECT_CONN_TBL_BITS          26
#define LB_REDIRECT_CONN_TBL_SIZE          (1 << LB_REDIRECT_CONN_TBL_BITS)
#define LB_REDIRECT_CONN_TBL_MASK          (LB_REDIRECT_CONN_TBL_SIZE - 1)

#define LB_REDIRECT_CONN_CACHE_LINES_LEFT 0
#define LB_REDIRECT_CONN_CACHE_LINES_DEF (1 << LB_REDIRECT_CONN_CACHE_LINES_LEFT)
#define lb_redirect_conn_cache_conns(af) af == AF_INET ? ((LB_REDIRECT_CONN_CACHE_LINES_DEF << 1) + LB_REDIRECT_CONN_CACHE_LINES_DEF): (LB_REDIRECT_CONN_CACHE_LINES_DEF << 1);

#define LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF 2
#define lb_redirect_conn_page_cache_conns(af) af == AF_INET ? ((LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF << 1) + LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF) : (LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF << 1) ;

#define LB_REDIRECT_CONN_HASH_ELEM_TBL_SIZE 26
static int lb_redirect_conn_hash_elem_pool_size = 1 << LB_REDIRECT_CONN_HASH_ELEM_TBL_SIZE;

extern uint32_t g_lb_conn_rnd; /* hash random */
static struct lb_conn_resource_pool g_redirect_conn_resource_pool;
static rte_spinlock_t g_ipv4_redirect_hash_lock[LB_REDIRECT_CONN_TBL_SIZE];
static rte_spinlock_t g_ipv6_redirect_hash_lock[LB_REDIRECT_CONN_TBL_SIZE];


static inline uint32_t lb_redirect_conn_hashkey(int af,
    const union inet_addr *saddr, uint16_t sport, uint32_t mask, struct lb_conn_hash_elem **conn_hash_tbl)
{
    switch (af) {
    case AF_INET:
        {
            *conn_hash_tbl = g_redirect_conn_resource_pool.ipv4_conn_hash_tbl;
            return rte_jhash_2words((uint32_t)saddr->in.s_addr, ((uint32_t)sport),
                g_lb_conn_rnd) & mask;
        }

    case AF_INET6:
        {
            uint32_t vect[5];

            *conn_hash_tbl = g_redirect_conn_resource_pool.ipv6_conn_hash_tbl;

            vect[0] = (uint32_t)sport;
            memcpy(&vect[1], &saddr->in6, LB_IPV6_ADDR_LEN);

            return rte_jhash_32b(vect, 5, g_lb_conn_rnd) & mask;
        }

    default:
        RTE_LOG(WARNING, IPVS, "%s: hashing unsupported protocol %d\n", __func__, af);
        return 0;
    }
}

struct lb_conn_hash_elem *lb_redirect_conn_cache_get(int af, union inet_addr *saddr, uint16_t sport, uint32_t *hash)
{
    struct lb_conn_hash_elem *conn_hash_tbl = NULL;

    *hash = lb_redirect_conn_hashkey(af, saddr, sport, LB_REDIRECT_CONN_TBL_MASK, &conn_hash_tbl);

    return &conn_hash_tbl[(*hash) << LB_REDIRECT_CONN_CACHE_LINES_LEFT];
}

static int64_t lb_redirect_ipv4_find_match_cid(struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    int i = 0;
    int j = 0;
    int k = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++, k++) {
        if (3 == k) {
            k = 0;
            j++;
        }
        if (hash_elem_head->conn_bit_map & (1 << i)) {
            struct lb_ipv4_conn_tuple *ipv4_tuple = &hash_elem_head[j].hash_tuple.ipv4_conn_array[k];
            if (saddr->in.s_addr == ipv4_tuple->saddr && sport == ipv4_tuple->sport && markid== ipv4_tuple->markid) {
                return ipv4_tuple->cid;
            }
        }
    }

    return -1;
}

static int lb_redirect_ipv4_find_conn_free(struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    int i = 0;
    int j = 0;
    int k = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++, k++) {
        if (3 == k) {
            k = 0;
            j++;
        }
        if (0 == (hash_elem_head->conn_bit_map & (1 << i))) {
            hash_elem_free->conn_page_head = hash_elem_head;
            hash_elem_free->free_hash_elem = &hash_elem_head[j];
            hash_elem_free->bit_map_index = i;
            hash_elem_free->conn_tuple_index = k;
            hash_elem_head->conn_bit_map |= (1 << i);
            //rte_smp_wmb();
            return 0;
        }
    }

    return -1;
}

static int64_t lb_redirect_ipv6_find_match_cid(struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    int i = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++) {
        if (hash_elem_head->conn_bit_map & (1 << i)) {
            struct lb_ipv6_conn_tuple *ipv6_tuple = &hash_elem_head[i >> 1].hash_tuple.ipv6_conn_array[i & 1];
            if ((memcmp(ipv6_tuple->saddr.in6.s6_addr, saddr->in6.s6_addr, LB_IPV6_ADDR_LEN) == 0)
                    && sport == ipv6_tuple->sport && markid== ipv6_tuple->markid) {
                return ipv6_tuple->cid;
            }
        }
    }

    return -1;
}

static int lb_redirect_ipv6_find_conn_free(struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    int i = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++) {
        if (0 == (hash_elem_head->conn_bit_map & (1 << i))) {
            hash_elem_free->conn_page_head = hash_elem_head;
            hash_elem_free->free_hash_elem = &hash_elem_head[i >> 1];
            hash_elem_free->bit_map_index = i;
            hash_elem_free->conn_tuple_index = i & 1;
            hash_elem_head->conn_bit_map |= (1 << i);
            //rte_smp_wmb();
            return 0;
        }
    }

    return -1;
}

static int64_t find_match_cid(int af, struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    if (AF_INET == af) {
        return lb_redirect_ipv4_find_match_cid(hash_elem_head, saddr, sport, markid);
    } else {
        return lb_redirect_ipv6_find_match_cid(hash_elem_head, saddr, sport, markid);
    }
}

static int lb_redirect_find_conn_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    if (AF_INET == af) {
        return lb_redirect_ipv4_find_conn_free(hash_elem_head, hash_elem_free);
    } {
        return lb_redirect_ipv6_find_conn_free(hash_elem_head, hash_elem_free);
    }
}

void lb_redirect_conn_get_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free, uint32_t hash)
{
    struct lb_conn_hash_elem * prev_hash_elem = NULL;
    struct lb_conn_hash_elem * new_hash_elem = NULL;

    if (unlikely(!hash_elem_head))
        return;
    
    //rte_smp_rmb();

    if (AF_INET == af) {
        rte_spinlock_lock(&g_ipv4_redirect_hash_lock[hash]);
    } else {
        rte_spinlock_lock(&g_ipv6_redirect_hash_lock[hash]);
    }

    while(hash_elem_head) {
        if (0 == lb_redirect_find_conn_free(af, hash_elem_head, hash_elem_free)) {
            goto unlock;
        } else {
            prev_hash_elem = hash_elem_head;
            hash_elem_head = hash_elem_head->conn_page;
        }
    }

    if (NULL == hash_elem_head) {
        if (unlikely(rte_mempool_get(g_redirect_conn_resource_pool.conn_hash_cache_in, (void **)&new_hash_elem) != 0)) {
            RTE_LOG(ERR, IPVS, "%s: can not get connect hash memory cache inbond.\n", __func__);
            goto unlock;
        }
        memset(new_hash_elem, 0, sizeof(struct lb_conn_hash_elem) * LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF);
        new_hash_elem->conn_alloc_cnt = lb_redirect_conn_page_cache_conns(af);
        prev_hash_elem->conn_page = new_hash_elem;
        hash_elem_head = new_hash_elem;
        (void)lb_redirect_find_conn_free(af, hash_elem_head, hash_elem_free);
    }

unlock:
    if (AF_INET == af) {
        rte_spinlock_unlock(&g_ipv4_redirect_hash_lock[hash]);
    } else {
        rte_spinlock_unlock(&g_ipv6_redirect_hash_lock[hash]);
    }
}

int64_t lb_redirect_conn_get_cid(struct lb_conn_hash_elem *hash_elem_head,
                                   int af, union inet_addr *saddr, uint16_t sport, uint8_t markid, uint32_t hash)
{
    int64_t cid = -1;
    struct lb_conn_hash_elem *current_hash_elem = NULL;
    struct lb_conn_hash_elem *prev_hash_elem = NULL;
    struct lb_conn_hash_elem *next_hash_elem = NULL;

    if (AF_INET == af) {
        rte_spinlock_lock(&g_ipv4_redirect_hash_lock[hash]);
    } else {
        rte_spinlock_lock(&g_ipv6_redirect_hash_lock[hash]);
    }

    //rte_smp_rmb();

    if (0 == hash_elem_head->conn_bit_map) {
        prev_hash_elem = hash_elem_head;
        current_hash_elem = hash_elem_head->conn_page;
    } else {
        current_hash_elem = hash_elem_head;
    }

    while (current_hash_elem) {
        if (current_hash_elem->conn_bit_map) {
            if ((cid = find_match_cid(af, current_hash_elem, saddr, sport, markid)) > 0) {
                goto unlock;
            }
            prev_hash_elem = current_hash_elem;
            current_hash_elem = current_hash_elem->conn_page;
        } else {
            next_hash_elem = current_hash_elem->conn_page;
            prev_hash_elem->conn_page = next_hash_elem;
            rte_mempool_put(g_redirect_conn_resource_pool.conn_hash_cache_in, current_hash_elem);
            current_hash_elem = next_hash_elem;
        }
    }

unlock:
    if (AF_INET == af) {
        rte_spinlock_unlock(&g_ipv4_redirect_hash_lock[hash]);
    } else {
        rte_spinlock_unlock(&g_ipv6_redirect_hash_lock[hash]);
    }

    return cid;
}

void lb_redirect_conn_hold_free_tuple(struct lb_conn_hash_elem_free *hash_elem_free, int cid, int af, union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    if (AF_INET == af) {
        struct lb_ipv4_conn_tuple *ipv4_conn_tuple = &hash_elem_free->free_hash_elem->hash_tuple.ipv4_conn_array[hash_elem_free->conn_tuple_index];
        ipv4_conn_tuple->saddr = saddr->in.s_addr;
        ipv4_conn_tuple->sport = sport;
        ipv4_conn_tuple->markid = markid;
        ipv4_conn_tuple->cid = cid;
    } else {
        struct lb_ipv6_conn_tuple *ipv6_conn_tuple = &hash_elem_free->free_hash_elem->hash_tuple.ipv6_conn_array[hash_elem_free->conn_tuple_index];
        rte_memcpy(&ipv6_conn_tuple->saddr.in6, &saddr->in6, sizeof(struct in6_addr));
        ipv6_conn_tuple->sport = sport;
        ipv6_conn_tuple->markid = markid;
        ipv6_conn_tuple->cid = cid;
    }
    //rte_smp_wmb();
}

void lb_redirect_conn_release_free_tuple(struct lb_conn *conn, struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index)
{
    conn_page_head->conn_bit_map &= (~(1 << free_bit_map_index));
    conn->flags &= ~LB_CONN_F_NEW;
    conn->flags &= LB_CONN_F_DROP;
}

void lb_redirect_conn_use_free_tuple(struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index, struct lb_conn *conn)
{
     conn->redirect_hash_elem_head = conn_page_head;
     conn->redirect_bit_map_index = free_bit_map_index;
}

void lb_redirect_conn_hash_free(struct lb_conn *conn)
{
    if (!conn) {
        return;
    }

    conn->redirect_hash_elem_head->conn_bit_map &= (~(1 << (conn->redirect_bit_map_index)));
}

void lb_redirect_conn_expire(void *priv)
{
    struct lb_conn* conn = list_entry(priv, struct lb_conn, timer);
    lb_conn_free(conn);
}

int lb_redirect_conn_hash_table_init(void)
{
    int i;
    struct lb_conn_hash_elem *conn_hash_tbl;
    struct rte_mempool *conn_hash_cache;

    conn_hash_tbl = rte_malloc_socket(NULL,
                        sizeof(struct lb_conn_hash_elem) * LB_REDIRECT_CONN_CACHE_LINES_DEF * LB_REDIRECT_CONN_TBL_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!conn_hash_tbl) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create ipv4 conn_hash_tbl\n",
                    __func__, rte_socket_id());
        goto err;
    }
    for (i = 0; i < LB_REDIRECT_CONN_TBL_SIZE; i++) {
        memset(&conn_hash_tbl[i << LB_REDIRECT_CONN_CACHE_LINES_LEFT], 0, sizeof(struct lb_conn_hash_elem));
        conn_hash_tbl[i << LB_REDIRECT_CONN_CACHE_LINES_LEFT].conn_alloc_cnt = lb_redirect_conn_cache_conns(AF_INET);
    }
    g_redirect_conn_resource_pool.ipv4_conn_hash_tbl = conn_hash_tbl;

    conn_hash_tbl = rte_malloc_socket(NULL,
                        sizeof(struct lb_conn_hash_elem) * LB_REDIRECT_CONN_CACHE_LINES_DEF * LB_REDIRECT_CONN_TBL_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!conn_hash_tbl) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create ipv6 conn_hash_tbl\n",
                    __func__, rte_socket_id());
        goto err;
    }
    for (i = 0; i < LB_REDIRECT_CONN_TBL_SIZE; i++) {
        memset(&conn_hash_tbl[i << LB_REDIRECT_CONN_CACHE_LINES_LEFT], 0, sizeof(struct lb_conn_hash_elem));
        conn_hash_tbl[i << LB_REDIRECT_CONN_CACHE_LINES_LEFT].conn_alloc_cnt = lb_redirect_conn_cache_conns(AF_INET6);
    }
    g_redirect_conn_resource_pool.ipv6_conn_hash_tbl = conn_hash_tbl;

    conn_hash_cache = rte_mempool_create("g_redirect_conn_cache_in",
                                    lb_redirect_conn_hash_elem_pool_size,
                                    sizeof(struct lb_conn_hash_elem) * LB_REDIRECT_CONN_PAGE_CACHE_LINES_DEF,
                                    0,
                                    0, NULL, NULL, NULL, NULL,
                                    rte_socket_id(),
                                    0);
    if (!conn_hash_cache) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create conn cache.\n",
                __func__, rte_lcore_id());
        goto err;
    }
    g_redirect_conn_resource_pool.conn_hash_cache_in = conn_hash_cache;

    for (i = 0; i < LB_REDIRECT_CONN_TBL_SIZE; i++) {
        rte_spinlock_init(&g_ipv4_redirect_hash_lock[i]);
    }

    for (i = 0; i < LB_REDIRECT_CONN_TBL_SIZE; i++) {
        rte_spinlock_init(&g_ipv6_redirect_hash_lock[i]);
    }

    return EDPVS_OK;
err:
    _exit(-1);
    return EDPVS_NOMEM;
}
