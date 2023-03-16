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
#include "dpdk.h"

#define LB_CONN_TBL_SIZE          (LB_CONN_POOL_SIZE_PERCORE << 2)
#define LB_CONN_TBL_MASK          (LB_CONN_TBL_SIZE - 1)

#define LB_CONN_CACHE_LINES_LEFT 0
#define LB_CONN_CACHE_LINES_DEF (1 << LB_CONN_CACHE_LINES_LEFT)
#define lb_conn_cache_conns(af) af == AF_INET ? ((LB_CONN_CACHE_LINES_DEF << 1) + LB_CONN_CACHE_LINES_DEF): (LB_CONN_CACHE_LINES_DEF << 1);

#define LB_CONN_PAGE_CACHE_LINES_DEF 2
#define lb_conn_page_cache_conns(af) af == AF_INET ? ((LB_CONN_PAGE_CACHE_LINES_DEF << 1) + LB_CONN_PAGE_CACHE_LINES_DEF) : (LB_CONN_PAGE_CACHE_LINES_DEF << 1) ;

#define LB_CONN_HASH_ELEM_TBL_SIZE 20
static int lb_conn_hash_elem_pool_size = 1 << LB_CONN_HASH_ELEM_TBL_SIZE;

#define LB_CONN_INIT_TIMEOUT_DEF   3   /* sec */

#define LB_FNAT_ADDR_POOL 8

uint32_t g_lb_conn_rnd; /* hash random */
static lb_tick_t g_conn_init_timeout = LB_CONN_INIT_TIMEOUT_DEF << LB_HZ_BITS;

#define this_conn_resource_pool     (RTE_PER_LCORE(conn_resource_pool))
static RTE_DEFINE_PER_LCORE(struct lb_conn_resource_pool , conn_resource_pool);

#define this_fnat_conn_out_info_head     (RTE_PER_LCORE(fnat_conn_out_info_head))
static RTE_DEFINE_PER_LCORE(struct list_head, fnat_conn_out_info_head);

#define this_conn_out_cache     (RTE_PER_LCORE(conn_out_cache))
static RTE_DEFINE_PER_LCORE(struct lb_conn_out **, conn_out_cache);

#define this_conn_out_cache_used     (RTE_PER_LCORE(conn_out_cache_used))
static RTE_DEFINE_PER_LCORE(uint8_t *, conn_out_cache_used);
struct snat_multiply_pool *snat_pool;

#define this_conn_snat_pool    (RTE_PER_LCORE(conn_snat_pool))
static RTE_DEFINE_PER_LCORE(struct snat_multiply_pool **, conn_snat_pool);

/* 
 * Used for initializing the conns_size in struct iter_conns_param.
 * Conns iteration stride(conns_count) + CONNS_MARGIN_SIZE => conns_size.
 * Because the found conns count may be larger than expected in each iteration 
 */
#define CONNS_MARGIN_SIZE 32
/* 
 * Used by lb_lcore_iter_conns_job, to store the lb service index and
 * hash table element index for next loop.
 */
struct iter_conns_param
{
    uint32_t count;                  /* Used as input(conn count wanted) and output(conn count gotten) of iteration function */
    //uint32_t this_iter_svc_idx;
    int      af;
    uint32_t hash_tbl_idx;
    bool     enabled;                /* flag to enable iteration */
    uint64_t stat_start_cycles;      /* used to store statistic period start time */
    uint64_t stat_sum_exec_cycles;   /* used to store execution time in statistic period */
    uint32_t conns_size;             /* the capacity of conns buffer */
    struct lb_conn **conns;          /* conns buffer */
};
static RTE_DEFINE_PER_LCORE(struct iter_conns_param*, iter_param);
#define this_iter_param (RTE_PER_LCORE(iter_param))

struct iter_sched_cfg
{
    uint64_t period_cycles;      /* statistic period cycles */
    uint64_t exec_cycles;        /* max execution cycles in statistic period */
};
static struct iter_sched_cfg iter_sched_cfg = {
    .period_cycles = 1024, 
    .exec_cycles = 8,
};

static struct netif_lcore_loop_job iter_conns_job;
struct iter_conns_job_param
{
    lb_conn_handler_t      conn_handler;
    lb_iter_done_handler_t done_handler;
    uint32_t               conns_count;  /* conn counts handled in one iteration round */
};
static struct iter_conns_job_param iter_conns_job_data;

void lb_init_jhash_conn_rnd(void)
{
    g_lb_conn_rnd = (uint32_t)random();
}

static inline uint32_t lb_conn_hashkey(int af,
    const union inet_addr *saddr, uint16_t sport, uint32_t mask, struct lb_conn_hash_elem **conn_hash_tbl)
{
    switch (af) {
    case AF_INET:
        {
            *conn_hash_tbl = this_conn_resource_pool.ipv4_conn_hash_tbl;
            return rte_jhash_2words((uint32_t)saddr->in.s_addr, ((uint32_t)sport),
                g_lb_conn_rnd) & mask;
        }

    case AF_INET6:
        {
            uint32_t vect[5];

            *conn_hash_tbl = this_conn_resource_pool.ipv6_conn_hash_tbl;

            vect[0] = (uint32_t)sport;
            memcpy(&vect[1], &saddr->in6, LB_IPV6_ADDR_LEN);

            return rte_jhash_32b(vect, 5, g_lb_conn_rnd) & mask;
        }

    default:
        RTE_LOG(WARNING, IPVS, "%s: hashing unsupported protocol %d\n", __func__, af);
        return 0;
    }
}

static struct lb_conn *lb_ipv4_find_match_conn(struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
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
                return ipv4_tuple->conn;
            }
        }
    }

    return NULL;
}

static int lb_ipv4_find_conn_free(struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
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
            return 0;
        }
    }

    return -1;
}

static struct lb_conn *lb_ipv6_find_match_conn(struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    int i = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++) {
        if (hash_elem_head->conn_bit_map & (1 << i)) {
            struct lb_ipv6_conn_tuple *ipv6_tuple = &hash_elem_head[i >> 1].hash_tuple.ipv6_conn_array[i & 1];
            if ((memcmp(ipv6_tuple->saddr.in6.s6_addr, saddr->in6.s6_addr, LB_IPV6_ADDR_LEN) == 0)
                    && sport == ipv6_tuple->sport && markid== ipv6_tuple->markid) {
                return ipv6_tuple->conn;
            }
        }
    }

    return NULL;
}

static int lb_ipv6_find_conn_free(struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    int i = 0;

    for (i = 0; i < hash_elem_head->conn_alloc_cnt; i++) {
        if (0 == (hash_elem_head->conn_bit_map & (1 << i))) {
            hash_elem_free->conn_page_head = hash_elem_head;
            hash_elem_free->free_hash_elem = &hash_elem_head[i >> 1];
            hash_elem_free->bit_map_index = i;
            hash_elem_free->conn_tuple_index = i & 1;
            return 0;
        }
    }

    return -1;
}

static struct lb_conn *find_match_conn(int af, struct lb_conn_hash_elem *hash_elem_head,  const union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    if (AF_INET == af) {
        return lb_ipv4_find_match_conn(hash_elem_head, saddr, sport, markid);
    } else {
        return lb_ipv6_find_match_conn(hash_elem_head, saddr, sport, markid);
    }
}

static int lb_find_conn_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    if (AF_INET == af) {
        return lb_ipv4_find_conn_free(hash_elem_head, hash_elem_free);
    } {
        return lb_ipv6_find_conn_free(hash_elem_head, hash_elem_free);
    }
}

void lb_conn_get_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free)
{
    struct lb_conn_hash_elem * prev_hash_elem = NULL;
    struct lb_conn_hash_elem * new_hash_elem = NULL;

    if (unlikely(!hash_elem_head || !hash_elem_free))
        return;

    while(hash_elem_head) {
        if (0 == lb_find_conn_free(af, hash_elem_head, hash_elem_free)) {
            return;
        } else {
            prev_hash_elem = hash_elem_head;
            hash_elem_head = hash_elem_head->conn_page;
        }
    }

    if (NULL == hash_elem_head) {
        if (unlikely(rte_mempool_get(this_conn_resource_pool.conn_hash_cache_in, (void **)&new_hash_elem) != 0)) {
            RTE_LOG(WARNING, IPVS, "%s: can not get connect hash memory cache inbond.\n", __func__);
            return;
        }
        new_hash_elem->conn_bit_map = 0;
        new_hash_elem->conn_alloc_cnt = lb_conn_page_cache_conns(af);
        new_hash_elem->conn_page = NULL;
        prev_hash_elem->conn_page = new_hash_elem;
        hash_elem_head = new_hash_elem;
        (void)lb_find_conn_free(af, hash_elem_head, hash_elem_free);
    }
}

struct lb_conn * lb_conn_get(struct lb_conn_hash_elem *hash_elem_head,
                                   int af, union inet_addr *saddr, uint16_t sport, uint8_t markid, struct lb_conn_hash_elem_free *hash_elem_free)
{
    struct lb_conn *conn = NULL;
    struct lb_conn_hash_elem *current_hash_elem = NULL;
    struct lb_conn_hash_elem *prev_hash_elem = NULL;
    struct lb_conn_hash_elem *next_hash_elem = NULL;

    if (0 == hash_elem_head->conn_bit_map) {
        prev_hash_elem = hash_elem_head;
        current_hash_elem = hash_elem_head->conn_page;
    } else {
        current_hash_elem = hash_elem_head;
    }

    while (current_hash_elem) {
        if (current_hash_elem->conn_bit_map) {
            if ((conn = find_match_conn(af, current_hash_elem, saddr, sport, markid))) {
                return conn;
            }
            prev_hash_elem = current_hash_elem;
            current_hash_elem = current_hash_elem->conn_page;
        } else {
            next_hash_elem = current_hash_elem->conn_page;
            prev_hash_elem->conn_page = next_hash_elem;
            rte_mempool_put(this_conn_resource_pool.conn_hash_cache_in, current_hash_elem);
            current_hash_elem = next_hash_elem;
        }
    }

    lb_conn_get_free(af, hash_elem_head, hash_elem_free);

    return NULL;
}

struct lb_conn_hash_elem *lb_conn_cache_get(int af, union inet_addr *saddr, uint16_t sport)
{
    uint32_t hash;
    struct lb_conn_hash_elem *conn_hash_tbl = NULL;

    hash = lb_conn_hashkey(af, saddr, sport, LB_CONN_TBL_MASK, &conn_hash_tbl);

    return &conn_hash_tbl[hash << LB_CONN_CACHE_LINES_LEFT];
}

void lb_conn_hold_free_tuple(struct lb_conn_hash_elem_free *hash_elem_free, int af, struct lb_conn *conn, union inet_addr *saddr, uint16_t sport, uint8_t markid)
{
    hash_elem_free->conn_page_head->conn_bit_map |= (1 << hash_elem_free->bit_map_index);
    if (AF_INET == af) {
        struct lb_ipv4_conn_tuple *ipv4_conn_tuple = &hash_elem_free->free_hash_elem->hash_tuple.ipv4_conn_array[hash_elem_free->conn_tuple_index];
        ipv4_conn_tuple->saddr = saddr->in.s_addr;
        ipv4_conn_tuple->sport = sport;
        ipv4_conn_tuple->markid = markid;
        ipv4_conn_tuple->conn = conn;
    } else {
        struct lb_ipv6_conn_tuple *ipv6_conn_tuple = &hash_elem_free->free_hash_elem->hash_tuple.ipv6_conn_array[hash_elem_free->conn_tuple_index];
        rte_memcpy(&ipv6_conn_tuple->saddr.in6, &saddr->in6, sizeof(struct in6_addr));
        ipv6_conn_tuple->sport = sport;
        ipv6_conn_tuple->markid = markid;
        ipv6_conn_tuple->conn = conn;
    }
}

void lb_conn_release_free_tuple(struct lb_conn *conn, struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index)
{
    conn_page_head->conn_bit_map &= (~(1 << free_bit_map_index));
    conn->flags &= ~LB_CONN_F_NEW;
    conn->flags &= LB_CONN_F_DROP;
}

void lb_conn_use_free_tuple(struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index, struct lb_conn *conn)
{
     conn->in_hash_elem_head = conn_page_head;
     conn->in_bit_map_index = free_bit_map_index;
}

struct lb_conn *lb_conn_alloc(void)
{
    struct lb_conn *conn = NULL;

    if (unlikely(rte_mempool_get(this_conn_resource_pool.conn_pool, (void **)&conn) != 0)) {
        RTE_LOG(ERR, IPVS, "%s: no memory for connection\n", __func__);
        return NULL;
    }

    return conn;
}

void lb_conn_put(struct lb_conn *conn)
{
    rte_mempool_put(this_conn_resource_pool.conn_pool, conn);
}

void lb_conn_free(struct lb_conn *conn)
{
    if (!conn) {
        return;
    }

    if (conn->in_hash_elem_head) {
        conn->in_hash_elem_head->conn_bit_map &= (~(1 << (conn->in_bit_map_index)));
    }
    
    rte_mempool_put(this_conn_resource_pool.conn_pool, conn);
}

int lb_conn_hash_table_init(uint32_t af)
{
    int i;
    struct lb_conn_hash_elem *conn_hash_tbl;

    conn_hash_tbl = rte_malloc_socket(NULL,
                        sizeof(struct lb_conn_hash_elem) * LB_CONN_CACHE_LINES_DEF * LB_CONN_TBL_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());

    if (!conn_hash_tbl) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create conn_hash_tbl\n",
                    __func__, rte_socket_id());
        goto err;
    }

    for (i = 0; i < LB_CONN_TBL_SIZE; i++) {
        memset(&conn_hash_tbl[i << LB_CONN_CACHE_LINES_LEFT], 0, sizeof(struct lb_conn_hash_elem));
        conn_hash_tbl[i << LB_CONN_CACHE_LINES_LEFT].conn_alloc_cnt = lb_conn_cache_conns(af);
    }

    if (AF_INET == af) {
        this_conn_resource_pool.ipv4_conn_hash_tbl = conn_hash_tbl;
    } else {
        this_conn_resource_pool.ipv6_conn_hash_tbl = conn_hash_tbl;
    }

    return 0;
err:
    _exit(-1);
    return EDPVS_NOMEM;
}

static int lb_conn_pool_init(void *args)
{
    struct rte_mempool *conn_pool;
    struct rte_mempool *conn_hash_cache;
    char poolname[32];

    if (netif_lcore_is_idle(rte_lcore_id())) {
        return EDPVS_OK;
    }

    snprintf(poolname, sizeof(poolname), "lb_conn_%d", rte_lcore_id());
    conn_pool = rte_mempool_create(poolname, LB_CONN_POOL_SIZE_PERCORE,
                        sizeof(struct lb_conn), 0,
                        0, NULL, NULL, NULL, NULL,
                        rte_socket_id(),
                        MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);

    if (!conn_pool) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create conn mempool failed.\n",
                    __func__, rte_lcore_id());
        return EDPVS_NOMEM;
    }
    this_conn_resource_pool.conn_pool = conn_pool;

    snprintf(poolname, sizeof(poolname), "lb_conn_hash_cache_%d", rte_lcore_id());
    conn_hash_cache = rte_mempool_create(poolname,
                                    lb_conn_hash_elem_pool_size,
                                    sizeof(struct lb_conn_hash_elem) * LB_CONN_PAGE_CACHE_LINES_DEF,
                                    0,
                                    0, NULL, NULL, NULL, NULL,
                                    rte_socket_id(),
                                    MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
    if (!conn_hash_cache) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create conn cache.\n",
                __func__, rte_lcore_id());
        return EDPVS_NOMEM;
    }
    this_conn_resource_pool.conn_hash_cache_in = conn_hash_cache;

    return EDPVS_OK;
}

int lb_alloc_fnat_conn_hash_cache_out(union inet_addr *base_addr, struct snat_multiply_pool * snat_pool)
{
    int i = 0;
    
    for (i = 0; i < LB_FNAT_ADDR_POOL; i++) {
        if (0 == this_conn_out_cache_used[i]) {
            break;
        }
    }

    if (i == LB_FNAT_ADDR_POOL) {
        return -1;
    }

    struct lb_conn_out *out = rte_zmalloc_socket(NULL,
                        sizeof(*out),
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!out) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create conn_hash_cache_out\n",
                    __func__, rte_lcore_id());
        return -1;
    }

    struct lb_conn_out_fnat_info *fnat_conn_outinfo = rte_zmalloc_socket(NULL,
                        sizeof(struct lb_conn_out_fnat_info),
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!fnat_conn_outinfo) {
        RTE_LOG(ERR, IPVS, "%s: lcore %d: create lb_conn_out_fnat_info\n",
                    __func__, rte_lcore_id());
        rte_free(out);
        return -1;
    }

    rte_memcpy(&fnat_conn_outinfo->base_addr, base_addr, sizeof(*base_addr));
    fnat_conn_outinfo->conn_out = out;
    list_add(&fnat_conn_outinfo->node, &this_fnat_conn_out_info_head);

    this_conn_out_cache[i] = out;

    this_conn_out_cache_used[i] = 1;

    this_conn_snat_pool[i] = snat_pool;

    return i;
}

void lb_free_fnat_conn_hash_cache_out(union inet_addr *base_addr, int index, uint32_t lcore_id)
{
    struct lb_conn_out_fnat_info *fnat_conn_outinfo = NULL;
    struct lb_conn_out_fnat_info *next = NULL;
    
    list_for_each_entry_safe(fnat_conn_outinfo, next, &this_fnat_conn_out_info_head, node) {
        if (!memcmp(base_addr, &fnat_conn_outinfo->base_addr, sizeof(*base_addr))) {
            list_del(&fnat_conn_outinfo->node);
            rte_free(fnat_conn_outinfo->conn_out);
            rte_free(fnat_conn_outinfo);
            this_conn_out_cache[index] = NULL;
            this_conn_out_cache_used[index] = 0;
            this_conn_snat_pool[index] = NULL;
        }
    }

    return;
}

struct lb_conn_out *lb_get_fnat_conn_hash_cache_out_use_addr(union inet_addr *base_addr)
{
    struct lb_conn_out_fnat_info *fnat_conn_outinfo = NULL;
    
    list_for_each_entry(fnat_conn_outinfo, &this_fnat_conn_out_info_head, node) {
        if (!memcmp(base_addr, &fnat_conn_outinfo->base_addr, sizeof(*base_addr))) {
            return fnat_conn_outinfo->conn_out;
        }
    }

    return NULL;
}

struct lb_conn_out *lb_get_fnat_conn_hash_cache_out_use_markid(uint8_t markid)
{
    return this_conn_out_cache[markid];
}

struct snat_multiply_pool *lb_get_snat_pool(uint8_t markid)
{
    return this_conn_snat_pool[markid];
}

lb_tick_t lb_get_conn_init_timeout(void)
{
    return g_conn_init_timeout;
}

static struct lb_conn_hash_elem* get_conn_hash_tbl(int start_af, int *found_af)
{
    struct lb_conn_hash_elem *conn_hash_tbl = NULL;
    uint32_t found_idx;
    struct lb_service *lbs = lb_lcore_get_service(0, &found_idx);
    if (NULL == lbs) {
        return NULL;
    }
    *found_af = AF_UNSPEC;
    while(start_af < AF_MAX) {
        switch (start_af) {
        case AF_INET:
            conn_hash_tbl = this_conn_resource_pool.ipv4_conn_hash_tbl;
            break;
        case AF_INET6:
            conn_hash_tbl = this_conn_resource_pool.ipv6_conn_hash_tbl;
            break;
        default:
            conn_hash_tbl = NULL;
            break;
        }
        if (conn_hash_tbl != NULL) {
            *found_af = start_af;
            break;
        }
        start_af++;
    }
    return conn_hash_tbl;
}

static bool lb_conn_lcore_iter_conns(lb_conn_handler_t conn_handler, struct lb_conn **conns, uint32_t conns_size
                                     , uint32_t *count, uint32_t *hash_tbl_idx, int *af)
{
    int hti;  /* element index in hash table */
    int i;    /* index for all hash tuples under a hash element head */
    int htii; /* 2nd level element index in hash table */
    int tupi; /* lb_conn_tuple array index in lb_conn_hash_elem */
    int found_af = AF_UNSPEC;
    /* 32(2^5) obtained by perf measure data, time multiple to read a hash element with vs. without conn */
    uint32_t perf_multiple_per_iter = 5 ;
    uint32_t iter_hit_count = 0;
    uint32_t iter_miss_count = 0;
    bool buffer_overflow = false;
    bool ret = false;
    struct lb_ipv4_conn_tuple* ipv4_tuple;
    struct lb_ipv6_conn_tuple* ipv6_tuple;

    struct lb_conn_hash_elem* conn_hash_tbl = NULL;
    struct lb_conn_hash_elem* current_hash_elem = NULL;

    conn_hash_tbl = get_conn_hash_tbl(*af, &found_af);
    while (conn_hash_tbl != NULL) {
        for (hti = *hash_tbl_idx; hti < LB_CONN_TBL_SIZE; hti++) {
            current_hash_elem = &conn_hash_tbl[hti << LB_CONN_CACHE_LINES_LEFT];
            iter_miss_count++;
            while (current_hash_elem != NULL) {
                if (current_hash_elem->conn_bit_map != 0) {
                    if (AF_INET == found_af) {
                        i = 0;
                        htii = 0;
                        tupi = 0;
                        for (i = 0; i < current_hash_elem->conn_alloc_cnt; i++, tupi++) {
                            if (3 == tupi) {
                                tupi = 0;
                                htii++;
                            }
                            if (current_hash_elem->conn_bit_map & (1 << i)) {
                                ipv4_tuple =
                                    &current_hash_elem[htii].hash_tuple.ipv4_conn_array[tupi];
                                if (likely(iter_hit_count + 1 <= conns_size)) {
                                    conns[iter_hit_count] = ipv4_tuple->conn;
                                    iter_hit_count++;
                                    iter_miss_count--;
                                } else {
                                    buffer_overflow = true;
                                    RTE_LOG(WARNING, IPVS, "%s buffer(size:%u) on lcore: %u overflows, iteration skips some conns.\n", __func__, conns_size, rte_lcore_id());
                                    break;
                                }
                            }
                        }
                    } else if (AF_INET6 == found_af) {
                        for (i = 0; i < current_hash_elem->conn_alloc_cnt; i++) {
                            if (current_hash_elem->conn_bit_map & (1 << i)) {
                                ipv6_tuple =
                                    &current_hash_elem[i >> 1].hash_tuple.ipv6_conn_array[i & 1];
                                if (iter_hit_count + 1 <= conns_size) {
                                    conns[iter_hit_count] = ipv6_tuple->conn;
                                    iter_hit_count++;
                                    iter_miss_count--;
                                } else {
                                    buffer_overflow = true;
                                    RTE_LOG(WARNING, IPVS, "%s buffer(size:%u) on lcore: %u overflows, iteration skips some conns.\n", __func__, conns_size, rte_lcore_id());
                                    break;
                                }
                            }
                        }
                    } else {
                        /* do nothing */
                    }
                }
                current_hash_elem = current_hash_elem->conn_page;
            } /* one hash element head iterated*/
            /* evalute exit condition only when one hash element head was iterated */
            if (iter_hit_count + (iter_miss_count >> perf_multiple_per_iter) >= *count 
                || buffer_overflow) {
                if (iter_hit_count > 0) {
                    conn_handler(conns, iter_hit_count, found_af);
                }
                *count = iter_hit_count;
                /* set next hash table element index as output value*/
                *hash_tbl_idx = hti + 1;
                *af = found_af;
                ret = false;
                goto end;
            }
        } /* one conn hash table iterated */
        if (iter_hit_count > 0) {
            conn_handler(conns, iter_hit_count, found_af);
            conn_hash_tbl = get_conn_hash_tbl(found_af + 1, &found_af);
            *count = iter_hit_count;
            *hash_tbl_idx = 0;
            *af = found_af;
            if (conn_hash_tbl != NULL) {
                ret = false;
            } else {
                ret = true;
            }
            goto end;
        } else {
            /* get next conn hash table */
            conn_hash_tbl = get_conn_hash_tbl(found_af + 1, &found_af);
            *hash_tbl_idx = 0;
        }
    } /* conn_hash_tbl != NULL */
    /* All connections are iterated */
    if (iter_hit_count > 0) {
        conn_handler(conns, iter_hit_count, found_af);
    }
    *count = iter_hit_count;
    *hash_tbl_idx = 0;
    *af = AF_UNSPEC;
    ret = true;
    return ret;
end:
    return ret;
}

static int lb_conn_lcore_iter_job(void* arg, int high_stat)
{
    uint32_t conns_size;
    if (this_iter_param->enabled) {
        uint64_t start = rte_rdtsc();
        uint64_t stat_all_cycles;
        if (unlikely(0 == this_iter_param->hash_tbl_idx)) {
            this_iter_param->stat_start_cycles = start;
            this_iter_param->stat_sum_exec_cycles = 0;
        } else {
            stat_all_cycles = start - this_iter_param->stat_start_cycles;
            if (stat_all_cycles < iter_sched_cfg.period_cycles) {
                if (this_iter_param->stat_sum_exec_cycles > iter_sched_cfg.exec_cycles) {
                    /* skip the iteration and only sum the cycles of overhead */
                    goto stat;
                } else {
                    /* the iteration get time slice to run */
                }
            } else {
                this_iter_param->stat_start_cycles = start;
                this_iter_param->stat_sum_exec_cycles = 0;
            }
        }
        struct iter_conns_job_param* job_data = (struct iter_conns_job_param*)arg;
        /* init input count with specified value */
        this_iter_param->count = job_data->conns_count;
        if (unlikely(0 == this_iter_param->conns_size)) {
            conns_size = this_iter_param->count + CONNS_MARGIN_SIZE;
            this_iter_param->conns = rte_zmalloc(NULL
                                                 , sizeof(struct lb_conn*) * conns_size
                                                 , 0);
            if (NULL == this_iter_param->conns) {
                /* if conns buffer allocation fails, exit iteration */
                RTE_LOG(WARNING, IPVS, "%s fail to allocate buffer(size:%u) on lcore: %u, conns iteration stop.\n", __func__, conns_size, rte_lcore_id());
                job_data->done_handler();
                goto stat;
            } else {
                this_iter_param->conns_size = conns_size;
            }
        }
        /* this call will modify count, hash_tbl_idx, af parameter */
        bool done = lb_conn_lcore_iter_conns(job_data->conn_handler
            , this_iter_param->conns
            , this_iter_param->conns_size
            , &this_iter_param->count
            , &this_iter_param->hash_tbl_idx
            , &this_iter_param->af);
        if (done) {
            rte_free(this_iter_param->conns);
            this_iter_param->conns = NULL;
            this_iter_param->conns_size = 0;
            job_data->done_handler();
        }
stat:
        this_iter_param->stat_sum_exec_cycles += rte_get_tsc_cycles() - start;
    }
    return 0;
}

void lb_conn_unregister_iter_job(void)
{
    if (netif_lcore_loop_job_unregister(&iter_conns_job) < 0) { 
        RTE_LOG(WARNING, IPVS, "%s fail to unregister %s on slave lcores\n", __func__, iter_conns_job.name);
    }
}

void lb_conn_register_iter_job(lb_conn_handler_t conn_handler, lb_iter_done_handler_t done_handler, uint32_t conns_count)
{
    iter_conns_job_data.conn_handler = conn_handler;
    iter_conns_job_data.done_handler = done_handler;
    iter_conns_job_data.conns_count = conns_count;
    snprintf(iter_conns_job.name, sizeof(iter_conns_job.name) - 1, "%s", "iter_conns_job");
    iter_conns_job.func = lb_conn_lcore_iter_job;
    iter_conns_job.data = &iter_conns_job_data;
    iter_conns_job.type = NETIF_LCORE_JOB_IDLE;
    if (netif_lcore_loop_job_register(&iter_conns_job) < 0) {
        RTE_LOG(WARNING, IPVS, "%s: fail to register %s on slave lcores\n", __func__, iter_conns_job.name);
    }
}

void lb_conn_set_iter_sched_cfg(uint8_t period, uint32_t percent)
{
    uint64_t cycles_per_sec = rte_get_tsc_hz();
    iter_sched_cfg.period_cycles = cycles_per_sec >> period;
    iter_sched_cfg.exec_cycles = iter_sched_cfg.period_cycles >> percent;
}

void lb_conn_lcore_enable_iter(bool enable)
{
    this_iter_param->enabled = enable;
}

static int lb_conn_init_lcore(void* arg)
{
    int ret = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();
    
    if (netif_lcore_is_idle(lcore_id)) {
        ret = EDPVS_IDLE;
    } else {
        this_iter_param = rte_zmalloc(NULL, sizeof(struct iter_conns_param), 0);
        if (this_iter_param != NULL) {
            this_iter_param->af = AF_UNSPEC;
            this_iter_param->hash_tbl_idx = 0;
            this_iter_param->count = 0;
            this_iter_param->enabled = false;
            this_iter_param->stat_start_cycles = 0;
            this_iter_param->stat_sum_exec_cycles = 0;
            this_iter_param->conns_size = 0;
            this_iter_param->conns = NULL;
        } else {
            ret = EDPVS_NOMEM;
        }
    }

    this_conn_out_cache = rte_zmalloc_socket(NULL,
                        sizeof(struct lb_conn_out *) * LB_FNAT_ADDR_POOL,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());

    this_conn_out_cache_used = rte_zmalloc_socket(NULL,
                            sizeof(uint8_t) * LB_FNAT_ADDR_POOL,
                            RTE_CACHE_LINE_SIZE, rte_socket_id());
    
    this_conn_snat_pool = rte_zmalloc_socket(NULL,
                            sizeof(struct snat_multiply_pool *) * LB_FNAT_ADDR_POOL,
                            RTE_CACHE_LINE_SIZE, rte_socket_id());

    INIT_LIST_HEAD(&this_fnat_conn_out_info_head);

    return ret;
}

int lb_conn_init(void)
{
    int err = EDPVS_OK;
    lcoreid_t lcore;
    int timeout = dp_vs_get_conn_init_timeout();

    if (timeout != LB_CONN_INIT_TIMEOUT_DEF)
        g_conn_init_timeout =  timeout << LB_HZ_BITS;

    lb_set_udp_timeout(udp_get_timeout());
    lb_set_tcp_timeouts(tcp_get_timeouts());
    lb_set_udp_uoa_mode(udp_get_uoa_mode());
    lb_set_udp_uoa_max_trail(udp_get_max_trail());

    lb_init_jhash_conn_rnd();

    /* Set sched stat period to 1 second, and time slice for iteration to 1/128 second */
    lb_conn_set_iter_sched_cfg(0, 7);
    
    rte_eal_mp_remote_launch(lb_conn_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                __func__, lcore, dpvs_strerror(err));
        }
    }

    rte_eal_mp_remote_launch(lb_conn_pool_init, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
            return err;
        }
    }

    return err;
}

struct lb_conn* lb_conn_new(struct lb_service* lbs, struct lb_conn_param *conn_param)
{
    struct lb_conn_hash_elem* hash_elem_head = NULL;
    struct lb_conn* new = NULL;
    struct lb_dest* dest = NULL;
    void** out_cache_conn = NULL;
    struct dp_vs_flowid flow_id;
    struct lb_conn_hash_elem_free hash_elem_free;
    hash_elem_free.conn_page_head = NULL;
    uint16_t offset;

    if (likely(lbs != NULL)) {
        if (unlikely(IPPROTO_ICMP == conn_param->proto || IPPROTO_ICMPV6 == conn_param->proto)) {
            goto errout;
        }
        hash_elem_head = lb_conn_cache_get(conn_param->af, &conn_param->caddr, conn_param->cport);
        lb_conn_get_free(conn_param->af, hash_elem_head, &hash_elem_free);
        if (unlikely(NULL == hash_elem_free.conn_page_head)) {
            goto errout;
        }
        new = lb_conn_alloc();
        if (unlikely(NULL == new)) {
            goto errout;
        }
        flow_id.value = lbs->markid;
        lb_conn_hold_free_tuple(&hash_elem_free, conn_param->af, new, &conn_param->caddr, conn_param->cport, flow_id.id);
        lb_conn_use_free_tuple(hash_elem_free.conn_page_head, hash_elem_free.bit_map_index, new);
        dest = lb_lcore_lookup_dest_by_tup(lbs, conn_param->af, conn_param->proto, &conn_param->daddr, conn_param->dport);
        if (unlikely(!lb_dest_is_valid(dest))) {
            goto errout;
        }

        new->timer.delay = conn_param->timeout;
        new->state = conn_param->state;
        new->flags = conn_param->flags;
        new->caddr = conn_param->caddr;
        new->cport = conn_param->cport;
        new->laddr = conn_param->laddr;  /* updated by FNAT */
        new->lport = conn_param->lport;  /* updated by FNAT */
        new->l4_proto = conn_param->proto;
        new->dest = dest;
        dest->stats.conns++;

        if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
            if (lb_snat_multiply_fetch(lbs->af, lbs->snat_pool, &new->laddr, &new->lport))
                goto errout;

            offset = lb_snat_multiply_offset(dest->af, lbs->snat_pool, &new->laddr);
            assert(offset < DPVS_MAX_LADDR_PERCORE);
            out_cache_conn = &(lbs->conn_cache_out->out[offset][rte_be_to_cpu_16(new->lport) - DEF_MIN_PORT].conn);
            lb_conn_set_out_value(out_cache_conn, new);
        }
        lb_dest_get(dest);
        lbs_get(lbs);
    }

    return new;

errout:
    if (new != NULL) {
        lb_conn_free(new);
    }
    return NULL;
}

struct lb_conn* lb_conn_simple_new(struct lb_conn_param* conn_param)
{
    struct lb_conn* new = lb_conn_alloc();
    if (unlikely(NULL == new)) {
        goto errout;
    }

    new->timer.delay = conn_param->timeout;
    new->state = conn_param->state;
    new->flags = conn_param->flags;
    new->caddr = conn_param->caddr;
    new->cport = conn_param->cport;
    new->laddr = conn_param->laddr;  /* updated by FNAT */
    new->lport = conn_param->lport;  /* updated by FNAT */
    new->l4_proto = conn_param->proto;
    return new;
errout:
    if (new != NULL) {
        lb_conn_free(new);
    }
    return NULL;
}

void lb_conn_simple_free(struct lb_conn* conn)
{
    if (NULL == conn) {
        return;
    }
    rte_mempool_put(this_conn_resource_pool.conn_pool, conn);
}
