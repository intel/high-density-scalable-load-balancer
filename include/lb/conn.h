/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_CONN_H__
#define __LB_CONN_H__

#include <arpa/inet.h>
#include "dpdk.h"
#include "lb/timer.h"
#include "lb/snat_pool.h"

#define LB_IPV6_ADDR_LEN 16

#pragma pack (1)

enum uoa_state {
    UOA_S_SENDING,
    UOA_S_DONE,
};

enum uoa_mode {
    UOA_M_OPP,      /* priave "option-protocol" (IPPROTO_OPT) with UOA */
    UOA_M_IPO,      /* add UOA as IPv4 Option field */
};

struct conn_udp {
    uint8_t         uoa_state;
    /* Record the number of packets before the connection is stable */
    uint8_t         in_pkts;
    uint8_t         out_pkts;
    uint8_t         acked;
};

struct conn_tcp {
    uint32_t        rs_end_seq;
    uint32_t        rs_end_ack;
};

#define LB_CONN_F_NEW       0x1
#define LB_CONN_F_STABLE    0X2
#define LB_CONN_F_DROP      0x4
#define LB_CONN_F_SYNC_SENT 0x8
#define LB_CONN_F_SYNC      0x20 /* entry created by sync, same as IP_VS_CONN_F_SYNC */

/* Initial bits allowed in backup server */
#define LB_CONN_F_BACKUP_MASK     LB_CONN_F_STABLE
/* Bits allowed to update in backup server */
#define LB_CONN_F_BACKUP_UPD_MASK LB_CONN_F_STABLE

struct lb_ipv4_conn_tuple {
    uint32_t            saddr;
    uint16_t            sport;
    uint8_t             markid;
    union {
        struct lb_conn  *conn;
        int64_t         cid;
    };
};

struct lb_ipv6_conn_tuple {
    union inet_addr     saddr;
    uint16_t            sport;
    uint8_t             markid;
    union {
        struct lb_conn  *conn;
        int64_t         cid;
    };
};

union lb_conn_tuple {
    struct lb_ipv4_conn_tuple ipv4_conn_array[3];
    struct lb_ipv6_conn_tuple ipv6_conn_array[2];
};

#pragma pack ()

#ifdef CONFIG_LB_REDIRECT
struct lb_conn_hash_elem {
    volatile uint8_t         conn_bit_map;
    uint8_t                  conn_alloc_cnt;
    union lb_conn_tuple      hash_tuple;
    struct lb_conn_hash_elem  *conn_page;
}__rte_cache_aligned;
#else
struct lb_conn_hash_elem {
    uint8_t                  conn_bit_map;
    uint8_t                  conn_alloc_cnt;
    union lb_conn_tuple      hash_tuple;
    struct lb_conn_hash_elem  *conn_page;
}__rte_cache_aligned;
#endif

struct lb_conn_hash_elem_free {
    struct lb_conn_hash_elem  *conn_page_head;
    struct lb_conn_hash_elem  *free_hash_elem;
    uint8_t                   bit_map_index;
    uint8_t                   conn_tuple_index;
};

struct lb_conn {
    /* cache line 0 */
    struct lb_timer         timer;
    struct lb_dest          *dest;  /* real server */
    union {
        struct conn_udp         udp;
        struct conn_tcp         tcp;
    };
    rte_be16_t              lport;
    rte_be16_t              cport;
    uint8_t                 flags;
    uint8_t                 state;
    uint8_t                 in_af;
    uint8_t                 out_af;

    /* cache line 1 */
    union inet_addr         laddr;  /* director Local address */
    struct netif_port       *out_dev;
    union inet_addr         caddr;  /* Client address */
    struct rte_ether_addr   out_smac;
    struct rte_ether_addr   out_dmac;
    uint8_t                 cid;
    uint8_t                 __pad;
    uint8_t                 l4_proto;   /* for session sync */
    uint8_t                 in_bit_map_index;
    struct lb_conn_hash_elem  *in_hash_elem_head;

    /* cache line 2 */
	uint8_t                 redirect_bit_map_index;
	struct lb_conn_hash_elem  *redirect_hash_elem_head;
    /* reserve 0 Bytes at end */
}__rte_cache_aligned;

struct lb_conn_resource_pool {
    struct lb_conn_hash_elem  *ipv4_conn_hash_tbl;
    struct lb_conn_hash_elem  *ipv6_conn_hash_tbl;
    struct rte_mempool        *conn_hash_cache_in;
    struct rte_mempool        *conn_pool;
} __rte_cache_aligned;

struct lb_conn_out {
    struct {
        void *conn;
    } out[DPVS_MAX_LADDR_PERCORE][POOL_BITS];
};

struct lb_conn_out_fnat_info {
    struct list_head node;
    union inet_addr base_addr;
    struct lb_conn_out *conn_out;
};

struct lb_conn_param
{
    int                    af;
    uint8_t                proto;
    union inet_addr        caddr;
    union inet_addr        vaddr;
    union inet_addr        daddr;
    union inet_addr        laddr;
    uint16_t               cport;
    uint16_t               vport;
    uint16_t               dport;
    uint16_t               lport;
    uint8_t                flags;
    uint8_t                state;
    uint64_t               timeout;
};

struct lb_service;
typedef void (*lb_conn_handler_t)(struct lb_conn *conns[], uint32_t conns_count, int af);
typedef void (*lb_iter_done_handler_t)(void);

void lb_init_jhash_conn_rnd(void);
int lb_conn_hash_table_init(uint32_t af);
int lb_conn_init(void);
lb_tick_t lb_get_conn_init_timeout(void);
struct lb_conn_hash_elem *lb_conn_cache_get(int af, union inet_addr *saddr, uint16_t sport);
void lb_conn_get_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free);
struct lb_conn * lb_conn_get(struct lb_conn_hash_elem *hash_elem_head,
                                   int af, union inet_addr *saddr, uint16_t sport, uint8_t markid, struct lb_conn_hash_elem_free *hash_elem_free);
void lb_conn_hold_free_tuple(struct lb_conn_hash_elem_free *hash_elem_free, int af, struct lb_conn *conn, union inet_addr *saddr, uint16_t sport, uint8_t markid);
void lb_conn_release_free_tuple(struct lb_conn *conn, struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index);
void lb_conn_use_free_tuple(struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index, struct lb_conn *conn);
void lb_conn_set_hash_value(struct lb_conn_hash_elem_free *hash_elem_free, int af, struct lb_conn *conn);
struct lb_conn *lb_conn_alloc(void);
void lb_conn_free(struct lb_conn *conn);
void lb_conn_put(struct lb_conn *conn);
int lb_alloc_fnat_conn_hash_cache_out(union inet_addr *base_addr, struct snat_multiply_pool * snat_pool);
void lb_free_fnat_conn_hash_cache_out(union inet_addr *base_addr, int index, uint32_t lcore_id);
struct lb_conn_out *lb_get_fnat_conn_hash_cache_out_use_addr(union inet_addr *addr);
struct lb_conn_out *lb_get_fnat_conn_hash_cache_out_use_markid(uint8_t markid);
struct snat_multiply_pool *lb_get_snat_pool(uint8_t markid);

static inline void lb_conn_set_out_value(void **out_cache_conn, void *conn)
{
    *out_cache_conn = conn;
}

void lb_conn_unregister_iter_job(void);
void lb_conn_register_iter_job(lb_conn_handler_t conn_handler, lb_iter_done_handler_t done_handler, uint32_t conns_count);
/*
 * Set conn iteration schedule statistic period, and the max
 * percent of the period which the iteration can consume.
 * @param period
 *   0: 1sec, 1: 1sec >> 1, 2: 1sec >> 2 ...
 * @param percent
 *   0: equal to period, 1: period >> 1, 2: period >> 2 ...
 */
void lb_conn_set_iter_sched_cfg(uint8_t period, uint32_t percent);
void lb_conn_lcore_enable_iter(bool enable);
struct lb_conn* lb_conn_new(struct lb_service* lbs, struct lb_conn_param* conn_param);
struct lb_conn* lb_conn_simple_new(struct lb_conn_param* conn_param);
void lb_conn_simple_free(struct lb_conn* conn);

#endif
