/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_SNAT_POOL_H__
#define __LB_SNAT_POOL_H__

#include "dpdk.h"
#include "inet.h"


enum snat_pool_mode {
    LB_SNAT_POOL_MODE_SINGLE,
    LB_SNAT_POOL_MODE_MULTIPLY
};

// TODO: support Other LADDR values, not only 256
#define LB_LADDR_BITS   ((DPVS_MAX_LADDR_PERCORE-1)/64 + 1)

#define DEF_MIN_PORT        1025
#define DEF_MAX_PORT        65535
#define MAX_PORT            65536
#define L4_PORT_COUNT       (65536-1025)

#define POOL_BITS   (DEF_MAX_PORT - DEF_MIN_PORT + 1)

struct snat_entry {
    struct list_head        list;
    rte_be16_t        port;
};

struct snat_entry_pool {
    union inet_addr     addr;
    struct list_head    free_enties;
    uint32_t            af;
    uint32_t            used_cnt;
    uint32_t            free_cnt;
    uint32_t            total_cnt;
    int                 netif_flowid;
    struct snat_entry   entries[L4_PORT_COUNT];
};

struct snat_normal_pool {
    struct list_head        list;
    struct snat_entry_pool  pool;
};

struct snat_multiply_pool {
    uint64_t    valid_bitmap[LB_LADDR_BITS];
    union inet_addr     base_addr;
    union inet_addr     core_base_addr;
    uint32_t            af;
    uint32_t            ref_cnt;
    int                 current_pos;
    struct snat_pool    *pool;
    struct snat_entry_pool epool[DPVS_MAX_LADDR_PERCORE];
};

struct snat_pool {
    enum snat_pool_mode     mode;
    void *pool;
    struct list_head        list;
};


struct snat_multiply_pool *
lb_snat_pool_association_multiply(int af, struct netif_port *dev, union inet_addr *addr,
                                            uint8_t proto, uint32_t lcore_id);
void lb_snat_pool_deassociation_multiply(struct snat_multiply_pool *mpool, struct netif_port *dev);
int lb_snat_fetch(int af, struct snat_pool *mpool, union inet_addr *addr, rte_be16_t *port);
int lb_snat_release(int af, struct snat_pool *mpool, union inet_addr *addr, rte_be16_t port);
int lb_snat_multiply_fetch(int af, struct snat_multiply_pool *mpool, union inet_addr *addr, rte_be16_t *port);
int lb_snat_multiply_release(int af, struct snat_multiply_pool *mpool, union inet_addr *addr, rte_be16_t port);
uint16_t lb_snat_multiply_offset(int af, struct snat_multiply_pool *mpool, union inet_addr *addr);
void lb_snat_pool_init(void);
void lb_snat_pool_debug(void);


#endif
