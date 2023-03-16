/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include "list.h"
#include "dpdk.h"
#include "inet.h"
#include "netif.h"
#include "route.h"
#include "route6.h"
#include "ctrl.h"
#include "lb/core.h"
#include "lb/snat_pool.h"
#include "lb/laddr.h"
#include "lb/conn.h"
#include "ipvs/service.h"
#include "linux_ipv6.h"
#include "parser/parser.h"
#include "parser/vector.h"
#include "laddr_multiply.h"

#define this_snat_pool_head            (RTE_PER_LCORE(lb_snat_pool_head))
static RTE_DEFINE_PER_LCORE(struct list_head, lb_snat_pool_head);

static int
snat_multiply_addr_set_bit(struct snat_multiply_pool *mpool, uint32_t position)
{
    uint32_t offset64 = position / 64;
    uint32_t offset = position % 64;

    mpool->valid_bitmap[offset64] |= 0x1UL << offset;

    return EDPVS_OK;
}

static int
snat_multiply_addr_clear_bit(struct snat_multiply_pool *mpool, uint32_t position)
{
    uint32_t offset64 = position / 64;
    uint32_t offset = position % 64;

    mpool->valid_bitmap[offset64] &= ~(0x1UL << offset);

    return EDPVS_OK;
}

static int
snat_multiply_addr_find_valid_position(struct snat_multiply_pool *mpool)
{
#if (LB_LADDR_BITS == 4)
    const __m256i bitmap256 = _mm256_set_epi64x(mpool->valid_bitmap[3], mpool->valid_bitmap[2], mpool->valid_bitmap[1], mpool->valid_bitmap[0]);
#endif
#if (LB_LADDR_BITS == 2)
    const __m256i bitmap256 = _mm256_set_epi64x(0, 0, mpool->valid_bitmap[1], mpool->valid_bitmap[0]);
#endif
#if (LB_LADDR_BITS == 1)
    const __m256i bitmap256 = _mm256_set_epi64x(0, 0, 0, mpool->valid_bitmap[0]);
#endif
    const __m256i mask256 = _mm256_setzero_si256();
    __mmask8 valid_mask = _mm256_cmpeq_epi64_mask(bitmap256, mask256);
    uint32_t offset64;
    uint32_t offset;

    valid_mask = ~valid_mask;
    valid_mask &= 0xF;

    if (valid_mask == 0) {
        RTE_LOG(ERR, LB_RUNNING, "SNAT no valid resource on core %d\n", rte_lcore_id());
        return EDPVS_NOROOM;
    }

    offset64 = rte_bsf32(valid_mask);
    offset = rte_bsf64(mpool->valid_bitmap[offset64]);
    //printf("offset64: %d, offset: %d, pos: %x on core %d\n", offset64, offset, offset + (offset64 << 6), rte_lcore_id());

    return offset + (offset64 << 6);
}

int
lb_snat_multiply_fetch(int af, struct snat_multiply_pool *mpool, union inet_addr *addr, rte_be16_t *port)
{
    struct snat_entry   *entry;
    struct snat_entry_pool *entry_pool;
    uint32_t pos;

    if (unlikely(!mpool))
        return EDPVS_INVAL;

    pos = mpool->current_pos;

    if (unlikely(pos <0 || pos >= DPVS_MAX_LADDR_PERCORE)) {
        mpool->current_pos = snat_multiply_addr_find_valid_position(mpool);
        if (mpool->current_pos < 0)
            return EDPVS_NOROOM;

        pos = mpool->current_pos;
    }

    entry_pool = &mpool->epool[pos];
    entry = list_first_entry_or_null(&entry_pool->free_enties, struct snat_entry, list);
    if (unlikely(!entry))
        return EDPVS_NOTEXIST;

    if (af == AF_INET)
        addr->in.s_addr = entry_pool->addr.in.s_addr;
    else
        rte_memcpy(addr, &entry_pool->addr, sizeof(*addr));
    *port = entry->port;

    list_del_init(&entry->list);
    entry_pool->free_cnt--;
    entry_pool->used_cnt++;
    //printf("Fetch addr 0x%x pos %d, port %d on core %d\n", rte_be_to_cpu_32(addr->in.s_addr),
                //pos, rte_be_to_cpu_16(*port), rte_lcore_id());

    if (unlikely(entry_pool->total_cnt == entry_pool->used_cnt)) {
        snat_multiply_addr_clear_bit( mpool, pos);
        mpool->current_pos = snat_multiply_addr_find_valid_position(mpool);
    }

    return EDPVS_OK;
}

uint16_t lb_snat_multiply_offset(int af, struct snat_multiply_pool *mpool, union inet_addr *addr)
{
    return laddr_multiply_offset(af, addr, &mpool->core_base_addr);
}

int
lb_snat_multiply_release(int af, struct snat_multiply_pool *mpool, union inet_addr *addr, rte_be16_t port)
{
    uint16_t addr_pos, port_pos;
    struct snat_entry_pool *entry_pool;
    struct snat_entry *entry;

    if (!mpool)
        return EDPVS_OK;

    addr_pos = laddr_multiply_offset(af, addr, &mpool->core_base_addr);
    if (unlikely((addr_pos < 0) || (addr_pos >= DPVS_MAX_LADDR_PERCORE))) {
        //printf("[%s,%d] invalid addr pos %d\n", __func__, __LINE__, addr_pos);
        return -EDPVS_INVAL;
    }

    entry_pool = &mpool->epool[addr_pos];

    port_pos = rte_be_to_cpu_16(port) - DEF_MIN_PORT;
    if (unlikely(port_pos >= (MAX_PORT-DEF_MIN_PORT))) {
        //printf("[%s,%d] invalid port pos %d\n", __func__, __LINE__, port_pos);
        return -EDPVS_INVAL;
    }

    entry = &entry_pool->entries[port_pos];
    list_add_tail(&entry->list, &entry_pool->free_enties);
    //printf("Release port %d, pos [%d: %d] on core %d, addr 0x%x pos %d\n", rte_be_to_cpu_16(port), 
                //port_pos, rte_be_to_cpu_16(entry->port),
                //rte_lcore_id(), rte_be_to_cpu_32(entry_pool->addr.in.s_addr), addr_pos);

    entry_pool->free_cnt++;
    entry_pool->used_cnt--;

    if (unlikely(entry_pool->total_cnt == (entry_pool->used_cnt+1))) {
        snat_multiply_addr_set_bit(mpool, addr_pos);
    }

    return EDPVS_OK;
}

int lb_snat_fetch(int af, struct snat_pool *pool, union inet_addr *addr, rte_be16_t *port)
{
    if (likely(pool->mode == LB_SNAT_POOL_MODE_MULTIPLY)) {
        return lb_snat_multiply_fetch(af, pool->pool, addr, port);
    }

    return EDPVS_OK;
}

int lb_snat_release(int af, struct snat_pool *pool, union inet_addr *addr, rte_be16_t port)
{
    if (pool->mode == LB_SNAT_POOL_MODE_MULTIPLY) {
        return lb_snat_multiply_release(af, pool->pool, addr, port);
    }

    return EDPVS_OK;
}

static int snat_add_netif_flow(int af, struct netif_port *dev, lcoreid_t cid,
                                    uint8_t proto, uint8_t markid, const union inet_addr *dip, queueid_t qid)
{
    struct rte_flow_attr attr;
    struct rte_flow_item patterns[4];
    struct rte_flow_item_ipv4 ipv4, ipv4_mask;
    struct rte_flow_item_ipv6 ipv6, ipv6_mask;
    struct rte_flow_action actions[3];
    struct rte_flow_action_queue queue;
    struct rte_flow_action_mark mark;

    /* Fill attr */
    memset(&attr, 0, sizeof(attr));
    attr.ingress = 1;

    /* Fill patterns */
    memset(&patterns, 0, sizeof(patterns));
    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    if (af == AF_INET) {
        memset(&ipv4, 0, sizeof(ipv4));
        memset(&ipv4_mask, 0, sizeof(ipv4_mask));
        ipv4.hdr.dst_addr = dip->in.s_addr ;
        ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        patterns[1].spec = &ipv4;
        patterns[1].mask = &ipv4_mask;
    } else if (af == AF_INET6) {
        memset(&ipv6, 0, sizeof(ipv6));
        memset(&ipv6_mask, 0, sizeof(ipv6_mask));
        memcpy(ipv6.hdr.dst_addr, (void*)(&dip->in6), sizeof(struct in6_addr));
        memset(ipv6_mask.hdr.dst_addr, 0xff, sizeof(struct in6_addr));
        patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
        patterns[1].spec = &ipv6;
        patterns[1].mask = &ipv6_mask;
    }
    if (proto == IPPROTO_TCP)
        patterns[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    else if (proto == IPPROTO_UDP)
        patterns[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    patterns[3].type = RTE_FLOW_ITEM_TYPE_END;

    /* Fill action */
    memset(&actions, 0, sizeof(actions));
    memset(&queue, 0, sizeof(queue));
    queue.index = qid;
    actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[0].conf = &queue;
    
    memset(&mark, 0, sizeof(mark));
    mark.id = markid;
    actions[1].type = RTE_FLOW_ACTION_TYPE_MARK;
    actions[1].conf = &mark;
    actions[2].type = RTE_FLOW_ACTION_TYPE_END;

    return netif_flow_create(dev, &attr, patterns, actions);
}

static int snat_add_netif_flow_multiply(struct snat_multiply_pool *mpool, int af, struct netif_port *dev,
                                    lcoreid_t cid, uint8_t proto, uint8_t markid)
{
    queueid_t qid;
    int err, i, ii;
    struct snat_entry_pool *epool;
    char addr_str[64];

    err = netif_get_queue(dev, cid, &qid);
    if (err != EDPVS_OK)
        return err;

    for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
        epool = &mpool->epool[i];
        inet_ntop(af, &epool->addr, addr_str, sizeof(addr_str));
        epool->netif_flowid = snat_add_netif_flow(af, dev, cid, proto, markid, &epool->addr, qid);
        if (epool->netif_flowid < 0)
            goto fail;
    }

    RTE_LOG(INFO, LB_RUNNING, "%s add flow rule on core%d success\n", __func__, cid);

    return EDPVS_OK;
fail:
    RTE_LOG(ERR, LB_RUNNING, "%s add flow rule dip %s failed\n", __func__, addr_str);
    for (ii=0; ii<i; ii++) {
        epool = &mpool->epool[ii];
        netif_flow_destroy(dev, epool->netif_flowid);
    }

    return EDPVS_IO;
}

static int snat_pool_lcore_multiply_one_fill_laddr(lcoreid_t cid,
                              int af, union inet_addr *laddr, void *arg, int index)
{
    struct snat_multiply_pool *mpool = arg;
    struct snat_entry_pool *epool = &mpool->epool[index];

    if (index >= DPVS_MAX_LADDR_PERCORE)
        return EDPVS_INVAL;

    if (cid != rte_lcore_id())
        return EDPVS_OK;

    if (0 == index)
        rte_memcpy(&mpool->core_base_addr, laddr, sizeof(*laddr));

    rte_memcpy(&epool->addr, laddr, sizeof(*laddr));
    return EDPVS_OK;
}


static struct snat_multiply_pool *
snat_pool_create_multiply(int af, struct netif_port *dev, union inet_addr *addr,
                                            uint8_t proto, uint32_t lcore_id)
{
    struct snat_pool *pool;
    struct snat_multiply_pool *mpool;
    struct snat_entry_pool  *epool;
    struct snat_entry *entry;
    struct dp_vs_flowid markid;
    int i, j;
    int index = 0;
    uint32_t pool_size = sizeof(*pool) + sizeof(*mpool);

    mpool = rte_zmalloc_socket(NULL, pool_size, RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!mpool) {
        RTE_LOG(ERR, LB_RUNNING, "Malloc %dMB memory failed on socket %d, core %d\n", pool_size >> 20, rte_socket_id(), lcore_id);
        return NULL;
    }

    for (i=0; i<LB_LADDR_BITS; i++)
        mpool->valid_bitmap[i] = 0xFFFFFFFFFFFFFFFF;
    mpool->ref_cnt = 1;
    mpool->af = af;
    mpool->current_pos = 0;
    pool = (void*)(mpool + 1);
    mpool->pool = pool;

    memcpy(&mpool->base_addr, addr, sizeof(*addr));
    for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
        epool = &mpool->epool[i];

        epool->af = af;
        epool->total_cnt = L4_PORT_COUNT;
        epool->free_cnt = L4_PORT_COUNT;
        epool->used_cnt = 0;

        INIT_LIST_HEAD(&epool->free_enties);
        for (j=0; j<L4_PORT_COUNT; j++) {
            entry = &epool->entries[j];

            INIT_LIST_HEAD(&entry->list);
            entry->port = rte_cpu_to_be_16(j + DEF_MIN_PORT);
            list_add_tail(&entry->list, &epool->free_enties);
        }
    }
    if (EDPVS_OK != laddr_multiply_process(af, addr, snat_pool_lcore_multiply_one_fill_laddr, NULL, mpool)) {
        RTE_LOG(ERR, LB_RUNNING, "SNAT laddr_multiply_process fail, cid: %d\n", lcore_id);
        return NULL;
    }

    index = lb_alloc_fnat_conn_hash_cache_out(&mpool->base_addr, mpool);
    if (-1 == index) {
        RTE_LOG(ERR, LB_RUNNING, "SNAT lb_alloc_fnat_conn_hash_cache_out fail, cid: %d\n", lcore_id);
        return NULL;
    }

    markid.id = (uint8_t)index;
    markid.dir = DP_VS_FLOW_DIR_SNAT_OUT;

    if (snat_add_netif_flow_multiply(mpool, af, dev, lcore_id, proto, markid.value)) {
        RTE_LOG(ERR, LB_RUNNING, "SNAT add netif rule on dev %d fail, cid: %d\n", dev->id, lcore_id);
        rte_free(mpool);
        return NULL;
    }

    pool->mode = LB_SNAT_POOL_MODE_MULTIPLY;
    pool->pool = mpool;
    list_add_tail(&pool->list, &this_snat_pool_head);

    return mpool;
}

static int 
snat_pool_destroy_multiply(struct snat_multiply_pool *mpool, struct netif_port *dev)
{
    struct snat_entry_pool  *epool;
    struct snat_pool *pool = mpool->pool;
    int i;

    for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
        epool = &mpool->epool[i];
        netif_flow_destroy(dev, epool->netif_flowid);
    }

    list_del(&pool->list);
    rte_free(mpool);
    RTE_LOG(NOTICE, LB_RUNNING, "destroy SNAT addr pool on core: %d\n", rte_lcore_id());
    return EDPVS_OK;
}

struct snat_multiply_pool *
lb_snat_pool_association_multiply(int af, struct netif_port *dev, union inet_addr *addr,
                                            uint8_t proto, uint32_t lcore_id)
{
    struct snat_pool *pool;
    struct snat_multiply_pool *mpool;
    
    list_for_each_entry(pool, &this_snat_pool_head, list) {
        if (pool->mode == LB_SNAT_POOL_MODE_SINGLE)
            continue;

        mpool = pool->pool;
        if (!memcmp(addr, &mpool->base_addr, sizeof(*addr))) {
            RTE_LOG(INFO, LB_RUNNING, "SNAT addr pool exist on core: %d\n", lcore_id);
            mpool->ref_cnt++;
            return mpool;
        }
    }

    return snat_pool_create_multiply(af, dev, addr, proto, lcore_id);
}

void lb_snat_pool_deassociation_multiply(struct snat_multiply_pool *mpool, struct netif_port *dev)
{
    if (!mpool)
        return;

    mpool->ref_cnt--;
    if (!mpool->ref_cnt) {
        snat_pool_destroy_multiply(mpool, dev);
    }
}

void lb_snat_pool_debug(void)
{
    struct snat_pool *pool;
    struct snat_multiply_pool *mpool;
    struct snat_entry_pool  *epool;
    struct snat_entry *entry;
    uint32_t total_frees, frees, i, total;

    list_for_each_entry(pool, &this_snat_pool_head, list) {
        if (pool->mode == LB_SNAT_POOL_MODE_SINGLE)
            continue;

        mpool = pool->pool;
        if (mpool->af == AF_INET) {
            printf("Show multiply pool addr 0x%x, ref_cnt %d, current pos %d on core %d\n", mpool->base_addr.in.s_addr, 
                            mpool->ref_cnt, mpool->current_pos, rte_lcore_id());

            total = 0;
            total_frees = 0;
            for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
                frees = 0;
                epool = &mpool->epool[i];
                list_for_each_entry(entry, &epool->free_enties, list) {
                    frees++;
                }

                if (frees != epool->free_cnt) {
                    printf("%d free list count %d != free_cnt %d\n", i, frees, epool->free_cnt);
                }
                total_frees += frees;
                total += epool->total_cnt;
            }
            printf("Total free list count %d, total %d\n", total_frees, total);
        }
    }

    return;
}

static int snat_init_lcore(void *arg)
{
    INIT_LIST_HEAD(&this_snat_pool_head);

    return EDPVS_OK;
}

void lb_snat_pool_init(void)
{
    lcoreid_t lcore;
    int err;

    rte_eal_mp_remote_launch(snat_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, LB_INIT, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }
}

