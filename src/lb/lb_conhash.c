/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <assert.h>
#include <netinet/ip6.h>
#include "common.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "lb/service.h"
#include "lb/dest.h"
#include "lb/sched.h"
#include "../ipvs/libconhash/conhash.h"
#include "lb/conhash.h"

struct lb_conhash_node {
    struct list_head    list;
    uint16_t            weight;
    int                 af;         /* address family */
    union inet_addr     addr;       /* IP address of the server */
    uint16_t            port;       /* port number of the server */
    struct node_s       node;       /* node in libconhash */
};

struct lb_conhash_sched_data {
    struct list_head    nodes;      /* node list */
    struct conhash_s   *conhash;    /* consistent hash meta data */
};

#define REPLICA 160
#define QUIC_PACKET_8BYTE_CONNECTION_ID  (1 << 3)

/*
 * QUIC CID hash target for quic*
 * QUIC CID(qid) should be configured in UDP service
 */

int lb_conhash_del_dest(struct lb_service *svc, struct lb_dest *dest);
int lb_conhash_edit_dest(struct lb_service *svc, struct lb_dest *dest);


static int lb_get_quic_hash_target(int af, const struct rte_mbuf *mbuf,
                                uint64_t *quic_cid)
{
    uint8_t pub_flags;
    uint32_t udphoff;
    char *quic_data;
    uint32_t quic_len;

    if (af == AF_INET6) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        uint8_t ip6nxt = ip6h->ip6_nxt;
        udphoff = ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);
    }
    else
        udphoff = ip4_hdrlen(mbuf);

    quic_len = udphoff + sizeof(struct rte_udp_hdr) +
               sizeof(pub_flags) + sizeof(*quic_cid);

    if (mbuf_may_pull((struct rte_mbuf *)mbuf, quic_len) != 0)
        return EDPVS_NOTEXIST;

    quic_data = rte_pktmbuf_mtod_offset(mbuf, char *,
                                        udphoff + sizeof(struct rte_udp_hdr));
    pub_flags = *((uint8_t *)quic_data);

    if ((pub_flags & QUIC_PACKET_8BYTE_CONNECTION_ID) == 0) {
        RTE_LOG(WARNING, IPVS, "packet without cid, pub_flag:%u\n", pub_flags);
        return EDPVS_NOTEXIST;
    }

    quic_data += sizeof(pub_flags);
    *quic_cid = *((uint64_t*)quic_data);

    return EDPVS_OK;
}

/*source ip hash target*/
static int lb_get_sip_hash_target(int af, const struct rte_mbuf *mbuf,
                               uint32_t *addr_fold)
{
    if (af == AF_INET) {
        *addr_fold = ip4_hdr(mbuf)->src_addr;
    } else if (af == AF_INET6) {
        struct in6_addr *saddr = &ip6_hdr(mbuf)->ip6_src;
        *addr_fold = saddr->s6_addr32[0]^saddr->s6_addr32[1]^
                     saddr->s6_addr32[2]^saddr->s6_addr32[3];
    } else {
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static inline struct lb_dest *
lb_conhash_get(struct lb_service *svc, struct conhash_s *conhash,
                  const struct rte_mbuf *mbuf)
{
    char str[40] = {0};
    uint64_t quic_cid;
    uint32_t addr_fold;
    const struct node_s *node;

    if (svc->flags & DP_VS_SVC_F_QID_HASH) {
        if (svc->proto != IPPROTO_UDP) {
            RTE_LOG(ERR, IPVS, "QUIC cid hash scheduler should only be set in UDP service.\n");
            return NULL;
        }
        /* try to get CID for hash target first, then source IP. */
        if (EDPVS_OK == lb_get_quic_hash_target(svc->af, mbuf, &quic_cid)) {
            snprintf(str, sizeof(str), "%lu", quic_cid);
        } else if (EDPVS_OK == lb_get_sip_hash_target(svc->af, mbuf, &addr_fold)) {
            snprintf(str, sizeof(str), "%u", addr_fold);
        } else {
            return NULL;
        }
    } else if (svc->flags & DP_VS_SVC_F_SIP_HASH) {
        if (EDPVS_OK == lb_get_sip_hash_target(svc->af, mbuf, &addr_fold)) {
            snprintf(str, sizeof(str), "%u", addr_fold);
        } else {
            return NULL;
        }
    } else {
        RTE_LOG(ERR, IPVS, "%s: invalid hash target.\n", __func__);
        return NULL;
    }

    node = conhash_lookup(conhash, str);
    return node == NULL? NULL: node->data;
}

static void lb_node_fini(struct node_s *node)
{
    struct lb_conhash_node *p_conhash_node = NULL;

    if (!node)
        return;

    if (node->data) {
        node->data = NULL;
    }

    p_conhash_node = container_of(node, struct lb_conhash_node, node);
    list_del(&(p_conhash_node->list));
    rte_free(p_conhash_node);
}

static int lb_conhash_add_dest(struct lb_service *svc,
        struct lb_dest *dest)
{
    int ret;
    char str[40];
    uint32_t addr_fold;
    int16_t weight = 0;
    struct node_s *p_node;
    struct lb_conhash_node *p_conhash_node;
    struct lb_conhash_sched_data *p_sched_data;

    p_sched_data = (struct lb_conhash_sched_data *)(svc->sched_data);

    weight = dest->weight;
    if (weight < 0) {
        RTE_LOG(ERR, IPVS, "%s: add dest with weight(%d) less than 0\n",
                __func__, weight);
        return EDPVS_INVAL;
    }

    p_conhash_node = rte_zmalloc(NULL, sizeof(struct lb_conhash_node),
            RTE_CACHE_LINE_SIZE);
    if (!p_conhash_node) {
        RTE_LOG(ERR, IPVS, "%s: alloc conhash node failed\n", __func__);
        return EDPVS_NOMEM;
    }

    INIT_LIST_HEAD(&(p_conhash_node->list));
    p_conhash_node->af = dest->af;
    p_conhash_node->addr = dest->addr;
    p_conhash_node->port = dest->port;
    p_conhash_node->weight = weight;

    // add node to conhash
    p_node = &(p_conhash_node->node);
    addr_fold = inet_addr_fold(dest->af, &dest->addr);
    snprintf(str, sizeof(str), "%u%d", addr_fold, dest->port);

    conhash_set_node(p_node, str, weight * REPLICA);
    ret = conhash_add_node(p_sched_data->conhash, p_node);
    if (ret < 0) {
        RTE_LOG(ERR, IPVS, "%s: conhash_add_node failed\n", __func__);
        rte_free(p_conhash_node);
        return EDPVS_INVAL;
    }

    // set node data
    p_node->data = dest;

    // add conhash node to list
    list_add(&(p_conhash_node->list), &(p_sched_data->nodes));

    return EDPVS_OK;
}

int lb_conhash_del_dest(struct lb_service *svc,
        struct lb_dest *dest)
{
    int ret;
    struct node_s *p_node;
    struct lb_conhash_node *p_conhash_node;
    struct lb_conhash_sched_data *p_sched_data;

    p_sched_data = (struct lb_conhash_sched_data *)(svc->sched_data);

    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        if (p_conhash_node->af == dest->af &&
                inet_addr_equal(dest->af, &p_conhash_node->addr, &dest->addr) &&
                p_conhash_node->port == dest->port) {
            p_node = &(p_conhash_node->node);
            ret = conhash_del_node(p_sched_data->conhash, p_node);
            if (ret < 0) {
                RTE_LOG(ERR, IPVS, "%s: conhash_del_node failed\n", __func__);
                return EDPVS_INVAL;
            }
            lb_node_fini(p_node);
            return EDPVS_OK;
        }
    }

    return EDPVS_NOTEXIST;
}

 int lb_conhash_edit_dest(struct lb_service *svc,
        struct lb_dest *dest)
{
    int ret;
    char str[40];
    uint32_t addr_fold;
    int16_t weight;
    struct node_s *p_node;
    struct lb_conhash_node *p_conhash_node;
    struct lb_conhash_sched_data *p_sched_data;

    weight = dest->weight;
    p_sched_data = (struct lb_conhash_sched_data *)(svc->sched_data);

    // find node by addr and port
    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        if (p_conhash_node->af == dest->af &&
                inet_addr_equal(dest->af, &p_conhash_node->addr, &dest->addr) &&
                p_conhash_node->port == dest->port) {
            if (p_conhash_node->weight == weight)
                return EDPVS_OK;

            // del from conhash
            p_node = &(p_conhash_node->node);
            ret = conhash_del_node(p_sched_data->conhash, p_node);
            if (ret < 0) {
                RTE_LOG(ERR, IPVS, "%s: conhash_del_node failed\n", __func__);
                return EDPVS_INVAL;
            }

            // adjust weight
            p_conhash_node->weight = weight;
            addr_fold = inet_addr_fold(dest->af, &dest->addr);
            snprintf(str, sizeof(str), "%u%d", addr_fold, dest->port);
            conhash_set_node(p_node, str, weight * REPLICA);

            // add to conhash again
            ret = conhash_add_node(p_sched_data->conhash, p_node);
            if (ret < 0) {
                RTE_LOG(ERR, IPVS, "%s: conhash_set_node failed\n", __func__);
                return EDPVS_INVAL;
            }

            return EDPVS_OK;
        }
    }

    return EDPVS_NOTEXIST;
}

/*
 *      Assign dest to connhash.
 */
static int
dp_vs_conhash_assign(struct lb_service *svc)
{
    int err;
    struct lb_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list) {
        err = lb_conhash_add_dest(svc, dest);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, IPVS, "%s: add dest to conhash failed\n", __func__);
            return err;
        }
    }

    return EDPVS_OK;
}

static int lb_conhash_init_svc(struct lb_service *svc)
{
    struct lb_conhash_sched_data *sched_data = NULL;

    svc->sched_data = NULL;

    // alloc schedule data
    sched_data = rte_zmalloc(NULL, sizeof(struct lb_conhash_sched_data),
            RTE_CACHE_LINE_SIZE);
    if (!sched_data) {
        RTE_LOG(ERR, IPVS, "%s: alloc schedule data faild\n", __func__);
        return EDPVS_NOMEM;
    }

    // init conhash
    sched_data->conhash = conhash_init(NULL);
    if (!sched_data->conhash) {
        RTE_LOG(ERR, IPVS, "%s: conhash init faild!\n", __func__);
        rte_free(sched_data);
        return EDPVS_NOMEM;
    }

    // init node list
    INIT_LIST_HEAD(&(sched_data->nodes));

    // assign node
    svc->sched_data = sched_data;
    return dp_vs_conhash_assign(svc);
}

static int lb_conhash_done_svc(struct lb_service *svc)
{
    struct lb_conhash_sched_data *sched_data =
        (struct lb_conhash_sched_data *)(svc->sched_data);
    struct lb_conhash_node *p_conhash_node, *p_conhash_node_next;

    conhash_fini(sched_data->conhash, lb_node_fini);

    // del nodes left in list when rs weight is 0
    list_for_each_entry_safe(p_conhash_node, p_conhash_node_next,
                             &(sched_data->nodes), list) {
       lb_node_fini(&(p_conhash_node->node));
    }

    rte_free(svc->sched_data);
    svc->sched_data = NULL;

    return EDPVS_OK;
}

static int lb_conhash_update_svc(struct lb_service *svc,
        struct lb_dest *dest)
{
    int ret;

    ret = lb_conhash_add_dest(svc, dest);
    if (ret != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: update service faild!\n", __func__);

    return ret;
}

/*
 *      Consistent Hashing scheduling
 */
static struct lb_dest *
lb_conhash_schedule(struct lb_service *svc, const struct rte_mbuf *mbuf)
{
    struct lb_dest *dest;
    struct lb_conhash_sched_data *sched_data =
        (struct lb_conhash_sched_data *)(svc->sched_data);

    dest = lb_conhash_get(svc, sched_data->conhash, mbuf);

    return dest;
}

static void lb_conhash_schedule_next(struct lb_service *lbs,
                                            const struct rte_mbuf *mbuf)
{
    return;
}

/*
 *      IPVS CONHASH Scheduler structure
 */
static struct lb_scheduler lb_conhash_scheduler =
{
    .name = "conhash",
    .type = LB_SCHED_CONHASH,
    .n_list =         LIST_HEAD_INIT(lb_conhash_scheduler.n_list),
    .init_service =   lb_conhash_init_svc,
    .exit_service =   lb_conhash_done_svc,
    .update_service = lb_conhash_update_svc,
    .schedule_prefetch = lb_conhash_schedule,
    .schedule_next = lb_conhash_schedule_next,
};

int lb_conhash_init(void)
{
    return register_lb_scheduler(&lb_conhash_scheduler);
}

int lb_conhash_term(void)
{
    return unregister_lb_scheduler(&lb_conhash_scheduler);
}
