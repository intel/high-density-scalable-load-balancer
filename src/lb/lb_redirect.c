/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include "lb/redirect.h"
#include "lb/redirect_conn_hash_table.h"

#define LB_REDIRECT_RING_SIZE  4096

extern bool dp_vs_redirect_disable;
static struct rte_ring *lb_vs_redirect_ring[DPVS_MAX_LCORE][DPVS_MAX_LCORE];


int lb_redirect_pkt(struct rte_mbuf *mbuf, lcoreid_t peer_cid)
{
    lcoreid_t cid = rte_lcore_id();
    int ret;

    ret = rte_ring_enqueue(lb_vs_redirect_ring[peer_cid][cid], mbuf);
    if (ret < 0) {
        RTE_LOG(ERR, LB_RUNNING,
                "%s: [%d] failed to enqueue mbuf to redirect_ring[%d][%d]\n",
                __func__, cid, peer_cid, cid);
        return EDPVS_DROP;
    }

    return EDPVS_OK;
}

void lb_redirect_ring_proc(struct netif_queue_conf *qconf, lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    lcoreid_t peer_cid;
    uint32_t processed = 0;

    if (dp_vs_redirect_disable) {
        return;
    }

    cid = rte_lcore_id();

    for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
        if (lb_vs_redirect_ring[cid][peer_cid]) {
            nb_rb = rte_ring_dequeue_burst(lb_vs_redirect_ring[cid][peer_cid],
                                           (void**)mbufs,
                                           NETIF_MAX_PKT_BURST, NULL);
            if (nb_rb > 0) {
                lcore_process_redirect_marked_flow(mbufs, cid, nb_rb);
                processed += nb_rb;
            }
        }
    }
    
    if (processed) {
        insert_empty_pkt();
    }
}

#ifdef CONFIG_LB_REDIRECT
static int lb_redirect_ring_create(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    lcoreid_t cid, peer_cid;

    socket_id = rte_socket_id();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid == rte_get_master_lcore() || netif_lcore_is_idle(cid)) {
            continue;
        }

        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            if (netif_lcore_is_idle(peer_cid)
                || peer_cid == rte_get_master_lcore()
                || cid == peer_cid) {
                continue;
            }

            snprintf(name_buf, RTE_RING_NAMESIZE,
                     "lb_vs_redirect_ring[%d[%d]", cid, peer_cid);

            lb_vs_redirect_ring[cid][peer_cid] =
                rte_ring_create(name_buf, LB_REDIRECT_RING_SIZE, socket_id,
                                RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (!lb_vs_redirect_ring[cid][peer_cid]) {
                RTE_LOG(ERR, LB_RUNNING,
                        "%s: failed to create redirect_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
                return EDPVS_NOMEM;
            }
        }
    }

    return EDPVS_OK;
}
#endif

static void lb_redirect_ring_free(void)
{
    lcoreid_t cid, peer_cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            rte_ring_free(lb_vs_redirect_ring[cid][peer_cid]);
        }
    }
}

int lb_redirect_init(void)
{
    int err = EDPVS_OK;

#ifdef CONFIG_LB_REDIRECT
    if (dp_vs_redirect_disable) {
        return EDPVS_OK;
    }

    err = lb_redirect_ring_create();
    if (err != EDPVS_OK) {
        return err;
    }
    
    err = lb_redirect_conn_hash_table_init();
    if (err != EDPVS_OK) {
        return err;
    }
#endif

    return err;
}

void lb_redirect_term(void)
{
    if (dp_vs_redirect_disable) {
        return;
    }

    lb_redirect_ring_free();
}
