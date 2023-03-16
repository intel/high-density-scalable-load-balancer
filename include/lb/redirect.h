/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_REDIRECT_H__
#define __LB_REDIRECT_H__

#include "common.h"
#include "core.h"
#include "list.h"
#include "dpdk.h"
#include "netif.h"

int lb_redirect_pkt(struct rte_mbuf *mbuf, lcoreid_t peer_cid);
void lb_redirect_ring_proc(struct netif_queue_conf *qconf, lcoreid_t cid);
int lb_redirect_init(void);
void lb_redirect_term(void);

#endif
