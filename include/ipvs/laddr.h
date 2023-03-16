/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_LADDR_H__
#define __DPVS_LADDR_H__
#include "common.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"

struct dpvs_laddr_arg {
    struct dp_vs_service *svc;
    int                     af;
    union inet_addr         *addr;
    struct netif_port       *iface;
};

struct dp_vs_laddr {
    int                     af;
    struct list_head        list;       /* svc->laddr_list elem */
    union inet_addr         addr;
    rte_atomic32_t          refcnt;
    rte_atomic32_t          conn_counts;

    struct netif_port       *iface;

    uint32_t                offset; // zhutao add for mark offset.
};

int dp_vs_laddr_bind(struct dp_vs_conn *conn, struct dp_vs_service *svc);
int dp_vs_laddr_unbind(struct dp_vs_conn *conn);

int dp_vs_laddr_add(struct dp_vs_service *svc, int af, const union inet_addr *addr,
                    const char *ifname);
int dp_vs_laddr_del(struct dp_vs_service *svc, int af, const union inet_addr *addr,
                    const char *ifname);
int dp_vs_laddr_flush(struct dp_vs_service *svc);

int dp_vs_laddr_init(void);
int dp_vs_laddr_term(void);

#endif /* __DPVS_LADDR_H__ */
