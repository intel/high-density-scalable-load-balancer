/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __IGMP_H__
#define __IGMP_H__

struct netif_port;
struct in_addr;
struct rte_ether_addr;

int igmp_join_group(struct netif_port *port
    , const struct in_addr *mc_addr
    , const struct in_addr *src_addr);

int igmp_leave_group(struct netif_port* port
    , const struct in_addr* mc_addr
    , const struct in_addr* src_addr);

#endif
