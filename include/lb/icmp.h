/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_ICMP_H__
#define __LB_ICMP_H__

#include "common.h"
#include "lb/dest.h"
#include "lb/conn.h"
#include "dpdk.h"

int get_ipv4_icmp_addr_port(struct rte_mbuf *mbuf, int iphdrlen, union inet_addr *saddr,
                                            union inet_addr *daddr, uint16_t *sport, uint16_t *dport, int *icmp_pkt_type);
int get_ipv6_icmp6_addr_port(struct rte_mbuf *mbuf, int iphdrlen, union inet_addr *saddr,
                                            union inet_addr *daddr, uint16_t *sport, uint16_t *dport, int *icmp_pkt_type);
int lb_ipv4_icmp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_icmp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_icmp6_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_icmp6_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
void icmp6_calculate_csum(struct rte_mbuf *mbuf);

#endif
