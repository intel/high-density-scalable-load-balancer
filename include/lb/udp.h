/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_UDP_H__
#define __LB_UDP_H__

#include "dpdk.h"
#include "lb/dest.h"
#include "lb/conn.h"

void get_udp_port(void *trans_head, uint16_t *sport, uint16_t *dport);
void lb_set_udp_timeout(int timeout);
void lb_set_udp_uoa_mode(int uoa_mode);
void lb_set_udp_uoa_max_trail(int uoa_max_trail);
int lb_udp_state_trans(struct lb_conn *conn, struct rte_mbuf *mbuf, int iphdrlen, int dir);
int lb_ipv4_udp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_udp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_udp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_udp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_udp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_udp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_udp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_udp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);

#endif
