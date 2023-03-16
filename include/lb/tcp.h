/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_TCP_H__
#define __LB_TCP_H__

#include "dpdk.h"
#include "lb/conn.h"

void get_tcp_port(void *trans_head, uint16_t *sport, uint16_t *dport);
void lb_set_tcp_timeouts(int *tcp_timeouts);
int lb_ipv4_tcp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_tcp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_tcp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_tcp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_tcp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv4_tcp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_tcp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_ipv6_tcp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf);
int lb_tcp_state_trans(struct lb_conn *conn, struct rte_mbuf *mbuf, int iphdrlen, int dir);
int lb_tcp_conn_expire(struct lb_conn *conn);

#endif
