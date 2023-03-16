/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_XMIT_H__
#define __LB_XMIT_H__

#include "dpdk.h"
#include "lb/conn.h"
#include "lb/dest.h"

void lb_xmit_inbound(struct lb_conn *conn, struct rte_mbuf *mbuf);
void lb_xmit_outbound(struct lb_conn *conn, struct rte_mbuf *mbuf);
void lb_dest_tunnel_xmit4(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_tunnel_xmit6(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_tunnel_xmit6o4(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_dr_xmit4(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_dr_xmit6(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit4_in(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit4_out(void *outconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit6_in(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit6_out(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit64_in(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_fnat_xmit46_out(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_nat_xmit4_in(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_nat_xmit4_out(void *outconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_nat_xmit6_in(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);
void lb_dest_nat_xmit6_out(void *inconn, struct rte_mbuf *mbuf, struct lb_dest *dest);

#endif
