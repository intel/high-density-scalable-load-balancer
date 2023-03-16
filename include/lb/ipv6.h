/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_IPV6_H__
#define __LB_IPV6_H__

void lb_flow_ipv6_in(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);
void lb_flow_nat_icmp6_ipv6_in(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);
void lb_flow_ipv6_out(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);
void lb_flow_nat_ipv6_out(struct rte_mbuf *mbuf, struct lb_service *lbs, uint8_t markid);
void ipv6_conn_expire_sync_conn(struct lb_conn* conn);

#endif
