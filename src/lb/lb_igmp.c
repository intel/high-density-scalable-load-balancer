/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <netinet/in.h>
#include <sys/types.h>
#include <linux/igmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "rte_ip.h"
#include "rte_ether.h"
#include "rte_mbuf.h"
#include "lb/igmp.h"
#include "lb/ip.h"
#include "netif.h"
#include "inetaddr.h"
#include "ipv4.h"
#include "inet.h"

/* igmp packet headers total length */
static const int igmp_pkthdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                   4 + sizeof(struct igmphdr);

static int igmp_send_report(struct netif_port *port
                     , const struct in_addr *mc_addr
                     , const struct in_addr *src_addr
                     , int type)
{
    int err = 0;
    struct rte_mbuf *mbuf;
    unsigned int offset;
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    uint8_t *ipopt;
    struct igmphdr *igmph;

    if (NULL == port || NULL == mc_addr || NULL == src_addr) {
        return -1;
    }

    mbuf = rte_pktmbuf_alloc(port->mbuf_pool);
    if (unlikely(NULL == mbuf)) {
        err = -1;
        goto errout;
    }

    ethh = (struct rte_ether_hdr *)rte_pktmbuf_append(mbuf, igmp_pkthdr_len);
    if (unlikely(NULL == ethh)) {
        err = -1;
        goto errout;
    }
    offset = sizeof(struct rte_ether_hdr);
    iph    = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, offset);
    offset = offset + sizeof(struct rte_ipv4_hdr);
    ipopt  = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, offset);
    offset = offset + 4;
    igmph  = rte_pktmbuf_mtod_offset(mbuf, struct igmphdr *, offset);

    ethh->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&port->addr, &ethh->s_addr);
    if (IGMP_HOST_LEAVE_MESSAGE == type) {
        ip_eth_mc_map(IGMP_ALL_ROUTER, ethh->d_addr.addr_bytes);
    } else {
        ip_eth_mc_map(mc_addr->s_addr, ethh->d_addr.addr_bytes);
    }

    iph->version_ihl     = (4 << 4 | (sizeof(struct rte_ipv4_hdr) + 4) >> 2);
    iph->type_of_service = 0xc0;
    iph->fragment_offset = htons(IP_DF);
    iph->time_to_live    = 1;
    if (IGMP_HOST_LEAVE_MESSAGE == type) {
        iph->dst_addr = IGMP_ALL_ROUTER;
    } else {
        iph->dst_addr = mc_addr->s_addr;
    }

    iph->src_addr        = src_addr->s_addr;
    iph->next_proto_id   = IPPROTO_IGMP;
    iph->packet_id       = ip4_select_id((struct rte_ipv4_hdr *)iph);
    iph->total_length    = htons(sizeof(struct rte_ipv4_hdr) + 4 + sizeof(struct igmphdr));
    
    /* RFC2236, RFC2113 */
    ipopt[0] = IPOPT_RA;
    ipopt[1] = 4; 
    ipopt[2] = 0;
    ipopt[3] = 0;

    iph->hdr_checksum = 0;
    iph->hdr_checksum = ip_compute_csum(iph, sizeof(struct rte_ipv4_hdr) + 4);

    igmph->type  = type;
    igmph->code  = 0; /* RFC2236 Page3 */
    igmph->group = mc_addr->s_addr;
    igmph->csum  = 0;
    igmph->csum  = ip_compute_csum(igmph, sizeof(struct igmphdr));

    netif_xmit(mbuf, port);
    return err;
errout:
    rte_pktmbuf_free(mbuf);
    return err;
}

int igmp_join_group(struct netif_port* port
                    , const struct in_addr* mc_addr
                    , const struct in_addr* src_addr)
{
    return igmp_send_report(port, mc_addr, src_addr, IGMPV2_HOST_MEMBERSHIP_REPORT);
}

int igmp_leave_group(struct netif_port *port
                     , const struct in_addr *mc_addr
                     , const struct in_addr *src_addr)
{
    return igmp_send_report(port, mc_addr, src_addr, IGMP_HOST_LEAVE_MESSAGE);
}
