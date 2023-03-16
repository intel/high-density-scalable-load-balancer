/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/icmp.h>
#include <netinet/icmp6.h>
#include "common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route6.h"
#include "neigh.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "parser/parser.h"
#include "lb/conn.h"
#include "lb/dest.h"
#include "lb/icmp.h"

static const uint8_t lb_invmap[] = {
    [ICMP_ECHO]           = ICMP_ECHOREPLY + 1,
    [ICMP_ECHOREPLY]      = ICMP_ECHO + 1,
    [ICMP_TIMESTAMP]      = ICMP_TIMESTAMPREPLY + 1,
    [ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
    [ICMP_INFO_REQUEST]   = ICMP_INFO_REPLY + 1,
    [ICMP_INFO_REPLY]     = ICMP_INFO_REQUEST + 1,
    [ICMP_ADDRESS]        = ICMP_ADDRESSREPLY + 1,
    [ICMP_ADDRESSREPLY]   = ICMP_ADDRESS + 1
};

static const uint8_t lb_invmap6[] = {
    [ICMP6_ECHO_REPLY]    = ICMP6_ECHO_REQUEST + 1,
    [ICMP6_ECHO_REQUEST]  = ICMP6_ECHO_REPLY + 1
};

static bool lb_icmp_invert_type(uint8_t *type, uint8_t orig)
{
    if (orig >= sizeof(lb_invmap) || !lb_invmap[orig]) {
        return false;
    }

    *type = lb_invmap[orig] - 1;
    
    return true;
}

static bool lb_icmp6_invert_type(uint8_t *type, uint8_t orig) {
    if (orig >= sizeof(lb_invmap6) || !lb_invmap6[orig]) {
        return false;
    }
    *type = lb_invmap6[orig] - 1;
    return true;
}

static bool lb_is_icmp_reply(uint8_t type)
{
    if (type == ICMP_ECHOREPLY || type == ICMP_TIMESTAMPREPLY ||
        type == ICMP_INFO_REPLY || type == ICMP_ADDRESSREPLY) {
        return true;
    } else {
        return false;
    }
}

static bool lb_is_icmp6_reply(uint8_t type) {
    if (type == ICMP6_ECHO_REPLY) {
        return true;
    }
    return false;
}

int get_ipv4_icmp_addr_port(struct rte_mbuf *mbuf, int iphdrlen, union inet_addr *saddr,
                                            union inet_addr *daddr, uint16_t *sport, uint16_t *dport, int *icmp_pkt_type)
{
    struct icmphdr *ich = NULL;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    uint8_t type;
    struct rte_ipv4_hdr *ip4h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = iphdrlen;

    ich = rte_pktmbuf_mtod_offset(mbuf, struct icmphdr *, off);
    if (ich->type != ICMP_DEST_UNREACH 
        && ich->type != ICMP_SOURCE_QUENCH
        && ich->type != ICMP_TIME_EXCEEDED) {
        ip4h = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
        saddr->in.s_addr = ip4h->src_addr;
        daddr->in.s_addr = ip4h->dst_addr;

        icmp_type = ich->type;
        icmp_code = ich->code;
        if (!lb_is_icmp_reply(icmp_type)) {
            *sport = ((struct icmphdr *)ich)->un.echo.id;
            *dport = icmp_type << 8 | icmp_code;
        } else if (lb_icmp_invert_type(&type, icmp_type)) {
            *sport = type << 8 | icmp_code;
            *dport = ich->un.echo.id;
        } else {
            return -1;
        }

        *icmp_pkt_type = 1;

        return 0;
    }

    *icmp_pkt_type = 0;

    off += sizeof(struct icmphdr);
    ip4h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, off);
    saddr->in.s_addr = ip4h->dst_addr;
    daddr->in.s_addr = ip4h->src_addr;

    off += ((ip4h->version_ihl & 0xf) < 2);
    if (ip4h->packet_id == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, off);
        *sport = th->dst_port;
        *dport = th->src_port;
    } else if (ip4h->packet_id == IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, off);
        *sport = uh->dst_port;
        *dport = uh->src_port;
    } else {
        return -1;
    }

    return 0;
}

int get_ipv6_icmp6_addr_port(struct rte_mbuf *mbuf, int iphdrlen, union inet_addr *saddr,
                                            union inet_addr *daddr, uint16_t *sport, uint16_t *dport, int *icmp_pkt_type)
{
    struct icmp6_hdr *ic6h = NULL;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    uint8_t type;
    struct rte_ipv6_hdr *ip6h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = iphdrlen;

    ic6h = rte_pktmbuf_mtod_offset(mbuf, struct icmp6_hdr *, off);
    if (ic6h->icmp6_type != ICMP6_DST_UNREACH
        && ic6h->icmp6_type != ICMP6_PACKET_TOO_BIG
        && ic6h->icmp6_type != ICMP6_TIME_EXCEEDED) {
        ip6h = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
        rte_memcpy(&saddr->in6, ip6h->src_addr, sizeof(struct in6_addr));
        rte_memcpy(&daddr->in6, ip6h->dst_addr, sizeof(struct in6_addr));

        icmp_type = ic6h->icmp6_type;
        icmp_code = ic6h->icmp6_code;
        if (! lb_is_icmp6_reply(icmp_type)) {
            *sport = ic6h->icmp6_id;
            *dport = icmp_type << 8 | icmp_code;
        } else if (lb_icmp6_invert_type(&type, icmp_type)) {
            *sport = type << 8 | icmp_code;
            *dport = ic6h->icmp6_id;
        } else {
            return -1;
        }

        *icmp_pkt_type = 1;

        return 0;
    }

    *icmp_pkt_type = 0;

    off += sizeof(struct icmp6_hdr);
    ip6h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, off);
    rte_memcpy(&saddr->in6, ip6h->dst_addr, sizeof(struct in6_addr));
    rte_memcpy(&daddr->in6, ip6h->src_addr, sizeof(struct in6_addr));
    rte_pktmbuf_adj(mbuf, off);

    if (ip6h->proto == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, ip6_hdrlen(mbuf));
        *sport = th->dst_port;
        *dport = th->src_port;
    } else if (ip6h->proto == IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, ip6_hdrlen(mbuf));
        *sport = uh->dst_port;
        *dport = uh->src_port;
    } else {
        return -1;
    }

    rte_pktmbuf_prepend(mbuf, off);

    return 0;
}

void icmp6_calculate_csum(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *ip6h = NULL;
    struct icmp6_hdr *ic6h = NULL;
    uint32_t csum, l4_len;

    ip6h = rte_pktmbuf_mtod(mbuf, struct ip6_hdr *);
    ic6h = rte_pktmbuf_mtod_offset(mbuf, struct icmp6_hdr *, ip6_hdrlen(mbuf));

    ic6h->icmp6_cksum = 0;

    l4_len = ntohs(ip6h->ip6_plen);

    csum = rte_raw_cksum(ic6h, l4_len);
    csum += rte_ipv6_phdr_cksum((struct rte_ipv6_hdr *)ip6h, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0) {
        csum = 0xffff;
    }

    ic6h->icmp6_cksum = csum;
}

int lb_ipv4_icmp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct icmphdr *ich = NULL;
    struct rte_ipv4_hdr *ip4h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = 0;

    off = ip4_hdrlen(mbuf);
    mbuf->l3_len = off;
    ich = rte_pktmbuf_mtod_offset(mbuf, struct icmphdr *, off);
    if (ich->type != ICMP_DEST_UNREACH 
        && ich->type != ICMP_SOURCE_QUENCH
        && ich->type != ICMP_TIME_EXCEEDED) {
        return EDPVS_OK;
    }

    off += sizeof(struct icmphdr);
    ip4h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, off);
    ip4h->src_addr = conn->dest->addr.in.s_addr;
    off += ((ip4h->version_ihl & 0xf) < 2);

    if (ip4h->packet_id == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, off);
        th->src_port = conn->dest->port;
    } else if (ip4h->packet_id == IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, off);
        uh->src_port = conn->dest->port;
    } else {
        return -1;
    }

    return EDPVS_OK;
}

int lb_ipv4_icmp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct icmphdr *ich = NULL;
    struct rte_ipv4_hdr *ip4h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = 0;

    off = ip4_hdrlen(mbuf);
    mbuf->l3_len = off;
    ich = rte_pktmbuf_mtod_offset(mbuf, struct icmphdr *, off);
    if (ich->type != ICMP_DEST_UNREACH 
            && ich->type != ICMP_SOURCE_QUENCH
            && ich->type != ICMP_TIME_EXCEEDED) {
        return EDPVS_OK;
    }

    off += sizeof(struct icmphdr);
    ip4h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, off);
    ip4h->dst_addr = conn->dest->vaddr.in.s_addr;
    off += ((ip4h->version_ihl & 0xf) < 2);

    if (ip4h->packet_id == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, off);
        th->dst_port = conn->dest->vport;
    } else if (ip4h->packet_id == IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, off);
        uh->dst_port = conn->dest->vport;
    } else {
        return -1;
    }

    return EDPVS_OK;

}

int lb_ipv6_icmp6_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct icmp6_hdr *ic6h = NULL;
    struct rte_ipv6_hdr *ip6h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = 0;

    off = ip6_hdrlen(mbuf);
    mbuf->l3_len = off;
    ic6h = rte_pktmbuf_mtod_offset(mbuf, struct icmp6_hdr *, off);
    if (ic6h->icmp6_type != ICMP6_DST_UNREACH
            && ic6h->icmp6_type != ICMP6_PACKET_TOO_BIG
            && ic6h->icmp6_type != ICMP6_TIME_EXCEEDED) {
        return EDPVS_OK;
    }

    off += sizeof(struct icmp6_hdr);
    ip6h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, off);
    rte_memcpy(ip6h->src_addr, &conn->dest->addr.in6, sizeof(struct in6_addr));
    rte_pktmbuf_adj(mbuf, off);

    if (ip6h->proto == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, ip6_hdrlen(mbuf));
        th->src_port = conn->dest->port;
    } else if (ip6h->proto== IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, ip6_hdrlen(mbuf));
        uh->src_port = conn->dest->port;
    } else {
        return -1;
    }

    rte_pktmbuf_prepend(mbuf, off);

    return EDPVS_OK;
}

int lb_ipv6_icmp6_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct icmp6_hdr *ic6h = NULL;
    struct rte_ipv6_hdr *ip6h = NULL;
    struct rte_tcp_hdr *th = NULL;
    struct rte_udp_hdr *uh = NULL;
    int off = 0;

    off = ip6_hdrlen(mbuf);
    mbuf->l3_len = off;
    ic6h = rte_pktmbuf_mtod_offset(mbuf, struct icmp6_hdr *, off);
    if (ic6h->icmp6_type != ICMP6_DST_UNREACH
            && ic6h->icmp6_type != ICMP6_PACKET_TOO_BIG
            && ic6h->icmp6_type != ICMP6_TIME_EXCEEDED) {
        return EDPVS_OK;
    }

    off += sizeof(struct icmp6_hdr);
    ip6h = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, off);
    rte_memcpy(ip6h->dst_addr, &conn->dest->vaddr.in6, sizeof(struct in6_addr));
    rte_pktmbuf_adj(mbuf, off);

    if (ip6h->proto == IPPROTO_TCP) {
        th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, ip6_hdrlen(mbuf));
        th->dst_port = conn->dest->vport;
    } else if (ip6h->proto== IPPROTO_UDP) {
        uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, ip6_hdrlen(mbuf));
        uh->dst_port = conn->dest->vport;
    } else {
        return -1;
    }

    rte_pktmbuf_prepend(mbuf, off);

    return EDPVS_OK;
}
