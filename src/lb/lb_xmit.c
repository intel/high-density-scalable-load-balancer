/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <assert.h>
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route.h"
#include "route6.h"
#include "icmp.h"
#include "icmp6.h"
#include "neigh.h"
#include "ipvs/xmit.h"
#include "ipvs/nat64.h"
#include "parser/parser.h"
#include "lb/conn.h"
#include "lb/dest.h"
#include "lb/icmp.h"
#include "conf/neigh.h"
#include "lb/xmit.h"

void lb_dest_tunnel_xmit4(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *new_iph, *old_iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    uint8_t tos = old_iph->type_of_service;
    uint16_t df = old_iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG);
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    new_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    if (!new_iph) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        goto error;
    }

    if (unlikely(mbuf->pkt_len > dest->mtu && df)) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(dest->mtu));
        goto error;
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    memset(new_iph, 0, sizeof(struct rte_ipv4_hdr));
    new_iph->version_ihl = 0x45;
    new_iph->type_of_service = tos;
    new_iph->total_length = htons(mbuf->pkt_len);
    new_iph->fragment_offset = df;
    new_iph->time_to_live = old_iph->time_to_live;
    new_iph->next_proto_id = IPPROTO_IPIP;
    //new_iph->src_addr = rte_cpu_to_be_32(rte_lcore_id());
    new_iph->dst_addr=conn->dest->addr.in.s_addr;
    new_iph->packet_id = rte_cpu_to_be_16(dest->ipv4_id++);
    new_iph->hdr_checksum = 0;
    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }
    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_tunnel_xmit6(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ether_hdr *eth_hdr;
    struct ip6_hdr *new_ip6h, *old_ip6h = ip6_hdr(mbuf);
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    new_ip6h = (struct ip6_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct ip6_hdr));
    if (unlikely(!new_ip6h)) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        goto error;
    }

    if (unlikely(mbuf->pkt_len > dest->mtu)) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(dest->mtu));
        goto error;
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    memset(new_ip6h, 0, sizeof(struct ip6_hdr));
    new_ip6h->ip6_flow = old_ip6h->ip6_flow;
    new_ip6h->ip6_plen = htons(mbuf->pkt_len - sizeof(struct ip6_hdr));
    new_ip6h->ip6_nxt = IPPROTO_IPV6;
    new_ip6h->ip6_hops = old_ip6h->ip6_hops;
    //rte_memcpy(&new_ip6h->ip6_src, );
    memcpy(&new_ip6h->ip6_dst, &dest->addr.in6, 16);

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }
    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_tunnel_xmit6o4(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *new_iph;
    struct ip6_hdr *old_ip6h = ip6_hdr(mbuf);
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    new_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    if (!new_iph) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        goto error;
    }

    if (unlikely(mbuf->pkt_len > dest->mtu)) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(dest->mtu));
        goto error;
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    memset(new_iph, 0, sizeof(struct rte_ipv4_hdr));
    new_iph->version_ihl = 0x45;
    new_iph->type_of_service = 0;
    new_iph->total_length = htons(mbuf->pkt_len);
    new_iph->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);;
    new_iph->time_to_live = old_ip6h->ip6_hlim;
    new_iph->next_proto_id = IPPROTO_IPV6;
    //new_iph->src_addr = rte_cpu_to_be_32(rte_lcore_id());
    new_iph->dst_addr=conn->dest->addr.in.s_addr;
    new_iph->packet_id = rte_cpu_to_be_16(dest->ipv4_id++);
    new_iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }
    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

/* Only change out NIC and dmac addr */
void lb_dest_dr_xmit4(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }
    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_dr_xmit6(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }
    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit4_in(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ipv4_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_in_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->dest->addr.in.s_addr;
    iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit4_out(void *outconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = outconn;
    struct rte_ipv4_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_OUTBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_out_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    iph->src_addr = conn->dest->vaddr.in.s_addr;
    iph->dst_addr = conn->caddr.in.s_addr;
    iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, conn->out_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit6_in(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ipv6_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip6_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_in_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    rte_memcpy(iph->src_addr, &conn->laddr.in6, sizeof(struct in6_addr));
    rte_memcpy(iph->dst_addr, &conn->dest->addr.in6, sizeof(struct in6_addr));
    mbuf->ol_flags |= PKT_TX_IPV6;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit6_out(void *outconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = outconn;
    struct rte_ipv6_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip6_hdrlen(mbuf), DPVS_CONN_DIR_OUTBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_out_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    rte_memcpy(iph->src_addr, &conn->dest->vaddr.in6, sizeof(struct in6_addr));
    rte_memcpy(iph->dst_addr, &conn->caddr.in6, sizeof(struct in6_addr));
    mbuf->ol_flags |= PKT_TX_IPV6;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, conn->out_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit64_in(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ipv4_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip6_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = mbuf_6to4(mbuf, &conn->laddr.in, &conn->dest->addr.in);
    if (err) {
        goto error;
    }

    err = dest->transport_in_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->dest->addr.in.s_addr;
    iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_fnat_xmit46_out(void *outconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = outconn;
    struct rte_ipv6_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_OUTBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = mbuf_4to6(mbuf, &conn->dest->vaddr.in6, &conn->caddr.in6);
    if (err) {
        goto error;
    }

    err = dest->transport_out_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    rte_memcpy(iph->src_addr, &conn->dest->vaddr.in6, sizeof(struct in6_addr));
    rte_memcpy(iph->dst_addr, &conn->caddr.in6, sizeof(struct in6_addr));
    mbuf->ol_flags |= PKT_TX_IPV6;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, conn->out_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_nat_xmit4_in(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ipv4_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_in_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    iph->dst_addr = conn->dest->addr.in.s_addr;
    iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_nat_xmit4_out(void *outconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = outconn;
    struct rte_ipv4_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip4_hdrlen(mbuf), DPVS_CONN_DIR_OUTBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_out_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    iph->src_addr = conn->dest->vaddr.in.s_addr;
    iph->hdr_checksum = 0;
    mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    netif_xmit(mbuf, conn->out_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_nat_xmit6_in(void *inconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = inconn;
    struct rte_ipv6_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip6_hdrlen(mbuf), DPVS_CONN_DIR_INBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_in_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    rte_memcpy(iph->dst_addr, &conn->dest->addr.in6, sizeof(struct in6_addr));
    mbuf->ol_flags |= PKT_TX_IPV6;

#ifdef CONFIG_LB_REDIRECT
    if (iph->proto == IPPROTO_ICMPV6) {
        icmp6_calculate_csum(mbuf);
    }
#endif

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&dest->in_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&dest->in_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, dest->in_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}

void lb_dest_nat_xmit6_out(void *outconn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    struct lb_conn *conn = outconn;
    struct rte_ipv6_hdr *iph;
    struct rte_ether_hdr *eth_hdr;
    int err;

    if (dest->state_trans) {
        err = dest->state_trans(conn, mbuf, ip6_hdrlen(mbuf), DPVS_CONN_DIR_OUTBOUND);
        if (EDPVS_OK != err) {
            goto error;
        }
    }

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    err = dest->transport_out_handler(dest, conn, mbuf);
    if (EDPVS_OK != err) {
        goto error;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    rte_memcpy(iph->src_addr, &conn->dest->vaddr.in6, sizeof(struct in6_addr));
    mbuf->ol_flags |= PKT_TX_IPV6;

#ifdef CONFIG_LB_REDIRECT
        if (iph->proto == IPPROTO_ICMPV6) {
            icmp6_calculate_csum(mbuf);
        }
#endif

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        goto error;
    }

    rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    netif_xmit(mbuf, conn->out_dev);

    return;

error:
    rte_pktmbuf_free(mbuf);
    return;
}


static inline int lb_stats_out(struct lb_conn *conn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    assert(conn && mbuf && dest);

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        dest->stats.outpkts++;
        dest->stats.outbytes++;
        return EDPVS_OK;
    }

    return EDPVS_INVAL;
}

static inline int lb_stats_in(struct lb_conn *conn, struct rte_mbuf *mbuf,
                                                struct lb_dest *dest)
{
    assert(conn && mbuf && dest);

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        dest->stats.inpkts++;
        dest->stats.inbytes++;
        return EDPVS_OK;
    }

    return EDPVS_INVAL;
}

void lb_xmit_inbound(struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    int err;
    struct lb_dest *dest = conn->dest;

    err = lb_stats_in(conn, mbuf, dest);
    if (err) {
        rte_pktmbuf_free(mbuf);
        return;
    }

    assert(dest->xmit_cb[LB_DEST_XMIT_IN]);
    dest->xmit_cb[LB_DEST_XMIT_IN](conn, mbuf, dest);
}

void lb_xmit_outbound(struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    int err;
    struct lb_dest *dest = conn->dest;

    err = lb_stats_out(conn, mbuf, dest);
    if (err) {
        rte_pktmbuf_free(mbuf);
        return;
    }

    assert(dest->xmit_cb[LB_DEST_XMIT_IN]);
    dest->xmit_cb[LB_DEST_XMIT_OUT](conn, mbuf, dest);
}
