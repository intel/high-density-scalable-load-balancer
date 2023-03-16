/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "common.h"
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/blklst.h"
#include "lb/service.h"
#include "lb/dest.h"
#include "lb/laddr.h"
#include "lb/sched.h"
#include "lb/conn.h"
#include "lb/ipv4.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "uoa.h"
#include "conf/neigh.h"
#include "sa_pool.h"
#include "lb/udp.h"

#define UOA_DEF_MAX_TRAIL   3
#define MAX_IPOPTLEN 40

#define UDP_STABLE_OUT_CNT  0
#define UDP_STABLE_IN_CNT   3

static int lb_g_uoa_max_trail = UOA_DEF_MAX_TRAIL; /* zero to disable UOA */
static int lb_g_uoa_mode = UOA_M_OPP; /* by default */
static lb_tick_t lb_udp_timeout;

static int lb_ipv4_insert_ipopt_uoa(struct lb_conn *conn, struct rte_mbuf *mbuf,
                            struct rte_ipv4_hdr *iph, struct rte_udp_hdr *uh, int mtu)
{
    struct rte_ipv4_hdr *niph = NULL;
    struct ipopt_uoa *optuoa;

    if ((ip4_hdrlen(mbuf) + sizeof(struct ipopt_uoa) >
                sizeof(struct rte_ipv4_hdr) + MAX_IPOPTLEN)
            || (mbuf->pkt_len + sizeof(struct ipopt_uoa) > mtu))
        goto error;

    /*
     * head-move or tail-move.
     *
     * move IP fixed header (not including options) if it's shorter,
     * otherwise move left parts (IP opts, UDP hdr and payloads).
     */
    if (likely(ntohs(iph->total_length) >= (sizeof(struct rte_ipv4_hdr) * 2))) {
        niph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, IPOLEN_UOA_IPV4);
        if (unlikely(!niph))
            goto error;

        rte_memcpy(niph, iph, sizeof(struct rte_ipv4_hdr));
    } else {
        unsigned char *ptr;

        niph = iph;

        /* pull all bits in segments to first segment */
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto error;

        ptr = (void *)rte_pktmbuf_append(mbuf, IPOLEN_UOA_IPV4);
        if (unlikely(!ptr))
            goto error;

        rte_memcpy((void *)(iph + 1) + IPOLEN_UOA_IPV4, iph + 1,
                ntohs(iph->total_length) - sizeof(struct rte_ipv4_hdr));
        uh = (void *)uh + IPOLEN_UOA_IPV4;
    }

    optuoa = (struct ipopt_uoa *)(niph + 1);
    optuoa->op_code = IPOPT_UOA;
    optuoa->op_len  = IPOLEN_UOA_IPV4;
    optuoa->op_port = uh->src_port;
    rte_memcpy(&optuoa->op_addr, &niph->src_addr, IPV4_ADDR_LEN_IN_BYTES);

    niph->version_ihl += (IPOLEN_UOA_IPV4 >> 2);
    niph->total_length = htons(ntohs(niph->total_length) + IPOLEN_UOA_IPV4);
    /* UDP/IP checksum will recalc later*/

    return EDPVS_OK;

error:
    return EDPVS_OK;
}

/*
 * insert_opp_uoa: insert IPPROTO_OPT with uoa
 *
 * @iph: pointer to ip header, type of void *
 *  will be cast to struct iphdr * or struct ip6_hdr * according to af
 * @uh: pointer to udp header
 * @return insertion status
 */
static int lb_ipv4_insert_opp_uoa(struct lb_conn *conn, struct rte_mbuf *mbuf,
                          void *iph, struct rte_udp_hdr *uh, int mtu)
{
    void *niph;
    struct opphdr *opph   = NULL;
    struct ipopt_uoa *uoa = NULL;
    int iphdrlen = 0, iptot_len = 0, ipolen_uoa = 0;

    /* the current af of mbuf before possible nat64,
     * i.e. the "tuplehash_in(conn).af" for FullNAT */

    iphdrlen   = ip4_hdrlen(mbuf);
    iptot_len  = ntohs(((struct rte_ipv4_hdr *)iph)->total_length);
    ipolen_uoa = IPOLEN_UOA_IPV4;


    if (mbuf->pkt_len + sizeof(*opph) + ipolen_uoa > mtu)
        goto error;

    /*
     * new protocol is inserted after IPv4/v6 header (including existing
     * options), and before UDP header. so unlike "ipo" mode, do not
     * need handle IPOPT_END coincide issue.
     */

    if (likely(iptot_len >= iphdrlen * 2)) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!niph))
            goto error;

        rte_memcpy(niph, iph, iphdrlen);
    } else {
        unsigned char *ptr;

        niph = iph;

        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto error;

        ptr = (void *)rte_pktmbuf_append(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!ptr))
            goto error;

        rte_memcpy((void *)iph + iphdrlen + sizeof(*opph) + ipolen_uoa,
                (void *)iph + iphdrlen,
                iptot_len - iphdrlen);

        uh = (void *)uh + sizeof(*opph) + ipolen_uoa;
    }

    opph = (struct opphdr *)((char *)niph + iphdrlen);
    memset(opph, 0, sizeof(*opph));

    opph->version  = OPPHDR_IPV4;
    opph->protocol = ((struct rte_ipv4_hdr *)niph)->next_proto_id;

    opph->length = htons(sizeof(*opph) + ipolen_uoa);

    uoa = (void *)opph->options;
    memset(uoa, 0, ipolen_uoa);
    uoa->op_code = IPOPT_UOA;
    uoa->op_len  = ipolen_uoa;
    uoa->op_port = uh->src_port;

    rte_memcpy(&uoa->op_addr, &((struct rte_ipv4_hdr *)niph)->src_addr,
                                                IPV4_ADDR_LEN_IN_BYTES);
    ((struct rte_ipv4_hdr *)niph)->next_proto_id = IPPROTO_OPT;
    /* UDP/IP checksum will recalc later*/
    ((struct rte_ipv4_hdr *)niph)->total_length =
                               htons(iptot_len + sizeof(*opph) + ipolen_uoa);

    return EDPVS_OK;

error:
    return EDPVS_OK;
}

static int lb_ipv4_udp_insert_uoa(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    int iphdrlen = 0;
    int err = EDPVS_OK;

    /* already send enough UOA */
    if (likely(conn->udp.uoa_state == UOA_S_DONE)) {
        if (unlikely(!(conn->flags & LB_CONN_F_STABLE)))
            conn->udp.in_pkts++;
        return EDPVS_OK;
    }

    /* stop sending if ACK received or max-trail reached */
    if (conn->udp.in_pkts >= lb_g_uoa_max_trail || conn->udp.acked) {
        conn->udp.uoa_state = UOA_S_DONE;
        return EDPVS_OK;
    }

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);

    /* get udp header before any 'standalone_uoa' */
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);

    /*
     * send standalone (empty-payload) UDP/IP pkt with UOA if
     * no room in IP header or exceeding MTU.
     *
     * Note: don't worry about inserting IPOPT_END, since it's
     * not mandatory and Linux codes can handle absent of IPOPT_END.
     * actually just adding UOA will not cause "... end of option coincide
     * with the end of the internet header. - RFC791". if original packet
     * is coincide, the IPOPT_END should already exist.
     */
    switch (lb_g_uoa_mode) {
        case UOA_M_IPO:
            err = lb_ipv4_insert_ipopt_uoa(conn, mbuf, iph, uh, dest->mtu);
            break;

        case UOA_M_OPP:
            err = lb_ipv4_insert_opp_uoa(conn, mbuf, iph, uh, dest->mtu);
            break;

        default:
            return EDPVS_INVAL;
    }

    if (err == EDPVS_OK)
        conn->udp.in_pkts++;
    else
        RTE_LOG(WARNING, IPVS, "fail to send UOA: %s\n", dpvs_strerror(err));

    return err;
}

static int lb_ipv6_insert_opp_uoa(struct lb_conn *conn, struct rte_mbuf *mbuf,
                          void *iph, struct rte_udp_hdr *uh, int mtu)
{
    void *niph;
    struct opphdr *opph   = NULL;
    struct ipopt_uoa *uoa = NULL;
    int iphdrlen = 0, iptot_len = 0, ipolen_uoa = 0;

    /* the current af of mbuf before possible nat64,
     * i.e. the "tuplehash_in(conn).af" for FullNAT */

    /*
     * iphdrlen:  ipv6 total header length =
     *   basic header length (40 B) + ext header length
     * iptot_len: ipv6 total length =
     *   basic header length (40 B) + payload length(including ext header)
     */
    iphdrlen = ip6_hdrlen(mbuf);
    if (iphdrlen != sizeof(struct rte_ipv6_hdr))
        goto error;
    iptot_len = sizeof(struct rte_ipv6_hdr) + ntohs(((struct rte_ipv6_hdr *)iph)->payload_len);
    ipolen_uoa = IPOLEN_UOA_IPV6;


    if (mbuf->pkt_len + sizeof(*opph) + ipolen_uoa > mtu)
        goto error;

    /*
     * new protocol is inserted after IPv4/v6 header (including existing
     * options), and before UDP header. so unlike "ipo" mode, do not
     * need handle IPOPT_END coincide issue.
     */

    if (likely(iptot_len >= iphdrlen * 2)) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!niph))
            goto error;

        rte_memcpy(niph, iph, iphdrlen);
    } else {
        unsigned char *ptr;

        niph = iph;

        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto error;

        ptr = (void *)rte_pktmbuf_append(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!ptr))
            goto error;

        rte_memcpy((void *)iph + iphdrlen + sizeof(*opph) + ipolen_uoa,
                (void *)iph + iphdrlen,
                iptot_len - iphdrlen);

        uh = (void *)uh + sizeof(*opph) + ipolen_uoa;
    }

    opph = (struct opphdr *)((void *)niph + iphdrlen);
    memset(opph, 0, sizeof(*opph));


    /* version 2 for ipv6 address family */
    uint8_t nexthdr = ((struct rte_ipv6_hdr *)niph)->proto;
    ip6_skip_exthdr(mbuf, sizeof(struct rte_ipv6_hdr), &nexthdr);
    opph->version  = OPPHDR_IPV6;
    opph->protocol = nexthdr;

    opph->length = htons(sizeof(*opph) + ipolen_uoa);

    uoa = (void *)opph->options;
    memset(uoa, 0, ipolen_uoa);
    uoa->op_code = IPOPT_UOA;
    uoa->op_len  = ipolen_uoa;
    uoa->op_port = uh->src_port;

    rte_memcpy(&uoa->op_addr, &((struct rte_ipv6_hdr *)niph)->src_addr,
                                                    IPV6_ADDR_LEN_IN_BYTES);
    /*
     * we should set the 'nexthdr' of the last ext header to IPPROTO_OPT here
     * but seems no efficient method to set that one
     * ip6_skip_exthdr was only used to get the value
     * so we send_standalone_uoa when has ip ext headers
     */
    ((struct rte_ipv6_hdr *)niph)->proto = IPPROTO_OPT;
    /* Update ipv6 payload length */
    ((struct rte_ipv6_hdr *)niph)->payload_len =
                htons(ntohs(((struct rte_ipv6_hdr *)niph)->payload_len) +
                sizeof(*opph) + ipolen_uoa);

    return EDPVS_OK;

error:
    return EDPVS_OK;
}

static int lb_ipv6_udp_insert_uoa(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv6_hdr *iph = NULL;
    int iphdrlen = 0;
    int err = EDPVS_OK;

    /* already send enough UOA */
    if (likely(conn->udp.uoa_state == UOA_S_DONE)) {
        return EDPVS_OK;
    }

    /* stop sending if ACK received or max-trail reached */
    if (conn->udp.in_pkts >= lb_g_uoa_max_trail || conn->udp.acked) {
        conn->udp.uoa_state = UOA_S_DONE;
        return EDPVS_OK;
    }

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    iphdrlen = ip6_hdrlen(mbuf);

    /* get udp header before any 'standalone_uoa' */
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);

    /*
     * send standalone (empty-payload) UDP/IP pkt with UOA if
     * no room in IP header or exceeding MTU.
     *
     * Note: don't worry about inserting IPOPT_END, since it's
     * not mandatory and Linux codes can handle absent of IPOPT_END.
     * actually just adding UOA will not cause "... end of option coincide
     * with the end of the internet header. - RFC791". if original packet
     * is coincide, the IPOPT_END should already exist.
     */
    switch (lb_g_uoa_mode) {
        case UOA_M_OPP:
            err = lb_ipv6_insert_opp_uoa(conn, mbuf, iph, uh, dest->mtu);
            break;

        default:
            return EDPVS_INVAL;
    }

    if (err == EDPVS_OK)
        conn->udp.in_pkts++;
    else
        RTE_LOG(WARNING, IPVS, "fail to send UOA: %s\n", dpvs_strerror(err));

    return err;
}

void get_udp_port(void *trans_head, uint16_t *sport, uint16_t *dport)
{
    struct rte_udp_hdr *uh = (struct rte_udp_hdr *)trans_head;
    *sport = uh->src_port;
    *dport = uh->dst_port;
}

void lb_set_udp_timeout(int timeout)
{
    lb_udp_timeout = timeout << LB_HZ_BITS;
}

void lb_set_udp_uoa_mode(int uoa_mode)
{
    lb_g_uoa_mode = uoa_mode;
}

void lb_set_udp_uoa_max_trail(int uoa_max_trail)
{
    lb_g_uoa_max_trail = uoa_max_trail;
}

int lb_udp_state_trans(struct lb_conn *conn, struct rte_mbuf *mbuf, int iphdrlen, int dir)
{
    if (likely(conn->flags & LB_CONN_F_STABLE))
        return EDPVS_OK;

    if (dir == DPVS_CONN_DIR_OUTBOUND)
        conn->udp.out_pkts++;
    else
	conn->udp.in_pkts++;

    if (conn->udp.out_pkts >= UDP_STABLE_OUT_CNT && conn->udp.in_pkts >= UDP_STABLE_IN_CNT) {
        conn->flags |= LB_CONN_F_STABLE;
        conn->timer.delay = lb_udp_timeout;
        // TODO notify sync new long connection session
    }

    return EDPVS_OK;
}

int lb_ipv4_udp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    int iphdrlen = 0;
    uint8_t nxt_proto;
    struct opphdr *opp = NULL;
    int err = EDPVS_OK;

    err = lb_ipv4_udp_insert_uoa(dest, conn, mbuf);

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    nxt_proto = iph->next_proto_id;

    if (nxt_proto == IPPROTO_UDP) {
        uh = (struct rte_udp_hdr *)((char *)iph + iphdrlen);
    } else if (nxt_proto == IPPROTO_OPT) {
        opp = (struct opphdr *)((char *)iph + iphdrlen);
        uh = (struct rte_udp_hdr *)((void *)opp + ntohs(opp->length));
    } else
        return EDPVS_NOTSUPP;

    uh->src_port = conn->lport;
    uh->dst_port = conn->dest->port;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv4_udp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    int iphdrlen = 0;
    int err = EDPVS_OK;

    iphdrlen = ip4_hdrlen(mbuf);

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);

    uh->src_port = conn->dest->vport;
    uh->dst_port = conn->cport;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv6_udp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv6_hdr *iph = NULL;
    int ip6hdrlen = 0;
    uint8_t nxt_proto;
    struct opphdr *opp = NULL;
    int err = EDPVS_OK;

    err = lb_ipv6_udp_insert_uoa(dest, conn, mbuf);

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    ip6hdrlen = ip6_hdrlen(mbuf);
    nxt_proto = iph->proto;
    ip6_skip_exthdr(mbuf, sizeof(struct rte_ipv6_hdr), &nxt_proto);

    if (nxt_proto == IPPROTO_UDP) {
        uh = (struct rte_udp_hdr *)((char *)iph + ip6hdrlen);
    } else if (nxt_proto == IPPROTO_OPT) {
        opp = (struct opphdr *)((char *)iph + ip6hdrlen);
        uh = (struct rte_udp_hdr *)((void *)opp + ntohs(opp->length));
    } else
        return EDPVS_NOTSUPP;

    uh->src_port = conn->lport;
    uh->dst_port = conn->dest->port;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv6_udp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    int ip6hdrlen = 0;
    int err = EDPVS_OK;

    ip6hdrlen = ip6_hdrlen(mbuf);

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, ip6hdrlen);

    uh->src_port = conn->dest->vport;
    uh->dst_port = conn->cport;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv4_udp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    int iphdrlen = 0;
    uint8_t nxt_proto;
    struct opphdr *opp = NULL;
    int err = EDPVS_OK;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    nxt_proto = iph->next_proto_id;

    if (nxt_proto == IPPROTO_UDP) {
        uh = (struct rte_udp_hdr *)((char *)iph + iphdrlen);
    } else if (nxt_proto == IPPROTO_OPT) {
        opp = (struct opphdr *)((char *)iph + iphdrlen);
        uh = (struct rte_udp_hdr *)((void *)opp + ntohs(opp->length));
    } else
        return EDPVS_NOTSUPP;

    uh->dst_port = conn->dest->port;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv4_udp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    int iphdrlen = 0;
    int err = EDPVS_OK;

    iphdrlen = ip4_hdrlen(mbuf);

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);

    uh->src_port = conn->dest->vport;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv6_udp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct rte_ipv6_hdr *iph = NULL;
    int ip6hdrlen = 0;
    uint8_t nxt_proto;
    struct opphdr *opp = NULL;
    int err = EDPVS_OK;

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    ip6hdrlen = ip6_hdrlen(mbuf);
    nxt_proto = iph->proto;
    ip6_skip_exthdr(mbuf, sizeof(struct rte_ipv6_hdr), &nxt_proto);

    if (nxt_proto == IPPROTO_UDP) {
        uh = (struct rte_udp_hdr *)((char *)iph + ip6hdrlen);
    } else if (nxt_proto == IPPROTO_OPT) {
        opp = (struct opphdr *)((char *)iph + ip6hdrlen);
        uh = (struct rte_udp_hdr *)((void *)opp + ntohs(opp->length));
    } else
        return EDPVS_NOTSUPP;

    uh->dst_port = conn->dest->port;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}

int lb_ipv6_udp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    int ip6hdrlen = 0;
    int err = EDPVS_OK;

    ip6hdrlen = ip6_hdrlen(mbuf);

    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, ip6hdrlen);

    uh->src_port = conn->dest->vport;
    uh->dgram_cksum = 0;
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = sizeof(struct rte_udp_hdr);

    return err;
}
