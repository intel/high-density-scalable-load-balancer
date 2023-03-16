/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include "common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route6.h"
#include "neigh.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_tcp.h"
#include "parser/parser.h"
#include "lb/conn.h"
#include "lb/dest.h"
#include "lb/tcp.h"

#define DPVS_TCP_DEFAULT_TIME    90
#define DPVS_IPV4_HDR_DF_FLAG 0x4000
#define DPVS_IPV4_DEFAULT_TTL    60
#define DPVS_IPV4_DEFAULT_VERSION_IHL    0x45
#define DPVS_IPV6_DEFAULT_VTC_FLOW		0x60000000
#define DPVS_IPV6_DEFAULT_HOT_LIMIT		60

static lb_tick_t lb_tcp_timeouts[DPVS_TCP_S_LAST + 1];

#ifdef CONFIG_DPVS_IPVS_DEBUG
static const char *tcp_state_names[] = {
    [DPVS_TCP_S_NONE]           = "NONE",
    [DPVS_TCP_S_ESTABLISHED]    = "ESTABLISHED",
    [DPVS_TCP_S_SYN_SENT]       = "SYN_SENT",
    [DPVS_TCP_S_SYN_RECV]       = "SYN_RECV",
    [DPVS_TCP_S_FIN_WAIT]       = "FIN_WAIT",
    [DPVS_TCP_S_TIME_WAIT]      = "TIME_WAIT",
    [DPVS_TCP_S_CLOSE]          = "CLOSE",
    [DPVS_TCP_S_CLOSE_WAIT]     = "CLOSE_WAIT",
    [DPVS_TCP_S_LAST_ACK]       = "LAST_ACK",
    [DPVS_TCP_S_LISTEN]         = "LISTEN",
    [DPVS_TCP_S_SYNACK]         = "SYNACK",
    [DPVS_TCP_S_LAST]           = "BUG!"
};
#endif

static struct tcp_state tcp_states[] = {
/*    INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR}},

/*    OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*    INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static inline int lb_seq_before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1 - seq2) < 0;
}


/* use NOP option to replace timestamp opt */
static void tcp_in_remove_ts(struct rte_tcp_hdr *tcph)
{
    unsigned char *ptr;
    int len, i;

    ptr = (unsigned char *)(tcph + 1);
    len = ((tcph->data_off & 0xf0) >> 2) - sizeof(struct rte_tcp_hdr);

    while (len > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCP_OPT_EOL:
            return;
        case TCP_OPT_NOP:
            len--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)    /* silly options */
                return;
            if (opsize > len)
                return;    /* partial options */
            if ((opcode == TCP_OPT_TIMESTAMP)
                    && (opsize == TCP_OLEN_TIMESTAMP)) {
                for (i = 0; i < TCP_OLEN_TIMESTAMP; i++)
                    *(ptr - 2 + i) = TCP_OPT_NOP;
                return;
            }

            ptr += opsize - 2;
            len -= opsize;
            break;
        }
    }
}

static int tcp_ipv4_in_add_toa(struct lb_conn *conn, struct rte_mbuf *mbuf,
                          struct rte_tcp_hdr *tcph, uint32_t mtu)
{
    struct tcpopt_addr *toa;
    uint32_t tcp_opt_len;
    uint8_t *p, *q, *tail;

    tcp_opt_len = TCP_OLEN_IP4_ADDR;
    /*
     * check if we can add the new option
     */

    if (unlikely(mbuf->pkt_len > (mtu - tcp_opt_len))) {
        RTE_LOG(DEBUG, IPVS, "add toa: need fragment, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_FRAG;
    }

    /* maximum TCP header is 60, and 40 for options */
    if (unlikely((60 - ((tcph->data_off & 0xf0) >> 2)) < tcp_opt_len)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no TCP header room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /* check tail room and expand mbuf.
     * have to pull all bits in segments for later operation. */
    if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
        return EDPVS_INVPKT;
    tail = (uint8_t *)rte_pktmbuf_append(mbuf, tcp_opt_len);
    if (unlikely(!tail)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no mbuf tail room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /*
     * now add address option
     */

    /* move data down, including existing tcp options
     * @p is last data byte,
     * @q is new position of last data byte */
    p = tail - 1;
    q = p + tcp_opt_len;
    while (p >= ((uint8_t *)tcph + sizeof(struct rte_tcp_hdr))) {
        *q = *p;
        p--, q--;
    }

    /* insert toa right after TCP basic header */
    toa = (struct tcpopt_addr *)(tcph + 1);
    toa->opcode = TCP_OPT_ADDR;
    toa->opsize = tcp_opt_len;
    toa->port = conn->cport;

    struct tcpopt_ip4_addr *toa_ip4 = (struct tcpopt_ip4_addr *)(tcph + 1);
    toa_ip4->addr = conn->caddr.in;

    /* reset tcp header length */
    tcph->data_off += (tcp_opt_len << 2);

    /*
     * reset ip header total length, notice nat64
     * toa is always for rs which is tuplehash_out conn
     */
    ip4_hdr(mbuf)->total_length =
            rte_cpu_to_be_16(rte_be_to_cpu_16(ip4_hdr(mbuf)->total_length) + tcp_opt_len);

    /* tcp csum will be recalc later,
     * so as IP hdr csum since iph.tot_len has been chagned. */
    return EDPVS_OK;
}

static int tcp_ipv6_in_add_toa(struct lb_conn *conn, struct rte_mbuf *mbuf,
                          struct rte_tcp_hdr *tcph, uint32_t mtu)
{
    struct tcpopt_addr *toa;
    uint32_t tcp_opt_len;
    uint8_t *p, *q, *tail;
    struct rte_ipv6_hdr *ip6h;

    tcp_opt_len = TCP_OLEN_IP6_ADDR;
    /*
     * check if we can add the new option
     */

    if (unlikely(mbuf->pkt_len > (mtu - tcp_opt_len))) {
        RTE_LOG(DEBUG, IPVS, "add toa: need fragment, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_FRAG;
    }

    /* maximum TCP header is 60, and 40 for options */
    if (unlikely((60 - ((tcph->data_off & 0xf0) >> 2)) < tcp_opt_len)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no TCP header room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /* check tail room and expand mbuf.
     * have to pull all bits in segments for later operation. */
    if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
        return EDPVS_INVPKT;
    tail = (uint8_t *)rte_pktmbuf_append(mbuf, tcp_opt_len);
    if (unlikely(!tail)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no mbuf tail room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /*
     * now add address option
     */

    /* move data down, including existing tcp options
     * @p is last data byte,
     * @q is new position of last data byte */
    p = tail - 1;
    q = p + tcp_opt_len;
    while (p >= ((uint8_t *)tcph + sizeof(struct rte_tcp_hdr))) {
        *q = *p;
        p--, q--;
    }

    /* insert toa right after TCP basic header */
    toa = (struct tcpopt_addr *)(tcph + 1);
    toa->opcode = TCP_OPT_ADDR;
    toa->opsize = tcp_opt_len;
    toa->port = conn->cport;

    struct tcpopt_ip6_addr *toa_ip6 = (struct tcpopt_ip6_addr *)(tcph + 1);
    rte_memcpy(&toa_ip6->addr, &conn->caddr.in6, sizeof(struct in6_addr));

    /* reset tcp header length */
    tcph->data_off += (tcp_opt_len << 2);

    /*
     * reset ip header total length, notice nat64
     * toa is always for rs which is tuplehash_out conn
     */

    ip6h = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    ip6h->payload_len =
            rte_cpu_to_be_16(rte_be_to_cpu_16(ip6h->payload_len) + tcp_opt_len);

    /* tcp csum will be recalc later,
     * so as IP hdr csum since iph.tot_len has been chagned. */
    return EDPVS_OK;
}


static inline int tcp_state_idx(struct rte_tcp_hdr *th)
{
    if (th->tcp_flags & RTE_TCP_RST_FLAG)
        return 3;
    if (th->tcp_flags & RTE_TCP_SYN_FLAG)
        return 0;
    if (th->tcp_flags & RTE_TCP_FIN_FLAG)
        return 1;
    if (th->tcp_flags & RTE_TCP_ACK_FLAG)
        return 2;

    return -1;
}

static unsigned lb_dp_vs_get_conn_timeout(struct lb_conn *conn)
{
    unsigned conn_timeout;
    if (conn->dest) {
        conn_timeout = conn->dest->conn_timeout;
        return conn_timeout;
    }
    return DPVS_TCP_DEFAULT_TIME;
}

int lb_tcp_state_trans(struct lb_conn *conn, struct rte_mbuf *mbuf, int iphdrlen, int dir)
{
    struct rte_tcp_hdr *th, _tcph;
    int idx, off;
    int new_state = DPVS_TCP_S_CLOSE;
    lb_tick_t conn_timeout = 0;

    th = mbuf_header_pointer(mbuf, iphdrlen, sizeof(_tcph), &_tcph);
    if (unlikely(!th))
        return EDPVS_INVPKT;
    if (conn->dest->fwdmode == DPVS_FWD_MODE_DR || conn->dest->fwdmode == DPVS_FWD_MODE_TUNNEL)
        off = 8;
    else if (dir == DPVS_CONN_DIR_INBOUND)
        off = 0;
    else if (dir == DPVS_CONN_DIR_OUTBOUND)
        off = 4;
    else
        return EDPVS_NOTSUPP; /* do not support INPUT_ONLY now */

    if ((idx = tcp_state_idx(th)) < 0) {
        RTE_LOG(DEBUG, IPVS, "tcp_state_idx=%d !\n", idx);
        goto tcp_state_out;
    }

    new_state = tcp_states[off + idx].next_state[conn->state];

tcp_state_out:
    if (new_state == conn->state)
        return EDPVS_OK;

    conn->state = new_state;

    // update timer, Zhu Tao mark
    if (new_state == DPVS_TCP_S_ESTABLISHED) {
        conn_timeout = lb_dp_vs_get_conn_timeout(conn);
        if (unlikely(conn_timeout > 0))
            conn_timeout = conn_timeout;
        else
            conn_timeout = lb_tcp_timeouts[new_state];
    } else {
        conn_timeout = lb_tcp_timeouts[new_state];
    }
    conn->timer.delay = conn_timeout;

    return EDPVS_OK;
}

void lb_set_tcp_timeouts(int *tcp_timeouts)
{
    int i;

    for (i=0; i<DPVS_TCP_S_LAST; i++) {
        lb_tcp_timeouts[i] = tcp_timeouts[i] << LB_HZ_BITS;
    }
}

void get_tcp_port(void *trans_head, uint16_t *sport, uint16_t *dport)
{
    struct rte_tcp_hdr *th = (struct rte_tcp_hdr *)trans_head;
    *sport = th->src_port;
    *dport = th->dst_port;
}

static void lb_tcp_out_save_seq(struct rte_mbuf *mbuf,
                             struct lb_conn *conn, struct rte_tcp_hdr *th)
{
    if (th->tcp_flags & RTE_TCP_RST_FLAG) {
        return;
    }

    if (lb_seq_before(rte_be_to_cpu_32(th->recv_ack), rte_be_to_cpu_32(conn->tcp.rs_end_ack))
            && conn->tcp.rs_end_ack != 0)
        return;

    if (unlikely((th->tcp_flags & RTE_TCP_SYN_FLAG) && (th->tcp_flags & RTE_TCP_ACK_FLAG)))
        conn->tcp.rs_end_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
    else
        conn->tcp.rs_end_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + mbuf->pkt_len
                - ip4_hdrlen(mbuf) - ((th->data_off & 0xf0) >> 2));

    conn->tcp.rs_end_ack = th->recv_ack;
}

static int lb_tcp_send_rst(struct lb_conn *conn, int dir)
{
    struct rte_mempool *pool;
    struct rte_mbuf *mbuf = NULL;
    struct rte_tcp_hdr *th;
    struct rte_ipv4_hdr *ip4h;
    struct rte_ipv6_hdr *ip6h;
    struct rte_ether_hdr *eth_hdr;
    struct netif_port *xmit_dev = NULL;

    if (conn->state != DPVS_TCP_S_ESTABLISHED) {
        return EDPVS_OK;
    }

    xmit_dev = (dir == DPVS_CONN_DIR_INBOUND) ? conn->dest->in_dev: conn->out_dev;
    pool = xmit_dev->mbuf_pool;
    if (!pool) {
        return EDPVS_NOROUTE;
    }

    mbuf = rte_pktmbuf_alloc(pool);
    if (!mbuf) {
        return EDPVS_NOMEM;
    }
    mbuf->userdata = NULL; /* make sure "no route info" */

    /*
     * reserve head room ?
     * mbuf has alreay configured header room
     * RTE_PKTMBUF_HEADROOM for lower layer headers.
     */
    assert(rte_pktmbuf_headroom(mbuf) >= 128); /* how to reserve. >_< */

    mbuf->ol_flags &= (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF);

    th = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_tcp_hdr));
    if (!th) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    memset(th, 0, sizeof(struct rte_tcp_hdr));
    if (dir == DPVS_CONN_DIR_INBOUND) {
        th->src_port = conn->lport;
        th->dst_port = conn->dest->port;
        th->sent_seq = conn->tcp.rs_end_ack;
    } else {
        th->src_port = conn->dest->vport;
        th->dst_port = conn->cport;
        th->sent_seq = conn->tcp.rs_end_seq;
    }

    th->recv_ack = 0;
    th->data_off = sizeof(struct rte_tcp_hdr) << 2;
    th->tcp_flags = 0;
    th->tcp_flags |= RTE_TCP_RST_FLAG;
    th->cksum = 0;
    mbuf->l4_len = sizeof(struct rte_tcp_hdr);
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;

    if (dir == DPVS_CONN_DIR_INBOUND) {
        if ((int)conn->in_af == AF_INET) {
            ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv4_hdr));
            if (!ip4h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip4h->version_ihl     = DPVS_IPV4_DEFAULT_VERSION_IHL;
            ip4h->total_length    = htons(mbuf->pkt_len);
            ip4h->packet_id       = 0;
            ip4h->fragment_offset = htons(DPVS_IPV4_HDR_DF_FLAG);
            ip4h->time_to_live    = DPVS_IPV4_DEFAULT_TTL;
            ip4h->next_proto_id   = IPPROTO_TCP;
            ip4h->src_addr        = conn->laddr.in.s_addr;
            ip4h->dst_addr        = conn->dest->addr.in.s_addr;
            ip4h->hdr_checksum = 0;
            mbuf->l3_len = sizeof(*ip4h);
            mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
        } else {
            int plen = mbuf->pkt_len;
            ip6h = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv6_hdr));
            if (!ip6h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip6h->vtc_flow  = rte_cpu_to_be_32(DPVS_IPV6_DEFAULT_VTC_FLOW);
            ip6h->payload_len = htons(plen);
            ip6h->hop_limits = DPVS_IPV6_DEFAULT_HOT_LIMIT;
            ip6h->proto     = IPPROTO_TCP;
            rte_memcpy(ip6h->src_addr, &conn->laddr.in6, sizeof(struct in6_addr));
            rte_memcpy(ip6h->dst_addr, &conn->dest->addr.in6, sizeof(struct in6_addr));

            mbuf->l3_len = sizeof(*ip6h);
            mbuf->ol_flags |= PKT_TX_IPV6;
        }
    } else {
        if ((int)conn->out_af == AF_INET) {
            ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv4_hdr));
            if (!ip4h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip4h->version_ihl     = DPVS_IPV4_DEFAULT_VERSION_IHL;
            ip4h->total_length    = htons(mbuf->pkt_len);
            ip4h->packet_id       = 0;
            ip4h->fragment_offset = htons(DPVS_IPV4_HDR_DF_FLAG);
            ip4h->time_to_live    = DPVS_IPV4_DEFAULT_TTL;
            ip4h->next_proto_id   = IPPROTO_TCP;
            ip4h->src_addr        = conn->dest->vaddr.in.s_addr;
            ip4h->dst_addr        = conn->caddr.in.s_addr;
            ip4h->hdr_checksum = 0;

            mbuf->l3_len = sizeof(*ip4h);
            mbuf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
        } else {
            int plen = mbuf->pkt_len;
            ip6h = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv6_hdr));
            if (!ip6h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip6h->vtc_flow  = rte_cpu_to_be_32(DPVS_IPV6_DEFAULT_VTC_FLOW);;
            ip6h->payload_len = htons(plen);
            ip6h->hop_limits = DPVS_IPV6_DEFAULT_HOT_LIMIT;
            ip6h->proto     = IPPROTO_TCP;
            rte_memcpy(ip6h->src_addr, &conn->dest->vaddr.in6, sizeof(struct in6_addr));
            rte_memcpy(ip6h->dst_addr, &conn->caddr.in6, sizeof(struct in6_addr));

            mbuf->l3_len = sizeof(*ip6h);
            mbuf->ol_flags |= PKT_TX_IPV6;
        }        
    }

    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
    if (!eth_hdr) {
        return EDPVS_NOROOM;
    }

    if (dir == DPVS_CONN_DIR_INBOUND) {
        rte_ether_addr_copy(&conn->dest->in_dmac, &eth_hdr->d_addr);
        rte_ether_addr_copy(&conn->dest->in_smac, &eth_hdr->s_addr);
        if ((int)conn->in_af == AF_INET) {
            eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
            mbuf->packet_type = RTE_ETHER_TYPE_IPV4;
        } else {
            eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
            mbuf->packet_type = RTE_ETHER_TYPE_IPV6;
        }
    } else {
        rte_ether_addr_copy(&conn->out_dmac, &eth_hdr->d_addr);
        rte_ether_addr_copy(&conn->out_smac, &eth_hdr->s_addr);
        if ((int)conn->out_af == AF_INET) {
            eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
            mbuf->packet_type = RTE_ETHER_TYPE_IPV4;
        } else {
            eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
            mbuf->packet_type = RTE_ETHER_TYPE_IPV6;
        }
    }

    netif_xmit(mbuf, xmit_dev);

    return EDPVS_OK;
}

int lb_tcp_conn_expire(struct lb_conn *conn)
{
    int err = EDPVS_OK;

    if (conn->dest->fwdmode == DPVS_FWD_MODE_NAT
            || conn->dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        /* send RST to RS and client */
        err = lb_tcp_send_rst(conn, DPVS_CONN_DIR_INBOUND);
        if (err != EDPVS_OK) {
            RTE_LOG(WARNING, IPVS, "%s: fail RST RS.\n", __func__);
        }
        err = lb_tcp_send_rst(conn, DPVS_CONN_DIR_OUTBOUND);
        if (err != EDPVS_OK) {
            RTE_LOG(WARNING, IPVS, "%s: fail RST Client.\n", __func__);
        }
    }

    return err;
}

int lb_ipv4_tcp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip4_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    if ((th->tcp_flags & RTE_TCP_SYN_FLAG) && !(th->tcp_flags & RTE_TCP_ACK_FLAG)) {
        tcp_in_remove_ts(th);
        tcp_ipv4_in_add_toa(conn, mbuf, th, dest->mtu);
    }

    th->src_port = conn->lport;
    th->dst_port = conn->dest->port;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv4_tcp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip4_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    if ((th->tcp_flags & RTE_TCP_SYN_FLAG) && (th->tcp_flags & RTE_TCP_ACK_FLAG)) {
        //tcp_out_adjust_mss(af, th);
    }

    lb_tcp_out_save_seq(mbuf, conn, th);

    th->src_port = conn->dest->vport;
    th->dst_port = conn->cport;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv6_tcp_fnat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int ip6hdrlen = 0;

    ip6hdrlen = ip6_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, ip6hdrlen);

    if ((th->tcp_flags & RTE_TCP_SYN_FLAG) && !(th->tcp_flags & RTE_TCP_ACK_FLAG)) {
        tcp_in_remove_ts(th);
        tcp_ipv6_in_add_toa(conn, mbuf, th, dest->mtu);
    }

    th->src_port = conn->lport;
    th->dst_port = conn->dest->port;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv6_tcp_fnat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip6_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    if ((th->tcp_flags & RTE_TCP_SYN_FLAG) && (th->tcp_flags & RTE_TCP_ACK_FLAG)) {
        //tcp_out_adjust_mss(af, th);
    }

    lb_tcp_out_save_seq(mbuf, conn, th);

    th->src_port = conn->dest->vport;
    th->dst_port = conn->cport;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv4_tcp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip4_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    th->dst_port = conn->dest->port;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv4_tcp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip4_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    lb_tcp_out_save_seq(mbuf, conn, th);

    th->src_port = conn->dest->vport;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv6_tcp_nat_in_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int ip6hdrlen = 0;

    ip6hdrlen = ip6_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, ip6hdrlen);

    th->dst_port = conn->dest->port;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = ip6hdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}

int lb_ipv6_tcp_nat_out_handler(struct lb_dest *dest, struct lb_conn *conn, struct rte_mbuf *mbuf)
{
    struct rte_tcp_hdr *th;
    int iphdrlen = 0;

    iphdrlen = ip6_hdrlen(mbuf);

    th = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, iphdrlen);

    lb_tcp_out_save_seq(mbuf, conn, th);

    th->src_port = conn->dest->vport;
    th->cksum = 0;
    mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
    mbuf->l3_len = iphdrlen;
    mbuf->l4_len = ((struct tcphdr *)th)->doff << 2;

    return EDPVS_OK;
}
