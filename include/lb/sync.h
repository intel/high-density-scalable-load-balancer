/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __SYNC_H__
#define __SYNC_H__

#include <stdbool.h>

/* IPv4 sync packet format */
struct lb_sync_v4 {
    uint8_t         type;
    uint8_t         protocol;
    uint16_t        ver_size;
    uint8_t         flags;
    uint8_t         state;
    uint16_t        fwmark;     /* firewall mark */
    uint32_t        timeout;    /* connection timeout */
    uint16_t        lport;      /* local port */
    uint16_t        cport;      /* client port */
    uint16_t        dport;      /* destination port */
    uint16_t        vport;      /* virtual server port */
    uint32_t        laddr;      /* local address */
    uint32_t        caddr;      /* client address */
    uint32_t        daddr;      /* destination address */
    uint32_t        vaddr;      /* virtual server address */
};

/* IPv6 sync packet format */
struct lb_sync_v6 {
    uint8_t         type;
    uint8_t         protocol;
    uint16_t        ver_size;
    uint8_t         flags;
    uint8_t         state;
    uint16_t        fwmark;     /* firewall mark */
    uint32_t        timeout;    /* connection timeout */
    uint16_t        lport;      /* local port */
    uint16_t        cport;      /* client port */
    uint16_t        dport;      /* destination port */
    uint16_t        vport;      /* virtual server port */
    struct in6_addr laddr;      /* local address */
    struct in6_addr caddr;      /* client address */
    struct in6_addr daddr;      /* destination address */
    struct in6_addr vaddr;      /* virtual server address */
};

union lb_sync_conn {
    struct lb_sync_v4 v4;
    struct lb_sync_v6 v6;
};

/* Type field in IPv4/IPv6 sync packet */
#define PTYPE_INET6   0
#define PTYPE_F_INET6 (1 << PTYPE_INET6)

struct rte_mbuf;
struct lb_conn;
struct lb_service;

int lb_sync_init(void);
void lb_sync_term(void);

bool lb_sync_conn_needed(struct lb_conn *conn);
/*
  * Sending Version 1 messages
 * @param flush
 *   if true flush all sync packet to slave server
 *   if false buffer the sync connection, flush until buffer is full
 */
void lb_sync_send_message(struct lb_conn* conn, struct lb_service* lbs, bool flush);

/*
 * Called in lcore_process_packets, process it if it is sync packet, otherwise
 * handover it to netif_deliver_mbuf
 * @return
 *   -1 if it is not sync packet
 *    0 if it is sync packet.
 */
int lb_sync_process_message(struct rte_mbuf* mbuf);

bool lb_sync_lcore_is_active(void);
bool lb_sync_lcore_is_backup(void);

#endif /* __SYNC_H__ */

