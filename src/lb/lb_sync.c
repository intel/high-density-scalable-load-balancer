/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/ip_vs.h>
#include <linux/igmp.h>
#include <immintrin.h>
#include "rte_per_lcore.h"
#include "rte_lcore.h"
#include "rte_mbuf.h"
#include "rte_udp.h"
#include "rte_ether.h"
#include "rte_ip.h"
#include "rte_ethdev.h"
#include "rte_byteorder.h"
#include "rte_log.h"
#include "rte_atomic.h"
#include "rte_flow.h"
#include "rte_cycles.h"
#include "ipvs/conn.h"
#include "ipvs/proto.h"
#include "netif.h"
#include "common.h"
#include "inetaddr.h"
#include "ipv4.h"
#include "inet.h"
#include "ctrl.h"
#include "ipvs/conn.h"
#include "ipvs/proto_tcp.h"
#include "conf/netif.h"
#include "lb/conn.h"
#include "lb/sync.h"
#include "lb/igmp.h"
#include "lb/service.h"
#include "lb/timer.h"
#include "lb/ipv4.h"
#include "lb/ipv6.h"
#include "lb/ip.h"
#include "lb/dest.h"
#include "conf/sync.h"

#ifdef CONFIG_SYNC_DEBUG
#include "lb/sync_debug.h"
#endif /* CONFIG_SYNC_DEBUG */

#define RTE_LOGTYPE_LB_SYNC RTE_LOGTYPE_USER1

#define SYNC_PROTO_VER 2    /* Protocol version in header */

struct lb_sync_daemon_cfg {
    struct in_addr  mcast_group;     /* multicast IP address in network byte order */
    struct in_addr  mcast_ifia;      /* IP address of multicast tx/rx interface dev */
    struct rte_ether_addr
                    mcast_group_ea;  /* multicast ethernet address in network byte order */
    uint16_t        mcast_port;      /* port number in network byte order */
    struct netif_port
                    *dev_ref;        /* multicast tx/rx interface dev */
    uint8_t         mcast_ttl;       /* TTL value for sync msgs (1 .. 255).  The default value is 1 */
    //uint8_t         state;           /* 0x1: active, 0x2: backup */
    char            mcast_ifn[IP_VS_IFNAME_MAXLEN];  /* multicast tx/rx interface name */
    int             flow_id;
};

#define PVER_SHIFT 12      /* Shift to get version */
#define PVER_MASK  0x0FFF  /* Mask to strip version */

/* Version 1 header */
struct lb_sync_mesg {
    uint8_t  reserved;
    uint8_t  syncid;
    uint16_t size;
    uint8_t  nr_conns;
    uint8_t  version;
    uint16_t spare;
};

#ifdef CONFIG_SYNC_STAT
struct lb_sync_stats {
    uint64_t iconns;    /* Total number of successfully received sync connections. */
    uint64_t oconns;    /* Total number of successfully transmitted sync connections.*/
    uint64_t ierrors;   /* Total number of erroneous received sync connections. */
    uint64_t oerrors;   /* Total number of failed transmitted sync connections. */
    uint64_t tx_nombuf; /* Total number of TX mbuf allocation failures. */
};
static struct lb_sync_stats lcore_sync_stats[DPVS_MAX_LCORE];
#endif /* CONFIG_SYNC_STAT */

/* Delay for next all session sync(seconds) */
static const uint64_t g_sync_all_period = 600;
/*
 * Delay for next all session sync, must be updated
 * according to sync_all_period when init
 */
static lb_tick_t g_sync_all_ticks;
/*
 * Sync conn expiration timer cycles, must be updated according to
 * sync_all_period when init, shall be 2 * (converted-to-cycles(sync_all_period))
 */
static uint64_t g_sync_exp_cycles;

/*Sync packet headers total length*/
static const uint32_t g_sync_pkthdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                   sizeof(struct rte_udp_hdr) + sizeof(struct lb_sync_mesg);

static const uint32_t g_iter_conns_count_4 = (ETH_DATA_LEN 
                                            - sizeof(struct rte_ipv4_hdr) 
                                            - sizeof(struct rte_udp_hdr) 
                                            - sizeof(struct lb_sync_mesg)) / sizeof(struct lb_sync_v4);
static const uint32_t g_iter_conns_count_6 = (ETH_DATA_LEN
                                            - sizeof(struct rte_ipv4_hdr)
                                            - sizeof(struct rte_udp_hdr)
                                            - sizeof(struct lb_sync_mesg)) / sizeof(struct lb_sync_v6);
/* 
 * Used as the min connection count in each iteration, reset with max of 
 * g_iter_conns_count_4 and g_iter_conns_count_6 when initialization .
 */
static uint32_t g_iter_conns_count = 40;

/* the conn which match this mask must not be synced to backup server */
static const uint8_t g_conn_flags_mask = LB_CONN_F_DROP | LB_CONN_F_NEW | LB_CONN_F_SYNC;

/* 
 * If 1, create the session sync fdir rule on dest ip and port.
 * If 0, create the rule on src ip and port. 
 */
static RTE_DEFINE_PER_LCORE(uint8_t, this_lcore_fdir_rule_for_dst) = 0;
#define this_fdir_rule_for_dst (RTE_PER_LCORE(this_lcore_fdir_rule_for_dst))
#define SYNC_MSG_SRC_PORT 0;

/*
 * Shall use organization-local Scope multicast address from 239.0.0.0 to 239.255.255.255
 */
static struct lb_sync_daemon_cfg lcores_sync_cfg[DPVS_MAX_LCORE] = {
     {.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  1), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  1), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  2), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  2), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  3), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  3), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  4), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  4), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  5), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  5), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  6), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  6), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  7), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  7), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  8), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  8), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1,  9), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0,  9), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 10), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 10), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 11), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 11), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 12), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 12), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 13), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 13), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 14), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 14), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 15), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 15), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 16), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 16), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 17), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 17), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 18), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 18), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 19), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 19), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 20), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 20), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 21), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 21), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 22), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 22), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 23), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 23), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 24), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 24), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 25), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 25), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 26), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 26), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 27), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 27), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 28), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 28), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 29), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 29), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 30), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 30), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 31), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 31), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 32), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 32), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 33), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 33), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 34), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 34), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 35), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 35), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 36), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 36), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 37), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 37), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 38), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 38), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 39), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 39), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 40), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 40), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 41), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 41), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 42), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 42), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 43), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 43), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 44), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 44), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 45), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 45), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 46), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 46), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 47), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 47), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 48), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 48), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 49), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 49), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 50), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 50), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 51), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 51), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 52), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 52), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 53), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 53), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 54), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 54), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 55), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 55), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 56), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 56), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 57), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 57), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 58), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 58), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 59), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 59), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 60), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 60), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 61), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 61), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 62), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 62), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 63), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 63), .flow_id = -1}
    ,{.mcast_group.s_addr = RTE_IPV4(239, 1, 1, 64), .mcast_port = 8848, .mcast_ttl = 1, .mcast_ifn = "dpdk0", .mcast_ifia.s_addr = RTE_IPV4(192, 168, 0, 64), .flow_id = -1}
};

/* 0x1: active, 0x2: backup */
static uint8_t lcores_sync_state[DPVS_MAX_LCORE];

static struct netif_lcore_loop_job sync_init_job;

/* RFC2236 Page18. unit: seconds */
static uint64_t g_group_membership_interval = 260;
/* Must be updated on init */
static lb_tick_t g_group_membership_ticks;

static RTE_DEFINE_PER_LCORE(struct rte_mbuf *, this_lcore_curr_mbuf) = NULL;
static RTE_DEFINE_PER_LCORE(struct lb_timer,   this_lcore_sync_enable_timer);
static RTE_DEFINE_PER_LCORE(struct lb_timer,   this_lcore_mgroup_timer);

#define this_curr_mbuf          (RTE_PER_LCORE(this_lcore_curr_mbuf))
#define this_sync_enable_timer  (RTE_PER_LCORE(this_lcore_sync_enable_timer))
#define this_mgroup_timer       (RTE_PER_LCORE(this_lcore_mgroup_timer))

/* 
 * Used as input in avx512 gather function to clear returned result, only for 
 * ipv4 session sync 
 */
__m256i  g_base_src_4;
/* 
 * Used as input mask in avx512 gather function, if bit is 0, specified bits of 
 * returned result is cleared by corresponding bits in g_base_src_4. It is only
 * used for ipv4 session sync.
 */
__mmask8 g_base_k_4 = 0;
/* contain 8 64-bit address offset */
__m512i  g_vindex_4;
/* avx512 store data to lb_sync_v4 from this address offset */
const size_t g_store_offset_4 = sizeof(struct lb_sync_v4) - 32;

/* the function handler to batch send ipv4 session sync message */
lb_conn_handler_t g_lb_sync_batch_conn_handler_4;

/*
 * Add flow rule to make ingress sync packet flow into the specified lcore
 * @param ip
 *   Must be network byte order
 * @return
 *   flow_id if > 0
 *   error   if < 0
 */
static int lb_sync_add_filter(unsigned lcore_id, struct netif_port *dev, uint8_t rule_for_dst, uint32_t ip, uint16_t port)
{
    struct rte_flow_attr         attr;
    struct rte_flow_item         patterns[4];
    struct rte_flow_action       actions[2];
    struct rte_flow_action_queue queue;
    struct rte_flow_item_ipv4    ipv4_spec;
    struct rte_flow_item_ipv4    ipv4_mask;
    struct rte_flow_item_udp     udp_spec;
    struct rte_flow_item_udp     udp_mask;
    queueid_t                    qid;
    int                          err = EDPVS_OK;

    if (NULL == dev) {
        return EDPVS_INVAL;
    }

    err = netif_get_queue(dev, lcore_id, &qid);
    if (err != EDPVS_OK) {
        goto end;
    }

    /* only ingress packets will be checked */
    memset(&attr, 0, sizeof(attr));
    attr.ingress = 1;

    memset(patterns, 0, sizeof(patterns));
    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    if (rule_for_dst) {
        memset(&ipv4_spec, 0, sizeof(ipv4_spec));
        memset(&ipv4_mask, 0, sizeof(ipv4_mask));
        ipv4_spec.hdr.dst_addr = ip;
        ipv4_mask.hdr.dst_addr = 0xffffffff;
        patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        patterns[1].spec = &ipv4_spec;
        patterns[1].mask = &ipv4_mask;
    } else {
        memset(&ipv4_spec, 0, sizeof(ipv4_spec));
        memset(&ipv4_mask, 0, sizeof(ipv4_mask));
        ipv4_spec.hdr.src_addr = ip;
        ipv4_mask.hdr.src_addr = 0xffffffff;
        patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        patterns[1].spec = &ipv4_spec;
        patterns[1].mask = &ipv4_mask;
        /* udp port spec is necessary for FDIR rule in some situation */
        memset(&udp_spec, 0, sizeof(udp_spec));
        memset(&udp_mask, 0, sizeof(udp_mask));
        udp_spec.hdr.src_port = port;
        udp_mask.hdr.src_port = 0xFFFF;
        patterns[2].spec = &udp_spec;
        patterns[2].mask = &udp_mask;
    }
    patterns[2].type       = RTE_FLOW_ITEM_TYPE_UDP;

    patterns[3].type       = RTE_FLOW_ITEM_TYPE_END;

    /* put packet into rx queue */
    memset(actions, 0, sizeof(actions));
    memset(&queue, 0, sizeof(queue));
    queue.index     = qid;
    actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[0].conf = &queue;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;

    err = netif_flow_create(dev, &attr, patterns, actions);
end:
    return err;
}

bool lb_sync_conn_needed(struct lb_conn *conn)
{
    bool force = false;

    if (unlikely(NULL == conn)) {
        goto end;
    }

    if (conn->flags & LB_CONN_F_SYNC_SENT) {
        goto end;
    }
    if (IPPROTO_TCP == conn->l4_proto) {
        if (DPVS_TCP_S_ESTABLISHED == conn->state) {
            force = true;
        }
    } else if (IPPROTO_UDP == conn->l4_proto) {
        if (conn->flags & LB_CONN_F_STABLE) {
            force = true;
        }
    }
end:
    return force;
}

static int lb_sync_enqueue_curr_mbuf(unsigned lcore_id)
{
    int err;
    unsigned int offset;

    struct rte_ipv4_hdr *ip4h;
    struct rte_udp_hdr  *udph;
    struct lb_sync_mesg *synch;

    if (unlikely(NULL == this_curr_mbuf)) {
        return 0;
    }

    offset = sizeof(struct rte_ether_hdr);
    ip4h   = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_ipv4_hdr *, offset);
    offset = offset + sizeof(struct rte_ipv4_hdr);
    udph   = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_udp_hdr *, offset);
    offset = offset + sizeof(struct rte_udp_hdr);
    synch  = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct lb_sync_mesg *, offset);

    /*When current mbuf is enqueued, change len to network order, and compute check sum*/
    ip4h->total_length = rte_cpu_to_be_16(ip4h->total_length);
    udph->dgram_len    = rte_cpu_to_be_16(udph->dgram_len);
    synch->size        = rte_cpu_to_be_16(synch->size);

    this_curr_mbuf->l2_len = sizeof(struct rte_ether_hdr);
    this_curr_mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
    ip4h->hdr_checksum = 0;
    //ip4h->hdr_checksum = ip_compute_csum(ip4h, sizeof(struct rte_ipv4_hdr));
    this_curr_mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    udph->dgram_cksum  = 0;
    //udph->dgram_cksum  = ip4_udptcp_cksum(ip4h, udph);
    this_curr_mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
#ifdef CONFIG_SYNC_DEBUG_LOOPBACK
    this_curr_mbuf->packet_type = ETH_PKT_MULTICAST;
    err = lb_sync_process_message(this_curr_mbuf);
#else
    err = netif_xmit(this_curr_mbuf, lcores_sync_cfg[lcore_id].dev_ref);
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */
#ifdef CONFIG_SYNC_STAT
    if (likely(EDPVS_OK == err)) {
        lcore_sync_stats[lcore_id].oconns += synch->nr_conns;
    } else {
        lcore_sync_stats[lcore_id].oerrors += synch->nr_conns;
    }
#endif /* CONFIG_SYNC_STAT */
    this_curr_mbuf = NULL;
    return err;
}

void lb_sync_send_message(struct lb_conn *conn, struct lb_service *lbs, bool flush)
{
    unsigned lcore_id;
    unsigned int sync_conn_len;
    unsigned int total_len;
    unsigned int offset;
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *ip4h;
    struct rte_udp_hdr *udph;
    struct lb_sync_mesg *synch;
    union lb_sync_conn *sync_conn;

    if (unlikely(NULL == conn || NULL == lbs)) {
        return;
    }

    lcore_id = rte_lcore_id();
    if (unlikely(NULL == lcores_sync_cfg[lcore_id].dev_ref)) {
        return;
    }

    if (AF_INET6 == lbs->af) {
        sync_conn_len = sizeof(struct lb_sync_v6);
    } else {
        sync_conn_len = sizeof(struct lb_sync_v4);
    }
check_mbuf:
    if (NULL == this_curr_mbuf) {
        this_curr_mbuf = rte_pktmbuf_alloc(lcores_sync_cfg[lcore_id].dev_ref->mbuf_pool);
        if (unlikely(NULL == this_curr_mbuf)) {
            goto mbuferr;
        }

        total_len = g_sync_pkthdr_len + sync_conn_len;
        ethh = (struct rte_ether_hdr *)rte_pktmbuf_append(this_curr_mbuf, total_len);
        if (unlikely(NULL == ethh)) {
            goto mbuferr;
        }
        offset    = sizeof(struct rte_ether_hdr);
        ip4h      = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_ipv4_hdr *, offset);
        offset    = offset + sizeof(struct rte_ipv4_hdr);
        udph      = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_udp_hdr *, offset);
        offset    = offset + sizeof(struct rte_udp_hdr);
        synch     = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct lb_sync_mesg *, offset);
        offset    = offset + sizeof(struct lb_sync_mesg);
        sync_conn = rte_pktmbuf_mtod_offset(this_curr_mbuf, union lb_sync_conn *, offset);

        ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].dev_ref->addr, &ethh->s_addr);
        rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].mcast_group_ea, &ethh->d_addr);

        ip4h->version_ihl     = (4 << 4 | (sizeof(struct rte_ipv4_hdr)) >> 2);
        ip4h->type_of_service = 0xc0;
        ip4h->fragment_offset = rte_cpu_to_be_16(IP_DF);
        ip4h->time_to_live    = lcores_sync_cfg[lcore_id].mcast_ttl;
        ip4h->dst_addr        = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
        ip4h->src_addr        = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
        ip4h->next_proto_id   = IPPROTO_UDP;
        ip4h->packet_id       = 0;
        /*use host order, change to network order before tansmit*/
        ip4h->total_length = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
                             sizeof(struct lb_sync_mesg);

        udph->src_port = SYNC_MSG_SRC_PORT;
        udph->dst_port = lcores_sync_cfg[lcore_id].mcast_port;
        /*use host order, change to network order before tansmit*/
        udph->dgram_len = sizeof(struct rte_udp_hdr) + sizeof(struct lb_sync_mesg);

        synch->reserved = 0;  /* old nr_conns i.e. must be zero now */
        synch->version  = SYNC_PROTO_VER;
        synch->syncid   = (uint8_t)lcore_id;
        /*use host order, change to network order before tansmit*/
        synch->size     = sizeof(struct lb_sync_mesg);
        synch->nr_conns = 0;
        synch->spare    = 0;
    } else {
        offset = sizeof(struct rte_ether_hdr);
        ip4h   = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_ipv4_hdr *, offset);
        offset = offset + sizeof(struct rte_ipv4_hdr);
        udph   = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct rte_udp_hdr *, offset);
        offset = offset + sizeof(struct rte_udp_hdr);
        synch  = rte_pktmbuf_mtod_offset(this_curr_mbuf, struct lb_sync_mesg *, offset);
        if (unlikely(ip4h->total_length + sync_conn_len > lcores_sync_cfg[lcore_id].dev_ref->mtu)) {
            lb_sync_enqueue_curr_mbuf(lcore_id);
            goto check_mbuf;
        }
        sync_conn = (union lb_sync_conn *)rte_pktmbuf_append(this_curr_mbuf, sync_conn_len);
        if (unlikely(NULL == sync_conn)) {
            /*if no tail room, enqueue current mbuf, and try to allocate new mbuf*/
            lb_sync_enqueue_curr_mbuf(lcore_id);
            goto check_mbuf;
        }
    }

    ip4h->total_length = ip4h->total_length + sync_conn_len;
    udph->dgram_len    = udph->dgram_len + sync_conn_len;
    synch->size        = synch->size + sync_conn_len;
    synch->nr_conns++;

    sync_conn->v4.type     = (lbs->af == AF_INET6 ? PTYPE_F_INET6 : 0);
    sync_conn->v4.ver_size = rte_cpu_to_be_16(sync_conn_len & PVER_MASK);  /* Version 0 */
    sync_conn->v4.flags    = conn->flags;
    sync_conn->v4.state    = conn->state;
    sync_conn->v4.protocol = conn->l4_proto;
    sync_conn->v4.cport    = conn->cport;
    sync_conn->v4.lport    = conn->lport;
    sync_conn->v4.vport    = conn->dest->vport;
    sync_conn->v4.dport    = conn->dest->port;
    sync_conn->v4.fwmark   = 0;
    sync_conn->v4.timeout = rte_cpu_to_be_32(conn->timer.delay);

    if (lbs->af == AF_INET6) {
        rte_memcpy(&sync_conn->v6.caddr, &conn->caddr.in6,       sizeof(sync_conn->v6.caddr));
        rte_memcpy(&sync_conn->v6.vaddr, &conn->dest->vaddr.in6, sizeof(sync_conn->v6.vaddr));
        rte_memcpy(&sync_conn->v6.daddr, &conn->dest->addr.in6,  sizeof(sync_conn->v6.daddr));
        rte_memcpy(&sync_conn->v6.laddr, &conn->laddr.in6,       sizeof(sync_conn->v6.laddr));
    } else {
        sync_conn->v4.caddr = conn->caddr.in.s_addr;
        sync_conn->v4.vaddr = conn->dest->vaddr.in.s_addr;
        sync_conn->v4.daddr = conn->dest->addr.in.s_addr;
        sync_conn->v4.laddr = conn->laddr.in.s_addr;
    }

    if (flush) {
        lb_sync_enqueue_curr_mbuf(lcore_id);
    }
    conn->flags |= LB_CONN_F_SYNC_SENT;
    return;
mbuferr:
    rte_pktmbuf_free(this_curr_mbuf);
    this_curr_mbuf = NULL;
#ifdef CONFIG_SYNC_STAT
    lcore_sync_stats[lcore_id].tx_nombuf++;
#endif /* CONFIG_SYNC_STAT */
}

static inline void lb_sync_try_expire_conn_4(struct lb_conn *conn)
{
    uint64_t now = rte_rdtsc();
    uint64_t time_diff;
    /* delay is reused as timer cycle elapse */
    if (likely(now > conn->timer.delay)) {
        time_diff = now - conn->timer.delay;
    } else {
        time_diff = UINT64_MAX - conn->timer.delay + now;
    }
    if (time_diff >= g_sync_exp_cycles) {
        /* delete synced conn when it is not updated intime */
        ipv4_conn_expire_sync_conn(conn);
    }
}

static inline void lb_sync_try_expire_conn_6(struct lb_conn *conn)
{
    uint64_t now = rte_rdtsc();
    uint64_t time_diff;
    /* delay is reused as timer cycle elapse */
    if (likely(now > conn->timer.delay)) {
        time_diff = now - conn->timer.delay;
    } else {
        time_diff = UINT64_MAX - conn->timer.delay + now;
    }
    if (time_diff >= g_sync_exp_cycles) {
        /* delete synced conn when it is not updated intime */
        ipv6_conn_expire_sync_conn(conn);
    }
}

static void lb_sync_batch_conn_handler_avx512_4(struct lb_conn* conns[], uint32_t conns_count, int af)
{
#ifdef CONFIG_SYNC_DEBUG
    char buf[64];
#endif
    int err;
    uint32_t i;
    unsigned lcore_id;
    uint32_t sync_conns_len;
    uint32_t total_len;
    uint32_t offset;
    uint32_t send_count;
    struct rte_ether_hdr* ethh;
    struct rte_ipv4_hdr* ip4h;
    struct rte_udp_hdr* udph;
    struct lb_sync_mesg* synch;
    struct lb_sync_v4* sync_conn;
    uint8_t  flags;
    struct rte_mbuf* curr_mbuf;
    long long ptr_diff;
    __m256i res;
    __m512i temp_vindex;

    if (unlikely(NULL == conns || 0 == conns_count)) {
        return;
    }

    rte_prefetch0(conns[0]);
    send_count = conns_count;
    lcore_id = rte_lcore_id();
    sync_conns_len = sizeof(struct lb_sync_v4) * conns_count;

    curr_mbuf = rte_pktmbuf_alloc(lcores_sync_cfg[lcore_id].dev_ref->mbuf_pool);
    if (unlikely(NULL == curr_mbuf)) {
        return;
    }
    rte_prefetch0(rte_pktmbuf_mtod(curr_mbuf, void*));

    total_len = g_sync_pkthdr_len + sync_conns_len;
    ethh = (struct rte_ether_hdr*)rte_pktmbuf_append(curr_mbuf, total_len);
    if (unlikely(NULL == ethh)) {
        rte_pktmbuf_free(curr_mbuf);
        return;
    }

    offset = sizeof(struct rte_ether_hdr);
    ip4h = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_ipv4_hdr*, offset);
    offset = offset + sizeof(struct rte_ipv4_hdr);
    udph = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_udp_hdr*, offset);
    offset = offset + sizeof(struct rte_udp_hdr);
    synch = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_mesg*, offset);
    offset = offset + sizeof(struct lb_sync_mesg);
    sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v4*, offset);

    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].dev_ref->addr, &ethh->s_addr);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].mcast_group_ea, &ethh->d_addr);

    ip4h->version_ihl = (4 << 4 | (sizeof(struct rte_ipv4_hdr)) >> 2);
    ip4h->type_of_service = 0xc0;
    ip4h->fragment_offset = rte_cpu_to_be_16(IP_DF);
    ip4h->time_to_live = lcores_sync_cfg[lcore_id].mcast_ttl;
    ip4h->dst_addr = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
    ip4h->src_addr = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
    ip4h->next_proto_id = IPPROTO_UDP;
    ip4h->packet_id = 0;

    udph->src_port = SYNC_MSG_SRC_PORT;
    udph->dst_port = lcores_sync_cfg[lcore_id].mcast_port;

    synch->reserved = 0;  /* old nr_conns i.e. must be zero now */
    synch->version = SYNC_PROTO_VER;
    synch->syncid = (uint8_t)lcore_id;
    synch->spare = 0;

    curr_mbuf->l2_len = sizeof(struct rte_ether_hdr);
    curr_mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
    ip4h->hdr_checksum = 0;
    curr_mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    udph->dgram_cksum = 0;
    curr_mbuf->ol_flags |= PKT_TX_UDP_CKSUM;

    for (i = 0; i < conns_count; i++) {
        rte_prefetch0(conns[i + 1]);
        flags = conns[i]->flags & g_conn_flags_mask;
        if (flags) {
            send_count--;
            sync_conns_len = sync_conns_len - sizeof(struct lb_sync_v4);
            if (flags & LB_CONN_F_SYNC) {
                lb_sync_try_expire_conn_4(conns[i]);
            }
        } else {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: all session sync running, session: caddr[cport]:%s[%u] will be sent from lcore_id:%u.\n"
                , __func__, inet_ntop(af, &conns[i]->caddr, buf, sizeof(buf)), ntohs(conns[i]->cport), rte_lcore_id());
#endif
            ptr_diff = (uint8_t*)conns[i]->dest - (uint8_t*)conns[i];
            temp_vindex = _mm512_set_epi64(ptr_diff
                , ptr_diff
                , 0
                , 0
                , ptr_diff
                , 0
                , 0, 0);
            temp_vindex = _mm512_add_epi64(g_vindex_4, temp_vindex);
            res = _mm512_mask_i64gather_epi32(g_base_src_4, g_base_k_4, temp_vindex, conns[i], 1);
            /* 32 bytes: 256 bits, store result into sync_conn from flags to vaddr. note: size of lb_sync_v4 is larger than 32 */
            _mm256_storeu_si256((void*)((uint8_t*)sync_conn + g_store_offset_4), res);

            sync_conn->type     = 0; //ipv4
            sync_conn->ver_size = rte_cpu_to_be_16(sizeof(struct lb_sync_v4) & PVER_MASK);  /* Version 0 */
            sync_conn->flags    = conns[i]->flags;
            sync_conn->state    = conns[i]->state;
            sync_conn->protocol = conns[i]->l4_proto;
            sync_conn->fwmark   = 0;
            //The timeout field in synced session will be updated in backup server
            //any value larger than 0 is ok.
            sync_conn->timeout  = rte_cpu_to_be_32(1);
            conns[i]->flags |= LB_CONN_F_SYNC_SENT;


            offset = offset + sizeof(struct lb_sync_v4);
            sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v4*, offset);
        }
    }

    ip4h->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)
        + sizeof(struct lb_sync_mesg) + sync_conns_len);
    udph->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->size = rte_cpu_to_be_16(sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->nr_conns = send_count;
    (void)err;
#ifdef CONFIG_SYNC_DEBUG_LOOPBACK
    curr_mbuf->packet_type = ETH_PKT_MULTICAST;
    err = lb_sync_process_message(curr_mbuf);
#else
    err = netif_xmit(curr_mbuf, lcores_sync_cfg[lcore_id].dev_ref);
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */
#ifdef CONFIG_SYNC_STAT
    if (likely(EDPVS_OK == err)) {
        lcore_sync_stats[lcore_id].oconns += synch->nr_conns;
    }
    else {
        lcore_sync_stats[lcore_id].oerrors += synch->nr_conns;
    }
#endif /* CONFIG_SYNC_STAT */
}

static void lb_sync_batch_conn_handler_4(struct lb_conn *conns[], uint32_t conns_count, int af)
{
#ifdef CONFIG_SYNC_DEBUG
    char buf[64];
#endif
    int err;
    uint32_t i;
    unsigned lcore_id;
    uint32_t sync_conns_len;
    uint32_t total_len;
    uint32_t offset;
    uint32_t send_count;
    struct rte_ether_hdr* ethh;
    struct rte_ipv4_hdr* ip4h;
    struct rte_udp_hdr* udph;
    struct lb_sync_mesg* synch;
    struct lb_sync_v4* sync_conn;
    uint8_t  flags;
    struct rte_mbuf* curr_mbuf;

    if (unlikely(NULL == conns || 0 == conns_count)) {
        return;
    }

    rte_prefetch0(conns[0]);
    send_count     = conns_count;
    lcore_id       = rte_lcore_id();
    sync_conns_len = sizeof(struct lb_sync_v4) * conns_count;

    curr_mbuf = rte_pktmbuf_alloc(lcores_sync_cfg[lcore_id].dev_ref->mbuf_pool);
    if (unlikely(NULL == curr_mbuf)) {
        return;
    }
    rte_prefetch0(rte_pktmbuf_mtod(curr_mbuf, void*));

    total_len = g_sync_pkthdr_len + sync_conns_len;
    ethh = (struct rte_ether_hdr*)rte_pktmbuf_append(curr_mbuf, total_len);
    if (unlikely(NULL == ethh)) {
        rte_pktmbuf_free(curr_mbuf);
        return;
    }

    offset    = sizeof(struct rte_ether_hdr);
    ip4h      = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_ipv4_hdr*, offset);
    offset    = offset + sizeof(struct rte_ipv4_hdr);
    udph      = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_udp_hdr*, offset);
    offset    = offset + sizeof(struct rte_udp_hdr);
    synch     = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_mesg*, offset);
    offset    = offset + sizeof(struct lb_sync_mesg);
    sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v4*, offset);

    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].dev_ref->addr,  &ethh->s_addr);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].mcast_group_ea, &ethh->d_addr);

    ip4h->version_ihl     = (4 << 4 | (sizeof(struct rte_ipv4_hdr)) >> 2);
    ip4h->type_of_service = 0xc0;
    ip4h->fragment_offset = rte_cpu_to_be_16(IP_DF);
    ip4h->time_to_live    = lcores_sync_cfg[lcore_id].mcast_ttl;
    ip4h->dst_addr        = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
    ip4h->src_addr        = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
    ip4h->next_proto_id   = IPPROTO_UDP;
    ip4h->packet_id       = 0;

    udph->src_port = SYNC_MSG_SRC_PORT;
    udph->dst_port = lcores_sync_cfg[lcore_id].mcast_port;

    synch->reserved = 0;  /* old nr_conns i.e. must be zero now */
    synch->version  = SYNC_PROTO_VER;
    synch->syncid   = (uint8_t)lcore_id;
    synch->spare    = 0;

    curr_mbuf->l2_len    = sizeof(struct rte_ether_hdr);
    curr_mbuf->l3_len    = sizeof(struct rte_ipv4_hdr);
    ip4h->hdr_checksum   = 0;
    curr_mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    udph->dgram_cksum    = 0;
    curr_mbuf->ol_flags |= PKT_TX_UDP_CKSUM;

    for (i = 0; i < conns_count; i++) {
        rte_prefetch0(conns[i + 1]);
        flags = conns[i]->flags & g_conn_flags_mask;
        if (flags) {
            send_count--;
            sync_conns_len = sync_conns_len - sizeof(struct lb_sync_v4);
            if (flags & LB_CONN_F_SYNC) {
                lb_sync_try_expire_conn_4(conns[i]);
            }
        } else {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: all session sync running, session: caddr[cport]:%s[%u] will be sent from lcore_id:%u.\n"
                    , __func__, inet_ntop(af, &conns[i]->caddr, buf, sizeof(buf)), ntohs(conns[i]->cport), rte_lcore_id());
#endif

            sync_conn->type     = 0; //ipv4
            sync_conn->ver_size = rte_cpu_to_be_16(sizeof(struct lb_sync_v4) & PVER_MASK);  /* Version 0 */
            sync_conn->flags    = conns[i]->flags;
            sync_conn->state    = conns[i]->state;
            sync_conn->protocol = conns[i]->l4_proto;
            sync_conn->cport    = conns[i]->cport;
            sync_conn->lport    = conns[i]->lport;
            sync_conn->vport    = conns[i]->dest->vport;
            sync_conn->dport    = conns[i]->dest->port;
            sync_conn->fwmark   = 0;
            //The timeout field in synced session will be updated in backup server
            sync_conn->timeout = rte_cpu_to_be_32(conns[i]->timer.delay);
            sync_conn->caddr   = conns[i]->caddr.in.s_addr;
            sync_conn->laddr   = conns[i]->laddr.in.s_addr;
            sync_conn->vaddr   = conns[i]->dest->vaddr.in.s_addr;
            sync_conn->daddr   = conns[i]->dest->addr.in.s_addr; /* TODO improve dest access performance */

            conns[i]->flags   |= LB_CONN_F_SYNC_SENT;

            offset    = offset + sizeof(struct lb_sync_v4);
            sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v4*, offset);
        }
    }

    ip4h->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)
                                          + sizeof(struct lb_sync_mesg) + sync_conns_len);
    udph->dgram_len    = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->size        = rte_cpu_to_be_16(sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->nr_conns    = send_count;
    (void)err;
#ifdef CONFIG_SYNC_DEBUG_LOOPBACK
    curr_mbuf->packet_type = ETH_PKT_MULTICAST;
    err = lb_sync_process_message(curr_mbuf);
#else
    err = netif_xmit(curr_mbuf, lcores_sync_cfg[lcore_id].dev_ref);
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */
#ifdef CONFIG_SYNC_STAT
    if (likely(EDPVS_OK == err)) {
        lcore_sync_stats[lcore_id].oconns += synch->nr_conns;
    }
    else {
        lcore_sync_stats[lcore_id].oerrors += synch->nr_conns;
    }
#endif /* CONFIG_SYNC_STAT */
}

static void lb_sync_batch_conn_handler_6(struct lb_conn* conns[], uint32_t conns_count, int af)
{
#ifdef CONFIG_SYNC_DEBUG
    char buf[64];
#endif
    int err;
    uint32_t i;
    unsigned lcore_id;
    uint32_t sync_conns_len;
    uint32_t total_len;
    uint32_t offset;
    uint32_t send_count;
    struct rte_ether_hdr* ethh;
    struct rte_ipv4_hdr* ip4h;
    struct rte_udp_hdr* udph;
    struct lb_sync_mesg* synch;
    struct lb_sync_v6* sync_conn;
    uint8_t  flags;
    struct rte_mbuf* curr_mbuf;

    if (unlikely(NULL == conns || 0 == conns_count)) {
        return;
    }

    rte_prefetch0(conns[0]);
    send_count     = conns_count;
    lcore_id       = rte_lcore_id();
    sync_conns_len = sizeof(struct lb_sync_v6) * conns_count;

    curr_mbuf = rte_pktmbuf_alloc(lcores_sync_cfg[lcore_id].dev_ref->mbuf_pool);
    if (unlikely(NULL == curr_mbuf)) {
        return;
    }
    rte_prefetch0(rte_pktmbuf_mtod(curr_mbuf, void*));

    total_len = g_sync_pkthdr_len + sync_conns_len;
    ethh = (struct rte_ether_hdr*)rte_pktmbuf_append(curr_mbuf, total_len);
    if (unlikely(NULL == ethh)) {
        rte_pktmbuf_free(curr_mbuf);
        return;
    }

    offset    = sizeof(struct rte_ether_hdr);
    ip4h      = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_ipv4_hdr*, offset);
    offset    = offset + sizeof(struct rte_ipv4_hdr);
    udph      = rte_pktmbuf_mtod_offset(curr_mbuf, struct rte_udp_hdr*, offset);
    offset    = offset + sizeof(struct rte_udp_hdr);
    synch     = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_mesg*, offset);
    offset    = offset + sizeof(struct lb_sync_mesg);
    sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v6*, offset);

    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].dev_ref->addr, &ethh->s_addr);
    rte_ether_addr_copy(&lcores_sync_cfg[lcore_id].mcast_group_ea, &ethh->d_addr);

    ip4h->version_ihl     = (4 << 4 | (sizeof(struct rte_ipv4_hdr)) >> 2);
    ip4h->type_of_service = 0xc0;
    ip4h->fragment_offset = rte_cpu_to_be_16(IP_DF);
    ip4h->time_to_live    = lcores_sync_cfg[lcore_id].mcast_ttl;
    ip4h->dst_addr        = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
    ip4h->src_addr        = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
    ip4h->next_proto_id   = IPPROTO_UDP;
    ip4h->packet_id       = 0;

    udph->src_port = SYNC_MSG_SRC_PORT;
    udph->dst_port = lcores_sync_cfg[lcore_id].mcast_port;

    synch->reserved = 0;  /* old nr_conns i.e. must be zero now */
    synch->version  = SYNC_PROTO_VER;
    synch->syncid   = (uint8_t)lcore_id;
    synch->spare    = 0;

    curr_mbuf->l2_len    = sizeof(struct rte_ether_hdr);
    curr_mbuf->l3_len    = sizeof(struct rte_ipv4_hdr);
    ip4h->hdr_checksum   = 0;
    curr_mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    udph->dgram_cksum    = 0;
    curr_mbuf->ol_flags |= PKT_TX_UDP_CKSUM;

    for (i = 0; i < conns_count; i++) {
        rte_prefetch0(conns[i + 1]);
        flags = conns[i]->flags & g_conn_flags_mask;
        if (flags) {
            send_count--;
            sync_conns_len = sync_conns_len - sizeof(struct lb_sync_v6);
            if (flags & LB_CONN_F_SYNC) {
                lb_sync_try_expire_conn_6(conns[i]);
            }
        } else {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: all session sync running, session: caddr[cport]:%s[%u] will be sent from lcore_id:%u.\n"
                    , __func__, inet_ntop(af, &conns[i]->caddr, buf, sizeof(buf)), ntohs(conns[i]->cport), rte_lcore_id());
#endif
            sync_conn->type     = PTYPE_F_INET6; //ipv6
            sync_conn->ver_size = rte_cpu_to_be_16(sizeof(struct lb_sync_v6) & PVER_MASK);  /* Version 0 */
            sync_conn->flags    = conns[i]->flags;
            sync_conn->state    = conns[i]->state;
            sync_conn->protocol = conns[i]->l4_proto;
            sync_conn->cport    = conns[i]->cport;
            sync_conn->lport    = conns[i]->lport;
            sync_conn->vport    = conns[i]->dest->vport;
            sync_conn->dport    = conns[i]->dest->port;
            sync_conn->fwmark   = 0;
            sync_conn->timeout = rte_cpu_to_be_32(conns[i]->timer.delay);
            rte_memcpy(&sync_conn->caddr, &conns[i]->caddr.in6,       sizeof(sync_conn->caddr));
            rte_memcpy(&sync_conn->laddr, &conns[i]->laddr.in6,       sizeof(sync_conn->laddr));
            rte_memcpy(&sync_conn->vaddr, &conns[i]->dest->vaddr.in6, sizeof(sync_conn->vaddr));
            rte_memcpy(&sync_conn->daddr, &conns[i]->dest->addr.in6,  sizeof(sync_conn->daddr));

            conns[i]->flags |= LB_CONN_F_SYNC_SENT;

            offset    = offset + sizeof(struct lb_sync_v6);
            sync_conn = rte_pktmbuf_mtod_offset(curr_mbuf, struct lb_sync_v6*, offset);
        }
    }

    ip4h->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)
                                          + sizeof(struct lb_sync_mesg) + sync_conns_len);
    udph->dgram_len    = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->size        = rte_cpu_to_be_16(sizeof(struct lb_sync_mesg) + sync_conns_len);
    synch->nr_conns    = send_count;
    (void)err;
#ifdef CONFIG_SYNC_DEBUG_LOOPBACK
    curr_mbuf->packet_type = ETH_PKT_MULTICAST;
    err = lb_sync_process_message(curr_mbuf);
#else
    err = netif_xmit(curr_mbuf, lcores_sync_cfg[lcore_id].dev_ref);
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */
#ifdef CONFIG_SYNC_STAT
    if (likely(EDPVS_OK == err)) {
        lcore_sync_stats[lcore_id].oconns += synch->nr_conns;
    }
    else {
        lcore_sync_stats[lcore_id].oerrors += synch->nr_conns;
    }
#endif /* CONFIG_SYNC_STAT */
}

static void lb_sync_batch_conn_handler(struct lb_conn *conns[], uint32_t conns_count, int af)
{
    if (NULL == conns) {
        return;
    }
    if (AF_INET6 == af) {
        while (conns_count > 0) {
            if (conns_count > g_iter_conns_count_6) {
                lb_sync_batch_conn_handler_6(conns, g_iter_conns_count_6, af);
                conns = conns + g_iter_conns_count_6;
                conns_count = conns_count - g_iter_conns_count_6;
            } else {
                lb_sync_batch_conn_handler_6(conns, conns_count, af);
                conns_count = 0;
            }
        }
    } else {
        while (conns_count > 0) {
            if (conns_count > g_iter_conns_count_4) {
                g_lb_sync_batch_conn_handler_4(conns, g_iter_conns_count_4, af);
                conns = conns + g_iter_conns_count_4;
                conns_count = conns_count - g_iter_conns_count_4;
            } else {
                g_lb_sync_batch_conn_handler_4(conns, conns_count, af);
                conns_count = 0;
            }
        }
    }
}

#ifndef CONFIG_SYNC_DEBUG_LOOPBACK
static int lb_sync_add_sync_conn(struct lb_conn_param *conn_param)
{
    int err = 0;
    struct lb_service* lbs = NULL;
    struct lb_conn_hash_elem* hash_elem = NULL;
    struct lb_conn_hash_elem_free hash_elem_free;
    struct lb_conn* conn;
    struct dp_vs_flowid flow_id;
    conn_param->flags |= LB_CONN_F_SYNC;
    /* TODO Improve performance of getting lbs */
    lbs = lb_lcore_lookup_service_by_tup(conn_param->af, conn_param->proto, &conn_param->vaddr, conn_param->vport);
    if (likely(lbs != NULL)) {
        hash_elem = lb_conn_cache_get(conn_param->af, &conn_param->caddr, conn_param->cport);
        flow_id.value = lbs->markid;
        conn = lb_conn_get(hash_elem, conn_param->af, &conn_param->caddr, conn_param->cport, flow_id.id, &hash_elem_free);
        if (conn != NULL) {
            if (likely(conn->flags & LB_CONN_F_SYNC)) {
                if (likely(conn_param->timeout > 0)) {
                    conn_param->flags &= LB_CONN_F_BACKUP_UPD_MASK;
                    conn_param->flags |= conn->flags & ~LB_CONN_F_BACKUP_UPD_MASK;
                    conn->flags = conn_param->flags;
                    conn->state = conn_param->state;
                    //conn->laddr = conn_param->laddr; /* TODO sync laddr and lport. requirement TBD. */
                    //conn->lport = conn_param->lport;
                    /* Reuse delay as timer cycles when conn synced */
                    conn->timer.delay = rte_rdtsc();
                } else {
                    if (AF_INET6 == lbs->af) {
                        ipv6_conn_expire_sync_conn(conn);
                    }
                    else {
                        ipv4_conn_expire_sync_conn(conn);
                    }
                }
            }
        } else {
            if (likely(conn_param->timeout > 0)) {
                conn_param->timeout = rte_rdtsc();
                conn = lb_conn_new(lbs, conn_param);
                if (NULL == conn) {
                    err = -1;
                }
            } else {
                /* timeout is zero, no need to create connection */
            }
        } 
    } else {
        /* lbs not found */
        err = -1;
    }
    return err;
}
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */

static int lb_sync_proc_sync_conn(union lb_sync_conn *sync_conn, unsigned int size)
{
    int err = 0;
    unsigned int sync_conn_len;
    struct lb_conn_param conn_param;
    uint32_t fwmark;

    if (sync_conn->v6.type & PTYPE_F_INET6) {
        conn_param.af              = AF_INET6;
        conn_param.proto           = sync_conn->v6.protocol;
        conn_param.flags           = sync_conn->v6.flags & LB_CONN_F_BACKUP_MASK;
        conn_param.state           = sync_conn->v6.state;
        conn_param.caddr.in6       = sync_conn->v6.caddr;
        conn_param.vaddr.in6       = sync_conn->v6.vaddr;
        conn_param.daddr.in6       = sync_conn->v6.daddr;
        conn_param.laddr.in6       = sync_conn->v6.laddr;
        conn_param.cport           = sync_conn->v6.cport;
        conn_param.vport           = sync_conn->v6.vport;
        conn_param.dport           = sync_conn->v6.dport;
        conn_param.lport           = sync_conn->v6.lport;
        conn_param.timeout         = rte_be_to_cpu_32(sync_conn->v6.timeout);
        fwmark                     = rte_be_to_cpu_16(sync_conn->v6.fwmark);
        sync_conn_len              = sizeof(struct lb_sync_v6);
    } else if (!sync_conn->v4.type) {
        conn_param.af              = AF_INET;
        conn_param.proto           = sync_conn->v4.protocol;
        conn_param.flags           = sync_conn->v4.flags & LB_CONN_F_BACKUP_MASK;
        conn_param.state           = sync_conn->v4.state;
        conn_param.caddr.in.s_addr = sync_conn->v4.caddr;
        conn_param.vaddr.in.s_addr = sync_conn->v4.vaddr;
        conn_param.daddr.in.s_addr = sync_conn->v4.daddr;
        conn_param.laddr.in.s_addr = sync_conn->v4.laddr;
        conn_param.cport           = sync_conn->v4.cport;
        conn_param.vport           = sync_conn->v4.vport;
        conn_param.dport           = sync_conn->v4.dport;
        conn_param.lport           = sync_conn->v4.lport;
        conn_param.timeout         = rte_be_to_cpu_32(sync_conn->v4.timeout);
        fwmark                     = rte_be_to_cpu_16(sync_conn->v4.fwmark);
        sync_conn_len              = sizeof(struct lb_sync_v4);
    } else {
        err = -1;
        goto end;
    }
    (void)fwmark;
    if (unlikely(sync_conn_len != size)) {
        err = -1;
        goto end;
    }

#ifdef CONFIG_SYNC_DEBUG
    lb_sync_disp_sync_conn(sync_conn);
#endif
    if (unlikely(conn_param.flags & IP_VS_CONN_F_TEMPLATE)) {
        /* Not support persistent connection */
        err = -1;
        goto end;
    }
#ifndef CONFIG_SYNC_DEBUG_LOOPBACK
    err = lb_sync_add_sync_conn(&conn_param);
#endif /* CONFIG_SYNC_DEBUG_LOOPBACK */
end:
    return err;
}

int lb_sync_process_message(struct rte_mbuf *mbuf)
{
    int err = 0;
    unsigned lcore_id;
    unsigned int offset;
    bool group_test;
    bool proto_test;
    bool inetport_test;
    bool len_test;
    bool synch_test;
    int i;
    int nr_conns;
    unsigned int size;

    struct rte_ipv4_hdr *ip4h;
    struct rte_udp_hdr *udph;
    struct lb_sync_mesg *synch;
    union lb_sync_conn *sync_conn;
#ifdef CONFIG_SYNC_DEBUG
    char buf[64];
#endif
    if (unlikely(NULL == mbuf)) {
        return -1;
    }
    if (likely(mbuf->packet_type != ETH_PKT_MULTICAST)) {
        err = -1;
    } else {
        lcore_id = rte_lcore_id();
        /* TODO check length */
        offset = sizeof(struct rte_ether_hdr);
        ip4h   = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr*, offset);
        offset = offset + sizeof(struct rte_ipv4_hdr);
        udph   = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr*, offset);
        offset = offset + sizeof(struct rte_udp_hdr);
        synch  = rte_pktmbuf_mtod_offset(mbuf, struct lb_sync_mesg*, offset);
        /* TODO length check */
        group_test = (ip4h->dst_addr == lcores_sync_cfg[lcore_id].mcast_group.s_addr);
        /*
         * Before call lb_sync_process_message, MAC dest addr shall be checked
         * to make sure mbuf dest addr is multicast address, therefore likely()
         * used here can make performance better.
         */
        if (likely(group_test)) {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: dest_ip:%s sync packet received on lcore_id:%u.\n", __func__, inet_ntop(AF_INET, &ip4h->dst_addr, buf, sizeof(buf)), lcore_id);
#endif
            proto_test    = (IPPROTO_UDP == ip4h->next_proto_id);
            inetport_test = (udph->dst_port == lcores_sync_cfg[lcore_id].mcast_port);
            len_test      = ((mbuf->pkt_len > g_sync_pkthdr_len));
            synch_test = (SYNC_PROTO_VER == synch->version && 0 == synch->reserved && 0 == synch->spare);
            if (likely(proto_test && inetport_test && len_test && synch_test)) {
                nr_conns  = synch->nr_conns;
                offset    = offset + sizeof(struct lb_sync_mesg);
                sync_conn = rte_pktmbuf_mtod_offset(mbuf, union lb_sync_conn*, offset);
                for (i = 0; i < nr_conns; i++) {
                    size   = rte_be_to_cpu_16(sync_conn->v4.ver_size) & PVER_MASK;
                    offset = offset + size;
#ifdef CONFIG_SYNC_STAT
                    if (unlikely(offset > mbuf->pkt_len || rte_be_to_cpu_16(sync_conn->v4.ver_size) >> PVER_SHIFT)) {
                        lcore_sync_stats[lcore_id].ierrors++;
                        /* Wrong sync connection size, or it is unknown version */
                        break;
                    } else {
                        if (unlikely(lb_sync_proc_sync_conn(sync_conn, size) == -1)) {
                            lcore_sync_stats[lcore_id].ierrors++;
                        } else {
                            lcore_sync_stats[lcore_id].iconns++;
                        }
                    }
#else
                    if (unlikely(offset > mbuf->pkt_len || rte_be_to_cpu_16(sync_conn->v4.ver_size) >> PVER_SHIFT)) {
                        break;
                    } else {
                        lb_sync_proc_sync_conn(sync_conn, size);
                    }
#endif /* CONFIG_SYNC_STAT */
                    sync_conn = rte_pktmbuf_mtod_offset(mbuf, union lb_sync_conn*, offset);
                }
                rte_pktmbuf_free(mbuf);
            } else {
                err = -1;
            }
        } else {
            err = -1;
        }
    }
    return err;
}

static void lb_sync_enable_sync(void *arg)
{
    lb_conn_lcore_enable_iter(true);
#ifdef CONFIG_SYNC_DEBUG
#ifndef CONFIG_SYNC_DEBUG_NEW_CONNS
#define CONFIG_SYNC_DEBUG_NEW_CONNS 0
#endif
    lb_sync_lcore_new_conns(CONFIG_SYNC_DEBUG_NEW_CONNS);
    lb_sync_lcore_simple_new_conns(CONFIG_SYNC_DEBUG_NEW_CONNS);
#endif
}

static void lb_sync_join_group(void* arg)
{
    unsigned lcore_id = rte_lcore_id();
    igmp_join_group(lcores_sync_cfg[lcore_id].dev_ref
                   , &lcores_sync_cfg[lcore_id].mcast_group
                   , &lcores_sync_cfg[lcore_id].mcast_ifia);

    lb_lcore_timer_sched(&this_mgroup_timer, g_group_membership_ticks, lb_sync_join_group);
}

static int lb_sync_lcore_init(void *arg)
{
    unsigned lcore_id;
    int err = EDPVS_OK;

    lcore_id = rte_lcore_id();

    if (netif_lcore_is_idle(lcore_id)) {
        err = EDPVS_IDLE;
    } else {
        /* do nothing */
    }
    return err;
}

static void lb_sync_iter_done(void)
{
    int err;
    unsigned lcore_id = rte_lcore_id();
    lb_sync_enqueue_curr_mbuf(lcore_id);
    lb_conn_lcore_enable_iter(false);

    err = lb_lcore_timer_sched(&this_sync_enable_timer, g_sync_all_ticks, lb_sync_enable_sync);
    if (err != 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: enable sync timer failed. lcore %u cannot send sync packet.\n"
                , __func__, lcore_id);
    }
}

bool lb_sync_lcore_is_active(void)
{
    unsigned lcore_id = rte_lcore_id();
    return lcores_sync_state[lcore_id] & IP_VS_STATE_MASTER;
}

bool lb_sync_lcore_is_backup(void)
{
    unsigned lcore_id = rte_lcore_id();
    return lcores_sync_state[lcore_id] & IP_VS_STATE_BACKUP;
}

static int lb_sync_init_job(void *arg, int high_stat)
{
    int err;
    unsigned lcore_id = rte_lcore_id();

    if (netif_lcore_is_idle(lcore_id)) {
        return EDPVS_IDLE;
    }
    if (NULL == lcores_sync_cfg[lcore_id].dev_ref) {
        return EDPVS_INVAL;
    }
    (void)err;
    //Do not create fdir rule on initialization, since it can cause following 
    //fdir rule creation failure on some NIC
    //On initialization, do not enable sync timer and igmp timer, do not send igmp message.
    //Therefore sync daemon(both active and backup) is disabled on initialization.
    /*
    uint32_t rule_ip;
    uint16_t rule_port;
    if (this_fdir_rule_for_dst) {
        rule_ip   = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
        rule_port = lcores_sync_cfg[lcore_id].mcast_port;
    } else {
        rule_ip   = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
        rule_port = SYNC_MSG_SRC_PORT;
    }
    lcores_sync_cfg[lcore_id].flow_id = lb_sync_add_filter(lcore_id, lcores_sync_cfg[lcore_id].dev_ref, this_fdir_rule_for_dst
                                        , rule_ip
                                        , rule_port);
    if (lcores_sync_cfg[lcore_id].flow_id < 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: create flow rule failed. lcore %u cannot recv sync packet.\n"
                , __func__, lcore_id);
    }

    err = lb_lcore_timer_sched(&this_sync_enable_timer, g_sync_all_ticks, lb_sync_enable_sync);
    if (err != 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: enable sync timer failed. lcore %u cannot send sync packet.\n"
                , __func__, lcore_id);
    }

    err = lb_lcore_timer_sched(&this_mgroup_timer, g_group_membership_ticks, lb_sync_join_group);
    if (err != 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: enable group join timer failed. lcore %u may not recv sync packet.\n"
            , __func__, lcore_id);
    }

    igmp_join_group(lcores_sync_cfg[lcore_id].dev_ref
                    , &lcores_sync_cfg[lcore_id].mcast_group
                    , &lcores_sync_cfg[lcore_id].mcast_ifia);
    */
    return 0;
}

static void lb_sync_register_init_job(void)
{
    snprintf(sync_init_job.name, sizeof(sync_init_job.name) - 1, "%s", "sync_init_job");
    sync_init_job.func = lb_sync_init_job;
    sync_init_job.data = NULL;
    sync_init_job.type = NETIF_LCORE_JOB_INIT;
    if (netif_lcore_loop_job_register(&sync_init_job) < 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to register %s on slave lcores, cannot send/recv sync packet.\n", __func__, sync_init_job.name);
    }
}

static void lb_sync_unregister_init_job(void)
{
    if (netif_lcore_loop_job_unregister(&sync_init_job) < 0) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to unregister %s on slave lcores.\n", __func__, sync_init_job.name);
    }
}

static int lb_sync_lcore_startdaemon(struct lb_sync_daemon_entry *de)
{
    uint32_t rule_ip;
    uint16_t rule_port;
    struct lb_service *lbs;
    struct lb_dest *dest;
    uint32_t found_idx;
    int      err       = EDPVS_OK;
    unsigned lcore_id  = rte_lcore_id();

    if (de->state & IP_VS_STATE_MASTER) {
        if (lcores_sync_state[lcore_id] & IP_VS_STATE_MASTER) {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u is in active state, nothing to do.\n", __func__, lcore_id);
#endif
        } else {
            err = lb_lcore_timer_sched(&this_sync_enable_timer, g_sync_all_ticks, lb_sync_enable_sync);
            if (err != 0) {
                RTE_LOG(WARNING, LB_SYNC, "%s: enable sync timer failed. lcore %u cannot send sync packet.\n"
                    , __func__, lcore_id);
            }
            lcores_sync_state[lcore_id] |= IP_VS_STATE_MASTER;
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u starts active state.\n", __func__, lcore_id);
#endif
        }
    }
    if (de->state & IP_VS_STATE_BACKUP) {
        if (lcores_sync_state[lcore_id] & IP_VS_STATE_BACKUP) {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u is in backup state, nothing to do.\n", __func__, lcore_id);
#endif
        } else {
            err = lb_lcore_timer_sched(&this_mgroup_timer, g_group_membership_ticks, lb_sync_join_group);
            if (err != 0) {
                RTE_LOG(WARNING, LB_SYNC, "%s: enable group join timer failed. lcore %u may not recv sync packet.\n"
                    , __func__, lcore_id);
            }
            err = igmp_join_group(lcores_sync_cfg[lcore_id].dev_ref
                , &lcores_sync_cfg[lcore_id].mcast_group
                , &lcores_sync_cfg[lcore_id].mcast_ifia);
            lcores_sync_state[lcore_id] |= IP_VS_STATE_BACKUP;
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u starts backup state.\n", __func__, lcore_id);
#endif
        }

        /* toggle fdir rule: make rule based on dest or src ip and port */
        lbs = lb_lcore_get_service(0, &found_idx);
        if (lbs != NULL) {
            dest = lb_lcore_get_dest(lbs, 0);
            if (dest != NULL) {
                if (DPVS_FWD_MODE_FNAT == dest->fwdmode) {
                    this_fdir_rule_for_dst = 1;
                }
                else if (DPVS_FWD_MODE_NAT == dest->fwdmode) {
                    this_fdir_rule_for_dst = 0;
                }
                else {
                    this_fdir_rule_for_dst = 0;
                }
            }
        }

        RTE_LOG(WARNING, LB_SYNC, "%s: Replacing flow rule on lcore %u, new rule is for dest: %s. \n"
            , __func__, lcore_id, (this_fdir_rule_for_dst == 0 ? "NO" : "YES"));
        if (lcores_sync_cfg[lcore_id].flow_id >= 0) {
            netif_flow_destroy(lcores_sync_cfg[lcore_id].dev_ref, lcores_sync_cfg[lcore_id].flow_id);
        }
        if (this_fdir_rule_for_dst) {
            rule_ip   = lcores_sync_cfg[lcore_id].mcast_group.s_addr;
            rule_port = lcores_sync_cfg[lcore_id].mcast_port;
        } else {
            rule_ip   = lcores_sync_cfg[lcore_id].mcast_ifia.s_addr;
            rule_port = SYNC_MSG_SRC_PORT;
        }
        lcores_sync_cfg[lcore_id].flow_id = lb_sync_add_filter(lcore_id, lcores_sync_cfg[lcore_id].dev_ref, this_fdir_rule_for_dst
            , rule_ip
            , rule_port);
        if (lcores_sync_cfg[lcore_id].flow_id < 0) {
            RTE_LOG(WARNING, LB_SYNC, "%s: create flow rule failed. lcore %u cannot recv sync packet.\n"
                , __func__, lcore_id);
        }
    }
    return err;
}

static int lb_sync_lcore_stopdaemon(struct lb_sync_daemon_entry *de)
{
    int      err      = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();
    if (de->state & IP_VS_STATE_MASTER) {
        if (lcores_sync_state[lcore_id] & IP_VS_STATE_MASTER) {
            lb_sync_enqueue_curr_mbuf(lcore_id);
            lb_lcore_del_timer(&this_sync_enable_timer);
            lcores_sync_state[lcore_id] &= ~IP_VS_STATE_MASTER;
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u stops active state.\n", __func__, lcore_id);
#endif
        } else {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u is not in active state, nothing to do.\n", __func__, lcore_id);
#endif
        }
    }
    if (de->state & IP_VS_STATE_BACKUP) {
        if (lcores_sync_state[lcore_id] & IP_VS_STATE_BACKUP) {
            lb_lcore_del_timer(&this_mgroup_timer);
            err = igmp_leave_group(lcores_sync_cfg[lcore_id].dev_ref
                , &lcores_sync_cfg[lcore_id].mcast_group
                , &lcores_sync_cfg[lcore_id].mcast_ifia);
            lcores_sync_state[lcore_id] &= ~IP_VS_STATE_BACKUP;
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u stops backup state.\n", __func__, lcore_id);
#endif
        } else {
#ifdef CONFIG_SYNC_DEBUG
            RTE_LOG(INFO, LB_SYNC, "%s: daemon on lcore %u is not in backup state, nothing to do.\n", __func__, lcore_id);
#endif
        }
    }
    return err;
}

static int lb_sync_lcore_setdaemon(struct lb_sync_daemon_entry *de)
{
    size_t         insize;
    size_t         bufsize;
    struct in_addr new_mcast_ifia     = { 0 };
    struct in_addr new_mcast_group    = { 0 };
    uint16_t       new_mcast_port     = 0;
    struct netif_port
                   *new_dev_ref       = NULL;
    struct {
        uint8_t mcast_group : 1;
        uint8_t mcast_port  : 1;
        uint8_t mcast_ifn   : 1;
        uint8_t mcast_ifia  : 1;
        uint8_t mcast_ttl   : 1;
    }              set_flag           = {0, 0, 0, 0};
    unsigned       lcore_id           = rte_lcore_id();
    int            err                = EDPVS_OK;

    /* the lcore which receives msg does not match the lcore id in msg */
    if (de->lcore_id != lcore_id) {
        return EDPVS_INVAL;
    }
    /* transmit sync packet before config modification */
    if (de->state & IP_VS_STATE_MASTER) {
        lb_sync_enqueue_curr_mbuf(lcore_id);
    }

    if (de->mcast_ifia.s_addr != 0 && de->mcast_ifia.s_addr != lcores_sync_cfg[lcore_id].mcast_ifia.s_addr) {
        set_flag.mcast_ifia = 1;
    }

    if (de->mcast_group.s_addr != 0 && de->mcast_group.s_addr != lcores_sync_cfg[lcore_id].mcast_group.s_addr) {
        set_flag.mcast_group = 1;
    }

    if (de->mcast_port != 0 && de->mcast_port != lcores_sync_cfg[lcore_id].mcast_port) {
        set_flag.mcast_port = 1;
    }

    if (de->mcast_ttl != 0 && de->mcast_ttl != lcores_sync_cfg[lcore_id].mcast_ttl) {
        set_flag.mcast_ttl = 1;
    }

    insize = strlen(de->mcast_ifn);
    bufsize = sizeof(lcores_sync_cfg[lcore_id].mcast_ifn);
    if (insize != 0) {
        if (insize + 1 <= bufsize) {
            if (strcmp(lcores_sync_cfg[lcore_id].mcast_ifn, de->mcast_ifn) != 0) {
                set_flag.mcast_ifn = 1;
            }
        } else {
            RTE_LOG(WARNING, LB_SYNC, "%s: new interface name %s is too long, cannot update it on lcore %u.\n"
                , __func__, de->mcast_ifn, lcore_id);
        }
    } 

    if (set_flag.mcast_ifia || set_flag.mcast_group || set_flag.mcast_ifn) {
        if (lcores_sync_cfg[lcore_id].flow_id >= 0) {
            netif_flow_destroy(lcores_sync_cfg[lcore_id].dev_ref, lcores_sync_cfg[lcore_id].flow_id);
            lcores_sync_cfg[lcore_id].flow_id = -1;
        }
        if (lcores_sync_cfg[lcore_id].flow_id < 0) {
            if (set_flag.mcast_ifn) {
                new_dev_ref = netif_port_get_by_name(de->mcast_ifn);
                if (NULL == new_dev_ref) {
                    err = EDPVS_NODEV;
                    RTE_LOG(WARNING, LB_SYNC, "%s: get device %s failed. lcore %u cannot send/recv sync packet: %s.\n"
                        , __func__, de->mcast_ifn, lcore_id, dpvs_strerror(err));
                }
            } else {
                new_dev_ref = lcores_sync_cfg[lcore_id].dev_ref;
            }

            if (set_flag.mcast_ifia) {
                new_mcast_ifia = de->mcast_ifia;
            } else {
                new_mcast_ifia = lcores_sync_cfg[lcore_id].mcast_ifia;
            }

            if (set_flag.mcast_group) {
                new_mcast_group = de->mcast_group;
            } else {
                new_mcast_group = lcores_sync_cfg[lcore_id].mcast_group;
            }

            if (set_flag.mcast_port) {
                new_mcast_port = de->mcast_port;
            } else {
                new_mcast_port = lcores_sync_cfg[lcore_id].mcast_port;
            }

            if (this_fdir_rule_for_dst) {
                lcores_sync_cfg[lcore_id].flow_id = lb_sync_add_filter(lcore_id, new_dev_ref, this_fdir_rule_for_dst
                    , new_mcast_group.s_addr, new_mcast_port);
            } else {
                lcores_sync_cfg[lcore_id].flow_id = lb_sync_add_filter(lcore_id, new_dev_ref, this_fdir_rule_for_dst
                    , new_mcast_ifia.s_addr, 0);
            }

            if (lcores_sync_cfg[lcore_id].flow_id < 0) {
                RTE_LOG(WARNING, LB_SYNC, "%s: create flow rule fail. lcore %u cannot recv sync packet.\n"
                    , __func__, lcore_id);
            }
        }
    }

    if (set_flag.mcast_group || set_flag.mcast_ifia || set_flag.mcast_ifn) {
        igmp_leave_group(lcores_sync_cfg[lcore_id].dev_ref
            , &lcores_sync_cfg[lcore_id].mcast_group
            , &lcores_sync_cfg[lcore_id].mcast_ifia);
    }

    if (set_flag.mcast_group) {
        lcores_sync_cfg[lcore_id].mcast_group = de->mcast_group;
        ip_eth_mc_map(lcores_sync_cfg[lcore_id].mcast_group.s_addr
            , lcores_sync_cfg[lcore_id].mcast_group_ea.addr_bytes);
    }
    if (set_flag.mcast_port) {
        lcores_sync_cfg[lcore_id].mcast_port = de->mcast_port;
    }
    if (set_flag.mcast_ifn) {
        strcpy(lcores_sync_cfg[lcore_id].mcast_ifn, de->mcast_ifn);
        lcores_sync_cfg[lcore_id].dev_ref = new_dev_ref;
    }

    if (set_flag.mcast_ttl) {
        lcores_sync_cfg[lcore_id].mcast_ttl = de->mcast_ttl;
    }

    if (set_flag.mcast_ifia) {
        lcores_sync_cfg[lcore_id].mcast_ifia = de->mcast_ifia;
    }

    if (set_flag.mcast_group || set_flag.mcast_ifia || set_flag.mcast_ifn) {
        err = igmp_join_group(lcores_sync_cfg[lcore_id].dev_ref
            , &lcores_sync_cfg[lcore_id].mcast_group
            , &lcores_sync_cfg[lcore_id].mcast_ifia);
    }
    return err;
}

static int lb_sync_startdaemon_msg_cb(struct dpvs_msg *msg)
{
    struct lb_sync_daemon_entry *de;
    int      err      = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();
    if (NULL == msg || NULL == msg->data) {
        return EDPVS_INVAL;
    }
    if (msg->len != sizeof(struct lb_sync_daemon_entry)) {
        return EDPVS_INVAL;
    }
    de = (struct lb_sync_daemon_entry*)msg->data;
    err = lb_sync_lcore_startdaemon(de);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: lcore %u fail to start dameon %s.\n",
                __func__, lcore_id, dpvs_strerror(err));
    }
    return err;
}

static int lb_sync_stopdaemon_msg_cb(struct dpvs_msg *msg)
{
    struct lb_sync_daemon_entry *de;
    int      err      = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();
    if (NULL == msg || NULL == msg->data) {
        return EDPVS_INVAL;
    }
    if (msg->len != sizeof(struct lb_sync_daemon_entry)) {
        return EDPVS_INVAL;
    }
    de = (struct lb_sync_daemon_entry*)msg->data;
    err = lb_sync_lcore_stopdaemon(de);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: lcore %u fail to stop dameon %s.\n",
            __func__, lcore_id, dpvs_strerror(err));
    }
    return err;
}

static int lb_sync_lcore_setdaemon_msg_cb(struct dpvs_msg *msg)
{
    struct lb_sync_daemon_entry *de;
    int      err      = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();
    if (NULL == msg || NULL == msg->data) {
        return EDPVS_INVAL;
    }
    if (msg->len != sizeof(struct lb_sync_daemon_entry)) {
        return EDPVS_INVAL;
    }
    de = (struct lb_sync_daemon_entry*)msg->data;
    err = lb_sync_lcore_setdaemon(de);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: lcore %u fail to set dameon %s.\n",
            __func__, lcore_id, dpvs_strerror(err));
    }
    return err;
}

/*
 * distribute the command to all lcores.
 */
static int lb_sync_switch_dameon(msgid_t type, struct lb_sync_daemon_entry *de)
{
    int             err      = EDPVS_OK;
    unsigned        lcore_id = rte_lcore_id();
    struct dpvs_msg *msg     = msg_make(type, 0, DPVS_MSG_MULTICAST, lcore_id,
        sizeof(struct lb_sync_daemon_entry), de);
    if (NULL == msg) {
        err = EDPVS_NOMEM;
    } else {
        /* send msg to all lcores to start or stop sync packet send/process */
        err = multicast_msg_send(msg, 0, NULL);
    }
    msg_destroy(&msg);
    return err;
}

static int lb_sync_set_dameon(msgid_t type, struct lb_sync_daemon_entry *de)
{
    int err                = EDPVS_OK;
    unsigned lcore_id      = rte_lcore_id();
    unsigned dest_lcore_id = de->lcore_id;
    struct dpvs_msg   *msg = NULL;

    if (!netif_lcore_is_idle(dest_lcore_id)) {
        /* continue */
    } else {
        return EDPVS_INVAL;
    }
    msg = msg_make(type, 0, DPVS_MSG_UNICAST, lcore_id,
        sizeof(struct lb_sync_daemon_entry), de);
    if (NULL == msg) {
        err = EDPVS_NOMEM;
    }
    else {
        err = msg_send(msg, dest_lcore_id, 0 ,NULL);
    }
    msg_destroy(&msg);
    return err;
}

/*
 * handle the cmd from unix socket.
 */
static int lb_sync_sockopt_set(sockoptid_t opt, const void *conf, size_t inlen)
{
    int err = EDPVS_OK;
    struct lb_sync_daemon_entry* de = (struct lb_sync_daemon_entry*)conf;

    if (NULL == conf || inlen != sizeof(struct lb_sync_daemon_entry)) {
        return EDPVS_INVAL;
    }

    switch (opt) {
    case SOCKOPT_SET_STARTDAEMON:
        err = lb_sync_switch_dameon(MSG_TYPE_STARTDAEMON, de);
        break;
    case SOCKOPT_SET_STOPDAEMON:
        err = lb_sync_switch_dameon(MSG_TYPE_STOPDAEMON, de);
        break;
    case SOCKOPT_SET_SETDAEMON:
        err = lb_sync_set_dameon(MSG_TYPE_SETDAEMON, de);
        break;
    default:
        err = EDPVS_NOTSUPP;
        break;
    }
    return err;
}

static int lb_sync_sockopt_get(sockoptid_t opt, const void *conf, size_t inlen,
    void **out, size_t *outlen)
{
    uint32_t i;
    int      ret;
    struct lb_sync_daemon_stats *stats;
    struct lb_sync_daemon_stat  *stat;
    int err = EDPVS_OK;
    struct lb_sync_daemon_entry* de = (struct lb_sync_daemon_entry*)conf;
    (void)de;

    if (NULL == conf || inlen != sizeof(struct lb_sync_daemon_entry)
        || NULL == out || NULL == outlen) {
        return EDPVS_INVAL;
    }
    if (opt != SOCKOPT_GET_DAEMON) {
        return EDPVS_NOTSUPP;
    }

    *outlen = sizeof(struct lb_sync_daemon_stats) + DPVS_MAX_LCORE * sizeof(struct lb_sync_daemon_stat);
    stats = rte_zmalloc(NULL, *outlen, 0);
    if (NULL == stats) {
        return EDPVS_NOMEM;
    }
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!netif_lcore_is_idle(i)) {
            stat                 = &stats->daemon_stat[stats->n];
            stat->lcore_id       = i;
            stat->mcast_group    = lcores_sync_cfg[i].mcast_group;
            stat->mcast_ifia     = lcores_sync_cfg[i].mcast_ifia;
            stat->mcast_port     = lcores_sync_cfg[i].mcast_port;
            stat->mcast_ttl      = lcores_sync_cfg[i].mcast_ttl;
            stat->daemon_state   = lcores_sync_state[i] & 0x03;
            stat->fdir_state     = (lcores_sync_cfg[i].flow_id < 0 ? 0x0 : 0x1);
            stat->mcast_if_exist = (lcores_sync_cfg[i].dev_ref == NULL ? 0x0 : 0x1);
            if (lcores_sync_cfg[i].dev_ref != NULL) {
                ret = rte_eth_allmulticast_get(lcores_sync_cfg[i].dev_ref->id);
            } else {
                ret = 2;
            }
            /* 0: disabled, 1: enabled, 2: error */
            switch (ret) {
            case 0:
                stat->mcast_if_allmulticast = 0;
                break;
            case 1:
                stat->mcast_if_allmulticast = 1;
                break;
            default:
                stat->mcast_if_allmulticast = 2;
                break;
            }
            if (sizeof(stat->mcast_ifn) >= sizeof(lcores_sync_cfg[i].mcast_ifn))
            {
                if (strlen(lcores_sync_cfg[i].mcast_ifn) < sizeof(lcores_sync_cfg[i].mcast_ifn)) {
                    strcpy(stat->mcast_ifn, lcores_sync_cfg[i].mcast_ifn);
                }
            } else {
                stat->mcast_ifn[0] = '\0';
            }
            stats->n++;
        }
    }
    if (stats->n != DPVS_MAX_LCORE) {
        *outlen = sizeof(struct lb_sync_daemon_stats) + stats->n * sizeof(struct lb_sync_daemon_stat);
        *out = rte_realloc(stats, *outlen, 0);
    } else {
        *out = stats;
    }

    return err;
}

static struct dpvs_sockopts lb_sync_sockopts = {
    .version     = SOCKOPT_VERSION,
    .set_opt_min = SOCKOPT_SET_STARTDAEMON,
    .set_opt_max = SOCKOPT_SET_SETDAEMON,
    .set         = lb_sync_sockopt_set,
    .get_opt_min = SOCKOPT_GET_DAEMON,
    .get_opt_max = SOCKOPT_GET_DAEMON,
    .get         = lb_sync_sockopt_get,
};

static int lb_sync_register_msg_cb(void)
{
    int err = EDPVS_OK;
    struct dpvs_msg_type msg_type;
    int i;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_STARTDAEMON;
    //msg_type.mode = DPVS_MSG_MULTICAST;
    msg_type.prio = MSG_PRIO_NORM;
    //msg_type.cid  = rte_lcore_id();
    msg_type.unicast_msg_cb = lb_sync_startdaemon_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to register msg, cannot start daemon via msg: %s\n", __func__, dpvs_strerror(err));
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_STOPDAEMON;
    //msg_type.mode = DPVS_MSG_MULTICAST;
    msg_type.prio = MSG_PRIO_NORM;
    //msg_type.cid = rte_lcore_id();
    msg_type.unicast_msg_cb = lb_sync_stopdaemon_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to register msg, cannot stop daemon via msg: %s\n", __func__, dpvs_strerror(err));
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_SETDAEMON;
    //msg_type.mode = DPVS_MSG_UNICAST;
    msg_type.prio = MSG_PRIO_NORM;
    //msg_type.cid = rte_lcore_id();
    msg_type.unicast_msg_cb = lb_sync_lcore_setdaemon_msg_cb;
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!netif_lcore_is_idle(i)) {
            msg_type.cid = i;
            err = msg_type_register(&msg_type);
            if (err != EDPVS_OK) {
                RTE_LOG(WARNING, LB_SYNC, "%s: fail to register msg on lcore %d, cannot set daemon via msg: %s\n"
                       , __func__, i, dpvs_strerror(err));
            }
        }
    }
    return err;
}

static int lb_sync_unregister_msg_cb(void)
{
    int err = EDPVS_OK;
    struct dpvs_msg_type msg_type;
    int i;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_STARTDAEMON;
    msg_type.prio = MSG_PRIO_NORM;
    err = msg_type_mc_register(&msg_type);


    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_STOPDAEMON;
    msg_type.prio = MSG_PRIO_NORM;
    err = msg_type_mc_register(&msg_type);

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type = MSG_TYPE_SETDAEMON;
    msg_type.prio = MSG_PRIO_NORM;
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!netif_lcore_is_idle(i)) {
            msg_type.cid = i;
            err = msg_type_unregister(&msg_type);
        }
    }

    return err;
}

/* Check data layout, if data layout changed, avx512 cannot work */
static bool lb_sync_avx512_capable(void)
{
    /* 8bits mask is not large enough, some bit setting will miss */
    uint32_t bitmask  = 0;
    int lcport_offset = 0;
    int dvport_offset = 0;
    int laddr_offset  = 0;
    int caddr_offset  = 0;
    int daddr_offset  = 0;
    int vaddr_offset  = 0;

    /* check lb_sync_v4 */
    /* check lport is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, lport) & 0x03) == 0) {
        /* check lport adjacent to cport */
        if ((offsetof(struct lb_sync_v4, cport) - offsetof(struct lb_sync_v4, lport)) == 2) {
            bitmask |= (1 << (offsetof(struct lb_sync_v4, lport) / 4));
        } else {
            return false;
        }
    } else {
        return false;
    }
    /* check dport is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, dport) & 0x03) == 0) {
        /* check vport adjacent to dport */
        if ((offsetof(struct lb_sync_v4, vport) - offsetof(struct lb_sync_v4, dport)) == 2) {
            bitmask |= (1 << (offsetof(struct lb_sync_v4, dport) / 4));
        } else {
            return false;
        }
    } else {
        return false;
    }
    /* check laddr is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, laddr) & 0x03) == 0) {
        bitmask |= (1 << (offsetof(struct lb_sync_v4, laddr) / 4));
    } else {
        return false;
    }
    /* check caddr is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, caddr) & 0x03) == 0) {
        bitmask |= (1 << (offsetof(struct lb_sync_v4, caddr) / 4));
    } else {
        return false;
    }
    /* check daddr is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, daddr) & 0x03) == 0) {
        bitmask |= (1 << (offsetof(struct lb_sync_v4, daddr) / 4));
    } else {
        return false;
    }
    /* check vaddr is 32bit aligned */
    if ((offsetof(struct lb_sync_v4, vaddr) & 0x03) == 0) {
        bitmask |= (1 << (offsetof(struct lb_sync_v4, vaddr) / 4));
    } else {
        return false;
    }
    /* 32byte: 256bits, note: size of lb_sync_v4 is larger than 32, g_base_k_4 affect from flags to vaddr*/
    if ((g_store_offset_4 & 0x03) == 0) {
        bitmask >>= (g_store_offset_4 / 4);
        /* type conversion will not lost info, 8bits can hold writemask for current lb_sync_v4 layout */
        g_base_k_4 = bitmask;
    } else {
        return false;
    }
    /* check lb_conn */
    /* check lport is 32bit aligned */
    if ((offsetof(struct lb_conn, lport) & 0x03) == 0) {
        /* check lport adjacent to cport */
        if ((offsetof(struct lb_conn, cport) - offsetof(struct lb_conn, lport)) == 2) {
            lcport_offset = offsetof(struct lb_conn, lport);
        } else {
            return false;
        }
    } else {
        return false;
    }
    /* check laddr is 32bit aligned */
    if ((offsetof(struct lb_conn, laddr) & 0x03) == 0) {
        laddr_offset = offsetof(struct lb_conn, laddr);
    } else {
        return false;
    }
    /* check caddr is 32bit aligned */
    if ((offsetof(struct lb_conn, caddr) & 0x03) == 0) {
        caddr_offset = offsetof(struct lb_conn, caddr);
    } else {
        return false;
    }

    /* check lb_dest */
    /* check dport is 32bit aligned */
    if ((offsetof(struct lb_dest, port) & 0x03) == 0) {
        /* check vport adjacent to dport */
        if ((offsetof(struct lb_dest, vport) - offsetof(struct lb_dest, port)) == 2) {
            dvport_offset = offsetof(struct lb_dest, port);
        } else {
            return false;
        }
    } else {
        return false;
    }
    /* check daddr is 32bit aligned */
    if ((offsetof(struct lb_dest, addr) & 0x03) == 0) {
        daddr_offset = offsetof(struct lb_dest, addr);
    } else {
        return false;
    }
    /* check daddr is 32bit aligned */
    if ((offsetof(struct lb_dest, vaddr) & 0x03) == 0) {
        vaddr_offset = offsetof(struct lb_dest, vaddr);
    } else {
        return false;
    }
    /* 
     * set data source address offset. dvport_offset, daddr_offset, vaddr_offset
     * need accumulate diff of address of lb_dest and lb_conn object on the fly when
     * it is used.
     */
    g_vindex_4 = _mm512_set_epi64(vaddr_offset  //e7
                                , daddr_offset  //e6
                                , caddr_offset  //e5
                                , laddr_offset  //e4
                                , dvport_offset //e3
                                , lcport_offset //e2
                                , 0, 0);        //e1, e0: exclude timeout, fwmark, state, flags
    
    g_base_src_4 = _mm256_maskz_set1_epi32(0, 0);
    return true;
}

int lb_sync_init(void)
{
    int err = EDPVS_OK;
    unsigned lcore_id;
    struct timeval tv;

    for (lcore_id = 0; lcore_id < DPVS_MAX_LCORE; lcore_id++) {
        if (!netif_lcore_is_idle(lcore_id)) {
            /*Change IP address and port to network order*/
            lcores_sync_cfg[lcore_id].mcast_group.s_addr =
                rte_cpu_to_be_32(lcores_sync_cfg[lcore_id].mcast_group.s_addr);
            lcores_sync_cfg[lcore_id].mcast_port =
                rte_cpu_to_be_16(lcores_sync_cfg[lcore_id].mcast_port);
            ip_eth_mc_map(lcores_sync_cfg[lcore_id].mcast_group.s_addr
                          , lcores_sync_cfg[lcore_id].mcast_group_ea.addr_bytes);
            lcores_sync_cfg[lcore_id].mcast_ifia.s_addr =
                rte_cpu_to_be_32(lcores_sync_cfg[lcore_id].mcast_ifia.s_addr);
            lcores_sync_cfg[lcore_id].dev_ref =
                netif_port_get_by_name(lcores_sync_cfg[lcore_id].mcast_ifn);

            if (NULL == lcores_sync_cfg[lcore_id].dev_ref) {
                err = EDPVS_NODEV;
                RTE_LOG(WARNING, LB_SYNC, "%s: get device %s failed. lcore %u cannot send/recv sync packet: %s\n"
                        , __func__, lcores_sync_cfg[lcore_id].mcast_ifn, lcore_id, dpvs_strerror(err));

            }
            /* Do not start active and backup sync daemon */
            lcores_sync_state[lcore_id] = 0;
        }
    }

    tv.tv_sec = g_sync_all_period;
    tv.tv_usec = 0;
    g_sync_all_ticks = lb_timeval_to_ticks(&tv);
    g_sync_exp_cycles = (g_sync_all_period * rte_get_tsc_hz()) << 1;

    tv.tv_sec = g_group_membership_interval;
    tv.tv_usec = 0;
    g_group_membership_ticks = lb_timeval_to_ticks(&tv);

    /* some init action must be defined here and be run after port start */
    lb_sync_register_init_job();

    /* Set sched stat period to 1 second, and time slice for iteration to 1/128 second */
    lb_conn_set_iter_sched_cfg(0, 7);
    g_iter_conns_count = g_iter_conns_count_4 > g_iter_conns_count_6 ? g_iter_conns_count_4 : g_iter_conns_count_6;
    lb_conn_register_iter_job(lb_sync_batch_conn_handler, lb_sync_iter_done, g_iter_conns_count);

    /* prepare avx512 */
    if (lb_sync_avx512_capable()) {
        g_lb_sync_batch_conn_handler_4 = lb_sync_batch_conn_handler_avx512_4;
    } else {
        g_lb_sync_batch_conn_handler_4 = lb_sync_batch_conn_handler_4;
    }

    rte_eal_mp_remote_launch(lb_sync_lcore_init, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if ((err = rte_eal_wait_lcore(lcore_id)) < 0) {
            RTE_LOG(WARNING, LB_SYNC, "%s: lcore %d: %s.\n",
                    __func__, lcore_id, dpvs_strerror(err));
        }
    }

    err = sockopt_register(&lb_sync_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to register sockopts, cannot config session sync.\n", __func__);
    }

    err = lb_sync_register_msg_cb();
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, LB_SYNC, "%s: fail to register msg, cannot config session sync.\n", __func__);
    }

    return err;
}

static int lb_sync_lcore_term(void *arg)
{
    int err = EDPVS_OK;
    unsigned lcore_id = rte_lcore_id();

    if (netif_lcore_is_idle(lcore_id)) {
        err = EDPVS_IDLE;
    } else {
        igmp_leave_group(lcores_sync_cfg[lcore_id].dev_ref
                        , &lcores_sync_cfg[lcore_id].mcast_group
                        , &lcores_sync_cfg[lcore_id].mcast_ifia);
        rte_pktmbuf_free(this_curr_mbuf);
        this_curr_mbuf = NULL;
        if (lcores_sync_cfg[lcore_id].dev_ref != NULL) {
            netif_flow_destroy(lcores_sync_cfg[lcore_id].dev_ref, lcores_sync_cfg[lcore_id].flow_id);
            lcores_sync_cfg[lcore_id].dev_ref = NULL;
        }
    }
    return err;
}

void lb_sync_term(void)
{
    unsigned lcore_id;

    lb_sync_unregister_msg_cb();
    sockopt_unregister(&lb_sync_sockopts);

    rte_eal_mp_remote_launch(lb_sync_lcore_term, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    lb_conn_unregister_iter_job();
    lb_sync_unregister_init_job();
}

