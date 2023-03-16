/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "rte_udp.h"
#include "rte_ether.h"
#include "rte_ip.h"
#include "rte_byteorder.h"
#include "rte_log.h"
#include "rte_cycles.h"
#include "ipvs/conn.h"
#include "ipvs/proto.h"
#include "netif.h"
#include "common.h"
#include "inetaddr.h"
#include "ipv4.h"
#include "ipvs/conn.h"
#include "inet.h"
#include "ipvs/proto_tcp.h"
#include "conf/netif.h"
#include "lb/conn.h"
#include "lb/sync.h"
#include "lb/igmp.h"
#include "lb/service.h"
#include "lb/ipv4.h"
#include "lb/ipv6.h"
#include "lb/ip.h"
#include "lb/dest.h"
#include "lb/sync_debug.h"

void lb_sync_disp_sync_conn(union lb_sync_conn* sync_conn)
{
    int err = 0;
    int af;
    uint8_t proto;
    union inet_addr caddr;
    union inet_addr vaddr;
    union inet_addr daddr;
    union inet_addr laddr;
    uint16_t cport;
    uint16_t vport;
    uint16_t dport;
    uint16_t lport;
    uint8_t  flags;
    uint8_t  state;
    uint32_t fwmark;
    uint32_t timeout;
    char buf[64];

    if (unlikely(NULL == sync_conn)) {
        return;
    }

    if (sync_conn->v6.type & PTYPE_F_INET6) {
        af = AF_INET6;
        proto = sync_conn->v6.protocol;
        flags = sync_conn->v6.flags;
        state = sync_conn->v6.state;
        caddr.in6 = sync_conn->v6.caddr;
        vaddr.in6 = sync_conn->v6.vaddr;
        daddr.in6 = sync_conn->v6.daddr;
        laddr.in6 = sync_conn->v6.laddr;
        cport = sync_conn->v6.cport;
        vport = sync_conn->v6.vport;
        dport = sync_conn->v6.dport;
        lport = sync_conn->v6.lport;
        timeout = rte_be_to_cpu_32(sync_conn->v6.timeout);
        fwmark = rte_be_to_cpu_16(sync_conn->v6.fwmark);
    }
    else if (!sync_conn->v4.type) {
        af = AF_INET;
        proto = sync_conn->v4.protocol;
        flags = sync_conn->v4.flags;
        state = sync_conn->v4.state;
        caddr.in.s_addr = sync_conn->v4.caddr;
        vaddr.in.s_addr = sync_conn->v4.vaddr;
        daddr.in.s_addr = sync_conn->v4.daddr;
        laddr.in.s_addr = sync_conn->v4.laddr;
        cport = sync_conn->v4.cport;
        vport = sync_conn->v4.vport;
        dport = sync_conn->v4.dport;
        lport = sync_conn->v4.lport;
        timeout = rte_be_to_cpu_32(sync_conn->v4.timeout);
        fwmark = rte_be_to_cpu_16(sync_conn->v4.fwmark);
    }
    else {
        err = -1;
        goto errout;
    }
    printf("sync conn dump:\n");
    printf(" protocol:%s\n", inet_proto_name(proto));
    printf(" flags:%#X\n", flags);
    printf(" state:%#X\n", state);
    printf(" caddr[cport]:%s[%u]\n", inet_ntop(af, &caddr, buf, sizeof(buf)), rte_be_to_cpu_16(cport));
    printf(" vaddr[vport]:%s[%u]\n", inet_ntop(af, &vaddr, buf, sizeof(buf)), rte_be_to_cpu_16(vport));
    printf(" daddr[dport]:%s[%u]\n", inet_ntop(af, &daddr, buf, sizeof(buf)), rte_be_to_cpu_16(dport));
    printf(" laddr[lport]:%s[%u]\n", inet_ntop(af, &laddr, buf, sizeof(buf)), rte_be_to_cpu_16(lport));
    printf(" timeout:%u\n", timeout);
    printf(" fwmark:%u\n", fwmark);
errout:
    if (err != 0) {
        printf("sync conn dump err:%d\n", err);
    }
}

#if (!defined CONFIG_SYNC_DEBUG_CADDR_MIN) || (!defined CONFIG_SYNC_DEBUG_CADDR_MAX)
#define CONFIG_SYNC_DEBUG_CADDR_MIN "192.168.1.1"
#define CONFIG_SYNC_DEBUG_CADDR_MAX "192.168.2.255"
#endif
void lb_sync_lcore_new_conns(unsigned int count)
{
    uint16_t port;
    uint32_t ip;
    uint32_t ip_sub;

    union inet_addr addr_min;
    union inet_addr addr_max;
    uint32_t ip_min;
    uint32_t ip_max;
    unsigned int new_count = 0;
    unsigned int exp_count = 0;

    struct lb_conn* conn;
    struct lb_conn_param conn_param;
    uint32_t start_idx = 0;
    uint32_t found_idx;

    struct lb_service* lbs;
    struct lb_dest* dest;
    struct lb_conn_hash_elem_free hash_elem_free;
    struct lb_conn_hash_elem* hash_elem = NULL;

    int err;
    bool stop = false;

    if (0 == count) {
        return;
    }
    conn_param.flags = 0;
    conn_param.state = 0;
    /* timeout is not used */
    conn_param.timeout = 300;

    lbs = lb_lcore_get_service(start_idx, &found_idx);
    if (likely(lbs != NULL)) {
        conn_param.af = lbs->af;
        conn_param.proto = lbs->proto;
        conn_param.vaddr = lbs->addr;
        conn_param.vport = lbs->port;
        dest = lb_lcore_get_dest(lbs, 0);
        if (dest != NULL) {
            conn_param.daddr = dest->addr;
            conn_param.dport = dest->port;
            err = -1;
            if (AF_INET == dest->af) {
                err = inet_pton(AF_INET, CONFIG_SYNC_DEBUG_CADDR_MIN, &addr_min.in);
                if (1 == err) {
                    err = inet_pton(AF_INET, CONFIG_SYNC_DEBUG_CADDR_MAX, &addr_max.in);
                }
            }
            else {
                /* AF_INET6 */
                err = inet_pton(AF_INET6, CONFIG_SYNC_DEBUG_CADDR_MIN, &addr_min.in6);
                if (1 == err) {
                    err = inet_pton(AF_INET6, CONFIG_SYNC_DEBUG_CADDR_MAX, &addr_max.in6);
                }
            }
            if (1 == err) {
                if (AF_INET == dest->af) {
                    ip_min = ntohl(addr_min.in.s_addr);
                    ip_max = ntohl(addr_max.in.s_addr);
                }
                else {
                    ip_min = ntohl(addr_min.in6.__in6_u.__u6_addr32[3]);
                    ip_max = ntohl(addr_max.in6.__in6_u.__u6_addr32[3]);
                }
                for (ip = ip_min; ip <= ip_max; ip++) {
                    ip_sub = ip & 0xff;
                    if (ip_sub == 255 || ip_sub == 0 || ip_sub == 1) {
                        /* skip special addr in ipv4 */
                        continue;
                    }
                    if (AF_INET == dest->af) {
                        conn_param.caddr.in.s_addr = htonl(ip);
                    }
                    else {
                        conn_param.caddr.in6 = addr_min.in6;
                        conn_param.caddr.in6.__in6_u.__u6_addr32[3] = htonl(ip);
                    }
                    for (port = 1024; port <= 65535 && port >= 1024; port++) {
                        conn_param.cport = htons(port);
                        hash_elem = lb_conn_cache_get(conn_param.af, &conn_param.caddr, conn_param.cport);
                        conn = lb_conn_get(hash_elem, conn_param.af, &conn_param.caddr, conn_param.cport, lbs->markid, &hash_elem_free);
                        if (conn != NULL) {
                            conn->timer.delay = 0;
                            lb_sync_send_message(conn, lbs, true);
                            if (AF_INET6 == lbs->af) {
                                ipv6_conn_expire_sync_conn(conn);
                            } else {
                                ipv4_conn_expire_sync_conn(conn);
                            }
                            exp_count++;
                        }
                        else {
                            conn = lb_conn_new(lbs, &conn_param);
                            if (NULL == conn) {
                                stop = true;
                                break;
                            }
                            else {
                                new_count++;
                                if (new_count >= count) {
                                    stop = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (stop) {
                        break;
                    }
                }
            }
            else {
                /* do nothing */
            }
        }
        else {
            /* do nothing */
        }
    }
    else {
        /* do nothing */
    }
}

void lb_sync_lcore_simple_new_conns(unsigned int count)
{
    uint16_t port;
    uint32_t ip;
    uint32_t ip_sub;

    union inet_addr addr_min;
    union inet_addr addr_max;
    uint32_t ip_min;
    uint32_t ip_max;
    unsigned int new_count = 0;

    struct lb_conn* conn = NULL;
    struct lb_conn_param conn_param;

    struct lb_service lbs;
    struct lb_dest dest;

    int err;
    unsigned lcore_id = rte_lcore_id();
    bool stop = false;

    if (0 == count) {
        return;
    }

    lbs.af = AF_INET;
    if (lcore_id & 0x01) {
        lbs.proto = IPPROTO_TCP;
    } else {
        lbs.proto = IPPROTO_UDP;
    }

    conn_param.flags = 0;
    conn_param.state = 0;
    /* timeout is not used */
    conn_param.timeout = 300;
    conn_param.af = lbs.af;
    conn_param.proto = lbs.proto;
    inet_pton(AF_INET, "10.0.0.100", &conn_param.vaddr.in);
    inet_pton(AF_INET, "192.168.100.1", &conn_param.laddr.in);
    inet_pton(AF_INET, "192.168.100.2", &conn_param.daddr.in);
    if (IPPROTO_TCP == conn_param.proto) {
        conn_param.vport = htons(80);
        conn_param.dport = htons(80);
    } else {
        conn_param.vport = htons(69);
        conn_param.dport = htons(69);
    }

    err = inet_pton(conn_param.af, CONFIG_SYNC_DEBUG_CADDR_MIN, &addr_min.in);
    if (1 == err) {
        err = inet_pton(conn_param.af, CONFIG_SYNC_DEBUG_CADDR_MAX, &addr_max.in);
    }

    if (1 == err) {
        ip_min = ntohl(addr_min.in.s_addr);
        ip_max = ntohl(addr_max.in.s_addr);
        for (ip = ip_min; ip <= ip_max; ip++) {
            ip_sub = ip & 0xff;
            if (ip_sub == 255 || ip_sub == 0 || ip_sub == 1) {
                /* skip special addr in ipv4 */
                continue;
            }
            conn_param.caddr.in.s_addr = htonl(ip);
            for (port = 1024; port <= 65535 && port >= 1024; port++) {
                conn_param.cport = htons(port);
                conn_param.lport = conn_param.cport;
                conn = lb_conn_simple_new(&conn_param);
                if (NULL == conn) {
                    stop = true;
                    break;
                } else {
                    new_count++;
                    if (IPPROTO_TCP == lbs.proto) {
                        conn->state = DPVS_TCP_S_ESTABLISHED;
                    } else {
                        conn->flags |= LB_CONN_F_STABLE;
                    }
                    dest.addr = conn_param.daddr;
                    dest.port = conn_param.dport;
                    dest.vaddr = conn_param.vaddr;
                    dest.vport = conn_param.vport;
                    conn->dest = &dest;
                    if (lb_sync_conn_needed(conn)) {
                        lb_sync_send_message(conn, &lbs, false);
                    }
                    lb_conn_simple_free(conn);
                    conn = NULL;
                    if (new_count >= count) {
                        stop = true;
                        break;
                    }
                }
            }
            if (stop) {
                break;
            }
        }
    } else {
        /* do nothing */
    }
}

