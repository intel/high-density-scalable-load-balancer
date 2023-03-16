#ifndef __LB_SYNC_CONF_H__
#define __LB_SYNC_CONF_H__

#include <net/if.h>

enum {
    /* set */
    SOCKOPT_SET_STARTDAEMON = 7000,
    SOCKOPT_SET_STOPDAEMON,
    SOCKOPT_SET_SETDAEMON,
    /* get */
    SOCKOPT_GET_DAEMON,
};

/* User use this to config sync daemon */
struct lb_sync_daemon_entry {
    union {
        uint32_t       syncid;       /* backup daemon uses SyncID to filter out sync msgs not matched with the SyncID value */
        uint32_t       lcore_id;     /* lcore id of the CPU where sync msg is sent or processed, */
    };
    struct in_addr mcast_group;      /* multicast IP address in network byte order */
    struct in_addr mcast_ifia ;      /* IP address of multicast tx/rx interface dev */
    char           mcast_ifn[IF_NAMESIZE]; /* multicast tx/rx interface name */
    uint16_t       mcast_port;       /* port number in network byte order */
    uint8_t        mcast_ttl;        /* TTL value for sync messages (1 .. 255).  The default value is 1 */
    uint8_t        state;            /* the sync daemon state: 0x1: active, 0x2: backup */
};

/* User use this to get sync daemon statistics */
struct lb_sync_daemon_stat {
    union {
        uint32_t    syncid;             /* backup daemon uses SyncID to filter out sync msgs not matched with the SyncID */
        uint32_t    lcore_id;           /* lcore id of the CPU where sync msg is sent or processed, */
    };
    struct in_addr  mcast_group;        /* multicast IP address in network byte order */
    struct in_addr  mcast_ifia;         /* IP address of multicast tx/rx interface dev */
    uint16_t        mcast_port;         /* port number in network byte order */
    uint8_t         mcast_ttl;          /* TTL value for sync messages (1 .. 255).  The default value is 1 */
    uint8_t         daemon_state   : 2; /* the sync daemon state: 0x1: active, 0x2: backup */
    uint8_t         fdir_state     : 1; /* the backup daemon FDIR state: 0x0: fdir rule failed, 0x1: fdir rule created */
    uint8_t         mcast_if_exist : 1; /* multicast tx/rx interface exist: 0x0: N, 0x1: Y */
    uint8_t         mcast_if_allmulticast : 2; /* multicast tx/rx interface allmulticast state: 0: disabled, 1: enabled, 2: error */
    char            mcast_ifn[IF_NAMESIZE];    /* multicast tx/rx interface name */

};

struct lb_sync_daemon_stats {
    int                        n;
    struct lb_sync_daemon_stat daemon_stat[0];
};

#endif /* __LB_SYNC_CONF_H__ */
