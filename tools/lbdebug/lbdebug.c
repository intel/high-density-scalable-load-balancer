/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include "common.h"
#include "sockopt.h"

enum{
    DPVS_SO_GET_VERSION = 200,
    DPVS_SO_GET_INFO,
    DPVS_SO_GET_SERVICES,
    DPVS_SO_GET_SERVICE,
    DPVS_SO_GET_DESTS,
    DPVS_SO_GET_LB_DEBUG,
};


#define LB_DEBUG_CMD_TIMER  0
#define LB_DEBUG_CMD_LOOP_CYCLE 1
#define LB_DEBUG_CMD_SNAT_POOL  2
#define LB_DEBUG_CMD_MEMPOOL    3
#define LB_DEBUG_CMD_NETIF_STAT 4

struct lb_debug_timer_arg {
    uint64_t delay;
};

struct lb_debug_loop_record {
    uint32_t percision;
    uint8_t  clean;
};

struct lb_debug_arg {
    uint8_t cmd;
    uint8_t cid;
    union {
        struct lb_debug_timer_arg timer_arg;
        struct lb_debug_loop_record loop_record_arg;
    };
};

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    lbdebug [OPTIONS] COMMAND arguments\n"
        "Options:\n"
        "    -c core id\n"
        "    -d timer delay\n"
        "    -p record job loop cycle precision\n"
        "Example:\n"
        "    lbdebug -t -c 1 -d 60      -- Display all timers on core 1 and output error messages if they don't timeouted in 60 seconds\n"
        "    lbdebug -r -c 1 -p 1       -- Show cycle consumption of jobs on core 1\n"
        "    lbdebug -s -c 1            -- Show SNAT pool info and debug\n"
        "    lbdebug -m                 -- Dump memory pool infomation\n"
        "    lbdebug -S -c 0            -- Show netif tx/rx stats\n"
        );
}

static int parse_args(int argc, char *argv[], struct lb_debug_arg *conf)
{
    int opt;
    struct option opts[] = {
        {"help",    no_argument, NULL, 'h'},
        {"timer", no_argument, NULL, 't'},
        {NULL, 0, NULL, 0},
    };

    memset(conf, 0, sizeof(*conf));

    if (argc <= 1) {
        usage();
        exit(0);
    }

    while ((opt = getopt_long(argc, argv, "mstrSCc:d:p:", opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            conf->cid = atoi(optarg);
            break;

        case 'd':
            conf->timer_arg.delay = atoi(optarg);
            break;

        case 't':
            conf->cmd = LB_DEBUG_CMD_TIMER;
            break;

        case 'r':
            conf->cmd = LB_DEBUG_CMD_LOOP_CYCLE;
            break;

        case 's':
            conf->cmd = LB_DEBUG_CMD_SNAT_POOL;
            break;

        case 'S':
            conf->cmd = LB_DEBUG_CMD_NETIF_STAT;
            break;

        case 'm':
            conf->cmd = LB_DEBUG_CMD_MEMPOOL;
            break;

        case 'p':
            conf->loop_record_arg.percision = atoi(optarg);
            break;

        case 'C':
            conf->loop_record_arg.clean = 1;
            break;

        case 'h':
            usage();
            exit(0);

        case '?':
        default:
            fprintf(stderr, "Invalid option: %s\n", argv[optind]);
            return -1;
        }
    }

    return 0;
}


int main(int argc, char *argv[])
{
    struct lb_debug_arg conf;
    void *out;
    size_t out_len;
    int ret;

    if (parse_args(argc, argv, &conf))
        return -1;


    ret = dpvs_getsockopt(DPVS_SO_GET_LB_DEBUG, &conf, sizeof(conf), &out, &out_len);
    if (out)
        free(out);

    return ret;
}

