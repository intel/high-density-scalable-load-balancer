#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <linux/if_addr.h>
#include "common.h"
#include "dpdk.h"
#include "netif.h"
#include "inetaddr.h"
#include "netif_addr.h"
#include "conf/inetaddr.h"

#include "laddr_multiply.h"

int laddr_multiply_process(int af, union inet_addr *base_laddr,
                    laddrhandler_t laddr_cbfn, laddrhandler_t rollback_cbfn, void *arg)
{
    int err, i;
    lcoreid_t cid;
    uint8_t nlcore;
    uint64_t lcore_mask;
    union inet_addr addr_tmp, addr_rollback;

    if (!base_laddr || !laddr_cbfn || (af != AF_INET && af != AF_INET6))
        return EDPVS_INVAL;

    /* enabled lcore should not change after init */
    netif_get_slave_lcores(&nlcore, &lcore_mask);

    memcpy(&addr_tmp, base_laddr, sizeof(addr_tmp));
    for (cid=0; cid < RTE_MAX_LCORE; cid++) {
        if (cid > 64 || !(lcore_mask & (1L << cid)))
            continue;

        for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
            err = (*laddr_cbfn)(cid, af, &addr_tmp, arg, i);
            if (err)
                goto rollback;

            laddr_multiply_inc(af, &addr_tmp);
        }
    }

    return EDPVS_OK;


rollback:
    if (!rollback_cbfn)
        return err;

    memcpy(&addr_rollback, &addr_tmp, sizeof(addr_tmp));
    memcpy(&addr_tmp, base_laddr, sizeof(addr_tmp));
    for (cid=0; cid<RTE_MAX_LCORE; cid++) {
        if (cid > 64 || !(lcore_mask & (1L << cid)))
            continue;

        for (i=0; i<DPVS_MAX_LADDR_PERCORE; i++) {
            if (!memcmp(&addr_rollback, &addr_tmp, sizeof(addr_tmp)))
                return err;

            (*rollback_cbfn)(cid, af, &addr_tmp, arg, i);
            laddr_multiply_inc(af, &addr_tmp);
        }
    }

    return err;
}

