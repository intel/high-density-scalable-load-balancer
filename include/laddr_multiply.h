#ifndef __LADDR_MULTIPLY_H__
#define __LADDR_MULTIPLY_H__

typedef int (*laddrhandler_t)(lcoreid_t cid, int af, union inet_addr *laddr, void *arg, int index);
int laddr_multiply_process(int af, union inet_addr *base_laddr,
                laddrhandler_t laddr_cbfn, laddrhandler_t rollback_cbfn, void *arg);

static inline int laddr_multiply_inc(int af, union inet_addr *laddr)
{
    uint32_t laddr4;
    int i = 15;
    uint8_t *laddr6 = laddr->in6.__in6_u.__u6_addr8;
    //char v6_buf[128] = "";

    if (af == AF_INET) {
        laddr4 = rte_be_to_cpu_32(laddr->in.s_addr) + 1;
        laddr->in.s_addr = rte_cpu_to_be_32(laddr4);
        return EDPVS_OK;
    }

    do {
        laddr6[i] += 1;
    } while (!laddr6[i] && --i);

    //inet_ntop(AF_INET6, laddr, v6_buf, 128);
    //printf("[%s,%d] out ipv6 addr: %s\n", __func__, __LINE__, v6_buf);

    return EDPVS_OK;
}

static inline uint16_t laddr_multiply_offset(int af, union inet_addr *laddr, union inet_addr *base_laddr)
{
    int pos;
    uint16_t v6, base_v6;

    if (af == AF_INET) {
        pos = rte_be_to_cpu_32(laddr->in.s_addr) - rte_be_to_cpu_32(base_laddr->in.s_addr);
    } else {
        v6 = (laddr->in6.__in6_u.__u6_addr8[14] << 8) + laddr->in6.__in6_u.__u6_addr8[15];
        base_v6 = (base_laddr->in6.__in6_u.__u6_addr8[14] << 8) + base_laddr->in6.__in6_u.__u6_addr8[15];
        pos = v6 - base_v6;
        if (pos < 0)
            pos += DPVS_MAX_LADDR_PERCORE;
    }

    return pos;
}

#endif
