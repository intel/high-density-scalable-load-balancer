/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __IP_H__
#define __IP_H__

static inline uint16_t ip_compute_csum(const void* buf, size_t len)
{
    uint16_t cksum;
    cksum = rte_raw_cksum(buf, len);
    return (cksum == 0xffff) ? cksum : ~cksum;
}

static inline void ip_eth_mc_map(uint32_t naddr, uint8_t* buf)
{
    uint32_t addr = rte_be_to_cpu_32(naddr);
    buf[0] = 0x01;
    buf[1] = 0x00;
    buf[2] = 0x5e;
    buf[5] = addr & 0xFF;
    addr >>= 8;
    buf[4] = addr & 0xFF;
    addr >>= 8;
    buf[3] = addr & 0x7F;
}

#endif
