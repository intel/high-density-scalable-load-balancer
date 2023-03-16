/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __SYNC_DEBUG_H__
#define __SYNC_DEBUG_H__

union lb_sync_conn;

void lb_sync_disp_sync_conn(union lb_sync_conn* sync_conn);
void lb_sync_lcore_new_conns(unsigned int count);
void lb_sync_lcore_simple_new_conns(unsigned int count);

#endif