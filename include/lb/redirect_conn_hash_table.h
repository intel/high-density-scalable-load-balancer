/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_NAT_CONN_HASH_TABLE_H__
#define __LB_NAT_CONN_HASH_TABLE_H__

#include "inet.h"
#include "lb/conn.h"

struct lb_conn_hash_elem *lb_redirect_conn_cache_get(int af, union inet_addr *saddr, uint16_t sport, uint32_t *hash);
void lb_redirect_conn_get_free(int af, struct lb_conn_hash_elem *hash_elem_head, struct lb_conn_hash_elem_free *hash_elem_free, uint32_t hash);
int64_t lb_redirect_conn_get_cid(struct lb_conn_hash_elem *hash_elem_head,
                                   int af, union inet_addr *saddr, uint16_t sport, uint8_t markid, uint32_t hash);
int lb_redirect_conn_hash_table_init(void);
void lb_redirect_conn_hold_free_tuple(struct lb_conn_hash_elem_free *hash_elem_free, int cid, int af, union inet_addr *saddr, uint16_t sport, uint8_t markid);
void lb_redirect_conn_release_free_tuple(struct lb_conn *conn, struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index);
void lb_redirect_conn_use_free_tuple(struct lb_conn_hash_elem  *conn_page_head, uint8_t free_bit_map_index, struct lb_conn *conn);
void lb_redirect_conn_hash_free(struct lb_conn *conn);
void lb_redirect_conn_expire(void *priv);

#endif
