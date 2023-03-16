/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_WRR_H__
#define __LB_WRR_H__

#include "lb/service.h"
#include "lb/dest.h"
#include "lb/sched.h"

int lb_wrr_init(void);
int lb_wrr_term(void);

#endif
