/* SPDX-License-Identifier: GPL-2.0-only
* Copyright(c) 2020 Intel Corporation
*/

#ifndef __LB_WLC_H__
#define __LB_WLC_H__

#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"

int lb_wlc_init(void);
int lb_wlc_term(void);

#endif
