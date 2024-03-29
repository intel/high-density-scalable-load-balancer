/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              
 *               This program is distributed in the hope that it will be useful,
 *               but WITHOUT ANY WARRANTY; without even the implied warranty of
 *               MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *               See the GNU General Public License for more details.
 *
 *               This program is free software; you can redistribute it and/or
 *               modify it under the terms of the GNU General Public License
 *               as published by the Free Software Foundation; either version
 *               2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "ipvswrapper.h"
#include "check_data.h"
#include "list.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"

/* local helpers functions */
static int parse_timeout(char *, unsigned *);
static int string_to_number(const char *, int, int);
static int parse_bps(char *, unsigned *);
static int parse_limit_proportion(char *, unsigned *);

/* fetch virtual server group from group name */
virtual_server_group_t *
ipvs_get_group_by_name(char *gname, list l)
{
	element e;
	virtual_server_group_t *vsg;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg = ELEMENT_DATA(e);
		if (!strcmp(vsg->gname, gname))
			return vsg;
	}
	return NULL;
}

local_addr_group *
ipvs_get_laddr_group_by_name(char *gname, list l)
{
	element e;
	local_addr_group *laddr_group;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		laddr_group = ELEMENT_DATA(e);
		if (!strcmp(laddr_group->gname, gname))
			return laddr_group;
	}
	return NULL;
}


blklst_addr_group *
ipvs_get_blklst_group_by_name(char *gname, list l)
{
        element e;
        blklst_addr_group *blklst_group;

        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                blklst_group = ELEMENT_DATA(e);
                if (!strcmp(blklst_group->gname, gname))
                        return blklst_group;
        }
        return NULL;
}

#ifdef _KRNL_2_4_			/* KERNEL 2.4 IPVS handling */

/* Global module def IPVS rules */
static struct ip_vs_rule_user *urule;

/* Initialization helpers */
int
ipvs_start(void)
{
	log_message(LOG_DEBUG, "Initializing ipvs 2.4");
	/* Init IPVS kernel channel */
	if (ipvs_init()) {
		log_message(LOG_INFO,
				"IPVS : Can't initialize ipvs: %s",
				ipvs_strerror(errno));
			return IPVS_ERROR;
		}
	}

	/* Allocate global user rules */
	urule = (struct ip_vs_rule_user *) MALLOC(sizeof (struct ip_vs_rule_user));
	return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
	/* Clean up the room */
	if (urule)
		FREE(urule);
	ipvs_close();
}

static int
ipvs_talk(int cmd)
{
	int result;
	if (result = ipvs_command(cmd, urule))
		if ((cmd == IP_VS_SO_SET_EDITDEST) &&
		    (errno == ENOENT))
			result = ipvs_command(IP_VS_SO_SET_ADDDEST, urule);
	if (result)
		log_message(LOG_INFO, "IPVS : %s", ipvs_strerror(errno));
	return IPVS_SUCCESS;
}

int
ipvs_syncd_cmd(int cmd, char *ifname, int state, int syncid)
{
#ifdef _HAVE_IPVS_SYNCD_

	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	/* prepare user rule */
	urule->state = state;
	urule->syncid = syncid;
	if (ifname != NULL)
		strncpy(urule->mcast_ifn, ifname, IP_VS_IFNAME_MAXLEN);

	/* Talk to the IPVS channel */
	return ipvs_talk(cmd);

#else
	log_message(LOG_INFO, "IPVS : Sync daemon not supported");
	return IPVS_ERROR;
#endif
}

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, virtual_server_group_entry_t *vsg_entry)
{
	uint32_t addr_ip;
	int err = 0;

	/* Parse the whole range */
	for (addr_ip = inet_sockaddrip4(&vsg_entry->addr);
	     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
	     addr_ip += 0x01000000) {
		urule->vaddr = addr_ip;
		urule->vport = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd);
	}

	return err;
}

/* set IPVS group rules */
static int
ipvs_group_cmd(int cmd, list vs_group, real_server_t * rs, char * vsgname)
{
	virtual_server_group_t *vsg = ipvs_get_group_by_name(vsgname, vs_group);
	virtual_server_group_entry_t *vsg_entry;
	list l;
	element e;
	int err = 1;

	/* return if jointure fails */
	if (!vsg) return -1;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		urule->vaddr = inet_sockaddrip4(&vsg_entry->addr);
		urule->vport = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit vfwmark list */
	l = vsg->vfwmark;
	urule->vaddr = 0;
	urule->vport = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		urule->vfwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	urule->vfwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_group_range_cmd(cmd, vsg_entry);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	return err;
}

/* Fill IPVS rule with root vs infos */
void
ipvs_set_rule(int cmd, virtual_server_t * vs, real_server_t * rs)
{
	/* Clean up target rule */
	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	strncpy(urule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	urule->weight = 1;
	urule->conn_flags = vs->loadbalancing_kind;
	urule->netmask = ((u_int32_t) 0xffffffff);
	urule->protocol = vs->service_type;

	if (!parse_timeout(vs->timeout_persistence, &urule->timeout))
		log_message(LOG_INFO, "IPVS : Virtual service %s illegal timeout."
					, FMT_VS(vs));

	if (!parse_bps(vs->bps, &urule->bps))
		log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal bps."
					, FMT_VS(vs));

        if (!parse_limit_proportion(vs->limit_proportion, &urule->limit_proportion))
                log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal limit_proportion."
                                        , FMT_VS(vs));

	if (urule->timeout != 0 || vs->granularity_persistence)
		urule->vs_flags = IP_VS_SVC_F_PERSISTENT;

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			urule->netmask = vs->granularity_persistence;

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST
		    || cmd == IP_VS_SO_SET_DELDEST
		    || cmd == IP_VS_SO_SET_EDITDEST) {
			urule->weight = rs->weight;
			urule->daddr = inet_sockaddrip4(&rs->addr);
			urule->dport = inet_sockaddrport(&rs->addr);
		}
	}
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, list vs_group, virtual_server_t * vs, real_server_t * rs)
{
	int err = 0;

	/* Prepare target rule */
	ipvs_set_rule(cmd, vs, rs);

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		urule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set flag */
	if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
		rs->set = 1;
	if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
		rs->set = 0;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		err = ipvs_group_cmd(cmd, vs_group, rs, vs->vsgname);
	} else {
		if (vs->vfwmark) {
			urule->vfwmark = vs->vfwmark;
		} else {
			urule->vaddr = inet_sockaddrip4(&vs->addr);
			urule->vport = inet_sockaddrport(&vs->addr);
		}

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd);
	}

	return err;
}

/* Remove a specific vs group entry */
int
ipvs_group_remove_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	real_server_t *rs;
	int err = 0;
	element e;
	list l = vs->rs;

	/* Clean target rules */
	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Prepare the IPVS rule */
			if (urule->daddr) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				urule->weight = rs->weight;
				urule->daddr = inet_sockaddrip4(&rs->addr);
				urule->dport = inet_sockaddrport(&rs->addr);
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, vsge);
			} else {
				urule->vfwmark = vsge->vfwmark;
				urule->vaddr = inet_sockaddrip4(&vsge->addr);
				urule->vport = inet_sockaddrport(&vsge->addr);

				/* Talk to the IPVS channel */
				err = ipvs_talk(IP_VS_SO_SET_DELDEST);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		err = ipvs_group_range_cmd(IP_VS_SO_SET_DEL, vsge);
	else
		err = ipvs_talk(IP_VS_SO_SET_DEL);
	return err;
}

#else					/* KERNEL 2.6 IPVS handling */

/* Global module def IPVS rules */
static ipvs_service_t *srule;
static ipvs_dest_t *drule;
static ipvs_daemon_t *daemonrule;
static ipvs_laddr_t *laddr_rule;
static ipvs_blklst_t *blklst_rule;
static ipvs_tunnel_t *tunnel_rule;

/* Initialization helpers */
int
ipvs_start(void)
{
	log_message(LOG_DEBUG, "Initializing ipvs 2.6");
	/* Initialize IPVS module */
	if (ipvs_init()) {
		log_message(LOG_INFO, "IPVS: Can't initialize ipvs: %s",
				ipvs_strerror(errno));
		return IPVS_ERROR;
	}

	/* Allocate global user rules */
	srule = (ipvs_service_t *) MALLOC(sizeof(ipvs_service_t));
	drule = (ipvs_dest_t *) MALLOC(sizeof(ipvs_dest_t));
	daemonrule = (ipvs_daemon_t *) MALLOC(sizeof(ipvs_daemon_t));
	laddr_rule = (ipvs_laddr_t *) MALLOC(sizeof(ipvs_laddr_t));
	blklst_rule = (ipvs_blklst_t *) MALLOC(sizeof(ipvs_blklst_t));
	tunnel_rule = (ipvs_tunnel_t *) MALLOC(sizeof(ipvs_tunnel_t));

	return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
	/* Clean up the room */
	FREE(srule);
	FREE(drule);
	FREE(daemonrule);
	FREE(laddr_rule);
	FREE(blklst_rule);
	FREE(tunnel_rule);

	ipvs_close();
}

/* Send user rules to IPVS module */
static int
ipvs_talk(int cmd)
{
	int result = -1;

	switch (cmd) {
		case IP_VS_SO_SET_STARTDAEMON:
			result = ipvs_start_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_STOPDAEMON:
			result = ipvs_stop_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_ADD:
			result = ipvs_add_service(srule);
			break;
		case IP_VS_SO_SET_DEL:
			result = ipvs_del_service(srule);
			break;
		case IP_VS_SO_SET_EDIT:
			result = ipvs_update_service(srule);
			break;
		case IP_VS_SO_SET_ZERO:
			result = ipvs_zero_service(srule);
			break;
		case IP_VS_SO_SET_ADDLADDR:
			result = ipvs_add_laddr(srule, laddr_rule);
			break;
		case IP_VS_SO_SET_DELLADDR:
			result = ipvs_del_laddr(srule, laddr_rule);
			break;
                case IP_VS_SO_SET_ADDBLKLST:
                        result = ipvs_add_blklst(srule, blklst_rule);
                        break;
                case IP_VS_SO_SET_DELBLKLST:
                        result = ipvs_del_blklst(srule, blklst_rule);
			break;
		case IP_VS_SO_SET_ADDDEST:
			result = ipvs_add_dest(srule, drule);
			break;
		case IP_VS_SO_SET_DELDEST:
			result = ipvs_del_dest(srule, drule);
			break;
		case IP_VS_SO_SET_EDITDEST:
			if ((result = ipvs_update_dest(srule, drule)) &&
			    (result == EDPVS_NOTEXIST))
				result = ipvs_add_dest(srule, drule);
			break;
		case IP_VS_SO_SET_ADDTUNNEL:
			result = ipvs_add_tunnel(tunnel_rule);
			break;
		case IP_VS_SO_SET_DELTUNNEL:
			result = ipvs_del_tunnel(tunnel_rule);
			break;
	}

	if (result) {
		if (result == EDPVS_EXIST && (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_ADDDEST))
			result = 0;
		else if (result == EDPVS_NOTEXIST && (cmd == IP_VS_SO_SET_DEL || cmd == IP_VS_SO_SET_DELDEST))
			result = 0;
		log_message(LOG_INFO, "IPVS: %s", ipvs_strerror(errno));
	}
	return result? IPVS_ERROR:IPVS_SUCCESS;
}

int
ipvs_syncd_cmd(int cmd, char *ifname, int state, int syncid)
{
	memset(daemonrule, 0, sizeof(ipvs_daemon_t));

	/* prepare user rule */
	daemonrule->state = state;
	daemonrule->syncid = syncid;
	if (ifname != NULL)
		strncpy(daemonrule->mcast_ifn, ifname, IP_VS_IFNAME_MAXLEN);

	/* Talk to the IPVS channel */
	ipvs_talk(cmd);
	return IPVS_SUCCESS;
}

/* IPVS group range rule */
static void
ipvs_group_range_cmd(int cmd, virtual_server_group_entry_t *vsg_entry)
{
	uint32_t addr_ip, ip;

	if (vsg_entry->addr.ss_family == AF_INET6) {
		inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		ip = srule->addr.in6.s6_addr32[3];
	} else {
		ip = inet_sockaddrip4(&vsg_entry->addr);
	}

	/* Set Address Family */
	srule->af = vsg_entry->addr.ss_family;

	/* Parse the whole range */
	for (addr_ip = ip;
	     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
	     addr_ip += 0x01000000) {
		if (srule->af == AF_INET6) {
			if (srule->netmask == 0xffffffff)
				srule->netmask = 128;
			srule->addr.in6.s6_addr32[3] = addr_ip;
		} else {
			srule->addr.ip = addr_ip;
		}
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		ipvs_talk(cmd);
	}
}

/* set IPVS group rules */
static int
ipvs_group_cmd(int cmd, list vs_group, real_server_t * rs, virtual_server_t * vs)
{
	virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
	virtual_server_group_entry_t *vsg_entry;
	list l;
	element e;

	/* return if jointure fails */
	if (!vsg) return IPVS_ERROR;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vsg_entry->addr.ss_family;
		if (vsg_entry->addr.ss_family == AF_INET6) {
			if (srule->netmask == 0xffffffff)
				srule->netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		} else
			srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			if (ipvs_talk(cmd) != IPVS_SUCCESS)
				return IPVS_ERROR;
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit vfwmark list */
	l = vsg->vfwmark;
	srule->addr.ip = 0;
	srule->af = 0;
	srule->port = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = AF_INET;
		/* Need to get address family from first real server */
		if (vs->rs && !LIST_ISEMPTY(vs->rs) &&
		    (((real_server_t *)ELEMENT_DATA(LIST_HEAD(vs->rs)))->addr.ss_family == AF_INET6)) {
			srule->af = AF_INET6;
			srule->netmask = 128;
		}
		srule->fwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			if (ipvs_talk(cmd) != IPVS_SUCCESS)
				return IPVS_ERROR;
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	srule->fwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			ipvs_group_range_cmd(cmd, vsg_entry);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}
	return IPVS_SUCCESS;
}

/* Fill IPVS rule with root vs infos */
void
ipvs_set_rule(int cmd, virtual_server_t * vs, real_server_t * rs)
{
	/* Clean target rule */
	memset(drule, 0, sizeof(ipvs_dest_t));

	drule->weight = 1;
	drule->u_threshold = 0;
	drule->l_threshold = 0;
	drule->conn_flags = vs->loadbalancing_kind;
	strncpy(srule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
	srule->protocol = vs->service_type;
	srule->conn_timeout = vs->conn_timeout;
	snprintf(srule->srange, 256, "%s", vs->srange);
	snprintf(srule->drange, 256, "%s", vs->drange);
	snprintf(srule->iifname, IFNAMSIZ, "%s", vs->iifname);
	snprintf(srule->oifname, IFNAMSIZ, "%s", vs->oifname);

	if (!parse_timeout(vs->timeout_persistence, &srule->timeout))
		log_message(LOG_INFO, "IPVS : Virtual service %s illegal timeout."
				    , FMT_VS(vs));

	if (!parse_bps(vs->bps, &srule->bps))
		log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal bps."
				 	, FMT_VS(vs));

	if (!parse_limit_proportion(vs->limit_proportion, &srule->limit_proportion))
		log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal limit_proportion."
					, FMT_VS(vs));

	if (srule->timeout != 0 || vs->granularity_persistence)
		srule->flags |= IP_VS_SVC_F_PERSISTENT;

	/* Only for UDP services */
	if (vs->ops == 1 && srule->protocol == IPPROTO_UDP)
		srule->flags |= IP_VS_SVC_F_ONEPACKET;

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			srule->netmask = vs->granularity_persistence;

	if (vs->syn_proxy)
		srule->flags |= IP_VS_CONN_F_SYNPROXY;

	if (!strcmp(vs->sched, "conhash")) {
		if (vs->hash_target) {
			if ((srule->protocol != IPPROTO_UDP) &&
			    (vs->hash_target == IP_VS_SVC_F_QID_HASH)) {
				log_message(LOG_ERR, "qid hash can only be set in udp service");
			} else {
				srule->flags |= vs->hash_target;
			}
		} else {
			srule->flags |= IP_VS_SVC_F_SIP_HASH; //default
		}
	}

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST ||
		    cmd == IP_VS_SO_SET_EDITDEST) {
			drule->af = rs->addr.ss_family;
			if (rs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&rs->addr, &drule->addr.in6);
			else
				drule->addr.ip = inet_sockaddrip4(&rs->addr);
			drule->port = inet_sockaddrport(&rs->addr);
			drule->weight = rs->weight;	
			drule->u_threshold = rs->u_threshold;
			drule->l_threshold = rs->l_threshold;
		}
	}
}

static void
ipvs_laddr_range_cmd(int cmd, local_addr_entry *laddr_entry)
{
	uint32_t addr_ip, ip;

	memset(laddr_rule, 0, sizeof(ipvs_laddr_t));
	laddr_rule->af = laddr_entry->addr.ss_family;
	if (laddr_entry->addr.ss_family == AF_INET6) {
		inet_sockaddrip6(&laddr_entry->addr, &laddr_rule->addr.in6);
		ip = laddr_rule->addr.in6.s6_addr32[3];
	} else {
		ip = inet_sockaddrip4(&laddr_entry->addr);
	}
    

	for (addr_ip = ip; ((addr_ip >> 24) & 0xFF) <= laddr_entry->range;
						     addr_ip += 0x01000000) {
		if (laddr_entry->addr.ss_family == AF_INET6)
			laddr_rule->addr.in6.s6_addr32[3] = addr_ip;
		else
			laddr_rule->addr.ip = addr_ip;
		strncpy(laddr_rule->ifname, laddr_entry->ifname, sizeof(laddr_rule->ifname));

		ipvs_talk(cmd);
	}
}

static void
ipvs_laddr_group_cmd(int cmd, local_addr_group *laddr_group)
{
	local_addr_entry *laddr_entry;
	list l;
	element e;

	if (!laddr_group)
		return;

	l = laddr_group->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		laddr_entry = ELEMENT_DATA(e);
		memset(laddr_rule, 0, sizeof(ipvs_laddr_t));
		laddr_rule->af = laddr_entry->addr.ss_family;
		if (laddr_entry->addr.ss_family == AF_INET6)
			inet_sockaddrip6(&laddr_entry->addr, &laddr_rule->addr.in6);
		else
			laddr_rule->addr.ip = inet_sockaddrip4(&laddr_entry->addr);
		strncpy(laddr_rule->ifname, laddr_entry->ifname, sizeof(laddr_rule->ifname));
		ipvs_talk(cmd);
	}

	l = laddr_group->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		laddr_entry = ELEMENT_DATA(e);
		ipvs_laddr_range_cmd(cmd, laddr_entry);
	}
}

static void
ipvs_laddr_vsg_cmd(int cmd, list vs_group, virtual_server_t * vs, local_addr_group *laddr_group)
{
	virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
	virtual_server_group_entry_t *vsg_entry;
	list l;
	element e;

	if (!vsg)
		return;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		srule->af = vsg_entry->addr.ss_family;
		if (srule->af == AF_INET6) {
			if (srule->netmask == 0xffffffff)
				srule->netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		} else
			srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		/* local address group channel */
		ipvs_laddr_group_cmd(cmd, laddr_group);
	}

	/* visit range list */
	l = vsg->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		uint32_t addr_ip, ip;
		
		srule->af = vsg_entry->addr.ss_family;
		if (srule->af == AF_INET6) {
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
			ip = srule->addr.in6.s6_addr32[3];
		} else {
			ip = inet_sockaddrip4(&vsg_entry->addr);
		}

		/* Parse the whole range */
		for (addr_ip = ip;
		     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
		     addr_ip += 0x01000000) {
			if (srule->af == AF_INET6) {
				if (srule->netmask == 0xffffffff)
					srule->netmask = 128;
				srule->addr.in6.s6_addr32[3] = addr_ip;
			} else {
				srule->addr.ip = addr_ip;
			}
			srule->port = inet_sockaddrport(&vsg_entry->addr);

			ipvs_laddr_group_cmd(cmd, laddr_group);
		}
	}
}

static int
ipvs_laddr_cmd(int cmd, list vs_group, virtual_server_t * vs)
{
	local_addr_group *laddr_group = ipvs_get_laddr_group_by_name(vs->local_addr_gname, 
							check_data->laddr_group);
	if (!laddr_group) {
		log_message(LOG_ERR, "No address in group %s", vs->local_addr_gname);
		return IPVS_ERROR;
	}

	memset(srule, 0, sizeof(ipvs_service_t));
	srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
	srule->protocol = vs->service_type;

	if(vs->vsgname) {
		ipvs_laddr_vsg_cmd(cmd, vs_group, vs, laddr_group);
	} else {
		if (!vs->vfwmark) {
			srule->af = vs->addr.ss_family;
			if (vs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&vs->addr, &srule->addr.in6);
			else
				srule->addr.ip = inet_sockaddrip4(&vs->addr);
			srule->port = inet_sockaddrport(&vs->addr);

			ipvs_laddr_group_cmd(cmd, laddr_group);
		}
	}

	return IPVS_SUCCESS;
}


/*check blocklist addr*/

static void
ipvs_blklst_range_cmd(int cmd, blklst_addr_entry *blklst_entry)
{
        uint32_t addr_ip, ip;

        memset(blklst_rule, 0, sizeof(ipvs_blklst_t));
        blklst_rule->af = blklst_entry->addr.ss_family;
        if (blklst_entry->addr.ss_family == AF_INET6) {
                inet_sockaddrip6(&blklst_entry->addr, &blklst_rule->addr.in6);
                ip = blklst_rule->addr.in6.s6_addr32[3];
        } else {
                ip = inet_sockaddrip4(&blklst_entry->addr);
        }


        for (addr_ip = ip; ((addr_ip >> 24) & 0xFF) <= blklst_entry->range;
                                                     addr_ip += 0x01000000) {
                if (blklst_entry->addr.ss_family == AF_INET6)
                        blklst_rule->addr.in6.s6_addr32[3] = addr_ip;
                else
                        blklst_rule->addr.ip = addr_ip;

                ipvs_talk(cmd);
        }
}

static void
ipvs_blklst_group_cmd(int cmd, blklst_addr_group *blklst_group)
{
        blklst_addr_entry *blklst_entry;
        list l;
        element e;

        if (!blklst_group)
                return;

        l = blklst_group->addr_ip;
        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                blklst_entry = ELEMENT_DATA(e);
                memset(blklst_rule, 0, sizeof(ipvs_blklst_t));
                blklst_rule->af = blklst_entry->addr.ss_family;
                if (blklst_entry->addr.ss_family == AF_INET6)
                        inet_sockaddrip6(&blklst_entry->addr, &blklst_rule->addr.in6);
                else
                        blklst_rule->addr.ip = inet_sockaddrip4(&blklst_entry->addr);
                ipvs_talk(cmd);
        }

        l = blklst_group->range;
        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                blklst_entry = ELEMENT_DATA(e);
                ipvs_blklst_range_cmd(cmd, blklst_entry);
        }
}

static void
ipvs_blklst_vsg_cmd(int cmd, list vs_group, virtual_server_t * vs, blklst_addr_group *blklst_group)
{
        virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
        virtual_server_group_entry_t *vsg_entry;
        list l;
        element e;
        if (!vsg) 
                return;

        /* visit addr_ip list */
        l = vsg->addr_ip;
        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                vsg_entry = ELEMENT_DATA(e);

                srule->af = vsg_entry->addr.ss_family;
                if (srule->af == AF_INET6) {
                        if (srule->netmask == 0xffffffff)
                                srule->netmask = 128;
                        inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
                } else
                        srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
                srule->port = inet_sockaddrport(&vsg_entry->addr);

                /* blocklist address group channel */
                ipvs_blklst_group_cmd(cmd, blklst_group);
        }

        /* visit range list */
        l = vsg->range;
        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                vsg_entry = ELEMENT_DATA(e);
                uint32_t addr_ip, ip;

                srule->af = vsg_entry->addr.ss_family;
                if (srule->af == AF_INET6) {
                        inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
                        ip = srule->addr.in6.s6_addr32[3];
                } else {
                        ip = inet_sockaddrip4(&vsg_entry->addr);
                }

                /* Parse the whole range */
                for (addr_ip = ip;
                     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                     addr_ip += 0x01000000) {
                        if (srule->af == AF_INET6) {
                                if (srule->netmask == 0xffffffff)
                                        srule->netmask = 128;
                                srule->addr.in6.s6_addr32[3] = addr_ip;
                        } else {
                                srule->addr.ip = addr_ip;
                        }
                        srule->port = inet_sockaddrport(&vsg_entry->addr);

                        ipvs_blklst_group_cmd(cmd, blklst_group);
                }
        }
}

static int
ipvs_blklst_cmd(int cmd, list vs_group, virtual_server_t * vs)
{
        uint32_t ip_addr = 0;
        blklst_addr_group *blklst_group = ipvs_get_blklst_group_by_name(vs->blklst_addr_gname,
                                                        check_data->blklst_group);
        if (!blklst_group) {
                log_message(LOG_ERR, "No address in group %s", vs->blklst_addr_gname);
                return IPVS_ERROR;
        }

        memset(srule, 0, sizeof(ipvs_service_t));
        srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
        srule->protocol = vs->service_type;

        if(vs->vsgname) {
                ipvs_blklst_vsg_cmd(cmd, vs_group, vs, blklst_group);
        } else {
                if (!vs->vfwmark) {
                        srule->af = vs->addr.ss_family;
                        if (vs->addr.ss_family == AF_INET6)
                                inet_sockaddrip6(&vs->addr, &srule->addr.in6);
                        else {
                            ip_addr = inet_sockaddrip4(&vs->addr);
                            if (ip_addr == 0xffffffff)
                                srule->addr.ip = 0;
                            else
                                srule->addr.ip = ip_addr;
                        }
                        srule->port = inet_sockaddrport(&vs->addr);
                        ipvs_blklst_group_cmd(cmd, blklst_group);
                }
        }
        return IPVS_SUCCESS;
}

int ipvs_tunnel_cmd(int cmd, tunnel_entry *entry)
{
    memset(tunnel_rule, 0, sizeof(ipvs_tunnel_t));
    strncpy(tunnel_rule->ifname, entry->ifname, sizeof(tunnel_rule->ifname));
    strncpy(tunnel_rule->kind, entry->kind, sizeof(tunnel_rule->kind));
    strncpy(tunnel_rule->link, entry->link, sizeof(tunnel_rule->link));

    tunnel_rule->laddr.ip = inet_sockaddrip4(&entry->local);
    tunnel_rule->raddr.ip = inet_sockaddrip4(&entry->remote);
    ipvs_talk(cmd);

    return IPVS_SUCCESS;
}

/* Set/Remove a RS or a local/deny address group from a VS */
int
ipvs_cmd(int cmd, list vs_group, virtual_server_t * vs, real_server_t * rs)
{
	/* Set/Remove local address */
	if (cmd == IP_VS_SO_SET_ADDLADDR || cmd == IP_VS_SO_SET_DELLADDR)	
		return ipvs_laddr_cmd(cmd, vs_group, vs);
        /* Set/Remove deny address */
	if (cmd == IP_VS_SO_SET_ADDBLKLST || cmd == IP_VS_SO_SET_DELBLKLST)
		return ipvs_blklst_cmd(cmd, vs_group, vs);
	/* Allocate the room */
	memset(srule, 0, sizeof(ipvs_service_t));
	ipvs_set_rule(cmd, vs, rs);

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		drule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set flag */
	if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
		rs->set = 1;
	if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
		rs->set = 0;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		return ipvs_group_cmd(cmd, vs_group, rs, vs);
	} else {
		if (vs->vfwmark) {
			srule->af = AF_INET;
			/* Need to get address family from first real server */
			if (vs->rs && !LIST_ISEMPTY(vs->rs) &&
			    (((real_server_t *)ELEMENT_DATA(LIST_HEAD(vs->rs)))->addr.ss_family == AF_INET6)) {
				srule->af = AF_INET6;
				srule->netmask = 128;
			}
			srule->fwmark = vs->vfwmark;
		} else if (vs->loadbalancing_kind == IP_VS_CONN_F_SNAT) {
			srule->af = vs->addr.ss_family;
			srule->addr.ip = 0;
			srule->port = inet_sockaddrport(&vs->addr);
		} else {
			srule->af = vs->addr.ss_family;
			if (vs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&vs->addr, &srule->addr.in6);
			else
				srule->addr.ip = inet_sockaddrip4(&vs->addr);
			srule->port = inet_sockaddrport(&vs->addr);
		}

		/* Talk to the IPVS channel */
		return ipvs_talk(cmd);
	}

	return IPVS_SUCCESS;
}

static void 
ipvs_rm_lentry_from_vsg(local_addr_entry *laddr_entry, char *vsgname)
{
	list l;
	element e;
	virtual_server_group_t *vsg;
	virtual_server_group_entry_t *vsg_entry;

	vsg = ipvs_get_group_by_name(vsgname, check_data->vs_group);
	if (!vsg) return;

	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vsg_entry->addr.ss_family;
		if (vsg_entry->addr.ss_family == AF_INET6) {
			srule->netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		} else {
			srule->netmask = 0xffffffff;
			srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		}
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		if (laddr_entry->range)
			ipvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry);
		else {
			memset(laddr_rule, 0, sizeof(ipvs_laddr_t));
			laddr_rule->af = laddr_entry->addr.ss_family;
			if (laddr_entry->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&laddr_entry->addr, &laddr_rule->addr.in6);
			else
				laddr_rule->addr.ip = inet_sockaddrip4(&laddr_entry->addr);
			strncpy(laddr_rule->ifname, laddr_entry->ifname, sizeof(laddr_rule->ifname));

			ipvs_talk(IP_VS_SO_SET_DELLADDR);
		}
	}

	l = vsg->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		uint32_t addr_ip, ip;

		srule->af = vsg_entry->addr.ss_family;
		srule->netmask = (vsg_entry->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
		srule->port = inet_sockaddrport(&vsg_entry->addr);
		if (vsg_entry->addr.ss_family == AF_INET6) {
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
			ip = srule->addr.in6.s6_addr32[3];
		} else {
			ip = inet_sockaddrip4(&vsg_entry->addr);
		}

		for (addr_ip = ip;
		     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
		     addr_ip += 0x01000000) {
			if (srule->af == AF_INET6)
				srule->addr.in6.s6_addr32[3] = addr_ip;
			else
				srule->addr.ip = addr_ip;

			if (laddr_entry->range)
				ipvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry);
			else {
				memset(laddr_rule, 0, sizeof(ipvs_laddr_t));
				laddr_rule->af = laddr_entry->addr.ss_family;
				if (laddr_entry->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&laddr_entry->addr, &laddr_rule->addr.in6);
				else
					laddr_rule->addr.ip = inet_sockaddrip4(&laddr_entry->addr);
				strncpy(laddr_rule->ifname, laddr_entry->ifname, sizeof(laddr_rule->ifname));

				ipvs_talk(IP_VS_SO_SET_DELLADDR);
			}
		}
	}
}

int
ipvs_laddr_remove_entry(virtual_server_t *vs, local_addr_entry *laddr_entry)
{
	memset(srule, 0, sizeof(ipvs_service_t));
	srule->protocol = vs->service_type;

	if (vs->vsgname) {
		ipvs_rm_lentry_from_vsg(laddr_entry, vs->vsgname);
	} else if (!vs->vfwmark) {
		srule->af = vs->addr.ss_family;
		if (vs->addr.ss_family == AF_INET6) {
			srule->netmask = 128;
			inet_sockaddrip6(&vs->addr, &srule->addr.in6);
		} else {
			srule->netmask = 0xffffffff;
			srule->addr.ip = inet_sockaddrip4(&vs->addr);
		}
		srule->port = inet_sockaddrport(&vs->addr);

		if (laddr_entry->range) {
			ipvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry);
		} else {
			memset(laddr_rule, 0, sizeof(ipvs_laddr_t));
			laddr_rule->af = laddr_entry->addr.ss_family;
			if (laddr_entry->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&laddr_entry->addr, &laddr_rule->addr.in6);
			else
				laddr_rule->addr.ip = inet_sockaddrip4(&laddr_entry->addr);
			strncpy(laddr_rule->ifname, laddr_entry->ifname, sizeof(laddr_rule->ifname));

			ipvs_talk(IP_VS_SO_SET_DELLADDR);
		}
	}

	return IPVS_SUCCESS;
}


static void
ipvs_rm_bentry_from_vsg(blklst_addr_entry *blklst_entry, char *vsgname)
{
	list l;
	element e;
	virtual_server_group_t *vsg;
	virtual_server_group_entry_t *vsg_entry;

	vsg = ipvs_get_group_by_name(vsgname, check_data->vs_group);
	if (!vsg) return;

	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vsg_entry->addr.ss_family;
		if (vsg_entry->addr.ss_family == AF_INET6) {
			srule->netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		} else {
			srule->netmask = 0xffffffff;
			srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		}
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		if (blklst_entry->range)
			ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry);
		else {
			memset(blklst_rule, 0, sizeof(ipvs_blklst_t));
			blklst_rule->af = blklst_entry->addr.ss_family;
			if (blklst_entry->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&blklst_entry->addr, &blklst_rule->addr.in6);
			else
				blklst_rule->addr.ip = inet_sockaddrip4(&blklst_entry->addr);

			ipvs_talk(IP_VS_SO_SET_DELBLKLST);
		}
	}

	l = vsg->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		uint32_t addr_ip, ip;

		srule->af = vsg_entry->addr.ss_family;
		srule->netmask = (vsg_entry->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
		srule->port = inet_sockaddrport(&vsg_entry->addr);
		if (vsg_entry->addr.ss_family == AF_INET6) {
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
			ip = srule->addr.in6.s6_addr32[3];
		} else {
			ip = inet_sockaddrip4(&vsg_entry->addr);
		}

		for (addr_ip = ip;
			((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
			addr_ip += 0x01000000) {
			if (srule->af == AF_INET6)
				srule->addr.in6.s6_addr32[3] = addr_ip;
			else
				srule->addr.ip = addr_ip;

			if (blklst_entry->range)
				ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry);
			else {
				memset(blklst_rule, 0, sizeof(ipvs_blklst_t));
				blklst_rule->af = blklst_entry->addr.ss_family;
				if (blklst_entry->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&blklst_entry->addr, &blklst_rule->addr.in6);
			else
					blklst_rule->addr.ip = inet_sockaddrip4(&blklst_entry->addr);

				ipvs_talk(IP_VS_SO_SET_DELBLKLST);
			}
		}
	}
}


int
ipvs_blklst_remove_entry(virtual_server_t *vs, blklst_addr_entry *blklst_entry)
{
	memset(srule, 0, sizeof(ipvs_service_t));
	srule->protocol = vs->service_type;

	if (vs->vsgname) {
		ipvs_rm_bentry_from_vsg(blklst_entry, vs->vsgname);
	} else if (!vs->vfwmark) {
		srule->af = vs->addr.ss_family;
		if (vs->addr.ss_family == AF_INET6) {
			srule->netmask = 128;
			inet_sockaddrip6(&vs->addr, &srule->addr.in6);
		} else {
			srule->netmask = 0xffffffff;
			srule->addr.ip = inet_sockaddrip4(&vs->addr);
		}
		srule->port = inet_sockaddrport(&vs->addr);

		if (blklst_entry->range) {
			ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry);
		} else {
			memset(blklst_rule, 0, sizeof(ipvs_blklst_t));
			blklst_rule->af = blklst_entry->addr.ss_family;
			if (blklst_entry->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&blklst_entry->addr, &blklst_rule->addr.in6);
			else
				blklst_rule->addr.ip = inet_sockaddrip4(&blklst_entry->addr);

			ipvs_talk(IP_VS_SO_SET_DELBLKLST);
		}
	}

	return IPVS_SUCCESS;
}

/* Remove a specific vs group entry */
int
ipvs_group_remove_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	real_server_t *rs;
	element e;
	list l = vs->rs;

	/* Clean target rules */
	memset(srule, 0, sizeof(ipvs_service_t));
	memset(drule, 0, sizeof(ipvs_dest_t));

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Prepare the IPVS rule */
			if (!drule->addr.ip) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				drule->af = rs->addr.ss_family;
				if (rs->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&rs->addr, &drule->addr.in6);
				else
					drule->addr.ip = inet_sockaddrip4(&rs->addr);
				drule->port = inet_sockaddrport(&rs->addr);
				drule->weight = rs->weight;
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, vsge);
			} else {
				srule->af = vsge->addr.ss_family;
				if (vsge->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&vsge->addr, &srule->addr.in6);
				else
					srule->addr.ip = inet_sockaddrip4(&vsge->addr);
				srule->port = inet_sockaddrport(&vsge->addr);
				srule->fwmark = vsge->vfwmark;
				drule->u_threshold = rs->u_threshold;
				drule->l_threshold = rs->l_threshold;

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_DELDEST);
			}
		}
	}

	/* In case of all rs is unalive */
	ipvs_set_rule(IP_VS_SO_SET_DEL, vs, NULL);

	/* Remove VS entry */
	if (vsge->range)
		ipvs_group_range_cmd(IP_VS_SO_SET_DEL, vsge);
	else {
		srule->af = vsge->addr.ss_family;
		if (vsge->addr.ss_family == AF_INET6)
			inet_sockaddrip6(&vsge->addr, &srule->addr.in6);
		else
			srule->addr.ip = inet_sockaddrip4(&vsge->addr);
		srule->port = inet_sockaddrport(&vsge->addr);
		srule->fwmark = vsge->vfwmark;

		ipvs_talk(IP_VS_SO_SET_DEL);
	}

	return IPVS_SUCCESS;
}

#ifdef _WITH_SNMP_
/* Update statistics for a given virtual server. This includes
   statistics of real servers. The update is only done if we need
   refreshing. */
void
ipvs_update_stats(virtual_server_t *vs)
{
	element e, ge = NULL;
	real_server_t *rs;
	virtual_server_group_t *vsg = NULL;
	virtual_server_group_entry_t *vsg_entry = NULL;
	uint32_t addr_ip = 0;
	union nf_inet_addr nfaddr;
	ipvs_service_entry_t * serv = NULL;
	struct ip_vs_get_dests * dests = NULL;
	int i;
#define UPDATE_STATS_INIT 1
#define UPDATE_STATS_VSG_IP 2
#define UPDATE_STATS_VSG_FWMARK 4
#define UPDATE_STATS_VSG_RANGE 6
#define UPDATE_STATS_VSG_RANGE_IP 7
#define UPDATE_STATS_END 99
	int state = UPDATE_STATS_INIT;

	if (time(NULL) - vs->lastupdated < STATS_REFRESH)
		return;
	vs->lastupdated = time(NULL);
	/* Reset stats */
	memset(&vs->stats, 0, sizeof(vs->stats));
	if (vs->s_svr) {
		memset(&vs->s_svr->stats, 0, sizeof(vs->s_svr->stats));
		vs->s_svr->activeconns =
			vs->s_svr->inactconns = vs->s_svr->persistconns = 0;
	}
	if (!LIST_ISEMPTY(vs->rs)) {
		for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
			rs = ELEMENT_DATA(e);
			memset(&rs->stats, 0, sizeof(rs->stats));
			rs->activeconns = rs->inactconns = rs->persistconns = 0;
		}
	}
	/* FSM: at each transition, we process "serv" if it is not NULL */
	while (state != UPDATE_STATS_END) {
		serv = NULL;
		switch (state) {
		case UPDATE_STATS_INIT:
			/* We need to know the next state to reach */
			if (vs->vsgname) {
				if (!LIST_ISEMPTY(check_data->vs_group))
					vsg = ipvs_get_group_by_name(vs->vsgname,
								     check_data->vs_group);
				else
					vsg = NULL;
				if (!vsg)
					state = UPDATE_STATS_END;
				else {
					state = UPDATE_STATS_VSG_IP;
					ge = NULL;
				}
				continue;
			}
			state = UPDATE_STATS_END;
			if (vs->vfwmark) {
				memset(&nfaddr, 0, sizeof(nfaddr));
				serv = ipvs_get_service(vs->vfwmark,
							AF_INET,
							vs->service_type,
							nfaddr, 0);
				break;
			}
			memcpy(&nfaddr, (vs->addr.ss_family == AF_INET6)?
			       (void*)(&((struct sockaddr_in6 *)&vs->addr)->sin6_addr):
			       (void*)(&((struct sockaddr_in *)&vs->addr)->sin_addr),
			       sizeof(nfaddr));
			serv = ipvs_get_service(0,
						vs->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vs->addr));
			break;
		case UPDATE_STATS_VSG_IP:
			if (!ge)
				ge = LIST_HEAD(vsg->addr_ip);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_VSG_FWMARK;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			memcpy(&nfaddr, (vsg_entry->addr.ss_family == AF_INET6)?
			       (void*)(&((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr):
			       (void*)(&((struct sockaddr_in *)&vsg_entry->addr)->sin_addr),
			       sizeof(nfaddr));
			serv = ipvs_get_service(0,
						vsg_entry->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vsg_entry->addr));
			break;
		case UPDATE_STATS_VSG_FWMARK:
			if (!ge)
				ge = LIST_HEAD(vsg->vfwmark);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_VSG_RANGE;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			memset(&nfaddr, 0, sizeof(nfaddr));
			serv = ipvs_get_service(vsg_entry->vfwmark,
						AF_INET,
						vs->service_type,
						nfaddr, 0);
			break;
		case UPDATE_STATS_VSG_RANGE:
			if (!ge)
				ge = LIST_HEAD(vsg->range);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_END;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			addr_ip = (vsg_entry->addr.ss_family == AF_INET6) ?
				  ((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr.s6_addr32[3]:
				  ((struct sockaddr_in *)&vsg_entry->addr)->sin_addr.s_addr;
			state = UPDATE_STATS_VSG_RANGE_IP;
			continue;
		case UPDATE_STATS_VSG_RANGE_IP:
			if (((addr_ip >> 24) & 0xFF) > vsg_entry->range) {
				state = UPDATE_STATS_VSG_RANGE;
				continue;
			}
			if (vsg_entry->addr.ss_family == AF_INET6) {
				inet_sockaddrip6(&vsg_entry->addr, &nfaddr.in6);
				nfaddr.in6.s6_addr32[3] = addr_ip;
			} else {
				nfaddr.in.s_addr = addr_ip;
			}
			serv = ipvs_get_service(0,
						vsg_entry->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vsg_entry->addr));
			addr_ip += 0x01000000;
			break;
		}
		if (!serv)
			continue;

		/* Update virtual server stats */
#define ADD_TO_VSSTATS(X) vs->stats.X += serv->stats.X;
		ADD_TO_VSSTATS(conns);
		ADD_TO_VSSTATS(inpkts);
		ADD_TO_VSSTATS(outpkts);
		ADD_TO_VSSTATS(inbytes);
		ADD_TO_VSSTATS(outbytes);
		ADD_TO_VSSTATS(cps);
		ADD_TO_VSSTATS(inpps);
		ADD_TO_VSSTATS(outpps);
		ADD_TO_VSSTATS(inbps);
		ADD_TO_VSSTATS(outbps);

		/* Get real servers */
		dests = ipvs_get_dests(serv);
		if (!dests) {
			FREE(serv);
			return;
		}
		for (i = 0; i < dests->num_dests; i++) {
			rs = NULL;

#define VSD_EQUAL(entity) (((entity)->addr.ss_family == AF_INET &&	\
			    dests->entrytable[i].af == AF_INET &&	\
			    inaddr_equal(AF_INET,			\
					 &dests->entrytable[i].addr,    \
					 &((struct sockaddr_in *)&(entity)->addr)->sin_addr) &&	\
			    dests->entrytable[i].port == ((struct sockaddr_in *)&(entity)->addr)->sin_port) || \
			    ((entity)->addr.ss_family == AF_INET6 &&	\
			    dests->entrytable[i].af == AF_INET6 &&	\
			    inaddr_equal(AF_INET6,			\
					 &dests->entrytable[i].addr,	\
					 &((struct sockaddr_in6 *)&(entity)->addr)->sin6_addr) &&	\
			    dests->entrytable[i].port == ((struct sockaddr_in6 *)&(entity)->addr)->sin6_port))
			/* Is it the sorry server? */
			if (vs->s_svr && VSD_EQUAL(vs->s_svr))
				rs = vs->s_svr;
			else if (!LIST_ISEMPTY(vs->rs))
				/* Search for a match in the list of real servers */
				for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
					rs = ELEMENT_DATA(e);
					if (VSD_EQUAL(rs))
						break;
				}
			if (rs) {
#define ADD_TO_RSSTATS(X) rs->X += dests->entrytable[i].X
				ADD_TO_RSSTATS(activeconns);
				ADD_TO_RSSTATS(inactconns);
				ADD_TO_RSSTATS(persistconns);
				ADD_TO_RSSTATS(stats.conns);
				ADD_TO_RSSTATS(stats.inpkts);
				ADD_TO_RSSTATS(stats.outpkts);
				ADD_TO_RSSTATS(stats.inbytes);
				ADD_TO_RSSTATS(stats.outbytes);
				ADD_TO_RSSTATS(stats.cps);
				ADD_TO_RSSTATS(stats.inpps);
				ADD_TO_RSSTATS(stats.outpps);
				ADD_TO_RSSTATS(stats.inbps);
				ADD_TO_RSSTATS(stats.outbps);
			}
		}
		FREE(dests);
		FREE(serv);
	}
}
#endif /* _WITH_SNMP_ */

#endif

/*
 * Common IPVS functions
 */
void
ipvs_syncd_master(char *ifname, int syncid)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_BACKUP, syncid);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_MASTER, syncid);
}

void
ipvs_syncd_backup(char *ifname, int syncid)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_MASTER, syncid);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_BACKUP, syncid);
}

/*
 * Utility functions coming from Wensong code
 */

static int
parse_bps(char *buf, unsigned *bps)
{
	int i;
	if (buf == NULL) {
		*bps = 0;
		return 1;
	}
	/**only support bps in MB??**/
	if ((i = string_to_number(buf, 0, 1024)) == -1)
		return 0;
	*bps = i;
	return 1;
}

static int
parse_limit_proportion(char *buf, unsigned *limit_proportion)
{
        int i;
        if (buf == NULL) {
                *limit_proportion = 100;
                return 1;
        }
        if ((i = string_to_number(buf, 0, 100)) == -1) {
                *limit_proportion = 100;
                return 0;
        }
        *limit_proportion = i;
        return 1;	
}

static int
parse_timeout(char *buf, unsigned *timeout)
{
	int i;

	if (buf == NULL) {
		*timeout = IP_VS_TEMPLATE_TIMEOUT;
		return 1;
	}

	if ((i = string_to_number(buf, 0, 86400 * 31)) == -1)
		return 0;

	*timeout = i * (IP_VS_TEMPLATE_TIMEOUT / (6*60));
	return 1;
}

static int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	number = (int) strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/*
		 * We parsed a number, let's see if we want this.
		 * If max <= min then ignore ranges
		 */
		if (max <= min || (min <= number && number <= max))
			return number;
		else
			return -1;
	} else
		return -1;
}
