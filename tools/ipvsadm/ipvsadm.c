/*
 *      ipvsadm - IP Virtual Server ADMinistration program
 *                for IPVS NetFilter Module in kernel 2.4
 *
 *      Version: $Id: ipvsadm.c 73 2010-10-07 12:59:40Z horms $
 *
 *      Authors: Wensong Zhang <wensong@linuxvirtualserver.org>
 *               Peter Kese <peter.kese@ijs.si>
 *
 *      This program is based on ippfvsadm.
 *
 *      Changes:
 *        Wensong Zhang       :   added the editting service & destination support
 *        Wensong Zhang       :   added the feature to specify persistent port
 *        Jacob Rief          :   found the bug that masquerading dest of
 *                                different vport and dport cannot be deleted.
 *        Wensong Zhang       :   fixed it and changed some cosmetic things
 *        Wensong Zhang       :   added the timeout setting for persistent service
 *        Wensong Zhang       :   added specifying the dest weight zero
 *        Wensong Zhang       :   fixed the -E and -e options
 *        Wensong Zhang       :   added the long options
 *        Wensong Zhang       :   added the hostname and portname input
 *        Wensong Zhang       :   added the hostname and portname output
 *	  Lars Marowsky-Br�e  :   added persistence granularity support
 *        Julian Anastasov    :   fixed the (null) print for unknown services
 *        Wensong Zhang       :   added the port_to_anyname function
 *        Horms               :   added option to read commands from stdin
 *        Horms               :   modified usage function so it prints to
 *                            :   stdout if an exit value of 0 is used and
 *                            :   stdout otherwise. Program is then terminated
 *                            :   with the supplied exit value.
 *        Horms               :   updated manpage and usage funtion so
 *                            :   the reflect the options available
 *        Wensong Zhang       :   added option to write rules to stdout
 *        Horms               :   added ability to specify a fwmark
 *                            :   instead of a server and port for
 *                            :   a virtual service
 *        Horms               :   tightened up checking of services
 *                            :   in parse_service
 *        Horms               :   ensure that a -r is passed when needed
 *        Wensong Zhang       :   fixed the output of fwmark rules
 *        Horms               :   added kernel version verification
 *        Horms               :   Specifying command and option options
 *                                (e.g. -Ln or -At) in one short option
 *                                with popt problem fixed.
 *        Wensong Zhang       :   split the process_options and make
 *                                two versions of parse_options.
 *        Horms               :   attempting to save or restore when
 *                                compiled against getopt_long now results
 *                                in an informative error message rather
 *                                than the usage information
 *        Horms               :   added -v option
 *        Wensong Zhang       :   rewrite most code of parsing options and
 *                                processing options.
 *        Alexandre Cassen    :   added ipvs_syncd SyncdID support to filter
 *                                incoming sync messages.
 *        Guy Waugh & Ratz    :   added --exact option and spelling cleanup
 *        vbusam@google.com   :   added IPv6 support
 *
 *
 *      ippfvsadm - Port Fowarding & Virtual Server ADMinistration program
 *
 *      Copyright (c) 1998 Wensong Zhang
 *      All rights reserved.
 *
 *      Author: Wensong Zhang <wensong@iinchina.net>
 *
 *      This ippfvsadm is derived from Steven Clarke's ipportfw program.
 *
 *      portfw - Port Forwarding Table Editing v1.1
 *
 *      Copyright (c) 1997 Steven Clarke
 *      All rights reserved.
 *
 *      Author: Steven Clarke <steven@monmouth.demon.co.uk>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#undef __KERNEL__	/* Makefile lazyness ;) */
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>           /* For waitpid */
#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "popt.h"
#define IPVS_OPTION_PROCESSING	"popt"

#include "config_stream.h"
#include "../keepalived/keepalived/libipvs-2.6/libipvs.h"

#define IPVSADM_VERSION_NO	"v" VERSION
#define IPVSADM_VERSION_DATE	"2008/5/15"
#define IPVSADM_VERSION		IPVSADM_VERSION_NO " " IPVSADM_VERSION_DATE

#define MAX_TIMEOUT		(86400*31)	/* 31 days */

#define CMD_NONE		0
#define CMD_ADD			(CMD_NONE+1)
#define CMD_EDIT		(CMD_NONE+2)
#define CMD_DEL			(CMD_NONE+3)
#define CMD_FLUSH		(CMD_NONE+4)
#define CMD_LIST		(CMD_NONE+5)
#define CMD_ADDDEST		(CMD_NONE+6)
#define CMD_DELDEST		(CMD_NONE+7)
#define CMD_EDITDEST		(CMD_NONE+8)
#define CMD_TIMEOUT		(CMD_NONE+9)
#define CMD_STARTDAEMON		(CMD_NONE+10)
#define CMD_STOPDAEMON		(CMD_NONE+11)
#define CMD_RESTORE		(CMD_NONE+12)
#define CMD_SAVE		(CMD_NONE+13)
#define CMD_ZERO		(CMD_NONE+14)
#define CMD_ADDLADDR		(CMD_NONE+15)
#define CMD_DELLADDR		(CMD_NONE+16)
#define CMD_GETLADDR		(CMD_NONE+17)
#define CMD_ADDBLKLST		(CMD_NONE+18)
#define CMD_DELBLKLST		(CMD_NONE+19)
#define CMD_GETBLKLST		(CMD_NONE+20)
#define CMD_SETDAEMON		(CMD_NONE+21)
#define CMD_MAX			CMD_SETDAEMON
#define NUMBER_OF_CMD		(CMD_MAX - CMD_NONE)

static const char* cmdnames[] = {
	"add-service",
	"edit-service",
	"delete-service",
	"flush",
	"list",
	"add-server",
	"delete-server",
	"edit-server",
	"set",
	"start-daemon",
	"stop-daemon",
	"restore",
	"save",
	"zero",
	"add-laddr" ,
	"del-laddr" ,
	"get-laddr" ,
	"add-blklst",
	"del-blklst",
	"get-blklst",
	"set-daemon",
};

static const char* optnames[] = {
	"numeric",
	"connection",
	"service-address",
	"scheduler",
	"persistent",
	"netmask",
	"real-server",
	"forwarding-method",
	"weight",
	"u-threshold",
	"l-threshold",
	"mcast-interface",
	"timeout",
	"daemon",
	"stats",
	"rate",
	"thresholds",
	"persistent-conn",
	"nosort",
	"syncid",
	"exact",
	"ops",
	"pe" ,
	"local-address" ,
	"blklst-address",
	"synproxy" ,
	"ifname" ,
	"sockpair" ,
	"hash-target",
	"lcore-id",
	"mcast-group",
	"mcast-port",
	"mcast-ttl",
	"mcast-interface-addr",
};

/*
 * Table of legal combinations of commands and options.
 * Key:
 *  '+'  compulsory
 *  'x'  illegal
 *  '1'  exclusive (only one '1' option can be supplied)
 *  ' '  optional
 */
static const char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
{
        /* -n   -c   svc  -s   -p   -M   -r   fwd  -w   -x   -y   -mc  tot  dmn  -st  -rt  thr  -pc  srt  sid  -ex  ops  pe   laddr blst syn ifname sockpair hashtag lcore-id,mcast-group,mcast-port,mcast-ttl,mcast-interface-addr */
/*ADD*/      {'x', 'x', '+', ' ', ' ', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x',  ' ', 'x' ,'x' ,' ',      'x',     'x',        'x',       'x',      'x'},
/*EDIT*/     {'x', 'x', '+', ' ', ' ', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x',  ' ', 'x' ,'x' ,' ',      'x',     'x',        'x',       'x',      'x'},
/*DEL*/      {'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*FLUSH*/    {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*LIST*/     {' ', '1', '1', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', '1', '1', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'x', 'x', 'x', 'x',  'x', 'x' ,' ' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*ADDSRV*/   {'x', 'x', '+', 'x', 'x', 'x', '+', ' ', ' ', ' ', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*DELSRV*/   {'x', 'x', '+', 'x', 'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*EDITSRV*/  {'x', 'x', '+', 'x', 'x', 'x', '+', ' ', ' ', ' ', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*TIMEOUT*/  {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*STARTD*/   {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      ' ',     'x',        'x',       'x',      'x'},
/*STOPD*/    {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      ' ',     'x',        'x',       'x',      'x'},
/*RESTORE*/  {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*SAVE*/     {' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*ZERO*/     {'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*ADDLADDR*/ {'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', '+', 'x',  'x', '+' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*DELLADDR*/ {'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', '+', 'x',  'x', '+' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*GETLADDR*/ {'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*ADDBLKLST*/{'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', '+',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*DELBLKLST*/{'x', 'x', '+', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', '+',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*GETBLKLST*/{'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      'x',     'x',        'x',       'x',      'x'},
/*SETDAEMON*/{'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',  'x', 'x' ,'x' ,'x',      '+',     ' ',        ' ',       ' ',      ' '},
};

/* printing format flags */
#define FMT_NONE		0x0000
#define FMT_NUMERIC		0x0001
#define FMT_RULE		0x0002
#define FMT_STATS		0x0004
#define FMT_RATE		0x0008
#define FMT_THRESHOLDS		0x0010
#define FMT_PERSISTENTCONN	0x0020
#define FMT_NOSORT		0x0040
#define FMT_EXACT		0x0080

#define SERVICE_NONE		0x0000
#define SERVICE_ADDR		0x0001
#define SERVICE_PORT		0x0002

/* default scheduler */
#define DEF_SCHED		"wlc"

/* default multicast interface name */
#define DEF_MCAST_IFN		"dpdk0"

struct ipvs_command_entry {
	int			cmd;
	ipvs_service_t		svc;
	ipvs_dest_t		dest;
	ipvs_timeout_t		timeout;
	ipvs_daemon_t		daemon;
	ipvs_laddr_t		laddr;
	ipvs_blklst_t		blklst;
	ipvs_sockpair_t		sockpair;
};

/* Use values outside ASCII range so that if an option has
 * a short name it can be used as the tag
 */
enum {
	TAG_SET	= 128,
	TAG_START_DAEMON,
	TAG_STOP_DAEMON	,
	TAG_MCAST_INTERFACE,
	TAG_TIMEOUT,
	TAG_DAEMON,
	TAG_STATS,
	TAG_RATE,
	TAG_THRESHOLDS,
	TAG_PERSISTENTCONN,
	TAG_SORT,
	TAG_NO_SORT,
	TAG_PERSISTENCE_ENGINE,
	TAG_SOCKPAIR,
	TAG_SET_DAEMON,
	TAG_LCORE_ID,
	TAG_MCAST_GROUP,
	TAG_MCAST_PORT,
	TAG_MCAST_TTL,
	TAG_MCAST_INTERFACE_ADDRESS,
};

/* various parsing helpers & parsing functions */
static int str_is_digit(const char *str);
static int string_to_number(const char *s, int min, int max);
static int host_to_addr(const char *name, struct in_addr *addr);
static char * addr_to_host(int af, const void *addr);
static char * addr_to_anyname(int af, const void *addr);
static int service_to_port(const char *name, unsigned short proto);
static char * port_to_service(unsigned short port, unsigned short proto);
static char * port_to_anyname(unsigned short port, unsigned short proto);
static char * addrport_to_anyname(int af, const void *addr, unsigned short port,
				  unsigned short proto, unsigned int format);
static int parse_service(char *buf, ipvs_service_t *svc);
static int parse_netmask(char *buf, u_int32_t *addr);
static int parse_timeout(char *buf, int min, int max);
static unsigned int parse_fwmark(char *buf);
static int parse_sockpair(char *buf, ipvs_sockpair_t *sockpair);
static int parse_match_snat(const char *buf, ipvs_service_t *svc);

/* check the options based on the commands_v_options table */
static void generic_opt_check(int command, uint64_t options);
static void set_command(int *cmd, const int newcmd);
static void set_option(uint64_t *options, uint64_t option);

static void tryhelp_exit(const char *program, const int exit_status);
static void usage_exit(const char *program, const int exit_status);
static void version_exit(int exit_status);
static void version(FILE *stream);
static void fail(int err, char *msg, ...);

/* various listing functions */
static void list_conn(int is_template, unsigned int format);
static void list_conn_sockpair(int is_template,
		ipvs_sockpair_t *sockpair, unsigned int format);
static void list_service(ipvs_service_t *svc, unsigned int format);
static void list_all(unsigned int format);
static void list_timeout(void);
static void list_daemon(void);
static int list_laddrs(ipvs_service_t *svc, int with_title);
static int list_all_laddrs(void);
static void list_blklsts_print_title(void);
static int list_blklst(uint32_t addr_v4, uint16_t port, uint16_t protocol);
static int list_all_blklsts(void);

#if 0
static int modprobe_ipvs(void);
static void check_ipvs_version(void);
#endif
static int process_options(int argc, char **argv, int reading_stdin);


int main(int argc, char **argv)
{
	int result;

	if (ipvs_init()) {
		fail(2, "Can't initialize ipvs: %s\n"
			"Are you sure that dpvs is running?",
			ipvs_strerror(errno));
	}

	/* warn the user if the IPVS version is out of date */
//	check_ipvs_version();

	/* list the table if there is no other arguement */
	if (argc == 1){
		list_all(FMT_NONE);
		ipvs_close();
		return 0;
	}

	/* process command line arguments */
	result = process_options(argc, argv, 0);

	ipvs_close();
	return result;
}


static int
parse_options(int argc, char **argv, struct ipvs_command_entry *ce,
	      uint64_t *options, unsigned int *format)
{
	int c, parse;
	poptContext context;
	char *optarg=NULL;
	struct poptOption options_table[] = {
		{ "add-service", 'A', POPT_ARG_NONE, NULL, 'A', NULL, NULL },
		{ "edit-service", 'E', POPT_ARG_NONE, NULL, 'E', NULL, NULL },
		{ "delete-service", 'D', POPT_ARG_NONE, NULL, 'D', NULL, NULL },
		{ "clear", 'C', POPT_ARG_NONE, NULL, 'C', NULL, NULL },
		{ "list", 'L', POPT_ARG_NONE, NULL, 'L', NULL, NULL },
		{ "list", 'l', POPT_ARG_NONE, NULL, 'l', NULL, NULL },
		{ "zero", 'Z', POPT_ARG_NONE, NULL, 'Z', NULL, NULL },
		{ "add-server", 'a', POPT_ARG_NONE, NULL, 'a', NULL, NULL },
		{ "edit-server", 'e', POPT_ARG_NONE, NULL, 'e', NULL, NULL },
		{ "delete-server", 'd', POPT_ARG_NONE, NULL, 'd', NULL, NULL },
		{ "set", '\0', POPT_ARG_NONE, NULL, TAG_SET, NULL, NULL },
		{ "help", 'h', POPT_ARG_NONE, NULL, 'h', NULL, NULL },
		{ "version", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL },
		{ "restore", 'R', POPT_ARG_NONE, NULL, 'R', NULL, NULL },
		{ "save", 'S', POPT_ARG_NONE, NULL, 'S', NULL, NULL },
		{ "start-daemon", '\0', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &optarg,
		  TAG_START_DAEMON, NULL, NULL },
		{ "stop-daemon", '\0', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &optarg,
		  TAG_STOP_DAEMON, NULL, NULL },
		{ "add-laddr", 'P', POPT_ARG_NONE, NULL, 'P', NULL, NULL },
		{ "del-laddr", 'Q', POPT_ARG_NONE, NULL, 'Q', NULL, NULL },
		{ "get-laddr", 'G', POPT_ARG_NONE, NULL, 'G', NULL, NULL },
		{ "add-blklst", 'U', POPT_ARG_NONE, NULL, 'U', NULL, NULL },
		{ "del-blklst", 'V', POPT_ARG_NONE, NULL, 'V', NULL, NULL },
		{ "get-blklst", 'B', POPT_ARG_NONE, NULL, 'B', NULL, NULL },
		{ "tcp-service", 't', POPT_ARG_STRING, &optarg, 't',
		  NULL, NULL },
		{ "udp-service", 'u', POPT_ARG_STRING, &optarg, 'u',
		  NULL, NULL },
		{ "icmp-service", 'q', POPT_ARG_STRING, &optarg, 'q',
		  NULL, NULL },
		{ "icmpv6-service", '1', POPT_ARG_STRING, &optarg, '1',
		  NULL, NULL },
		{ "fwmark-service", 'f', POPT_ARG_STRING, &optarg, 'f',
		  NULL, NULL },
		{ "scheduler", 's', POPT_ARG_STRING, &optarg, 's', NULL, NULL },
		{ "persistent", 'p', POPT_ARG_STRING|POPT_ARGFLAG_OPTIONAL,
		 &optarg, 'p', NULL, NULL },
		{ "netmask", 'M', POPT_ARG_STRING, &optarg, 'M', NULL, NULL },
		{ "real-server", 'r', POPT_ARG_STRING, &optarg, 'r',
		  NULL, NULL },
		{ "masquerading", 'm', POPT_ARG_NONE, NULL, 'm', NULL, NULL },
		{ "ipip", 'i', POPT_ARG_NONE, NULL, 'i', NULL, NULL },
		{ "gatewaying", 'g', POPT_ARG_NONE, NULL, 'g', NULL, NULL },
		{ "fullnat" , 'b' , POPT_ARG_NONE, NULL, 'b', NULL, NULL },
		{ "snat" , 'J' , POPT_ARG_NONE, NULL, 'J', NULL, NULL },
		{ "weight", 'w', POPT_ARG_STRING, &optarg, 'w', NULL, NULL },
		{ "u-threshold", 'x', POPT_ARG_STRING, &optarg, 'x',
		  NULL, NULL },
		{ "l-threshold", 'y', POPT_ARG_STRING, &optarg, 'y',
		  NULL, NULL },
		{ "numeric", 'n', POPT_ARG_NONE, NULL, 'n', NULL, NULL },
		{ "connection", 'c', POPT_ARG_NONE, NULL, 'c', NULL, NULL },
		{ "mcast-interface", '\0', POPT_ARG_STRING, &optarg,
		  TAG_MCAST_INTERFACE, NULL, NULL },
		{ "syncid", '\0', POPT_ARG_STRING, &optarg, 'I', NULL, NULL },
		{ "timeout", '\0', POPT_ARG_NONE, NULL, TAG_TIMEOUT,
		  NULL, NULL },
		{ "daemon", '\0', POPT_ARG_NONE, NULL, TAG_DAEMON, NULL, NULL },
		{ "stats", '\0', POPT_ARG_NONE, NULL, TAG_STATS, NULL, NULL },
		{ "rate", '\0', POPT_ARG_NONE, NULL, TAG_RATE, NULL, NULL },
		{ "thresholds", '\0', POPT_ARG_NONE, NULL,
		   TAG_THRESHOLDS, NULL, NULL },
		{ "persistent-conn", '\0', POPT_ARG_NONE, NULL,
		  TAG_PERSISTENTCONN, NULL, NULL },
		{ "sockpair", '\0', POPT_ARG_STRING, &optarg,
		  TAG_SOCKPAIR, NULL, NULL },
		{ "nosort", '\0', POPT_ARG_NONE, NULL,
		   TAG_NO_SORT, NULL, NULL },
		{ "sort", '\0', POPT_ARG_NONE, NULL, TAG_SORT, NULL, NULL },
		{ "exact", 'X', POPT_ARG_NONE, NULL, 'X', NULL, NULL },
		{ "ipv6", '6', POPT_ARG_NONE, NULL, '6', NULL, NULL },
		{ "ops", 'o', POPT_ARG_NONE, NULL, 'o', NULL, NULL },
		{ "pe", '\0', POPT_ARG_STRING, &optarg, TAG_PERSISTENCE_ENGINE,
		  NULL, NULL },
		{ "laddr", 'z', POPT_ARG_STRING, &optarg, 'z', NULL, NULL },
		{ "blklst", 'k', POPT_ARG_STRING, &optarg, 'k', NULL, NULL },
		{ "synproxy", 'j' , POPT_ARG_STRING, &optarg, 'j', NULL, NULL },
		{ "ifname", 'F', POPT_ARG_STRING, &optarg, 'F', NULL, NULL },
		{ "match", 'H', POPT_ARG_STRING, &optarg, 'H', NULL, NULL },
		{ "hash-target", 'Y', POPT_ARG_STRING, &optarg, 'Y', NULL, NULL },
		{ "set-daemon",             '\0', POPT_ARG_NONE,   NULL,    TAG_SET_DAEMON,              NULL, NULL },
		{ "lcore-id",               '\0', POPT_ARG_STRING, &optarg, TAG_LCORE_ID,                NULL, NULL },
		{ "mcast-group",            '\0', POPT_ARG_STRING, &optarg, TAG_MCAST_GROUP,             NULL, NULL },
		{ "mcast-port",             '\0', POPT_ARG_STRING, &optarg, TAG_MCAST_PORT,              NULL, NULL },
		{ "mcast-ttl",              '\0', POPT_ARG_STRING, &optarg, TAG_MCAST_TTL,               NULL, NULL },
		{ "mcast-interface-addr",   '\0', POPT_ARG_STRING, &optarg, TAG_MCAST_INTERFACE_ADDRESS, NULL, NULL },
		{ NULL, 0, 0, NULL, 0, NULL, NULL }
	};

	context = poptGetContext("ipvsadm", argc, (const char **)argv,
				 options_table, 0);

	if ((c = poptGetNextOpt(context)) < 0)
		tryhelp_exit(argv[0], -1);

	switch (c) {
	case 'A':
		set_command(&ce->cmd, CMD_ADD);
		break;
	case 'E':
		set_command(&ce->cmd, CMD_EDIT);
		break;
	case 'D':
		set_command(&ce->cmd, CMD_DEL);
		break;
	case 'a':
		set_command(&ce->cmd, CMD_ADDDEST);
		break;
	case 'e':
		set_command(&ce->cmd, CMD_EDITDEST);
		break;
	case 'd':
		set_command(&ce->cmd, CMD_DELDEST);
		break;
	case 'C':
		set_command(&ce->cmd, CMD_FLUSH);
		break;
	case 'L':
	case 'l':
		set_command(&ce->cmd, CMD_LIST);
		break;
	case 'Z':
		set_command(&ce->cmd, CMD_ZERO);
		break;
	case TAG_SET:
		set_command(&ce->cmd, CMD_TIMEOUT);
		break;
	case 'R':
		set_command(&ce->cmd, CMD_RESTORE);
		break;
	case 'S':
		set_command(&ce->cmd, CMD_SAVE);
		break;
	case TAG_START_DAEMON:
		set_command(&ce->cmd, CMD_STARTDAEMON);
		if (NULL == optarg)
			ce->daemon.state = IP_VS_STATE_MASTER | IP_VS_STATE_BACKUP;
		else if (!strcmp(optarg, "active"))
			ce->daemon.state = IP_VS_STATE_MASTER;
		else if (!strcmp(optarg, "backup"))
			ce->daemon.state = IP_VS_STATE_BACKUP;
		else fail(2, "illegal start-daemon parameter specified");
		break;
	case TAG_STOP_DAEMON:
		set_command(&ce->cmd, CMD_STOPDAEMON);
		if (NULL == optarg)
			ce->daemon.state = IP_VS_STATE_MASTER | IP_VS_STATE_BACKUP;
		else if (!strcmp(optarg, "active"))
			ce->daemon.state = IP_VS_STATE_MASTER;
		else if (!strcmp(optarg, "backup"))
			ce->daemon.state = IP_VS_STATE_BACKUP;
		else fail(2, "illegal start_daemon specified");
		break;
	case TAG_SET_DAEMON:
		set_command(&ce->cmd, CMD_SETDAEMON);
		break;
	case 'h':
		usage_exit(argv[0], 0);
		break;
	case 'v':
		version_exit(0);
		break;
	case 'P':
		set_command(&ce->cmd, CMD_ADDLADDR);
		break;
	case 'Q':
		set_command(&ce->cmd, CMD_DELLADDR);
		break;
	case 'G':
		set_command(&ce->cmd, CMD_GETLADDR);
		break;
	case 'U':
		set_command(&ce->cmd, CMD_ADDBLKLST);
		break;
	case 'V':
		set_command(&ce->cmd, CMD_DELBLKLST);
		break;
	case 'B':
		set_command(&ce->cmd, CMD_GETBLKLST);
		break;
	default:
		tryhelp_exit(argv[0], -1);
	}

	while ((c=poptGetNextOpt(context)) >= 0){
		switch (c) {
		case 't':
		case 'u':
		case 'q':
        case '1':
			set_option(options, OPT_SERVICE);
			if (c == 't')
				ce->svc.protocol = IPPROTO_TCP;
			else if (c == 'u')
				ce->svc.protocol = IPPROTO_UDP;
			else if (c == 'q')
				ce->svc.protocol = IPPROTO_ICMP;
			else if (c == '1') // a~Z is out. ipvsadm is really not friendly here
				ce->svc.protocol = IPPROTO_ICMPV6;

			parse = parse_service(optarg, &ce->svc);
			if (!(parse & SERVICE_ADDR))
				fail(2, "illegal virtual server "
				     "address[:port] specified");
			break;
		case 'H':
			set_option(options, OPT_SERVICE);
		if (parse_match_snat(optarg, &ce->svc) != 0)
				fail(2, "illegal match specified");
			break;
		case 'f':
			set_option(options, OPT_SERVICE);
			/*
			 * Set protocol to a sane values, even
			 * though it is not used
			 */
			ce->svc.af = AF_INET;/*FIXME:DPVS not support fwmark?*/
			ce->svc.protocol = IPPROTO_TCP;
			ce->svc.fwmark = parse_fwmark(optarg);
			break;
		case 's':
			set_option(options, OPT_SCHEDULER);
			strncpy(ce->svc.sched_name,
				optarg, IP_VS_SCHEDNAME_MAXLEN);
			if (!memcmp(ce->svc.sched_name, "conhash", strlen("conhash")))
				ce->svc.flags = ce->svc.flags | IP_VS_SVC_F_SIP_HASH;
			break;
		case 'p':
			set_option(options, OPT_PERSISTENT);
			ce->svc.flags |= IP_VS_SVC_F_PERSISTENT;
			ce->svc.timeout =
				parse_timeout(optarg, 1, MAX_TIMEOUT);
			break;
		case 'M':
			set_option(options, OPT_NETMASK);
			if (ce->svc.af != AF_INET6) {
				parse = parse_netmask(optarg, &ce->svc.netmask);
				if (parse != 1)
					fail(2, "illegal virtual server "
					     "persistent mask specified");
			} else {
				ce->svc.netmask = atoi(optarg);
				if ((ce->svc.netmask < 1) || (ce->svc.netmask > 128))
					fail(2, "illegal ipv6 netmask specified");
			}
			break;
		case 'r':
			set_option(options, OPT_SERVER);
			ipvs_service_t t_dest = ce->svc;
			parse = parse_service(optarg, &t_dest);
			ce->dest.af = t_dest.af;
			ce->dest.addr = t_dest.addr;
			ce->dest.port = t_dest.port;
			if (!(parse & SERVICE_ADDR))
				fail(2, "illegal real server "
				     "address[:port] specified");
			/* copy vport to dport if not specified */
			if (parse == 1)
				ce->dest.port = ce->svc.port;
			break;
		case 'i':
			set_option(options, OPT_FORWARD);
			ce->dest.conn_flags = IP_VS_CONN_F_TUNNEL;
			break;
		case 'g':
			set_option(options, OPT_FORWARD);
			ce->dest.conn_flags = IP_VS_CONN_F_DROUTE;
			break;
		case 'b':
			set_option(options, OPT_FORWARD);
			ce->dest.conn_flags = IP_VS_CONN_F_FULLNAT;
			break;
		case 'J':
			set_option(options, OPT_FORWARD);
			ce->dest.conn_flags = IP_VS_CONN_F_SNAT;
			break;
		case 'm':
			set_option(options, OPT_FORWARD);
			ce->dest.conn_flags = IP_VS_CONN_F_MASQ;
			break;
		case 'w':
			set_option(options, OPT_WEIGHT);
			if ((ce->dest.weight =
			     string_to_number(optarg, 0, 65535)) == -1)
				fail(2, "illegal weight specified");
			break;
		case 'x':
			set_option(options, OPT_UTHRESHOLD);
			if ((ce->dest.u_threshold =
			     string_to_number(optarg, 0, INT_MAX)) == -1)
				fail(2, "illegal u_threshold specified");
			break;
		case 'y':
			set_option(options, OPT_LTHRESHOLD);
			if ((ce->dest.l_threshold =
			     string_to_number(optarg, 0, INT_MAX)) == -1)
				fail(2, "illegal l_threshold specified");
			break;
		case 'c':
			set_option(options, OPT_CONNECTION);
			break;
		case 'n':
			set_option(options, OPT_NUMERIC);
			*format |= FMT_NUMERIC;
			break;
		case TAG_MCAST_INTERFACE:
			set_option(options, OPT_MCAST);
			strncpy(ce->daemon.mcast_ifn,
				optarg, IP_VS_IFNAME_MAXLEN);
			break;
		case 'I':
			set_option(options, OPT_SYNCID);
			if ((ce->daemon.syncid =
			     string_to_number(optarg, 0, 255)) == -1)
				fail(2, "illegal syncid specified");
			break;
		case TAG_TIMEOUT:
			set_option(options, OPT_TIMEOUT);
			break;
		case TAG_DAEMON:
			set_option(options, OPT_DAEMON);
			break;
		case TAG_STATS:
			set_option(options, OPT_STATS);
			*format |= FMT_STATS;
			break;
		case TAG_RATE:
			set_option(options, OPT_RATE);
			*format |= FMT_RATE;
			break;
		case TAG_THRESHOLDS:
			set_option(options, OPT_THRESHOLDS);
			*format |= FMT_THRESHOLDS;
			break;
		case TAG_PERSISTENTCONN:
			set_option(options, OPT_PERSISTENTCONN);
			*format |= FMT_PERSISTENTCONN;
			break;
		case TAG_SOCKPAIR:
			set_option(options, OPT_SOCKPAIR);
			parse = parse_sockpair(optarg, &ce->sockpair);
			if (parse != 1)
				fail(2, "illegal sockpair<af:sip:sport:tip:tport> specified");
			break;
		case TAG_NO_SORT:
			set_option(options, OPT_NOSORT);
			*format |= FMT_NOSORT;
			break;
		case TAG_SORT:
			/* Sort is the default, this is a no-op for compatibility */
			break;
		case 'X':
			set_option(options, OPT_EXACT);
			*format |= FMT_EXACT;
			break;
		case '6':
			if (ce->svc.fwmark) {
				ce->svc.af = AF_INET6;
				ce->svc.netmask = 128;
			} else {
				fail(2, "-6 used before -f\n");
			}
			break;
		case 'o':
			set_option(options, OPT_ONEPACKET);
			ce->svc.flags |= IP_VS_SVC_F_ONEPACKET;
			break;
		case TAG_PERSISTENCE_ENGINE:
			set_option(options, OPT_PERSISTENCE_ENGINE);
			strncpy(ce->svc.pe_name, optarg, IP_VS_PENAME_MAXLEN);
			break;
		case 'z':
			{
			ipvs_service_t		nsvc;

			set_option(options, OPT_LOCAL_ADDRESS);
			parse = parse_service(optarg, &nsvc);
			if (!(parse & SERVICE_ADDR))
				fail(2, "illegal local address");
			ce->laddr.af = nsvc.af;
			ce->laddr.addr = nsvc.addr;
			ce->laddr.__addr_v4 = nsvc.addr.ip;
			break;

			}
		case 'k':
			{
			ipvs_service_t		nsvc;
			set_option(options,OPT_BLKLST_ADDRESS);
			parse = parse_service(optarg, &nsvc);
			if (!(parse & SERVICE_ADDR))
				fail(2, "illegal blocklist address");
			ce->blklst.af = nsvc.af;
			ce->blklst.addr = nsvc.addr;
			ce->blklst.__addr_v4 = nsvc.addr.ip;
			break;

			}
		case 'F':
			set_option(options, OPT_IFNAME);
			snprintf(ce->laddr.ifname, sizeof(ce->laddr.ifname), "%s", optarg);
			break;
		case 'j':
			{
			set_option(options, OPT_SYNPROXY);

			if(!memcmp(optarg , "enable" , strlen("enable")))
				ce->svc.flags = ce->svc.flags | IP_VS_CONN_F_SYNPROXY;
			else if(!memcmp(optarg , "disable" , strlen("disable")))
				ce->svc.flags = ce->svc.flags & (~IP_VS_CONN_F_SYNPROXY);
			else
				fail(2 , "synproxy switch must be enable or disable\n");

			break;
			}
		case 'Y':
			{
			set_option(options, OPT_HASHTAG);

			if (strcmp(ce->svc.sched_name, "conhash"))
				fail(2 , "hash target can only be set when schedule is conhash\n");
			if (!memcmp(optarg, "sip", strlen("sip"))) {
				ce->svc.flags = ce->svc.flags | IP_VS_SVC_F_SIP_HASH;
				ce->svc.flags = ce->svc.flags & (~IP_VS_SVC_F_QID_HASH);
			}
			else if (!memcmp(optarg, "qid", strlen("qid"))) {
				if (ce->svc.protocol != IPPROTO_UDP)
					fail(2 , "qid hash can only be set in udp service\n");
				ce->svc.flags = ce->svc.flags | IP_VS_SVC_F_QID_HASH;
				ce->svc.flags = ce->svc.flags & (~IP_VS_SVC_F_SIP_HASH);
			}
			else
				fail(2 , "hash target not support\n");
			break;
			}
		case TAG_LCORE_ID:
			set_option(options, OPT_LCORE_ID);
			parse = string_to_number(optarg, 0, INT32_MAX);
			if (-1 == parse) {
			    fail(2, "illegal lcore-id specified\n");
			}
			ce->daemon.lcore_id = parse;
			break;
		case TAG_MCAST_GROUP:
			set_option(options, OPT_MCAST_GROUP);
			if (strchr(optarg, '.') != NULL) {
			    if (inet_pton(AF_INET, optarg, &ce->daemon.mcast_group) <= 0
				|| !IN_MULTICAST(ntohl(ce->daemon.mcast_group.s_addr))) {
				fail(2, "illegal mcast-group specified\n");
			    } else {
			        /* do nothing */
			    }
			} else {
			    fail(2, "illegal mcast-group specified\n");
			}
			break;
		case TAG_MCAST_PORT:
			set_option(options, OPT_MCAST_PORT);
			parse = string_to_number(optarg, 1, 65535);
			if (-1 == parse) {
			    fail(2, "illegal mcast-port specified\n");
			}
			ce->daemon.mcast_port = htons(parse);
			break;
		case TAG_MCAST_TTL:
			set_option(options, OPT_MCAST_TTL);
			parse = string_to_number(optarg, 1, 255);
			if (-1 == parse) {
			    fail(2, "illegal mcast-ttl specified");
			}
			ce->daemon.mcast_ttl = parse;
			break;
		case TAG_MCAST_INTERFACE_ADDRESS:
			set_option(options, OPT_MCAST_IFADDESS);
			if (strchr(optarg, '.') != NULL) {
			    if (inet_pton(AF_INET, optarg, &ce->daemon.mcast_ifia) <= 0) {
				fail(2, "illegal mcast-interface-addr specified\n");
			    } else {
			        /* do nothing */
			    }
			} else {
			    fail(2, "illegal mcast-interface-addr specified\n");
			}
			break;
		default:
			fail(2, "invalid option `%s'",
			     poptBadOption(context, POPT_BADOPTION_NOALIAS));
		}
	}

	if (c < -1) {
		/* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(context, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		poptFreeContext(context);
		return -1;
	}

	if (ce->cmd == CMD_TIMEOUT) {
		char *optarg1, *optarg2;

		if ((optarg=(char *)poptGetArg(context))
		    && (optarg1=(char *)poptGetArg(context))
		    && (optarg2=(char *)poptGetArg(context))) {
			ce->timeout.tcp_timeout =
				parse_timeout(optarg, 0, MAX_TIMEOUT);
			ce->timeout.tcp_fin_timeout =
				parse_timeout(optarg1, 0, MAX_TIMEOUT);
			ce->timeout.udp_timeout =
				parse_timeout(optarg2, 0, MAX_TIMEOUT);
		} else
			fail(2, "--set option requires 3 timeout values");
	}

	if ((optarg=(char *)poptGetArg(context)))
		fail(2, "unexpected argument %s", optarg);

	poptFreeContext(context);

	return 0;
}



static int restore_table(int argc, char **argv, int reading_stdin)
{
	int result = 0;
	dynamic_array_t *a;

	/* avoid infinite loop */
	if (reading_stdin != 0)
		tryhelp_exit(argv[0], -1);

	while ((a = config_stream_read(stdin, argv[0])) != NULL) {
		int i;
		if ((i = (int)dynamic_array_get_count(a)) > 1) {
			char **strv = dynamic_array_get_vector(a);
			result = process_options(i, strv, 1);
		}
		dynamic_array_destroy(a, DESTROY_STR);
	}
	return result;
}

static int process_options(int argc, char **argv, int reading_stdin)
{
	struct ipvs_command_entry ce;
	uint64_t options = OPT_NONE;
	unsigned int format = FMT_NONE;
	int result = 0;

	memset(&ce, 0, sizeof(struct ipvs_command_entry));
	ce.cmd = CMD_NONE;
	/* Set the default weight 1 */
	ce.dest.weight = 1;
	/* Set direct routing as default forwarding method */
	ce.dest.conn_flags = IP_VS_CONN_F_DROUTE;
	/* Set the default persistent granularity to /32 mask */
	ce.svc.netmask = ((u_int32_t) 0xffffffff);

	if (parse_options(argc, argv, &ce, &options, &format))
		return -1;

	generic_opt_check(ce.cmd, options);

	if (ce.cmd == CMD_ADD || ce.cmd == CMD_EDIT) {
		/* Make sure that port zero service is persistent */
		if (!ce.svc.fwmark && !ce.svc.port &&
		    !(ce.svc.flags & IP_VS_SVC_F_PERSISTENT) &&
            (!strlen(ce.svc.srange) && !strlen(ce.svc.drange) &&
             !strlen(ce.svc.iifname) && !strlen(ce.svc.oifname)))
			fail(2, "Zero port specified "
			     "for no-match and non-persistent service");

		if (ce.svc.flags & IP_VS_SVC_F_ONEPACKET &&
		    !ce.svc.fwmark && ce.svc.protocol != IPPROTO_UDP)
			fail(2, "One-Packet Scheduling is only "
			     "for UDP virtual services");

		/* Set the default scheduling algorithm if not specified */
		if (strlen(ce.svc.sched_name) == 0)
			strcpy(ce.svc.sched_name, DEF_SCHED);
	}

	if (ce.cmd == CMD_STARTDAEMON && strlen(ce.daemon.mcast_ifn) == 0)
		strcpy(ce.daemon.mcast_ifn, DEF_MCAST_IFN);

	if (ce.cmd == CMD_ADDDEST || ce.cmd == CMD_EDITDEST) {
		/*
		 * The destination port must be equal to the service port
		 * if the IP_VS_CONN_F_TUNNEL or IP_VS_CONN_F_DROUTE is set.
		 * Don't worry about this if fwmark is used.
		 */
		if (!ce.svc.fwmark &&
		    (ce.dest.conn_flags == IP_VS_CONN_F_TUNNEL
		     || ce.dest.conn_flags == IP_VS_CONN_F_DROUTE))
			ce.dest.port = ce.svc.port;
	}

	switch (ce.cmd) {
	case CMD_LIST:
		if ((options & (OPT_CONNECTION|OPT_TIMEOUT|OPT_DAEMON) &&
		     options & (OPT_STATS|OPT_RATE|OPT_THRESHOLDS)) ||
		    (options & (OPT_TIMEOUT|OPT_DAEMON) &&
		     options & OPT_PERSISTENTCONN))
			fail(2, "options conflicts in the list command");

		if (options & OPT_CONNECTION)
            if (options & OPT_SOCKPAIR)
                list_conn_sockpair(options & OPT_PERSISTENTCONN,
						&ce.sockpair, format);
            else
                list_conn(options & OPT_PERSISTENTCONN, format);
		else if (options & OPT_SERVICE)
			list_service(&ce.svc, format);
		else if (options & OPT_TIMEOUT)
			list_timeout();
		else if (options & OPT_DAEMON)
			list_daemon();
		else
			list_all(format);
		return 0;

	case CMD_RESTORE:
		return restore_table(argc, argv, reading_stdin);

	case CMD_SAVE:
		format |= FMT_RULE;
		list_all(format);
		return 0;

	case CMD_FLUSH:
		result = ipvs_flush();
		break;

	case CMD_ADD:
		result = ipvs_add_service(&ce.svc);
		break;

	case CMD_EDIT:
		result = ipvs_update_service_by_options(&ce.svc, options);
		break;

	case CMD_DEL:
		result = ipvs_del_service(&ce.svc);
		break;

	case CMD_ZERO:
		result = ipvs_zero_service(&ce.svc);
		break;

	case CMD_ADDDEST:
		result = ipvs_add_dest(&ce.svc, &ce.dest);
		break;

	case CMD_EDITDEST:
		result = ipvs_update_dest(&ce.svc, &ce.dest);
		break;

	case CMD_DELDEST:
		result = ipvs_del_dest(&ce.svc, &ce.dest);
		break;

	case CMD_TIMEOUT:
		result = ipvs_set_timeout(&ce.timeout);
		break;

	case CMD_STARTDAEMON:
		result = ipvs_start_daemon(&ce.daemon);
		break;

	case CMD_STOPDAEMON:
		result = ipvs_stop_daemon(&ce.daemon);
		break;

	case CMD_SETDAEMON:
		result = ipvs_set_daemon(&ce.daemon);
		if (result) {
			fprintf(stderr, "%s\n", "Refer to the list below to modify daemon configuration with valid lcore-id:");
			list_daemon();
			fprintf(stderr, "%s\n", "\nCommand arguments example:");
			fprintf(stderr, "%s\n", "ipvsadm --set-daemon --lcore-id 1 --mcast-interface dpdk0 --mcast-group 239.1.1.2 --mcast-port 8848 --mcast-ttl 1");
			result = 0;
		}
		break;

	case CMD_ADDLADDR:
		result = ipvs_add_laddr(&ce.svc , &ce.laddr);
		break;

	case CMD_DELLADDR:
		result = ipvs_del_laddr(&ce.svc , &ce.laddr);
		break;

	case CMD_GETLADDR:
		if(options & OPT_SERVICE)
			result = list_laddrs(&ce.svc , 1);
		else
			result = list_all_laddrs();
		break;

	case CMD_ADDBLKLST:
		result = ipvs_add_blklst(&ce.svc , &ce.blklst);
		break;

	case CMD_DELBLKLST:
		result = ipvs_del_blklst(&ce.svc , &ce.blklst);
		break;

	case CMD_GETBLKLST:
		if(options & OPT_SERVICE) {
			list_blklsts_print_title();
			result = list_blklst(ce.svc.addr.ip, ce.svc.port, ce.svc.protocol);
		}
		else
			result = list_all_blklsts();
		break;
	}
	if (result)
		fprintf(stderr, "%s\n", ipvs_strerror(errno));

	return result;
}


static int string_to_number(const char *s, int min, int max)
{
	long number;
	char *end;

	errno = 0;
	number = strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/* We parsed a number, let's see if we want this. */
		if (errno != ERANGE && min <= number && number <= max)
			return number;
	}
	return -1;
}


/*
 * Parse the timeout value.
 */
static int parse_timeout(char *buf, int min, int max)
{
	int i;

	/* it is just for parsing timeout of persistent service */
	if (buf == NULL)
		return IPVS_SVC_PERSISTENT_TIMEOUT;

	if ((i=string_to_number(buf, min, max)) == -1)
		fail(2, "invalid timeout value `%s' specified", buf);

	return i;
}


/*
 * Parse IP fwmark from the argument.
 */
static unsigned int parse_fwmark(char *buf)
{
	unsigned long l;
	char *end;

	errno = 0;
	l = strtol(buf, &end, 10);
	if (*end != '\0' || end == buf ||
	    errno == ERANGE || l <= 0 || l > UINT_MAX)
		fail(2, "invalid fwmark value `%s' specified", buf);

	return l;
}


/*
 * Get netmask.
 * Return 0 if failed,
 *	  1 if addr read
 */
static int parse_netmask(char *buf, u_int32_t *addr)
{
	struct in_addr inaddr;

	if(buf == NULL)
		return 0;

	if (inet_aton(buf, &inaddr) != 0)
		*addr = inaddr.s_addr;
	else if (host_to_addr(buf, &inaddr) != -1)
		*addr = inaddr.s_addr;
	else
		return 0;

	return 1;
}


/*
 * Get IP address and port from the argument.
 * Result is a logical or of
 * SERVICE_NONE:   no service elements set/error
 * SERVICE_ADDR:   addr set
 * SERVICE_PORT:   port set
 */
static int
parse_service(char *buf, ipvs_service_t *svc)
{
	char *portp = NULL;
	long portn;
	int result=SERVICE_NONE;
	struct in_addr inaddr;
	struct in6_addr inaddr6;

	if (buf == NULL || str_is_digit(buf))
		return SERVICE_NONE;
	if (buf[0] == '[') {
		buf++;
		portp = strchr(buf, ']');
		if (portp == NULL)
			return SERVICE_NONE;
		*portp = '\0';
		portp++;
		if (*portp == ':')
			*portp = '\0';
		else
			return SERVICE_NONE;
	}
	if (inet_pton(AF_INET6, buf, &inaddr6) > 0) {
		svc->addr.in6 = inaddr6;
		svc->af = AF_INET6;
		svc->netmask = 128;
	} else {
		portp = strrchr(buf, ':');
		if (portp != NULL)
			*portp = '\0';

		if (inet_aton(buf, &inaddr) != 0) {
			svc->addr.ip = inaddr.s_addr;
			svc->af = AF_INET;
		} else if (host_to_addr(buf, &inaddr) != -1) {
			svc->addr.ip = inaddr.s_addr;
			svc->af = AF_INET;
		} else
			return SERVICE_NONE;
	}

	result |= SERVICE_ADDR;

	if (portp != NULL) {
		result |= SERVICE_PORT;

		if ((portn = string_to_number(portp+1, 0, 65535)) != -1)
			svc->port = htons(portn);
		else if ((portn = service_to_port(portp+1, svc->protocol)) != -1)
			svc->port = htons(portn);
		else
			return SERVICE_NONE;
	}

	return result;
}
/*
 * Get sockpair from the arguments.
 * sockpair := PROTO:SIP:SPORT:TIP:TPORT
 * PROTO := [tcp|udp]
 * SIP,TIP := dotted-decimal ip address or square-blacketed ip6 address
 * SPORT,TPORT := range(0, 65535)
 */
static int
parse_sockpair(char *buf, ipvs_sockpair_t *sockpair)
{
    char *pos = buf, *end;
    int af = (strchr(pos, '[') == NULL ? AF_INET : AF_INET6);
    union inet_addr sip, tip;
    unsigned short proto, sport, tport;
    long portn;

    memset(sockpair, 0, sizeof(ipvs_sockpair_t));

	end = strchr(pos,':');
	if (!end)
		return 0;
	*end++ = '\0';
	if (strncmp(pos, "tcp", 3) == 0)
		proto = IPPROTO_TCP;
	else if (strncmp(pos, "udp", 3) == 0)
		proto = IPPROTO_UDP;
	else
		return 0;

    if (af == AF_INET) {
        pos = end;
        end = strchr(pos, ':');
        if (!end)
            return 0;
        *end++ = '\0';
        if (inet_pton(af, pos, &sip) != 1)
            return 0;
    } else {
        if (*end != '[')
            return 0;
        pos = end + 1;
        end = strchr(pos, ']');
        if (!end || *(end+1) != ':')
            return 0;
        *end++ = '\0';
        *end++ = '\0';
        if (inet_pton(af, pos, &sip.in6) != 1)
            return 0;
    }

    pos = end;
    end = strchr(pos, ':');
    if (!end)
        return 0;
    *end++ = '\0';
    if ((portn = string_to_number(pos, 0, 65535)) == -1)
        return 0;
    sport = portn;

    if (af == AF_INET) {
        pos = end;
        end = strchr(pos, ':');
        if (!end)
            return 0;
        *end++ = '\0';
        if (inet_pton(af, pos, &tip.in) != 1)
            return 0;
    } else {
        if (*end !='[')
            return 0;
        pos = end + 1;
        end = strchr(pos, ']');
        if (!end || *(end+1) != ':')
            return 0;
        *end++ = '\0';
        *end++ = '\0';
        if (inet_pton(af, pos, &tip.in6) != 1)
            return 0;
    }

    pos = end;
    if ((portn = string_to_number(pos, 0, 65535)) == -1)
        return 0;
    tport = portn;

    sockpair->af = af;
	sockpair->proto = proto;
    sockpair->sip = sip;
    sockpair->sport = ntohs(sport);
    sockpair->tip = tip;
    sockpair->tport = ntohs(tport);

    return 1;
}
/*
 * comma separated parameters list, all fields is used to match packets.
 *
 *   proto      := tcp | udp | icmp |icmpv6
 *   src-range  := RANGE
 *   dst-range  := RANGE
 *   iif        := IFNAME
 *   oif        := IFNAME
 *   RANGE      := IP1[-IP2][:PORT1[-PORT2]]
 *
 * example:
 *
 *   proto=tcp,src-range=192.168.0.1-10:80-100,dst-range=10.0.0.1:1024,iif=eth0
 */
static int parse_match_snat(const char *buf, ipvs_service_t *svc)
{
    char params[256];
    char *arg, *start, *sp, key[32], val[128];
    int r;

    snprintf(params, sizeof(params), "%s", buf);

    svc->af = AF_INET; /* now IPv4 only */
    svc->protocol = IPPROTO_NONE;

    for (start = params; (arg = strtok_r(start, ",", &sp)); start = NULL) {
        r = sscanf(arg, "%31[^=]=%127s", key, val);
        if (r != 2) {
            if (sscanf(arg, "%31[^=]=", key) != 1)
                return -1;
            val[0] = '\0';
        }

        if (strcmp(key, "proto") == 0) {
            if (strcmp(val, "tcp") == 0)
                svc->protocol = IPPROTO_TCP;
            else if (strcmp(val, "udp") == 0)
                svc->protocol = IPPROTO_UDP;
            else if (strcmp(val, "icmp") == 0)
                svc->protocol = IPPROTO_ICMP;
            else if (strcmp(val, "icmpv6") == 0)
                svc->protocol = IPPROTO_ICMPV6;
            else
                return -1;
        } else if (strcmp(key, "src-range") == 0) {
            snprintf(svc->srange, sizeof(svc->srange), "%s", val);
        } else if (strcmp(key, "dst-range") == 0) {
            snprintf(svc->drange, sizeof(svc->drange), "%s", val);
        } else if (strcmp(key, "iif") == 0) {
            snprintf(svc->iifname, sizeof(svc->iifname), "%s", val);
        } else if (strcmp(key, "oif") == 0) {
            snprintf(svc->oifname, sizeof(svc->oifname), "%s", val);
        } else {
            return -1;
        }
    }

    return 0;
}

static void
generic_opt_check(int command, uint64_t options)
{
	int i, j;
	int last = 0, count = 0;
	uint64_t bit_flag = 1;

	/* Check that commands are valid with options. */
	i = command - CMD_NONE -1;

	for (j = 0; j < NUMBER_OF_OPT; j++) {
		if (!(options & (bit_flag<<j))) {
			if (commands_v_options[i][j] == '+')
				fail(2, "You need to supply the '%s' "
				     "option for the '%s' command",
				     optnames[j], cmdnames[i]);
		} else {
			if (commands_v_options[i][j] == 'x')
				fail(2, "Illegal '%s' option with "
				     "the '%s' command",
				     optnames[j], cmdnames[i]);
			if (commands_v_options[i][j] == '1') {
				count++;
				if (count == 1) {
					last = j;
					continue;
				}
				fail(2, "The option '%s' conflicts with the "
				     "'%s' option in the '%s' command",
				     optnames[j], optnames[last], cmdnames[i]);
			}
		}
	}
}

static inline const char *
opt2name(int option)
{
	const char **ptr;
	for (ptr = optnames; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static void
set_command(int *cmd, const int newcmd)
{
	if (*cmd != CMD_NONE)
		fail(2, "multiple commands specified");
	*cmd = newcmd;
}

static void
set_option(uint64_t *options, uint64_t option)
{
	if (*options & option)
		fail(2, "multiple '%s' options specified", opt2name(option));
	*options |= option;
}


static void tryhelp_exit(const char *program, const int exit_status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
		program, program);
	exit(exit_status);
}


static void usage_exit(const char *program, const int exit_status)
{
	FILE *stream;

	if (exit_status != 0)
		stream = stderr;
	else
		stream = stdout;

	version(stream);
	fprintf(stream,
		"Usage:\n"
		"  %s -A|E -t|u|q|f service-address [-s scheduler] [-j eanble/disable] [-p [timeout]] [-M netmask] [--pe persistence_engine]\n"
		"  %s -D -t|u|q|f service-address\n"
		"  %s -C\n"
		"  %s -R\n"
		"  %s -S [-n]\n"
		"  %s -P|Q -t|u|q|f service-address -z local-address\n"
		"  %s -G -t|u|q|f service-address \n"
		"  %s -U|V -t|u|q|f service-address -k blocklist-address\n"
		"  %s -a|e -t|u|q|f service-address -r server-address [options]\n"
		"  %s -d -t|u|q|f service-address -r server-address\n"
		"  %s -L|l [options]\n"
		"  %s -Z [-t|u|q|f service-address]\n"
		"  %s --set tcp tcpfin udp\n"
		"  %s --start-daemon [state]\n"
		"  %s --stop-daemon [state]\n"
		"  %s --set-daemon --lcore-id lcoreid [--mcast-interface interface] \n"
		"                         [--mcast-interface-addr IPv4-address] \n"
		"                         [--mcast-group IPv4-group-address] [--mcast-port port-number]\n"
		"                         [--mcast-ttl ttl]\n"
		"  %s -h\n\n",
		program, program, program,
		program, program, program,
		program, program, program, program, program,
		program, program, program, program, program,
		program);

	fprintf(stream,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  --add-service     -A        add virtual service with options\n"
		"  --edit-service    -E        edit virtual service with options\n"
		"  --delete-service  -D        delete virtual service\n"
		"  --clear           -C        clear the whole table\n"
		"  --restore         -R        restore rules from stdin\n"
		"  --add-laddr       -P        add local address\n"
		"  --del-laddr       -Q        del local address\n"
		"  --get-laddr       -G        get local address\n"
		"  --add-blklst      -U        add blocklist address\n"
		"  --del-blklst      -V        del blocklist address\n"
		"  --get-blklst      -B        get blocklist address\n"
		"  --save            -S        save rules to stdout\n"
		"  --add-server      -a        add real server with options\n"
		"  --edit-server     -e        edit real server with options\n"
		"  --delete-server   -d        delete real server\n"
		"  --list            -L|-l     list the table\n"
		"  --zero            -Z        zero counters in a service or all services\n"
		"  --set tcp tcpfin udp        set connection timeout values\n"
		"  --start-daemon              start connection sync daemon, the state argument is optional\n"
		"  --stop-daemon               stop connection sync daemon, the state argument is optional\n"
		"                              if state is omit, the daemon is started or stopped as both active and backup\n"
		"                              if state is given as active or backup, the daemon is started or stopped as\n"
		"                              active or backup\n"
		"  --set-daemon                set connection sync daemon\n"
		"  --help            -h        display this help message\n\n"
		);

	fprintf(stream,
		"Options:\n"
		"  --tcp-service  -t service-address   service-address is host[:port]\n"
		"  --udp-service  -u service-address   service-address is host[:port]\n"
		"  --icmp-service -q service-address   service-address is host[:port]\n"
		"  --icmpv6-service -1 service-address   service-address is host[:port]\n"
		"  --fwmark-service  -f fwmark         fwmark is an integer greater than zero\n"
		"  --ipv6         -6                   fwmark entry uses IPv6\n"
		"  --scheduler    -s scheduler         one of " SCHEDULERS ",\n"
		"                                      the default scheduler is %s.\n"
		"  --pe            engine              alternate persistence engine may be " PE_LIST ",\n"
		"                                      not set by default.\n"
		"  --persistent   -p [timeout]         persistent service\n"
		"  --netmask      -M netmask           persistent granularity mask\n"
		"  --real-server  -r server-address    server-address is host (and port)\n"
		"  --gatewaying   -g                   gatewaying (direct routing) (default)\n"
		"  --ipip         -i                   ipip encapsulation (tunneling)\n"
		"  --fullnat      -b                   fullnat mode\n"
		"  --snat         -J                   SNAT mode\n"
		"  --masquerading -m                   masquerading (NAT)\n"
		"  --weight       -w weight            capacity of real server\n"
		"  --u-threshold  -x uthreshold        upper threshold of connections\n"
		"  --l-threshold  -y lthreshold        lower threshold of connections\n"
		"  --mcast-interface interface         multicast interface for connection sync\n"
		"  --mcast-interface-addr IPv4-address\n"
		"                                      multicast interface address for connection sync\n"
		"  --lcore-id     lcoreid              logical core id of the CPU on which the sync daemon run\n"
		"  --mcast-group  IPv4-group-address   multicast group address for the sync messages\n"
		"  --mcast-port   port-number          UDP port for sync messages, the default value is 8848\n"
		"  --mcast-ttl    ttl                  TTL value for sync messages (1 .. 255), the default value is 1\n"
		"  --syncid sid                        backup daemon uses syncid to filter out sync messages (default=255)\n"
		"  --connection   -c                   output of current IPVS connections\n"
		"  --timeout                           output of timeout (tcp tcpfin udp)\n"
		"  --daemon                            output of daemon information\n"
		"  --stats                             output of statistics information\n"
		"  --rate                              output of rate information\n"
		"  --exact                             expand numbers (display exact values)\n"
		"  --thresholds                        output of thresholds information\n"
		"  --persistent-conn                   output of persistent connection info\n"
		"  --sockpair                          output connection info of specified socket pair (proto:sip:sport:tip:tport)\n"
		"  --nosort                            disable sorting output of service/server entries\n"
		"  --sort                              does nothing, for backwards compatibility\n"
		"  --ops          -o                   one-packet scheduling\n"
		"  --numeric      -n                   numeric output of addresses and ports\n"
		"  --ifname       -F                   nic interface for laddrs\n"
		"  --synproxy     -j                   TCP syn proxy\n"
		"  --match        -H MATCH             select service by MATCH 'proto,srange,drange,iif,oif'\n"
		"  --hash-target  -Y hashtag           choose target for conhash (support sip or qid for quic)\n",
		DEF_SCHED);

	exit(exit_status);
}


static void version_exit(const int exit_status)
{
	FILE *stream;

	if (exit_status != 0)
		stream = stderr;
	else
		stream = stdout;

	version(stream);

	exit(exit_status);
}


static void version(FILE *stream)
{
	fprintf(stream,
		"ipvsadm " IPVSADM_VERSION " (compiled with "
		IPVS_OPTION_PROCESSING " and IPVS v%d.%d.%d)\n",
		NVERSION(IP_VS_VERSION_CODE));
}


static void fail(int err, char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(err);
}


static void print_conn_entry(const ipvs_conn_entry_t *conn_entry,
		unsigned int format)
{
	char *cname, *vname, *lname, *dname;
	char proto_str[8], time_str[8];

	if (conn_entry->proto == IPPROTO_TCP)
		snprintf(proto_str, sizeof(proto_str), "%s", "tcp");
	else if (conn_entry->proto == IPPROTO_UDP)
		snprintf(proto_str, sizeof(proto_str), "%s", "udp");
	else if (conn_entry->proto == IPPROTO_ICMP)
		snprintf(proto_str, sizeof(proto_str), "%s", "icmp");
	else if (conn_entry->proto == IPPROTO_ICMPV6)
		snprintf(proto_str, sizeof(proto_str), "%s", "icmpv6");
	else
		snprintf(proto_str, sizeof(proto_str), "%s", "--");

	snprintf(time_str, sizeof(time_str), "%ds", conn_entry->timeout);

	if (!(cname = addrport_to_anyname(conn_entry->in_af, &conn_entry->caddr,
                    ntohs(conn_entry->cport), conn_entry->proto, format)))
		goto exit;
	if (!(vname = addrport_to_anyname(conn_entry->in_af, &conn_entry->vaddr,
                    ntohs(conn_entry->vport), conn_entry->proto, format)))
		goto exit;
	if (!(lname = addrport_to_anyname(conn_entry->out_af, &conn_entry->laddr,
                    ntohs(conn_entry->lport), conn_entry->proto, format)))
		goto exit;
	if (!(dname = addrport_to_anyname(conn_entry->out_af, &conn_entry->daddr,
                    ntohs(conn_entry->dport), conn_entry->proto, format)))
		goto exit;

	printf("[%d]%-3s %-6s %-11s %-18s %-18s %-18s %s\n",
			conn_entry->lcoreid, proto_str, time_str, conn_entry->state,
			cname, vname, lname, dname);
exit:
	if (cname)
		free(cname);
	if (vname)
		free(vname);
	if (lname)
		free(lname);
	if (dname)
		free(dname);
}

static void list_conn(int is_template, unsigned int format)
{
    struct ip_vs_conn_array *conn_array;
    struct ip_vs_conn_req req;
    int i, more = 0;

    memset(&req, 0, sizeof(struct ip_vs_conn_req));
    if (is_template)
        req.flag |= GET_IPVS_CONN_FLAG_TEMPLATE;
    req.flag |= GET_IPVS_CONN_FLAG_ALL;

    while((conn_array = ip_vs_get_conns(&req)) != NULL) {
		for (i = 0; i < conn_array->nconns; i++)
			print_conn_entry(&conn_array->array[i], format);
        req.whence = conn_array->curcid;
        more = conn_array->resl & GET_IPVS_CONN_FLAG_MORE;
        free(conn_array);
        if (!more)
            break;
        req.flag |= GET_IPVS_CONN_FLAG_MORE;
    }

    if (more)
        fprintf(stderr, "Fail to fetch all connection entries!\n");
}

static void list_conn_sockpair(int is_template,
		ipvs_sockpair_t *sockpair, unsigned int format)
{
    struct ip_vs_conn_array *conn_array;
    struct ip_vs_conn_req req;

    memset(&req, 0, sizeof(struct ip_vs_conn_req));
    req.flag = GET_IPVS_CONN_FLAG_SPECIFIED;
    if (is_template)
        req.flag |= GET_IPVS_CONN_FLAG_TEMPLATE;
    memcpy(&req.sockpair, sockpair, sizeof(ipvs_sockpair_t));

    conn_array = ip_vs_get_conns(&req);
    if (conn_array == NULL) {
        fprintf(stderr, "connection specified not found\n");
        return;
    }
	print_conn_entry(&conn_array->array[0], format);
    free(conn_array);
}


static inline char *fwd_name(unsigned flags)
{
	char *fwd = NULL;

	switch (flags & IP_VS_CONN_F_FWD_MASK) {
	case IP_VS_CONN_F_MASQ:
		fwd = "Masq";
		break;
	case IP_VS_CONN_F_LOCALNODE:
		fwd = "Local";
		break;
	case IP_VS_CONN_F_TUNNEL:
		fwd = "Tunnel";
		break;
	case IP_VS_CONN_F_DROUTE:
		fwd = "Route";
		break;
	case IP_VS_CONN_F_FULLNAT:
		fwd = "FullNat";
		break;
	case IP_VS_CONN_F_SNAT:
		fwd = "SNAT";
		break;
	}
	return fwd;
}

static inline char *fwd_switch(unsigned flags)
{
	char *swt = NULL;

	switch (flags & IP_VS_CONN_F_FWD_MASK) {
	case IP_VS_CONN_F_MASQ:
		swt = "-m"; break;
	case IP_VS_CONN_F_TUNNEL:
		swt = "-i"; break;
	case IP_VS_CONN_F_LOCALNODE:
	case IP_VS_CONN_F_DROUTE:
		swt = "-g"; break;
	}
	return swt;
}

/*notice when rs is deleted svc stats count will be less than before*/
static void copy_stats_from_dest(ipvs_service_entry_t *se, struct ip_vs_get_dests *d)
{
	int i = 0;
	for (i = 0; i < d->num_dests; i++) {
		ipvs_dest_entry_t *e = &d->entrytable[i];
		se->stats.conns += e->stats.conns;
		se->stats.inpkts += e->stats.inpkts;
		se->stats.outpkts += e->stats.outpkts;
		se->stats.inbytes += e->stats.inbytes;
		se->stats.outbytes += e->stats.outbytes;
	}
}

static void print_largenum(unsigned long long i, unsigned int format)
{
	char mytmp[32];
	int len;

	if (format & FMT_EXACT) {
		len = snprintf(mytmp, 32, "%llu", i);
		printf("%*llu", len <= 8 ? 9 : len + 1, i);
		return;
	}

	if (i < 100000000)			/* less than 100 million */
		printf("%9llu", i);
	else if (i < 1000000000)		/* less than 1 billion */
		printf("%8lluK", i / 1000);
	else if (i < 100000000000ULL)		/* less than 100 billion */
		printf("%8lluM", i / 1000000);
	else if (i < 100000000000000ULL)	/* less than 100 trillion */
		printf("%8lluG", i / 1000000000ULL);
	else
		printf("%8lluT", i / 1000000000000ULL);
}


static void print_title(unsigned int format)
{
	if (format & FMT_STATS)
		printf("%-33s %8s %8s %8s %8s %8s\n"
		       "  -> RemoteAddress:Port\n",
		       "Prot LocalAddress:Port",
		       "Conns", "InPkts", "OutPkts", "InBytes", "OutBytes");
	else if (format & FMT_RATE)
		printf("%-33s %8s %8s %8s %8s %8s\n"
		       "  -> RemoteAddress:Port\n",
		       "Prot LocalAddress:Port",
		       "CPS", "InPPS", "OutPPS", "InBPS", "OutBPS");
	else if (format & FMT_THRESHOLDS)
		printf("%-33s %-10s %-10s %-10s %-10s\n"
		       "  -> RemoteAddress:Port\n",
		       "Prot LocalAddress:Port",
		       "Uthreshold", "Lthreshold", "ActiveConn", "InActConn");
	else if (format & FMT_PERSISTENTCONN)
		printf("%-33s %-9s %-11s %-10s %-10s\n"
		       "  -> RemoteAddress:Port\n",
		       "Prot LocalAddress:Port",
		       "Weight", "PersistConn", "ActiveConn", "InActConn");
	else if (!(format & FMT_RULE))
		printf("Prot LocalAddress:Port Scheduler Flags\n"
		       "  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn\n");
}


static void
print_service_entry(ipvs_service_entry_t *se, unsigned int format)
{
	struct ip_vs_get_dests *d;
	char svc_name[256];
	int i;

	if (!(d = ipvs_get_dests(se))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}

	if (se->fwmark) {
		if (format & FMT_RULE)
			if (se->af == AF_INET6)
				sprintf(svc_name, "-f %d -6", se->fwmark);
			else
				sprintf(svc_name, "-f %d", se->fwmark);
		else
			if (se->af == AF_INET6)
				sprintf(svc_name, "FWM  %d IPv6", se->fwmark);
			else
				sprintf(svc_name, "FWM  %d", se->fwmark);
	} else if (se->__addr_v4 || se->port) {
		char *vname, *proto;

		if (!(vname = addrport_to_anyname(se->af, &se->addr, ntohs(se->port),
						  se->protocol, format)))
			fail(2, "addrport_to_anyname: %s", strerror(errno));
		if (format & FMT_RULE) {
			if (se->protocol == IPPROTO_TCP)
				proto = "-t";
			else if (se->protocol == IPPROTO_UDP)
				proto = "-u";
			else
				proto = "-q";

			sprintf(svc_name, "%s %s", proto, vname);
		} else {
			if (se->protocol == IPPROTO_TCP)
				proto = "TCP";
			else if (se->protocol == IPPROTO_UDP)
				proto = "UDP";
			else if (se->protocol == IPPROTO_ICMP)
				proto = "ICMP";
			else
				proto = "ICMPv6";

			sprintf(svc_name, "%s  %s", proto, vname);
			if (se->af != AF_INET6)
				svc_name[33] = '\0';
		}
		free(vname);
	} else { /* match */
		char *proto;

		if (se->protocol == IPPROTO_TCP)
			proto = "tcp";
		else if (se->protocol == IPPROTO_UDP)
			proto = "udp";
		else if (se->protocol == IPPROTO_ICMP)
			proto = "icmp";
		else
			proto = "icmpv6";

		if (format & FMT_RULE) {
			snprintf(svc_name, sizeof(svc_name),
			"-H proto=%s,src-range=%s,dst-range=%s,iif=%s,oif=%s",
			proto, se->srange, se->drange, se->iifname, se->oifname);

		} else {
			int left = sizeof(svc_name);
			svc_name[0] = '\0';

			left -= snprintf(svc_name + strlen(svc_name), left,
				"MATCH %s", proto);

			if (strcmp(se->srange, "[::-::]:0-0") != 0 &&
                            strcmp(se->srange, "0.0.0.0-0.0.0.0:0-0") != 0)
				left -= snprintf(svc_name + strlen(svc_name), left,
				",from=%s", se->srange);

			if (strcmp(se->drange, "[::-::]:0-0") != 0 &&
                            strcmp(se->drange, "0.0.0.0-0.0.0.0:0-0") != 0)
				left -= snprintf(svc_name + strlen(svc_name), left,
				",to=%s", se->drange);

			if (strlen(se->iifname))
				left -= snprintf(svc_name + strlen(svc_name), left,
				",iif=%s", se->iifname);

			if (strlen(se->oifname))
				left -= snprintf(svc_name + strlen(svc_name), left,
				",oif=%s", se->oifname);
		}
	}

	/* copy svc's stats from dest */
	copy_stats_from_dest(se, d);

	/* print virtual service info */
	if (format & FMT_RULE) {
		printf("-A %s -s %s", svc_name, se->sched_name);
		if (se->flags & IP_VS_SVC_F_PERSISTENT) {
			printf(" -p %u", se->timeout);
			if (se->af == AF_INET)
				if (se->netmask != (unsigned long int) 0xffffffff) {
					struct in_addr mask;
					mask.s_addr = se->netmask;
					printf(" -M %s", inet_ntoa(mask));
				}
			if (se->af == AF_INET6)
				if (se->netmask != 128) {
					printf(" -M %i", se->netmask);
				}
		}
		if (se->pe_name[0])
			printf(" pe %s", se->pe_name);
		if (se->flags & IP_VS_SVC_F_ONEPACKET)
			printf(" ops");
	} else if (format & FMT_STATS) {
		printf("%-33s", svc_name);
		print_largenum(se->stats.conns, format);
		print_largenum(se->stats.inpkts, format);
		print_largenum(se->stats.outpkts, format);
		print_largenum(se->stats.inbytes, format);
		print_largenum(se->stats.outbytes, format);
	} else if (format & FMT_RATE) {
		if (se->bps > 0) {
			sprintf(svc_name, "%s bps %dM", svc_name, se->bps);
		}
		printf("%-33s", svc_name);
		print_largenum(se->stats.cps, format);
		print_largenum(se->stats.inpps, format);
		print_largenum(se->stats.outpps, format);
		print_largenum(se->stats.inbps, format);
		print_largenum(se->stats.outbps, format);
	} else {
		printf("%s %s", svc_name, se->sched_name);
		if (se->flags & IP_VS_SVC_F_SIP_HASH)
			printf(" sip");
		if (se->flags & IP_VS_SVC_F_QID_HASH)
			printf(" qid");
		if (se->flags & IP_VS_SVC_F_PERSISTENT) {
			printf(" persistent %u", se->timeout);
			if (se->af == AF_INET)
				if (se->netmask != (unsigned long int) 0xffffffff) {
					struct in_addr mask;
					mask.s_addr = se->netmask;
					printf(" mask %s", inet_ntoa(mask));
				}
			if (se->af == AF_INET6)
				if (se->netmask != 128)
					printf(" mask %i", se->netmask);
			if (se->pe_name[0])
				printf(" pe %s", se->pe_name);
			if (se->flags & IP_VS_SVC_F_ONEPACKET)
				printf(" ops");
		}
		if (se->flags & IP_VS_CONN_F_SYNPROXY)
			printf(" synproxy");
        if (se->conn_timeout != 0)
            printf(" conn_timeout %u", se->conn_timeout);
	}
	printf("\n");

	/* print all the destination entries */
	if (!(format & FMT_NOSORT))
		ipvs_sort_dests(d, ipvs_cmp_dests);

	for (i = 0; i < d->num_dests; i++) {
		char *dname;
		ipvs_dest_entry_t *e = &d->entrytable[i];

		if (!(dname = addrport_to_anyname(e->af, &(e->addr), ntohs(e->port),
						  se->protocol, format))) {
			fprintf(stderr, "addrport_to_anyname fails\n");
			exit(1);
		}
		if (!(format & FMT_RULE) && (se->af != AF_INET6))
			dname[28] = '\0';

		if (format & FMT_RULE) {
			printf("-a %s -r %s %s -w %d\n", svc_name, dname,
			       fwd_switch(e->conn_flags), e->weight);
		} else if (format & FMT_STATS) {
			printf("  -> %-28s", dname);
			print_largenum(e->stats.conns, format);
			print_largenum(e->stats.inpkts, format);
			print_largenum(e->stats.outpkts, format);
			print_largenum(e->stats.inbytes, format);
			print_largenum(e->stats.outbytes, format);
			printf("\n");
		} else if (format & FMT_RATE) {
			printf("  -> %-28s %8u %8u %8u", dname,
			       e->stats.cps,
			       e->stats.inpps,
			       e->stats.outpps);
			print_largenum(e->stats.inbps, format);
			print_largenum(e->stats.outbps, format);
			printf("\n");
		} else if (format & FMT_THRESHOLDS) {
			printf("  -> %-28s %-10u %-10u %-10u %-10u\n", dname,
			       e->u_threshold, e->l_threshold,
			       e->activeconns, e->inactconns);
		} else if (format & FMT_PERSISTENTCONN) {
			printf("  -> %-28s %-9u %-11u %-10u %-10u\n", dname,
			       e->weight, e->persistconns,
			       e->activeconns, e->inactconns);
		} else
			printf("  -> %-28s %-7s %-6d %-10u %-10u\n",
			       dname, fwd_name(e->conn_flags),
			       e->weight, e->activeconns, e->inactconns);
		free(dname);
	}
	free(d);
}

static void list_laddrs_print_title(void)
{
	printf("%-20s %-8s %-20s %-10s %-10s\n" ,
		"VIP:VPORT" ,
		"TOTAL" ,
		"SNAT_IP",
		"CONFLICTS",
		"CONNS" );
}

static void list_laddrs_print_service(struct ip_vs_get_laddrs *d)
{
	char *	vname;

	if (!(vname = addrport_to_anyname(d->af, &d->addr, ntohs(d->port),
		d->protocol, FMT_NUMERIC)))
		fail(2, "addrport_to_anyname: %s", strerror(errno));

	printf("%-20s %-8u \n" , vname , d->num_laddrs);
	free(vname);
}

#define PRINT_NIP(x)\
	((x >>  0) & 0xff) , \
	((x >>  8) & 0xff) , \
	((x >>  16) & 0xff) , \
	((x >>  24) & 0xff)

static void list_laddrs_print_laddr(struct ip_vs_laddr_entry * entry)
{
	char	pbuf[INET6_ADDRSTRLEN];

	inet_ntop(entry->af, (char *)&entry->addr, pbuf, sizeof(pbuf));

	printf("%-20s %-8s %-20s %-10lu %-10u\n",
		"",
		"",
		pbuf,
		entry->port_conflict,
		entry->conn_counts);
}

static void print_service_and_laddrs(struct ip_vs_get_laddrs* d, int with_title)
{
	int i = 0;

	if(with_title)
		list_laddrs_print_title();

	list_laddrs_print_service(d);
	for(i = 0 ; i < d->num_laddrs ; i ++){
		list_laddrs_print_laddr(d->entrytable + i);
	}

	return;
}


static int list_laddrs(ipvs_service_t *svc , int with_title)
{
	ipvs_service_entry_t *entry;
	struct ip_vs_get_laddrs *d;

	if (!(entry = ipvs_get_service(svc))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		return -1;
	}

	if (!(d = ipvs_get_laddrs(entry))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		free(entry);
		return -1;
	}

	print_service_and_laddrs(d, with_title);

	free(entry);
	free(d);

	return 0;
}


static int list_all_laddrs(void)
{
	struct ip_vs_get_services *get;
	struct ip_vs_get_laddrs   *d;
	int i;
	int title_enable = 1;

	if (!(get = ipvs_get_services())) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		return -1;
	}

	for (i = 0; i < get->num_services; i++){
		if(!(d = ipvs_get_laddrs(&(get->entrytable[i])))) {
			free(get);
			fprintf(stderr, "%s\n", ipvs_strerror(errno));
			return -1;
		}

		if(i != 0)
			title_enable = 0;
		print_service_and_laddrs(d, title_enable);

		free(d);
	}

	free(get);
	return 0;

}

static void list_blklsts_print_title(void)
{
	printf("%-20s %-8s %-20s\n" ,
		"VIP:VPORT" ,
		"PROTO" ,
		"BLACKLIST");
}

static void print_service_and_blklsts(struct dp_vs_blklst_conf *blklst)
{
	char pbuf_v[32], pbuf_d[32], port[6];
	sprintf(pbuf_v , "%u.%u.%u.%u" , PRINT_NIP(blklst->vaddr.in.s_addr));
	sprintf(pbuf_d , "%u.%u.%u.%u" , PRINT_NIP(blklst->blklst.in.s_addr));
	sprintf(port, "%d", ntohs(blklst->vport));
	if (blklst->proto ==IPPROTO_TCP)
		printf("%s:%-8s %-8s %-20s\n" , pbuf_v, port, "TCP", pbuf_d);
	else if(blklst->proto ==IPPROTO_UDP)
		printf("%s:%-8s %-8s %-20s\n" , pbuf_v, port, "UDP", pbuf_d);
	else if (blklst->proto == IPPROTO_ICMP)
		printf("%s:%-8s %-8s %-20s\n" , pbuf_v, port, "ICMP", pbuf_d);
	else
		printf("proto not support!");
}

static int list_blklst(uint32_t addr_v4, uint16_t port, uint16_t protocol)
{
	struct dp_vs_blklst_conf_array *get;
	int i;
	if (!(get = ipvs_get_blklsts())) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		return -1;
	}

	for (i = 0; i < get->naddr; i++) {
		if ( addr_v4== get->blklsts[i].vaddr.in.s_addr &&
		     port == get->blklsts[i].vport&&
		     protocol == get->blklsts[i].proto) {
			print_service_and_blklsts(&get->blklsts[i]);
		}
	}
	free(get);
	return 0;
}

static int list_all_blklsts(void)
{
	struct ip_vs_get_services *get;
	int i;

	if (!(get = ipvs_get_services())) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}

	list_blklsts_print_title();
	for (i = 0; i < get->num_services; i++)
		list_blklst(get->entrytable[i].__addr_v4, get->entrytable[i].port,
				get->entrytable[i].protocol);

	free(get);
	return 0;
}

static void list_service(ipvs_service_t *svc, unsigned int format)
{
	ipvs_service_entry_t *entry;

	if (!(entry = ipvs_get_service(svc))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}

	print_title(format);
	print_service_entry(entry, format);
	free(entry);

}


static void list_all(unsigned int format)
{
	struct ip_vs_get_services *get;
	int i;

	if (!(format & FMT_RULE))
		printf("IP Virtual Server version %d.%d.%d (size=%d)\n",
		       NVERSION(ipvs_info.version), ipvs_info.size);

	if (!(get = ipvs_get_services())) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}

	if (!(format & FMT_NOSORT))
		ipvs_sort_services(get, ipvs_cmp_services);

	print_title(format);
	for (i = 0; i < get->num_services; i++)
		print_service_entry(&get->entrytable[i], format);
	free(get);
}


void list_timeout(void)
{
	ipvs_timeout_t *u;

	if (!(u = ipvs_get_timeout()))
		exit(1);
	printf("Timeout (tcp tcpfin udp): %d %d %d\n",
	       u->tcp_timeout, u->tcp_fin_timeout, u->udp_timeout);
	free(u);
}

static void list_daemon_print_title(void)
{
	printf("%-8s %-14s %-16s %-16s %-8s %-12s %-8s %-16s %-12s %-4s \n",
		"Lcore-id",
		"Daemon-state",
		"IF-name",
		"IF-address",
		"IF-exist",
		"IF-allmulti",
		"IF-FDIR",
		"Group-address",
		"Port-number",
		"TTL");
}

static char *daemon_stat(uint8_t state)
{
	char *ret;
	switch (state) {
	case 0x1:
		ret = "active";
		break;
	case 0x2:
		ret = "backup";
		break;
	case 0x3:
		ret = "active&backup";
		break;
	default:
		ret = "disabled";
		break;
	}
	return ret;
}

static char* if_allmulticast(uint8_t flag)
{
	char* ret;
	switch (flag) {
	case 0x0:
		ret = "disabled";
		break;
	case 0x1:
		ret = "enabled";
		break;
	default:
		ret = "error";
		break;
	}
	return ret;
}

static void list_daemon_print_dameons(struct lb_sync_daemon_stat *stat)
{
	char ifbuf[64];
	char grbuf[64];
	printf("%-8u %-14s %-16s %-16s %-8s %-12s %-8s %-16s %-12u %-4u \n",
		stat->lcore_id,
		daemon_stat(stat->daemon_state),
		stat->mcast_ifn,
		inet_ntop(AF_INET, &stat->mcast_ifia, ifbuf, sizeof(ifbuf)),
		(stat->mcast_if_exist ? "Y" : "N"),
		if_allmulticast(stat->mcast_if_allmulticast),
		(stat->fdir_state ? "created" : "error"),
		inet_ntop(AF_INET, &stat->mcast_group, grbuf, sizeof(grbuf)),
		ntohs(stat->mcast_port),
		stat->mcast_ttl);
}

static void list_daemon(void)
{
	struct lb_sync_daemon_stats* stats;
	int i;

	stats = ipvs_get_daemon();
	if (NULL == stats) {
		exit(1);
	}

	list_daemon_print_title();

	for (i = 0; i < stats->n ; i++) {
		list_daemon_print_dameons(&stats->daemon_stat[i]);
	}
	free(stats);
}


int host_to_addr(const char *name, struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr))
			return -1;
		/* warning: we just handle h_addr_list[0] here */
		memcpy(addr, host->h_addr_list[0], sizeof(struct in_addr));
		return 0;
	}
	return -1;
}


static char * addr_to_host(int af, const void *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
				  sizeof(struct in_addr), af)) != NULL)
		return (char *) host->h_name;
	else
		return (char *) NULL;
}


static char * addr_to_anyname(int af, const void *addr)
{
	char *name;
	static char buf[INET6_ADDRSTRLEN];

	if ((name = addr_to_host(af, addr)) != NULL)
		return name;
	inet_ntop(af, addr, buf, sizeof(buf));
	return buf;
}


int service_to_port(const char *name, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP
	    && (service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_UDP
		 && (service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_ICMP
		 && (service = getservbyname(name, "icmp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_ICMPV6
		 && (service = getservbyname(name, "icmpv6")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else
		return -1;
}


static char * port_to_service(unsigned short port, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP &&
	    (service = getservbyport(htons(port), "tcp")) != NULL)
		return service->s_name;
	else if (proto == IPPROTO_UDP &&
		 (service = getservbyport(htons(port), "udp")) != NULL)
		return service->s_name;
	else if (proto == IPPROTO_ICMP &&
		 (service = getservbyport(htons(port), "icmp")) != NULL)
		return service->s_name;
	else if (proto == IPPROTO_ICMPV6 &&
		 (service = getservbyport(htons(port), "icmpv6")) != NULL)
		return service->s_name;
	else
		return (char *) NULL;
}


static char * port_to_anyname(unsigned short port, unsigned short proto)
{
	char *name;
	static char buf[10];

	if ((name = port_to_service(port, proto)) != NULL)
		return name;
	else {
		sprintf(buf, "%u", port);
		return buf;
	}
}


static char *
addrport_to_anyname(int af, const void *addr, unsigned short port,
		    unsigned short proto, unsigned int format)
{
 	char *buf, pbuf[INET6_ADDRSTRLEN];

	if (!(buf=malloc(60)))
		return NULL;

	if (format & FMT_NUMERIC) {
		snprintf(buf, 60, "%s%s%s:%u",
			 af == AF_INET ? "" : "[",
			 inet_ntop(af, addr, pbuf, sizeof(pbuf)),
			 af == AF_INET ? "" : "]",
			 port);
	} else {
	  snprintf(buf, 60, "%s%s%s:%s",
		   af == AF_INET ? "" : "[",
		   addr_to_anyname(af, addr),
		   af == AF_INET ? "" : "]",
		   port_to_anyname(port, proto));
	}

	return buf;
}


static int str_is_digit(const char *str)
{
	size_t offset;
	size_t top;

	top = strlen(str);
	for (offset=0; offset<top; offset++) {
		if (!isdigit((int)*(str+offset))) {
			break;
		}
	}

	return (offset<top)?0:1;
}
