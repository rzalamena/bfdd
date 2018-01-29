/*********************************************************************
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _BFD_H_
#define _BFD_H_

#include <netinet/in.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#include <event.h>

#include "queue.h"
#include "uthash.h"

#include "bfdctl.h"

#define ETHERNET_ADDRESS_LENGTH 6

/**
 * List of type of listening socket Fds supported by BFD.
 * BFD_SHOP_FD: Single hop socket Fd
 * BFD_MHOP_FD: Multi hop socket Fd
 * BFD_ECHO_FD: Echo socket Fd
 * BFD_SHOP6_FD: Single hop IPv6 socket Fd
 * BFD_MHOP6_FD: Multi hop IPv6 socket Fd
 * BFD_MAX_FD: Max socket Fd
 */
typedef enum {
	BFD_SHOP_FD = 0,
	BFD_MHOP_FD,
	BFD_ECHO_FD,
	BFD_VXLAN_FD,
	BFD_SHOP6_FD,
	BFD_MHOP6_FD,
	BFD_MAX_FD
} bfd_fd_type_e;

typedef struct bfd_timers {
	uint32_t desired_min_tx;
	uint32_t required_min_rx;
	uint32_t required_min_echo;
} bfd_timers_t;

typedef struct bfd_discrs {
	uint32_t my_discr;
	uint32_t remote_discr;
} bfd_discrs_t;

/*
 * Format of control packet.  From section 4)
 */
typedef struct bfd_pkt_s {
	union {
		uint32_t byteFields;
		struct {
			uint8_t diag;
			uint8_t flags;
			uint8_t detect_mult;
			uint8_t len;
		};
	};
	bfd_discrs_t discrs;
	bfd_timers_t timers;
} bfd_pkt_t;

/*
 * Format of Echo packet.
 */
typedef struct bfd_echo_pkt_s {
	union {
		uint32_t byteFields;
		struct {
			uint8_t ver;
			uint8_t len;
			uint16_t reserved;
		};
	};
	uint32_t my_discr;
	uint8_t pad[16];
} bfd_echo_pkt_t;


/* Macros for manipulating control packets */
#define BFD_VERMASK 0x03
#define BFD_GETVER(diag) ((diag >> 5) & BFD_VERMASK)
#define BFD_SETVER(diag, val) ((diag) |= (val & BFD_VERMASK) << 5)
#define BFD_VERSION 1
#define BFD_PBIT 0x20
#define BFD_FBIT 0x10
#define BFD_CBIT 0x08
#define BFD_ABIT 0x04
#define BFD_DEMANDBIT 0x02
#define BFD_DIAGNEIGHDOWN 3
#define BFD_DIAGDETECTTIME 1
#define BFD_DIAGADMINDOWN 7
#define BFD_SETDEMANDBIT(flags, val)                                           \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_DEMANDBIT;                                \
	}
#define BFD_SETPBIT(flags, val)                                                \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_PBIT;                                     \
	}
#define BFD_GETPBIT(flags) (flags & BFD_PBIT)
#define BFD_SETFBIT(flags, val)                                                \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_FBIT;                                     \
	}
#define BFD_GETFBIT(flags) (flags & BFD_FBIT)
#define BFD_SETSTATE(flags, val)                                               \
	{                                                                      \
		if ((val))                                                     \
			flags |= (val & 0x3) << 6;                             \
	}
#define BFD_GETSTATE(flags) ((flags >> 6) & 0x3)
#define BFD_ECHO_VERSION 1
#define BFD_ECHO_PKT_LEN sizeof(bfd_echo_pkt_t) /* Length of Echo packet */
#define BFD_CTRL_PKT_LEN sizeof(bfd_pkt_t)
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define ETH_HDR_LEN 14
#define VXLAN_HDR_LEN 8
#define BFD_ECHO_PKT_TOT_LEN                                                   \
	((int)(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + BFD_ECHO_PKT_LEN))
#define BFD_VXLAN_PKT_TOT_LEN                                                  \
	((int)(VXLAN_HDR_LEN + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN          \
	       + BFD_CTRL_PKT_LEN))
#define BFD_RX_BUF_LEN 160

/* BFD session flags */
typedef enum ptm_bfd_session_flags {
	BFD_SESS_FLAG_NONE = 0,
	BFD_SESS_FLAG_ECHO = 1 << 0,	/* BFD Echo functionality */
	BFD_SESS_FLAG_ECHO_ACTIVE = 1 << 1, /* BFD Echo Packets are being sent
					     * actively */
	BFD_SESS_FLAG_MH = 1 << 2,	  /* BFD Multi-hop session */
	BFD_SESS_FLAG_VXLAN = 1 << 3,       /* BFD Multi-hop session which is
					     * used to monitor vxlan tunnel */
	BFD_SESS_FLAG_IPV6 = 1 << 4,	/* BFD IPv6 session */
	BFD_SESS_FLAG_SEND_EVT_ACTIVE = 1 << 5, /* send event timer active */
	BFD_SESS_FLAG_SEND_EVT_IGNORE = 1 << 6, /* ignore send event when timer
						 * expires */
} bfd_session_flags;

#define BFD_SET_FLAG(field, flag) (field |= flag)
#define BFD_UNSET_FLAG(field, flag) (field &= ~flag)
#define BFD_CHECK_FLAG(field, flag) (field & flag)

/* BFD session hash keys */
typedef struct ptm_bfd_shop_key {
	struct sockaddr_any peer;
	char port_name[MAXNAMELEN + 1];
} bfd_shop_key;

typedef struct ptm_bfd_mhop_key {
	struct sockaddr_any peer;
	struct sockaddr_any local;
	char vrf_name[MAXNAMELEN + 1];
} bfd_mhop_key;

typedef struct ptm_bfd_session_stats {
	uint64_t rx_ctrl_pkt;
	uint64_t tx_ctrl_pkt;
	uint64_t rx_echo_pkt;
	uint64_t tx_echo_pkt;
} bfd_session_stats_t;

typedef struct {
	uint32_t seqid;
	char name[MAXNAMELEN];
	uint32_t num_sessions;
	uint32_t num_pend_sessions;
} ptm_bfd_client_t;

typedef struct ptm_bfd_session_vxlan_info {
	uint32_t vnid;
	uint32_t decay_min_rx;
	uint8_t forwarding_if_rx;
	uint8_t cpath_down;
	uint8_t check_tnl_key;
	uint8_t local_dst_mac[ETHERNET_ADDRESS_LENGTH];
	uint8_t peer_dst_mac[ETHERNET_ADDRESS_LENGTH];
	struct in_addr local_dst_ip;
	struct in_addr peer_dst_ip;
} bfd_session_vxlan_info_t;

/*
 * Session state information
 */
typedef struct ptm_bfd_session {

	/* protocol state per RFC 5880*/
	uint8_t ses_state;
	bfd_discrs_t discrs;
	uint8_t local_diag;
	uint8_t demand_mode;
	uint8_t detect_mult;
	uint8_t remote_detect_mult;
	uint8_t mh_ttl;

	/* Timers */
	bfd_timers_t timers;
	bfd_timers_t new_timers;
	uint32_t slow_min_tx;
	uint32_t up_min_tx;
	uint64_t detect_TO;
	struct event echo_recvtimer_ev;
	struct event recvtimer_ev;
	uint64_t xmt_TO;
	uint64_t echo_xmt_TO;
	struct event xmttimer_ev;
	struct event echo_xmttimer_ev;
	uint64_t echo_detect_TO;

	/* software object state */
	uint8_t polling;

	/* This and the localDiscr are the keys to state info */
	union {
		bfd_shop_key shop;
		bfd_mhop_key mhop;
	};
	int sock;

	/* fields needed for uthash integration */
	UT_hash_handle sh; /* use session as key */
	union {
		UT_hash_handle ph; /* use peer and port as key */
		UT_hash_handle mh; /* use peer and local as key */
	};

	struct sockaddr_any local_ip;
	int ifindex;
	uint8_t local_mac[ETHERNET_ADDRESS_LENGTH];
	uint8_t peer_mac[ETHERNET_ADDRESS_LENGTH];
	uint16_t ip_id;

	/* BFD session flags */
	bfd_session_flags flags;

	uint8_t echo_pkt[BFD_ECHO_PKT_TOT_LEN]; /* Save the Echo Packet
						 * which will be transmitted */
	bfd_session_stats_t stats;
	bfd_session_vxlan_info_t vxlan_info;

	struct timeval uptime;   /* last up time */
	struct timeval downtime; /* last down time */
} bfd_session;

/**
 * List of IP address family supported by BFD session.
 * BFD_AFI_V4: Support only IPv4 peer sessions
 * BFD_AFI_V6: Support only IPv6 peer sessions
 * BFD_AFI_BOTH: Support both IPv4 and IPv6 peer sessions
 */
typedef enum bfd_afi_e {
	BFD_AFI_V4 = 1,
	BFD_AFI_V6,
	BFD_AFI_BOTH,
} bfd_afi;

typedef struct bfd_diag_str_list_s {
	char *str;
	int type;
} bfd_diag_str_list;

typedef struct bfd_state_str_list_s {
	char *str;
	int type;
} bfd_state_str_list;

struct bfd_vrf {
	int vrf_id;
	char name[MAXNAMELEN + 1];
	UT_hash_handle vh;
} bfd_vrf;

struct bfd_iface {
	int vrf_id;
	char ifname[MAXNAMELEN + 1];
	UT_hash_handle ifh;
} bfd_iface;


/* States defined per 4.1 */
#define PTM_BFD_ADM_DOWN 0
#define PTM_BFD_DOWN 1
#define PTM_BFD_INIT 2
#define PTM_BFD_UP 3


/* Various constants */
/* Retrieved from ptm_timer.h from Cumulus PTM sources. */
#define MSEC_PER_SEC 1000L
#define NSEC_PER_MSEC 1000000L

#define BFD_DEF_DEMAND 0
#define BFD_DEFDETECTMULT 3
#define BFD_DEFDESIREDMINTX (300 * MSEC_PER_SEC)
#define BFD_DEFREQUIREDMINRX (300 * MSEC_PER_SEC)
#define BFD_DEF_REQ_MIN_ECHO (50 * MSEC_PER_SEC)
#define BFD_DEF_SLOWTX (2000 * MSEC_PER_SEC)
#define BFD_DEF_MHOP_TTL 5
#define BFD_PKT_LEN 24 /* Length of control packet */
#define BFD_TTL_VAL 255
#define BFD_RCV_TTL_VAL 1
#define BFD_TOS_VAL 0xC0
#define BFD_PKT_INFO_VAL 1
#define BFD_IPV6_PKT_INFO_VAL 1
#define BFD_IPV6_ONLY_VAL 1
#define BFD_SRCPORTINIT 49142
#define BFD_SRCPORTMAX 65536
#define BFD_DEFDESTPORT 3784
#define BFD_DEF_ECHO_PORT 3785
#define BFD_DEF_MHOP_DEST_PORT 4784
#define BFD_CMD_STRING_LEN (MAXNAMELEN + 50)
#define BFD_BUFFER_LEN (BFD_CMD_STRING_LEN + MAXNAMELEN + 1)

/*
 * control.c
 *
 * Daemon control code to speak with local consumers.
 */

/* See 'bfdctrl.h' for client protocol definitions. */

struct bfd_control_buffer {
	size_t bcb_left;
	size_t bcb_pos;
	union {
		struct bfd_control_msg *bcb_bcm;
		uint8_t *bcb_buf;
	};
};

struct bfd_control_queue {
	TAILQ_ENTRY(bfd_control_queue) bcq_entry;

	struct bfd_control_buffer bcq_bcb;
};
TAILQ_HEAD(bcqueue, bfd_control_queue);

struct bfd_control_socket {
	TAILQ_ENTRY(bfd_control_socket) bcs_entry;

	int bcs_sd;
	struct event bcs_ev;
	struct event bcs_outev;
	struct bcqueue bcs_bcqueue;

	uint64_t bcs_notify;
	enum bc_msg_version bcs_version;
	enum bc_msg_type bcs_type;

	/* Message buffering */
	struct bfd_control_buffer bcs_bin;
	struct bfd_control_buffer *bcs_bout;
};
TAILQ_HEAD(bcslist, bfd_control_socket);

int control_init(void);


/*
 * bfdd.c
 *
 * Daemon specific code.
 */
struct bfd_global {
	int bg_shop;
	int bg_mhop;
	int bg_shop6;
	int bg_mhop6;
	int bg_echo;
	int bg_vxlan;
	struct event bg_ev[6];

	int bg_csock;
	struct event bg_csockev;
	struct bcslist bg_bcslist;

	struct event_base *bg_eb;
};
extern struct bfd_global bglobal;


/*
 * bfd_config.c
 *
 * Contains the code related with loading/reloading configuration.
 */
int parse_config(const char *);
int config_request_add(const char *jsonstr);
int config_request_del(const char *jsonstr);
char *config_response(const char *status, const char *error);


/*
 * log.c
 *
 * Contains code that does the logging procedures. Might implement multiple
 * backends (e.g. zebra log, syslog or other logging lib).
 */
enum blog_level {
	/* level vs syslog equivalent */
	BLOG_DEBUG = 0,   /* LOG_DEBUG */
	BLOG_INFO = 1,    /* LOG_INFO */
	BLOG_WARNING = 2, /* LOG_WARNING */
	BLOG_ERROR = 3,   /* LOG_ERR */
	BLOG_FATAL = 4,   /* LOG_CRIT */
};

void log_init(int foreground, enum blog_level level);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_warning(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_fatal(const char *fmt, ...);

/* Compatibility code: code to avoid touching ported code debug messages. */
#define DLOG(fmt, args...) log_debug(fmt "\n", ##args)
#define INFOLOG(fmt, args...) log_info(fmt "\n", ##args)
#define ERRLOG(fmt, args...) log_error(fmt "\n", ##args)
#define CRITLOG(fmt, args...) log_fatal(fmt "\n", ##args)

/*
 * bfd_packet.c
 *
 * Contains the code related with receiving/seding, packing/unpacking BFD data.
 */

int bp_set_ttlv6(int sd);
int bp_set_ttl(int sd);
int bp_set_tosv6(int sd);
int bp_set_tos(int sd);
int bp_bind_dev(int sd, const char *dev);

int bp_udp_shop(void);
int bp_udp_mhop(void);
int bp_udp6_shop(void);
int bp_udp6_mhop(void);
int ptm_bfd_echo_sock_init(void);
int ptm_bfd_vxlan_sock_init(void);
int bp_peer_socket(struct bfd_peer_cfg *bpc);
int bp_peer_socketv6(struct bfd_peer_cfg *bpc);

void ptm_bfd_snd(bfd_session *bfd, int fbit);
void ptm_bfd_echo_snd(bfd_session *bfd);

void bfd_recv_cb(evutil_socket_t sd, short events, void *arg);


/*
 * bfd_event.c
 *
 * Contains the code related with event loop.
 */
typedef void (*bfd_ev_cb)(evutil_socket_t sd, short events, void *arg);

void bfd_recvtimer_update(bfd_session *bs);
void bfd_echo_recvtimer_update(bfd_session *bs);
void bfd_xmttimer_update(bfd_session *bs, uint64_t jitter);
void bfd_echo_xmttimer_update(bfd_session *bs, uint64_t jitter);

void bfd_xmttimer_delete(bfd_session *bs);
void bfd_echo_xmttimer_delete(bfd_session *bs);
void bfd_recvtimer_delete(bfd_session *bs);
void bfd_echo_recvtimer_delete(bfd_session *bs);

void bfd_recvtimer_assign(bfd_session *bs, bfd_ev_cb cb, int sd);
void bfd_echo_recvtimer_assign(bfd_session *bs, bfd_ev_cb cb, int sd);
void bfd_xmttimer_assign(bfd_session *bs, bfd_ev_cb cb);
void bfd_echo_xmttimer_assign(bfd_session *bs, bfd_ev_cb cb);


/*
 * util.c
 *
 * Contains utility code that doesn't fit the other files.
 */
size_t strxcpy(char *dst, const char *src, size_t len);
const char *satostr(struct sockaddr_any *sa);
int strtosa(const char *addr, struct sockaddr_any *sa);
time_t get_monotime(struct timeval *tv);


/*
 * bfd.c
 *
 * BFD protocol specific code.
 */
extern bfd_state_str_list state_list[];

bfd_session *bs_session_find(uint32_t discr);
bfd_session *ptm_bfd_sess_new(struct bfd_peer_cfg *bpc);
void ptm_bfd_ses_del(struct bfd_peer_cfg *bpc);
void ptm_bfd_ses_dn(bfd_session *bfd, uint8_t diag);
void ptm_bfd_ses_up(bfd_session *bfd);
void fetch_portname_from_ifindex(int ifindex, char *ifname, size_t ifnamelen);
void ptm_bfd_echo_stop(bfd_session *bfd, int polling);
void ptm_bfd_echo_start(bfd_session *bfd);
void ptm_bfd_xmt_TO(bfd_session *bfd, int fbit);
void ptm_bfd_start_xmt_timer(bfd_session *bfd, bool is_echo);
int ptm_bfd_fetch_ifindex(const char *ifname);
bfd_session *ptm_bfd_sess_find(bfd_pkt_t *cp, char *port_name,
			       struct sockaddr_any *peer,
			       struct sockaddr_any *local, char *vrf_name,
			       bool is_mhop);

#endif /* _BFD_H_ */
