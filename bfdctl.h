/*********************************************************************
 * Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * bfdd.h all BFDd control socket protocol definitions.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#ifndef _BFDCTRL_H_
#define _BFDCTRL_H_

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>

/*
 * Auxiliary definitions
 */
struct sockaddr_any {
	union {
		struct sockaddr_in sa_sin;
		struct sockaddr_in6 sa_sin6;
	};
};

#ifndef MAXNAMELEN
#define MAXNAMELEN 32
#endif

#define BPC_DEF_DETECTMULTIPLIER 3
#define BPC_DEF_RECEIVEINTERVAL 300  /* milliseconds */
#define BPC_DEF_TRANSMITINTERVAL 300 /* milliseconds */

/* Peer status */
enum bfd_peer_status {
	BPS_SHUTDOWN = 0, /* == PTM_BFD_ADM_DOWN, "adm-down" */
	BPS_DOWN = 1,     /* == PTM_BFD_DOWN, "down" */
	BPS_INIT = 2,     /* == PTM_BFD_INIT, "init" */
	BPS_UP = 3,       /* == PTM_BFD_UP, "up" */
};

struct bfd_peer_cfg {
	bool bpc_mhop;
	bool bpc_ipv4;
	struct sockaddr_any bpc_peer;
	struct sockaddr_any bpc_local;

	bool bpc_has_label;
	char bpc_label[MAXNAMELEN];

	bool bpc_has_vxlan;
	unsigned int bpc_vxlan;

	bool bpc_has_localif;
	char bpc_localif[MAXNAMELEN + 1];

	bool bpc_has_vrfname;
	char bpc_vrfname[MAXNAMELEN + 1];

	bool bpc_has_detectmultiplier;
	uint8_t bpc_detectmultiplier;

	bool bpc_has_recvinterval;
	uint64_t bpc_recvinterval;

	bool bpc_has_txinterval;
	uint64_t bpc_txinterval;

	bool bpc_createonly;
	bool bpc_shutdown;

	/* Status information */
	enum bfd_peer_status bpc_bps;
	uint32_t bpc_id;
	uint32_t bpc_remoteid;
};


/*
 * Protocol definitions
 */

#define BFD_CONTROL_SOCK_PATH "/var/run/bfdd.sock"

enum bc_msg_version {
	BMV_VERSION_1 = 1,
};

enum bc_msg_type {
	BMT_RESPONSE = 1,
	BMT_REQUEST_ADD = 2,
	BMT_REQUEST_DEL = 3,
	BMT_NOTIFY = 4,
	BMT_NOTIFY_ADD = 5,
	BMT_NOTIFY_DEL = 6,
};

/* Notify flags to use with bcm_notify. */
#define BCM_NOTIFY_ALL ((uint64_t)-1)
#define BCM_NOTIFY_PEER_STATE (1ULL << 0)
#define BCM_NOTIFY_CONFIG (1ULL << 1)
#define BCM_NOTIFY_NONE 0

/* Response 'status' definitions. */
#define BCM_RESPONSE_OK "ok"
#define BCM_RESPONSE_ERROR "error"

/* Notify operation. */
#define BCM_NOTIFY_PEER_STATUS "status"
#define BCM_NOTIFY_CONFIG_ADD "add"
#define BCM_NOTIFY_CONFIG_DELETE "delete"
#define BCM_NOTIFY_CONFIG_UPDATE "update"

/* Notification special ID. */
#define BCM_NOTIFY_ID 0

struct bfd_control_msg {
	/* Total length without the header. */
	uint32_t bcm_length;
	/*
	 * Message request/response id.
	 * All requests will have a correspondent response with the
	 * same id.
	 */
	uint16_t bcm_id;
	/* Message type. */
	uint8_t bcm_type;
	/* Message version. */
	uint8_t bcm_ver;
	/* Message payload. */
	uint8_t bcm_data[0];
};

#endif
