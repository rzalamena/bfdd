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

struct bfd_peer_cfg {
	bool bpc_mhop;
	bool bpc_ipv4;
	struct sockaddr_any bpc_peer;
	struct sockaddr_any bpc_local;

	bool bpc_has_vxlan;
	unsigned int bpc_vxlan;

	bool bpc_has_localif;
	char bpc_localif[MAXNAMELEN + 1];

	bool bpc_has_vrfname;
	char bpc_vrfname[MAXNAMELEN + 1];
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
#define BCM_NOTIFY_NONE 0

/* Response 'status' definitions. */
#define BCM_RESPONSE_OK "ok"
#define BCM_RESPONSE_ERROR "error"

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
