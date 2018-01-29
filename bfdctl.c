/*********************************************************************
 * Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * bfdd.c implements the BFD daemon controller
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */


#include <arpa/inet.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>

#include "bfdctl.h"

/*
 * Prototypes
 */
void usage(void);

int control_init(void);
void control_send(int sd, enum bc_msg_type bmt, const char *jsonstr);

struct json_object *ctrl_new_json(void);
void ctrl_add_peer(struct json_object *msg, struct bfd_peer_cfg *bpc);

const char *satostr(struct sockaddr_any *sa);
int strtosa(const char *addr, struct sockaddr_any *sa);


/*
 * Functions
 */
void usage(void)
{
	extern const char *__progname;

	fprintf(stderr,
		"%s: [OPTIONS...]\n"
		"\t-a: add peer\n"
		"\t-d: delete peer\n"
		"\t-i <ifname>: interface\n"
		"\t-l <address>: local address (e.g. 192.168.0.1 or 2001:db8::100)\n"
		"\t-m: multihop\n"
		"\t-p <address>: peer address (e.g. 192.168.0.1 or 2001:db8::100)\n"
		"\t-v: verbose mode\n",
		__progname);

	exit(1);
}

int main(int argc, char *argv[])
{
	struct json_object *jo;
	const char *ifname = NULL;
	const char *jsonstr;
	enum bc_msg_type bmt = 0;
	int csock;
	int opt;
	bool mhop = false, verbose = false;
	struct sockaddr_any local, peer;
	struct bfd_peer_cfg bpc;

	memset(&local, 0, sizeof(local));
	memset(&peer, 0, sizeof(peer));

	while ((opt = getopt(argc, argv, "adi:l:mp:v")) != -1) {
		switch (opt) {
		case 'a':
			if (bmt != 0) {
				fprintf(stderr,
					"you must choose only one of the following: "
					"'-a' or '-d'\n\n");
				usage();
			}
			bmt = BMT_REQUEST_ADD;
			break;

		case 'd':
			if (bmt != 0) {
				fprintf(stderr,
					"you must choose only one of the following: "
					"'-a' or '-d'\n\n");
				usage();
			}
			bmt = BMT_REQUEST_DEL;
			break;

		case 'i':
			ifname = optarg;
			if (strlen(ifname) > MAXNAMELEN) {
				fprintf(stderr,
					"Interface name too long (expected < %d, got %ld)\n",
					MAXNAMELEN, strlen(ifname));
				exit(1);
			}
			break;

		case 'l':
			if (strtosa(optarg, &local) != 0) {
				fprintf(stderr, "wrong address format: %s\n",
					optarg);
				exit(1);
			}
			break;

		case 'p':
			if (strtosa(optarg, &peer) != 0) {
				fprintf(stderr, "wrong address format: %s\n",
					optarg);
				exit(1);
			}
			break;

		case 'm':
			mhop = true;
			break;

		case 'v':
			verbose = true;
			break;

		default:
			usage();
			break;
		}
	}

	if (bmt == 0) {
		fprintf(stderr, "you must specify an operation\n");
		exit(1);
	}

	if (peer.sa_sin.sin_family == 0) {
		fprintf(stderr, "you must specify a remote peer\n");
		exit(1);
	}

	if (peer.sa_sin.sin_family != 0 && local.sa_sin.sin_family != 0) {
		if (peer.sa_sin.sin_family != local.sa_sin.sin_family) {
			fprintf(stderr,
				"local address type different from remote\n");
			exit(1);
		}
	}

	/* Fill the BFD peer configuration */
	bpc.bpc_mhop = mhop;
	if (ifname) {
		bpc.bpc_has_localif = true;
		strcpy(bpc.bpc_localif, ifname);
	}

	if (peer.sa_sin.sin_family == AF_INET)
		bpc.bpc_ipv4 = true;

	bpc.bpc_peer = peer;
	bpc.bpc_local = local;

	/* Create the JSON string. */
	jo = ctrl_new_json();
	ctrl_add_peer(jo, &bpc);

	jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
	if (verbose) {
		fprintf(stderr, "%s\n", jsonstr);
	}

	if ((csock = control_init()) == -1) {
		exit(1);
	}

	control_send(csock, bmt, jsonstr);

	return 0;
}

/*
 * JSON queries build
 */
struct json_object *ctrl_new_json(void)
{
	struct json_object *jo, *jon;

	/* Create the main object: '{}' */
	jo = json_object_new_object();
	if (jo == NULL)
		return NULL;

	/* Create the IPv4 list: '{ 'ipv4': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "ipv4", jon);

	/* Create the IPv6 list: '{ 'ipv4': [], 'ipv6': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "ipv6", jon);

	return jo;
}

void ctrl_add_peer(struct json_object *msg, struct bfd_peer_cfg *bpc)
{
	struct json_object *peer_jo, *jo, *plist;

	peer_jo = json_object_new_object();
	if (peer_jo == NULL)
		return;

	jo = json_object_new_boolean(bpc->bpc_mhop);
	if (jo == NULL) {
		json_object_put(peer_jo);
		return;
	}
	json_object_object_add(peer_jo, "multihop", jo);

	if (bpc->bpc_mhop) {
		jo = json_object_new_string(satostr(&bpc->bpc_local));
		if (jo == NULL) {
			json_object_put(peer_jo);
			return;
		}
		json_object_object_add(peer_jo, "local-address", jo);
	}

	jo = json_object_new_string(satostr(&bpc->bpc_peer));
	if (jo == NULL) {
		json_object_put(peer_jo);
		return;
	}
	json_object_object_add(peer_jo, "peer-address", jo);

	if (bpc->bpc_has_localif) {
		jo = json_object_new_string(bpc->bpc_localif);
		if (jo == NULL) {
			json_object_put(peer_jo);
			return;
		}
		json_object_object_add(peer_jo, "local-interface", jo);
	}

	/* Select the appropriated peer list and add the peer to it. */
	if (bpc->bpc_ipv4)
		json_object_object_get_ex(msg, "ipv4", &plist);
	else
		json_object_object_get_ex(msg, "ipv6", &plist);

	json_object_array_add(plist, peer_jo);
}


/*
 * Control socket
 */
int control_init(void)
{
	struct sockaddr_un sun = {.sun_family = AF_UNIX,
				  .sun_path = BFD_CONTROL_SOCK_PATH};
	int sd;

	sd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC);
	if (sd == -1) {
		fprintf(stderr, "%s: socket: %s\n", __FUNCTION__,
			strerror(errno));
		return -1;
	}

	if (connect(sd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		fprintf(stderr, "%s: connect: %s\n", __FUNCTION__,
			strerror(errno));
		return -1;
	}

	return sd;
}

void control_send(int sd, enum bc_msg_type bmt, const char *jsonstr)
{
	ssize_t sent;
	size_t total = strlen(jsonstr), cur = 0;
	struct bfd_control_msg bcm = {
		.bcm_length = total,
		.bcm_type = bmt,
		.bcm_ver = BMV_VERSION_1,
		.bcm_zero = 0,
	};

	if ((sent = write(sd, &bcm, sizeof(bcm))) <= 0) {
		if (sent == 0) {
			fprintf(stderr, "%s: bfdd closed connection\n",
				__FUNCTION__);
			exit(1);
		}
		fprintf(stderr, "%s: write: %s\n", __FUNCTION__,
			strerror(errno));
		exit(1);
	}

	while (total > 0) {
		if ((sent = write(sd, &jsonstr[cur], total)) <= 0) {
			if (sent == 0) {
				fprintf(stderr, "%s: bfdd closed connection\n",
					__FUNCTION__);
				exit(1);
			}
			fprintf(stderr, "%s: write: %s\n", __FUNCTION__,
				strerror(errno));
			exit(1);
		}

		total -= sent;
		cur += sent;
	}
}


/*
 * Utility functions
 */
const char *satostr(struct sockaddr_any *sa)
{
#define INETSTR_BUFCOUNT 8
	static char buf[INETSTR_BUFCOUNT][INET6_ADDRSTRLEN];
	static int bufidx = 0;
	struct sockaddr_in *sin = &sa->sa_sin;
	struct sockaddr_in6 *sin6;

	bufidx += (bufidx + 1) % INETSTR_BUFCOUNT;
	strcpy(buf[bufidx], "unknown");
	buf[bufidx][0] = 0;

	switch (sin->sin_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sin->sin_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	case AF_INET6:
		sin6 = &sa->sa_sin6;
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	}

	return buf[bufidx];
}

int strtosa(const char *addr, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	if (inet_pton(AF_INET, addr, &sa->sa_sin.sin_addr) == 1) {
		sa->sa_sin.sin_family = AF_INET;
		return 0;
	}

	if (inet_pton(AF_INET6, addr, &sa->sa_sin6.sin6_addr) == 1) {
		sa->sa_sin6.sin6_family = AF_INET6;
		return 0;
	}

	return -1;
}
