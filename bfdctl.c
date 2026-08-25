/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * bfdctl.c: implements the BFD daemon standalone controller.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */


#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>

#include "bfdctl.h"

#define BFDCTL_BACKWARDS_COMPAT 1

/*
 * Internal types
 */

struct bcm_recv_exec_ctx {
	uint16_t *id_p;
	char *cmd;
};

/*
 * Prototypes
 */
void usage(void);

int control_init(const char *path);
uint16_t control_send(int sd, enum bc_msg_type bmt, const void *data,
		      size_t datalen);

typedef int (*control_recv_cb)(struct bfd_control_msg *, void *arg);
int control_recv(int sd, control_recv_cb cb, void *arg);

struct json_object *ctrl_new_json(void);
void ctrl_add_peer_by_address(struct json_object *msg, struct json_object *peer_jo,
			      struct bfd_peer_cfg *bpc);
void ctrl_add_peer_by_label(struct json_object *msg, struct json_object *peer_jo,
			    struct bfd_peer_cfg *bpc);

int bcm_recv(struct bfd_control_msg *bcm, void *arg);
int bcm_recv_exec(struct bfd_control_msg *bcm, void *arg);
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
		"\t-C: control socket path\n"
		"\t-M: monitor (show notifications for all peers or a specific)\n"
		"\t-E <program>: on every event (notification or response to a request) execute:\n"
		"\t              <program> (Response|Notification) <event json>\n"
		"\t              instead of printing the JSON to stdout\n"
		"\t-a: add or update peer\n"
		"\t-d: delete peer\n"
		"\t-j <peer json>: custom peer definition json (same syntax as config file)\n"
		"\t                note: fields set through other options will override"
				 " fields in the json\n"
		"\t-L <label>: find peer by label instead of by address (peer must already exist)\n"
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
	const char *jsonstr = NULL;
	const char *label = NULL;
	const char *ctl_path = BFD_CONTROL_SOCK_PATH;
	char *event_handler = NULL;
	enum bc_msg_type bmt = 0;
	int csock;
	int opt;
	uint16_t cur_id;
	bool mhop = false, verbose = false, monitor = false;
	bool update_by_address = false, update_by_label = false;
	struct json_object *peer_jo = NULL;
	struct sockaddr_any local, peer;
	struct bfd_peer_cfg bpc;
	struct bcm_recv_exec_ctx bre_ctx;
	control_recv_cb recv_cb;
	void *recv_cb_arg;
	uint64_t notify_flags = BCM_NOTIFY_ALL;

	memset(&local, 0, sizeof(local));
	memset(&peer, 0, sizeof(peer));
	memset(&bpc, 0, sizeof(bpc));

	while ((opt = getopt(argc, argv, "aC:dE:i:j:l:L:Mmp:v")) != -1) {
		switch (opt) {
		case 'C':
			ctl_path = optarg;
			break;

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

		case 'E':
			event_handler = optarg;
			break;

		case 'i':
			ifname = optarg;
			if (strlen(ifname) > MAXNAMELEN) {
				fprintf(stderr,
					"Interface name too long (expected < %d, got %zd)\n",
					MAXNAMELEN, strlen(ifname));
				exit(1);
			}
			update_by_address = true;
			break;

		case 'j':
			peer_jo = json_tokener_parse(optarg);
			if (peer_jo == NULL) {
				fprintf(stderr, "invalid json: %s\n", optarg);
				exit(1);
			}
			break;

		case 'l':
			if (strtosa(optarg, &local) != 0) {
				fprintf(stderr, "wrong address format: %s\n",
					optarg);
				exit(1);
			}
			update_by_address = true;
			break;

		case 'L':
			label = optarg;
			if (strlen(label) > MAXLABELLEN) {
				fprintf(stderr,
					"Label name too long (expected < %d, got %zd)\n",
					MAXLABELLEN, strlen(label));
				exit(1);
			}
			update_by_label = true;
			break;

		case 'p':
			if (strtosa(optarg, &peer) != 0) {
				fprintf(stderr, "wrong address format: %s\n",
					optarg);
				exit(1);
			}
			update_by_address = true;
			break;

		case 'M':
			monitor = true;
			break;

		case 'm':
			mhop = true;
			update_by_address = true;
			break;

		case 'v':
			verbose = true;
			break;

		default:
			usage();
			break;
		}
	}

	if (event_handler != NULL) {
		bre_ctx.id_p = &cur_id;
		bre_ctx.cmd = event_handler;

		recv_cb = bcm_recv_exec;
		recv_cb_arg = &bre_ctx;
	} else {
		recv_cb = bcm_recv;
		recv_cb_arg = &cur_id;
	}

	if (bmt == 0 && !monitor) {
		fprintf(stderr, "you must specify an operation\n");
		exit(1);
	}

#if BFDCTL_BACKWARDS_COMPAT
	if (peer.sa_sin.sin_family == 0 && !update_by_label && monitor && bmt == 0) {
		/*
		 * Historically, when passing `-M` but no `-p`,
		 * other options related to peer addres
		 * (multihop, local address, local interface)
		 * were allowed and simply ignored.
		 *
		 * Preserve that behaviour for backwards compatibility.
		 *
		 * Passing -M -a or -M -d without -p used to crash,
		 * so we don't need to preserve that (hence bmt == 0 check above)
		 */
		if (update_by_address) {
			fprintf(stderr,
				"Warning: ignoring select-by-address options (-i/-l/-m) "
				"because no peer address was specified. "
				"This will be an error in the future.\n");
			update_by_address = false;
		}
	}
#endif

	if (!update_by_address && !update_by_label) {
		if (bmt == 0) {
			goto skip_json;
		}

		fprintf(stderr, "you must specify a remote peer or label\n");
		exit(1);
	}

	if (update_by_address && update_by_label) {
		fprintf(stderr, "cannot use select-by-address options (-p/-i/-l/-m) "
			"when selecting peer by label\n");
		exit(1);
	}

	if (update_by_address && peer.sa_sin.sin_family == 0) {
		fprintf(stderr, "you must specify a remote peer "
			"when using any of -i/-l/-m\n");
		exit(1);
	}

	if (peer.sa_sin.sin_family != 0 && local.sa_sin.sin_family != 0) {
		if (peer.sa_sin.sin_family != local.sa_sin.sin_family) {
			fprintf(stderr,
				"local address type different from remote\n");
			exit(1);
		}
	}

	/* Fill the BFD peer configuration and convert it to JSON object */
	jo = ctrl_new_json();

	if (peer_jo == NULL)
		peer_jo = json_object_new_object();

	if (update_by_address) {
		bpc.bpc_mhop = mhop;
		if (ifname) {
			bpc.bpc_has_localif = true;
			strcpy(bpc.bpc_localif, ifname);
		}

		if (peer.sa_sin.sin_family == AF_INET)
			bpc.bpc_ipv4 = true;

		bpc.bpc_peer = peer;
		bpc.bpc_local = local;

		ctrl_add_peer_by_address(jo, peer_jo, &bpc);
	}

	if (update_by_label) {
		if (label) {
			bpc.bpc_has_label = true;
			strcpy(bpc.bpc_label, label);
		}

		ctrl_add_peer_by_label(jo, peer_jo, &bpc);
	}

	/* Create the JSON string. */
	jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
	if (verbose) {
		fprintf(stderr, "%s\n", jsonstr);
	}

skip_json:
	if ((csock = control_init(ctl_path)) == -1) {
		exit(1);
	}

	if (bmt != 0) {
		cur_id = control_send(csock, bmt, jsonstr, strlen(jsonstr));
		if (cur_id == 0) {
			fprintf(stderr, "failed to send message\n");
			exit(1);
		}

		control_recv(csock, recv_cb, recv_cb_arg);
	}

	if (monitor) {
		if (jsonstr == NULL) {
			cur_id = control_send(csock, BMT_NOTIFY, &notify_flags,
					      sizeof(notify_flags));
		} else {
			cur_id = control_send(csock, BMT_NOTIFY_ADD, jsonstr,
					      strlen(jsonstr));
		}
		if (cur_id == 0) {
			fprintf(stderr, "failed to send message\n");
			exit(1);
		}

		control_recv(csock, recv_cb, recv_cb_arg);

		printf("Listening for events\n");

		/* Expect notifications only */
		cur_id = BCM_NOTIFY_ID;
		while (control_recv(csock, recv_cb, recv_cb_arg) == 0) {
			/* NOTHING */;
		}
	}

	return 0;
}

static int bcm_check_id(const struct bfd_control_msg *bcm, uint16_t id, const char *function)
{
	if (ntohs(bcm->bcm_id) != id) {
		fprintf(stderr, "%s: expected id %d, but got %d\n",
			function, id, ntohs(bcm->bcm_id));
		return -1;
	}

	return 0;
}

int bcm_recv(struct bfd_control_msg *bcm, void *arg)
{
	uint16_t *id = arg;
	struct json_object *jo;
	const char *jsonstr;

	(void)bcm_check_id(bcm, *id, __FUNCTION__);

	switch (bcm->bcm_type) {
	case BMT_RESPONSE:
		jo = json_tokener_parse((const char *)bcm->bcm_data);
		if (jo == NULL) {
			printf("Response:\n%s\n", bcm->bcm_data);
		} else {
			jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
			printf("Response:\n%s\n", jsonstr);
			json_object_put(jo);
		}
		break;

	case BMT_NOTIFY:
		jo = json_tokener_parse((const char *)bcm->bcm_data);
		if (jo == NULL) {
			printf("Notification:\n%s\n", bcm->bcm_data);
		} else {
			jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
			printf("Notification:\n%s\n", jsonstr);
			json_object_put(jo);
		}
		break;

	case BMT_NOTIFY_ADD:
	case BMT_NOTIFY_DEL:
	case BMT_REQUEST_ADD:
	case BMT_REQUEST_DEL:
	default:
		fprintf(stderr, "%s: invalid response type (%d)\n",
			__FUNCTION__, bcm->bcm_type);
		return -1;
	}

	// flush stdout after every event, in case we're piped to an event-handling script
	fflush(stdout);

	return 0;
}

static int run_command(char *const argv[]) {
	const char *prog = argv[0];
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "%s: failed to fork before running %s: %s",
		        __FUNCTION__, prog, strerror(errno));
		return -1;
	}

	if (pid == 0) {
		// child
		execvp(prog, argv);
		// if we're here, exec failed
		fprintf(stderr, "%s: failed to execvp %s: %s\n",
		        __FUNCTION__, prog, strerror(errno));
		_exit(1);
	}

	// parent
	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR) continue;
		fprintf(stderr, "%s: failed waitid for %s(%d): %s",
	                __FUNCTION__, prog, pid, strerror(errno));
		return -1;
	}

	if (status != 0) {
		fprintf(stderr, "%s: child %s(%d) exitted with status: %d",
		        __FUNCTION__, prog, pid, status);
		// TODO: try to detect statuses which indicate that prog is broken
		// and we'll never execute it successfully - return -1 in those cases
	return 1;

	}
	return 0;
}

int bcm_recv_exec(struct bfd_control_msg *bcm, void *arg)
{
	struct bcm_recv_exec_ctx *ctx = arg;
	int ret;

	(void)bcm_check_id(bcm, *ctx->id_p, __FUNCTION__);

	switch (bcm->bcm_type) {
	case BMT_RESPONSE:
		ret = run_command(
			(char *const[]){ctx->cmd, "Response", (char *)bcm->bcm_data, NULL});
		break;
	case BMT_NOTIFY:
		ret = run_command(
			(char *const[]){ctx->cmd, "Notification", (char *)bcm->bcm_data, NULL});
		break;
	case BMT_NOTIFY_ADD:
	case BMT_NOTIFY_DEL:
	case BMT_REQUEST_ADD:
	case BMT_REQUEST_DEL:
	default:
		fprintf(stderr, "%s: invalid response type (%d)\n",
			__FUNCTION__, bcm->bcm_type);
		return -1;
	}

	return ret;
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

	/* Create the label list: '{ 'ipv4': [], 'ipv6': [], 'label': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "label", jon);

	return jo;
}

void ctrl_add_peer_by_label(struct json_object *msg, struct json_object *peer_jo,
			    struct bfd_peer_cfg *bpc)
{
	struct json_object *jo, *plist;

	if (peer_jo == NULL)
		return;

	if (bpc->bpc_has_label) {
		jo = json_object_new_string(bpc->bpc_label);
		if (jo == NULL) {
			json_object_put(peer_jo);
			return;
		}
		json_object_object_add(peer_jo, "label", jo);
	}

	json_object_object_get_ex(msg, "label", &plist);
	json_object_array_add(plist, peer_jo);
}

void ctrl_add_peer_by_address(struct json_object *msg, struct json_object *peer_jo,
			      struct bfd_peer_cfg *bpc)
{
	struct json_object *jo, *plist;

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
int control_init(const char *path)
{
	struct sockaddr_un sun = {.sun_family = AF_UNIX,
				  .sun_path = BFD_CONTROL_SOCK_PATH};
	int sd;

	if (path) {
		strncpy(sun.sun_path, path, sizeof(sun.sun_path));
		sun.sun_path[sizeof(sun.sun_path) - 1] = 0;
	}

	sd = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
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

uint16_t control_send(int sd, enum bc_msg_type bmt, const void *data,
		      size_t datalen)
{
	static uint16_t id = 0;
	const uint8_t *dataptr = data;
	ssize_t sent;
	size_t cur = 0;
	struct bfd_control_msg bcm = {
		.bcm_length = htonl(datalen),
		.bcm_type = bmt,
		.bcm_ver = BMV_VERSION_1,
		.bcm_id = htons(++id),
	};

	sent = write(sd, &bcm, sizeof(bcm));
	if (sent == 0) {
		fprintf(stderr, "%s: bfdd closed connection\n", __FUNCTION__);
		return 0;
	}
	if (sent < 0) {
		fprintf(stderr, "%s: write: %s\n", __FUNCTION__,
			strerror(errno));
		return 0;
	}

	while (datalen > 0) {
		sent = write(sd, &dataptr[cur], datalen);
		if (sent == 0) {
			fprintf(stderr, "%s: bfdd closed connection\n",
				__FUNCTION__);
			return 0;
		}
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				continue;

			fprintf(stderr, "%s: write: %s\n", __FUNCTION__,
				strerror(errno));
			return 0;
		}

		datalen -= sent;
		cur += sent;
	}

	return id;
}

int control_recv(int sd, control_recv_cb cb, void *arg)
{
	size_t bufpos, bufremaining, plen;
	ssize_t bread;
	struct bfd_control_msg *bcm, bcmh;
	int ret;

	bread = read(sd, &bcmh, sizeof(bcmh));
	if (bread == 0) {
		fprintf(stderr, "%s: bfdd closed connection\n", __FUNCTION__);
		return -1;
	}
	if (bread < 0) {
		fprintf(stderr, "%s: read: %s\n", __FUNCTION__,
			strerror(errno));
		return -1;
	}

	if (bcmh.bcm_ver != BMV_VERSION_1) {
		fprintf(stderr, "%s: wrong protocol version (%d)\n",
			__FUNCTION__, bcmh.bcm_ver);
		return -1;
	}

	plen = ntohl(bcmh.bcm_length);
	if (plen > 0) {
		/* Allocate the space for NULL byte as well. */
		bcm = malloc(sizeof(bcmh) + plen + 1);
		if (bcm == NULL) {
			fprintf(stderr, "%s: malloc: %s\n", __FUNCTION__,
				strerror(errno));
			return -1;
		}

		*bcm = bcmh;
		bufremaining = plen;
		bufpos = 0;
	} else {
		bcm = &bcmh;
		bufremaining = 0;
		bufpos = 0;
	}

	while (bufremaining > 0) {
		bread = read(sd, &bcm->bcm_data[bufpos], bufremaining);
		if (bread == 0) {
			fprintf(stderr, "%s: bfdd closed connection\n",
				__FUNCTION__);
			return -1;
		}
		if (bread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				continue;

			fprintf(stderr, "%s: read: %s\n", __FUNCTION__,
				strerror(errno));
			return -1;
		}

		bufremaining -= bread;
		bufpos += bread;
	}

	/* Terminate possible JSON string with NULL. */
	if (bufpos > 0)
		bcm->bcm_data[bufpos] = 0;

	/* Use the callback, otherwise return success. */
	if (cb != NULL)
		ret = cb(bcm, arg);
	else
		ret = 0;

	/*
	 * Only try to free() memory that was allocated and not from
	 * heap. Use plen to find if we allocated memory.
	 */
	if (plen > 0)
		free(bcm);

	return ret;
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
