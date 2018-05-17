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
 * control.c: implements the BFD daemon control socket. It will be used
 * to talk with clients daemon/scripts/consumers.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bfd.h"

/*
 * Prototypes
 */
void control_accept(evutil_socket_t sd, short ev, void *arg);

struct bfd_control_queue *control_queue_new(struct bfd_control_socket *bcs);
void control_queue_free(struct bfd_control_socket *bcs,
			struct bfd_control_queue *bcq);
int control_queue_dequeue(struct bfd_control_socket *bcs);
int control_queue_enqueue(struct bfd_control_socket *bcs,
			  struct bfd_control_msg *bcm);
struct bfd_notify_peer *control_notifypeer_new(struct bfd_control_socket *bcs,
					       bfd_session *bs);
void control_notifypeer_free(struct bfd_control_socket *bcs,
			     struct bfd_notify_peer *bnp);
struct bfd_notify_peer *control_notifypeer_find(struct bfd_control_socket *bcs,
						bfd_session *bs);


struct bfd_control_socket *control_new(int sd);
void control_free(struct bfd_control_socket *bcs);
void control_reset_buf(struct bfd_control_buffer *bcb);
void control_read(evutil_socket_t sd, short ev, void *arg);
void control_write(evutil_socket_t sd, short ev, void *arg);

void control_handle_request_add(struct bfd_control_socket *bcs,
				struct bfd_control_msg *bcm);
void control_handle_request_del(struct bfd_control_socket *bcs,
				struct bfd_control_msg *bcm);
int notify_add_cb(struct bfd_peer_cfg *bpc, void *arg);
int notify_del_cb(struct bfd_peer_cfg *bpc, void *arg);
void control_handle_notify_add(struct bfd_control_socket *bcs,
			       struct bfd_control_msg *bcm);
void control_handle_notify_del(struct bfd_control_socket *bcs,
			       struct bfd_control_msg *bcm);
void control_handle_notify(struct bfd_control_socket *bcs,
			   struct bfd_control_msg *bcm);
void control_response(struct bfd_control_socket *bcs, uint16_t id,
		      const char *status, const char *error);

static void _control_notify_config(struct bfd_control_socket *bcs,
				   const char *op, bfd_session *bs);
static void _control_notify(struct bfd_control_socket *bcs, bfd_session *bs);


/*
 * Functions
 */
int control_init(const char *path)
{
	int sd;
	mode_t umval;
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX, .sun_path = BFD_CONTROL_SOCK_PATH,
	};

	if (path) {
		strxcpy(sun.sun_path, path, sizeof(sun.sun_path));
	}

	/* Remove previously created sockets. */
	unlink(sun.sun_path);

	sd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    PF_UNSPEC);
	if (sd == -1) {
		log_error("%s: socket: %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	umval = umask(0);
	if (bind(sd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_error("%s: bind: %s\n", __FUNCTION__, strerror(errno));
		close(sd);
		return -1;
	}
	umask(umval);

	if (listen(sd, SOMAXCONN) == -1) {
		log_error("%s: listen: %s\n", __FUNCTION__, strerror(errno));
		close(sd);
		return -1;
	}

	bglobal.bg_csock = sd;
	event_assign(&bglobal.bg_csockev, bglobal.bg_eb, sd,
		     EV_READ | EV_PERSIST, control_accept, NULL);
	event_add(&bglobal.bg_csockev, NULL);

	return 0;
}

void control_accept(evutil_socket_t sd, short ev __attribute__((unused)),
		    void *arg __attribute__((unused)))
{
	int csock;

	csock = accept(sd, NULL, 0);
	if (csock == -1) {
		log_warning("%s: accept: %s\n", __FUNCTION__, strerror(errno));
		return;
	}

	if (control_new(csock) == NULL)
		close(csock);
}


/*
 * Client handling
 */
struct bfd_control_socket *control_new(int sd)
{
	struct bfd_control_socket *bcs;

	bcs = calloc(1, sizeof(*bcs));
	if (bcs == NULL)
		return NULL;

	/* Disable notifications by default. */
	bcs->bcs_notify = 0;

	bcs->bcs_sd = sd;
	event_assign(&bcs->bcs_ev, bglobal.bg_eb, sd, EV_READ | EV_PERSIST,
		     control_read, bcs);
	event_assign(&bcs->bcs_outev, bglobal.bg_eb, sd, EV_WRITE | EV_PERSIST,
		     control_write, bcs);
	event_add(&bcs->bcs_ev, NULL);

	TAILQ_INIT(&bcs->bcs_bcqueue);
	TAILQ_INIT(&bcs->bcs_bnplist);
	TAILQ_INSERT_TAIL(&bglobal.bg_bcslist, bcs, bcs_entry);

	return bcs;
}

void control_free(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;
	struct bfd_notify_peer *bnp;

	event_del(&bcs->bcs_outev);
	event_del(&bcs->bcs_ev);
	close(bcs->bcs_sd);

	TAILQ_REMOVE(&bglobal.bg_bcslist, bcs, bcs_entry);

	/* Empty output queue. */
	while (!TAILQ_EMPTY(&bcs->bcs_bcqueue)) {
		bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
		control_queue_free(bcs, bcq);
	}

	/* Empty notification list. */
	while (!TAILQ_EMPTY(&bcs->bcs_bnplist)) {
		bnp = TAILQ_FIRST(&bcs->bcs_bnplist);
		control_notifypeer_free(bcs, bnp);
	}

	control_reset_buf(&bcs->bcs_bin);
	free(bcs);
}

struct bfd_notify_peer *control_notifypeer_new(struct bfd_control_socket *bcs,
					       bfd_session *bs)
{
	struct bfd_notify_peer *bnp;

	bnp = control_notifypeer_find(bcs, bs);
	if (bnp)
		return bnp;

	bnp = calloc(1, sizeof(*bnp));
	if (bnp == NULL) {
		log_warning("%s: calloc: %s", __FUNCTION__, strerror(errno));
		return NULL;
	}

	TAILQ_INSERT_TAIL(&bcs->bcs_bnplist, bnp, bnp_entry);
	bnp->bnp_bs = bs;
	bs->refcount++;

	return bnp;
}

void control_notifypeer_free(struct bfd_control_socket *bcs,
			     struct bfd_notify_peer *bnp)
{
	TAILQ_REMOVE(&bcs->bcs_bnplist, bnp, bnp_entry);
	bnp->bnp_bs->refcount--;
	free(bnp);
}

struct bfd_notify_peer *control_notifypeer_find(struct bfd_control_socket *bcs,
						bfd_session *bs)
{
	struct bfd_notify_peer *bnp;

	TAILQ_FOREACH (bnp, &bcs->bcs_bnplist, bnp_entry) {
		if (bnp->bnp_bs == bs)
			return bnp;
	}

	return NULL;
}

struct bfd_control_queue *control_queue_new(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;

	bcq = calloc(1, sizeof(*bcq));
	if (bcq == NULL) {
		log_warning("%s: calloc: %s\n", __FUNCTION__, strerror(errno));
		return NULL;
	}

	control_reset_buf(&bcq->bcq_bcb);
	TAILQ_INSERT_TAIL(&bcs->bcs_bcqueue, bcq, bcq_entry);

	return bcq;
}

void control_queue_free(struct bfd_control_socket *bcs,
			struct bfd_control_queue *bcq)
{
	control_reset_buf(&bcq->bcq_bcb);
	TAILQ_REMOVE(&bcs->bcs_bcqueue, bcq, bcq_entry);
	free(bcq);
}

int control_queue_dequeue(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;

	/* List is empty, nothing to do. */
	if (TAILQ_EMPTY(&bcs->bcs_bcqueue)) {
		event_del(&bcs->bcs_outev);
		bcs->bcs_bout = NULL;
		return 0;
	}

	bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
	control_queue_free(bcs, bcq);

	/* Get the next buffer to send. */
	if (TAILQ_EMPTY(&bcs->bcs_bcqueue)) {
		event_del(&bcs->bcs_outev);
		bcs->bcs_bout = NULL;
		return 0;
	}

	bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
	bcs->bcs_bout = &bcq->bcq_bcb;

	return 1;
}

int control_queue_enqueue(struct bfd_control_socket *bcs,
			  struct bfd_control_msg *bcm)
{
	struct bfd_control_queue *bcq;
	struct bfd_control_buffer *bcb;

	bcq = control_queue_new(bcs);
	if (bcq == NULL)
		return -1;

	bcb = &bcq->bcq_bcb;
	bcb->bcb_left = sizeof(struct bfd_control_msg) + ntohl(bcm->bcm_length);
	bcb->bcb_pos = 0;
	bcb->bcb_bcm = bcm;

	/* If this is the first item, then dequeue and start using it. */
	if (bcs->bcs_bout == NULL) {
		bcs->bcs_bout = bcb;

		/* New messages, active write events. */
		event_add(&bcs->bcs_outev, NULL);
	}

	return 0;
}

void control_reset_buf(struct bfd_control_buffer *bcb)
{
	/* Get ride of old data. */
	free(bcb->bcb_buf);
	bcb->bcb_buf = NULL;
	bcb->bcb_pos = 0;
	bcb->bcb_left = 0;
}

void control_read(evutil_socket_t sd, short ev __attribute__((unused)),
		  void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_control_buffer *bcb = &bcs->bcs_bin;
	struct bfd_control_msg bcm;
	ssize_t bread;
	size_t plen;

	/*
	 * Check if we have already downloaded message content, if so then skip
	 * to
	 * download the rest of it and process.
	 *
	 * Otherwise download a new message header and allocate the necessary
	 * memory.
	 */
	if (bcb->bcb_buf != NULL)
		goto skip_header;

	bread = read(sd, &bcm, sizeof(bcm));
	if (bread == 0) {
		control_free(bcs);
		return;
	}
	if (bread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		log_warning("%s: read: %s\n", __FUNCTION__, strerror(errno));
		control_free(bcs);
		return;
	}

	/* Validate header fields. */
	plen = ntohl(bcm.bcm_length);
	if (plen < 2) {
		log_debug("%s: client closed due small message length: %d\n",
			  __FUNCTION__, bcm.bcm_length);
		control_free(bcs);
		return;
	}

	if (bcm.bcm_ver != BMV_VERSION_1) {
		log_debug("%s: client closed due bad version: %d\n",
			  __FUNCTION__, bcm.bcm_ver);
		control_free(bcs);
		return;
	}

	/* Prepare the buffer to load the message. */
	bcs->bcs_version = bcm.bcm_ver;
	bcs->bcs_type = bcm.bcm_type;

	bcb->bcb_pos = sizeof(bcm);
	bcb->bcb_left = plen;
	bcb->bcb_buf = malloc(sizeof(bcm) + bcb->bcb_left + 1);
	if (bcb->bcb_buf == NULL) {
		log_warning("%s: not enough memory for message size: %u\n",
			    __FUNCTION__, bcb->bcb_left);
		control_free(bcs);
		return;
	}

	memcpy(bcb->bcb_buf, &bcm, sizeof(bcm));

	/* Terminate data string with NULL for later processing. */
	bcb->bcb_buf[sizeof(bcm) + bcb->bcb_left] = 0;

skip_header:
	/* Download the remaining data of the message and process it. */
	bread = read(sd, &bcb->bcb_buf[bcb->bcb_pos], bcb->bcb_left);
	if (bread == 0) {
		control_free(bcs);
		return;
	}
	if (bread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		log_warning("%s: read: %s\n", __FUNCTION__, strerror(errno));
		control_free(bcs);
		return;
	}

	bcb->bcb_pos += bread;
	bcb->bcb_left -= bread;
	/* We need more data, return to wait more. */
	if (bcb->bcb_left > 0)
		return;

	switch (bcm.bcm_type) {
	case BMT_REQUEST_ADD:
		control_handle_request_add(bcs, bcb->bcb_bcm);
		break;
	case BMT_REQUEST_DEL:
		control_handle_request_del(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY:
		control_handle_notify(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY_ADD:
		control_handle_notify_add(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY_DEL:
		control_handle_notify_del(bcs, bcb->bcb_bcm);
		break;

	default:
		log_debug("%s: unhandled message type: %d\n", __FUNCTION__,
			  bcm.bcm_type);
		control_response(bcs, bcm.bcm_id, BCM_RESPONSE_ERROR,
				 "invalid message type");
		break;
	}

	bcs->bcs_version = 0;
	bcs->bcs_type = 0;
	control_reset_buf(bcb);
}

void control_write(evutil_socket_t sd, short ev __attribute__((unused)),
		   void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_control_buffer *bcb = bcs->bcs_bout;
	ssize_t bwrite;

	bwrite = write(sd, &bcb->bcb_buf[bcb->bcb_pos], bcb->bcb_left);
	if (bwrite == 0) {
		control_free(bcs);
		return;
	}
	if (bwrite < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		log_warning("%s: write: %s\n", __FUNCTION__, strerror(errno));
		control_free(bcs);
		return;
	}

	bcb->bcb_pos += bwrite;
	bcb->bcb_left -= bwrite;
	if (bcb->bcb_left > 0)
		return;

	control_queue_dequeue(bcs);
}


/*
 * Message processing
 */
void control_handle_request_add(struct bfd_control_socket *bcs,
				struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_request_add(json) == 0)
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
	else
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
				 "request add failed");
}

void control_handle_request_del(struct bfd_control_socket *bcs,
				struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_request_del(json) == 0)
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
	else
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
				 "request del failed");
}

static bfd_session *_notify_find_peer(struct bfd_peer_cfg *bpc)
{
	struct peer_label *pl;
	bfd_session *bs;
	bfd_shop_key shop;
	bfd_mhop_key mhop;

	if (bpc->bpc_has_label) {
		pl = pl_find(bpc->bpc_label);
		if (pl)
			return pl->pl_bs;
	}

	memset(&shop, 0, sizeof(shop));
	if (bpc->bpc_mhop) {
		memset(&mhop, 0, sizeof(mhop));
		mhop.peer = bpc->bpc_peer;
		mhop.local = bpc->bpc_local;
		if (bpc->bpc_has_vrfname)
			strxcpy(mhop.vrf_name, bpc->bpc_vrfname,
				sizeof(mhop.vrf_name));

		bs = bfd_find_mhop(&mhop);
	} else {
		memset(&shop, 0, sizeof(shop));
		shop.peer = bpc->bpc_peer;
		if (!bpc->bpc_has_vxlan && bpc->bpc_has_localif)
			strxcpy(shop.port_name, bpc->bpc_localif,
				sizeof(shop.port_name));

		bs = bfd_find_shop(&shop);
	}

	return bs;
}

void control_handle_notify(struct bfd_control_socket *bcs,
			   struct bfd_control_msg *bcm)
{
	bcs->bcs_notify = *(uint64_t *)bcm->bcm_data;

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);

	/*
	 * If peer asked for notification configuration, send everything that
	 * was configured until the moment to sync up.
	 */
	if (bcs->bcs_notify & BCM_NOTIFY_CONFIG) {
		bfd_session *bs, *tmp;
		extern bfd_session *session_hash;

		HASH_ITER (sh, session_hash, bs, tmp) {
			/* Notify peer configuration. */
			_control_notify_config(bcs, BCM_NOTIFY_CONFIG_ADD, bs);
			/* Notify peer status. */
			_control_notify(bcs, bs);
		}
	}

	/*
	 * If peer asked for notification configuration, send the current
	 * state to sync.
	 */
	if (bcs->bcs_notify & BCM_NOTIFY_PEER_STATE) {
		bfd_session *bs, *tmp;
		extern bfd_session *session_hash;

		HASH_ITER (sh, session_hash, bs, tmp) {
			/* Notify peer status. */
			_control_notify(bcs, bs);
		}
	}
}

int notify_add_cb(struct bfd_peer_cfg *bpc, void *arg)
{
	struct bfd_control_socket *bcs = arg;
	bfd_session *bs = _notify_find_peer(bpc);

	if (bs == NULL)
		return -1;

	if (control_notifypeer_new(bcs, bs) == NULL)
		return -1;

	/* Notify peer status. */
	_control_notify(bcs, bs);

	return 0;
}

int notify_del_cb(struct bfd_peer_cfg *bpc, void *arg)
{
	struct bfd_control_socket *bcs = arg;
	bfd_session *bs = _notify_find_peer(bpc);
	struct bfd_notify_peer *bnp;

	if (bs == NULL)
		return -1;

	bnp = control_notifypeer_find(bcs, bs);
	if (bnp)
		control_notifypeer_free(bcs, bnp);

	return 0;
}

void control_handle_notify_add(struct bfd_control_socket *bcs,
			       struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_notify_request(bcs, json, notify_add_cb) == 0) {
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
		return;
	}

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
			 "failed to parse notify data");
}

void control_handle_notify_del(struct bfd_control_socket *bcs,
			       struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_notify_request(bcs, json, notify_del_cb) == 0) {
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
		return;
	}

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
			 "failed to parse notify data");
}


/*
 * Internal functions used by the BFD daemon.
 */
void control_response(struct bfd_control_socket *bcs, uint16_t id,
		      const char *status, const char *error)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_response(status, error);
	if (jsonstr == NULL) {
		log_warning("%s: config_response: failed to get JSON str\n",
			    __FUNCTION__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = malloc(sizeof(struct bfd_control_msg) + jsonstrlen);
	if (bcm == NULL) {
		log_warning("%s: malloc: %s\n", __FUNCTION__, strerror(errno));
		free(jsonstr);
		return;
	}

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_RESPONSE;
	bcm->bcm_id = id;
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	free(jsonstr);

	control_queue_enqueue(bcs, bcm);
}

static void _control_notify(struct bfd_control_socket *bcs, bfd_session *bs)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_notify(bs);
	if (jsonstr == NULL) {
		log_warning("%s: config_notify: failed to get JSON str\n",
			    __FUNCTION__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = malloc(sizeof(struct bfd_control_msg) + jsonstrlen);
	if (bcm == NULL) {
		log_warning("%s: malloc: %s\n", __FUNCTION__, strerror(errno));
		free(jsonstr);
		return;
	}

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_NOTIFY;
	bcm->bcm_id = htons(BCM_NOTIFY_ID);
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	free(jsonstr);

	control_queue_enqueue(bcs, bcm);
}

int control_notify(bfd_session *bs)
{
	struct bfd_control_socket *bcs;
	struct bfd_notify_peer *bnp;

	/*
	 * PERFORMANCE: reuse the bfd_control_msg allocated data for
	 * all control sockets to avoid wasting memory.
	 */
	TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
		/*
		 * Test for all notifications first, then search for
		 * specific peers.
		 */
		if ((bcs->bcs_notify & BCM_NOTIFY_PEER_STATE) == 0) {
			bnp = control_notifypeer_find(bcs, bs);
			/*
			 * If the notification is not configured here,
			 * don't send it.
			 */
			if (bnp == NULL)
				continue;
		}

		_control_notify(bcs, bs);
	}

	return 0;
}

static void _control_notify_config(struct bfd_control_socket *bcs,
				   const char *op, bfd_session *bs)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_notify_config(op, bs);
	if (jsonstr == NULL) {
		log_warning(
			"%s: config_notify_config: failed to get JSON str\n",
			__FUNCTION__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = malloc(sizeof(struct bfd_control_msg) + jsonstrlen);
	if (bcm == NULL) {
		log_warning("%s: malloc: %s\n", __FUNCTION__, strerror(errno));
		free(jsonstr);
		return;
	}

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_NOTIFY;
	bcm->bcm_id = htons(BCM_NOTIFY_ID);
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	free(jsonstr);

	control_queue_enqueue(bcs, bcm);
}

int control_notify_config(const char *op, bfd_session *bs)
{
	struct bfd_control_socket *bcs;
	struct bfd_notify_peer *bnp;

	/* Remove the control sockets notification for this peer. */
	if (strcmp(op, BCM_NOTIFY_CONFIG_DELETE) == 0 && bs->refcount > 0) {
		TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
			bnp = control_notifypeer_find(bcs, bs);
			if (bnp)
				control_notifypeer_free(bcs, bnp);
		}
	}

	/*
	 * PERFORMANCE: reuse the bfd_control_msg allocated data for
	 * all control sockets to avoid wasting memory.
	 */
	TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
		/*
		 * Test for all notifications first, then search for
		 * specific peers.
		 */
		if ((bcs->bcs_notify & BCM_NOTIFY_CONFIG) == 0) {
			continue;
		}

		_control_notify_config(bcs, op, bs);
	}

	return 0;
}
