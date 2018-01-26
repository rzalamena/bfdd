/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * control.c implements the BFD daemon control socket. It will be used to talk
 * with clients daemon/scripts/consumers.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bfd.h"

/*
 * Prototypes
 */
void control_accept(evutil_socket_t sd, short ev, void *arg);

struct bfd_control_socket *control_new(int sd);
void control_free(struct bfd_control_socket *bcs);
void control_read(evutil_socket_t sd, short ev, void *arg);

void control_handle_request_add(struct bfd_control_msg *bcm);
void control_handle_request_del(struct bfd_control_msg *bcm);
void control_handle_notify(struct bfd_control_socket *bcs,
			   struct bfd_control_msg *bcm);


/*
 * Functions
 */
int control_init(void)
{
	int sd;
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX, .sun_path = BFD_CONTROL_SOCK_PATH,
	};

	/* Remove previously created sockets. */
	unlink(sun.sun_path);

	sd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    PF_UNSPEC);
	if (sd == -1) {
		log_error("%s: socket: %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	if (bind(sd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_error("%s: bind: %s\n", __FUNCTION__, strerror(errno));
		close(sd);
		return -1;
	}

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
	bcs->bcs_notify = false;

	bcs->bcs_sd = sd;
	event_assign(&bcs->bcs_ev, bglobal.bg_eb, sd, EV_READ | EV_PERSIST,
		     control_read, bcs);
	event_add(&bcs->bcs_ev, NULL);

	TAILQ_INSERT_TAIL(&bglobal.bg_bcslist, bcs, bcs_entry);

	return bcs;
}

void control_free(struct bfd_control_socket *bcs)
{
	event_del(&bcs->bcs_ev);
	close(bcs->bcs_sd);

	TAILQ_REMOVE(&bglobal.bg_bcslist, bcs, bcs_entry);

	free(bcs->bcs_buf);
	free(bcs);
}

void control_read(evutil_socket_t sd, short ev __attribute__((unused)),
		  void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_control_msg bcm;
	ssize_t bread;

	/*
	 * Check if we have already downloaded message content, if so then skip
	 * to
	 * download the rest of it and process.
	 *
	 * Otherwise download a new message header and allocate the necessary
	 * memory.
	 */
	if (bcs->bcs_buf)
		goto skip_header;

	bread = read(sd, &bcm, sizeof(bcm));
	if (bread <= 0) {
		if (bread == -1)
			log_warning("%s: read: %s\n", __FUNCTION__,
				    strerror(errno));

		control_free(bcs);
		return;
	}

	/* Validate header fields. */
	if (bcm.bcm_length < 2) {
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
	bcs->bcs_type = ntohs(bcm.bcm_type);
	bcs->bcs_bufpos = sizeof(bcm);
	bcs->bcs_bytesleft = ntohl(bcm.bcm_length);
	bcs->bcs_buf = malloc(sizeof(bcm) + bcs->bcs_bytesleft + 1);
	if (bcs->bcs_buf == NULL) {
		log_debug("%s: not enough memory for message size: %u\n",
			  __FUNCTION__, bcs->bcs_bytesleft);
		control_free(bcs);
		return;
	}

	memcpy(bcs->bcs_buf, &bcm, sizeof(bcm));

	/* Terminate data string with NULL for later processing. */
	bcs->bcs_buf[sizeof(bcm) + bcs->bcs_bytesleft] = 0;

skip_header:
	/* Download the remaining data of the message and process it. */
	bread = read(sd, &bcs->bcs_buf[bcs->bcs_bufpos], bcs->bcs_bytesleft);
	if (bread <= 0) {
		if (bread == -1)
			log_warning("%s: read: %s\n", __FUNCTION__,
				    strerror(errno));

		control_free(bcs);
		return;
	}

	bcs->bcs_bufpos += bread;
	bcs->bcs_bytesleft -= bread;
	/* We need more data, return to wait more. */
	if (bcs->bcs_bytesleft == 0)
		return;

	switch (bcm.bcm_type) {
	case BMT_REQUEST_ADD:
		control_handle_request_add(bcs->bcs_bcm);
		break;
	case BMT_REQUEST_DEL:
		control_handle_request_del(bcs->bcs_bcm);
		break;
	case BMT_NOTIFY:
		control_handle_notify(bcs, bcs->bcs_bcm);
		break;

	default:
		log_debug("%s: unhandled message type: %d\n", __FUNCTION__,
			  bcm.bcm_type);
		break;
	}

	/* Get ride of old data. */
	free(bcs->bcs_buf);
	bcs->bcs_buf = NULL;
	bcs->bcs_bufpos = 0;
	bcs->bcs_bytesleft = 0;

	bcs->bcs_version = 0;
	bcs->bcs_type = 0;
}


/*
 * Message processing
 */
void control_handle_request_add(struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	config_request_add(json);
}

void control_handle_request_del(struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	config_request_del(json);
}

void control_handle_notify(struct bfd_control_socket *bcs,
			   struct bfd_control_msg *bcm)
{
	bcs->bcs_notify = *(uint64_t *)bcm->bcm_data;
}
