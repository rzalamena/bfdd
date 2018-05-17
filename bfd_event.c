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
 * bfd_event.c: implements the BFD loop event handlers.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <event.h>

#include "bfd.h"

void tv_normalize(struct timeval *tv);

void tv_normalize(struct timeval *tv)
{
	/* Remove seconds part from microseconds. */
	tv->tv_sec = tv->tv_usec / 1000000;
	tv->tv_usec = tv->tv_usec % 1000000;
}

void bfd_recvtimer_update(bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->detect_TO};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN)) {
		return;
	}

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	event_add(&bs->recvtimer_ev, &tv);
}

void bfd_echo_recvtimer_update(bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->echo_detect_TO};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN)) {
		return;
	}

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	event_add(&bs->echo_recvtimer_ev, &tv);
}

void bfd_xmttimer_update(bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN)) {
		return;
	}

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	event_add(&bs->xmttimer_ev, &tv);
}

void bfd_echo_xmttimer_update(bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN)) {
		return;
	}

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	event_add(&bs->echo_xmttimer_ev, &tv);
}

void bfd_recvtimer_delete(bfd_session *bs)
{
	event_del(&bs->recvtimer_ev);
}

void bfd_echo_recvtimer_delete(bfd_session *bs)
{
	event_del(&bs->echo_recvtimer_ev);
}

void bfd_xmttimer_delete(bfd_session *bs)
{
	event_del(&bs->xmttimer_ev);
}

void bfd_echo_xmttimer_delete(bfd_session *bs)
{
	event_del(&bs->echo_xmttimer_ev);
}

void bfd_recvtimer_assign(bfd_session *bs, bfd_ev_cb cb, int sd)
{
	event_assign(&bs->recvtimer_ev, bglobal.bg_eb, sd, EV_PERSIST | EV_READ,
		     cb, bs);
}

void bfd_echo_recvtimer_assign(bfd_session *bs, bfd_ev_cb cb, int sd)
{
	event_assign(&bs->echo_recvtimer_ev, bglobal.bg_eb, sd,
		     EV_PERSIST | EV_READ, cb, bs);
}

void bfd_xmttimer_assign(bfd_session *bs, bfd_ev_cb cb)
{
	evtimer_assign(&bs->xmttimer_ev, bglobal.bg_eb, cb, bs);
}

void bfd_echo_xmttimer_assign(bfd_session *bs, bfd_ev_cb cb)
{
	evtimer_assign(&bs->echo_xmttimer_ev, bglobal.bg_eb, cb, bs);
}
