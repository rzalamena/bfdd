/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * bfd_event.c implements the BFD loop event handlers
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
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->echo_detect_TO};

	tv_normalize(&tv);
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);

	event_add(&bs->recvtimer_ev, &tv);
}

void bfd_detecttimer_update(bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->detect_TO};

	tv_normalize(&tv);
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);

	event_add(&bs->recvtimer_ev, &tv);
}

void bfd_xmttimer_update(bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	tv_normalize(&tv);
	log_debug("%s: sec = %ld, usec = %ld\n", __FUNCTION__, tv.tv_sec,
		  tv.tv_usec);

	event_add(&bs->xmttimer_ev, &tv);
}

void bfd_xmttimer_delete(bfd_session *bs)
{
	event_del(&bs->xmttimer_ev);
}

void bfd_detecttimer_delete(bfd_session *bs)
{
	event_del(&bs->recvtimer_ev);
}

void bfd_recvtimer_assign(bfd_session *bs, bfd_ev_cb cb, int sd)
{
	event_assign(&bs->recvtimer_ev, bglobal.bg_eb, sd, EV_PERSIST | EV_READ,
		     cb, bs);
}

void bfd_xmttimer_assign(bfd_session *bs, bfd_ev_cb cb)
{
	evtimer_assign(&bs->xmttimer_ev, bglobal.bg_eb, cb, bs);
}

#if 0 /* TODO translate this code to libevent loop */
/*
 * This function is the timer loop for bfd events. The actual timer
 * used will be only tracking the time to next epoch, tracked by
 * bfd_tt_epoch.  On epoch expiry every bfd session entry within
 * bfd_epoch_skid, will be acted upon, and the tt_epoch updated if
 * needed
 */
void ptm_bfd_timer_wheel(void)
{
    bfd_session *bfd, *tmp;
    struct timespec cts;
    uint8_t low_init;

    /* get current time and adjust for allowable skid */
    cl_cur_time(&cts);
    cl_add_time(&cts, bfd_epoch_skid);

    if (ptm_bfd.session_count > 0)
    {
        do {
#ifdef DEBUG_TIMERWHEEL
            DLOG("BFD timer fired\n");
#endif // DEBUG_TIMERWHEEL
            low_init = 0;
            HASH_ITER(sh, session_hash, bfd, tmp) {

                /* check expiry status and update timers if needed */
                if (cl_comp_time(&cts, &bfd->xmt_timer) >= 0) {
                    ptm_bfd_xmt_TO(bfd, 0);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        cl_comp_time(&cts, &bfd->echo_xmt_timer) >= 0) {
                    ptm_bfd_echo_xmt_TO(bfd);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE) &&
                        cl_comp_time(&cts, &bfd->send_evt_timer) >= 0) {
                    ptm_bfd_send_evt_TO(bfd);
                }
                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&cts, &bfd->detect_timer) >= 0) {
                        ptm_bfd_detect_TO(bfd);
                    }
                    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        (bfd->ses_state == PTM_BFD_UP) &&
                        (cl_comp_time(&cts, &bfd->echo_detect_timer)) >= 0) {
                        ptm_bfd_echo_detect_TO(bfd);
                    }
                }

                /* with new timers now, setup running lowest time to epoch */
                if (!low_init) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->xmt_timer);
                    low_init = 1;
                }

                if (cl_comp_time(&bfd_tt_epoch, &bfd->xmt_timer) >= 0) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->xmt_timer);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                    (cl_comp_time(&bfd_tt_epoch, &bfd->echo_xmt_timer) >= 0)) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->echo_xmt_timer);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE) &&
                    (cl_comp_time(&bfd_tt_epoch, &bfd->send_evt_timer) >= 0)) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->send_evt_timer);
                }

                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&bfd_tt_epoch, &bfd->detect_timer) >= 0) {
                        cl_cp_time(&bfd_tt_epoch, &bfd->detect_timer);
                    }
                    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        (bfd->ses_state == PTM_BFD_UP) &&
                        (cl_comp_time(&bfd_tt_epoch, &bfd->echo_detect_timer)) >= 0) {
                        cl_cp_time(&bfd_tt_epoch, &bfd->echo_detect_timer);
                    }
                }
            }

        } while (cl_comp_time(&cts, &bfd_tt_epoch) > 0);

        ptm_bfd_start_timer(&bfd_tt_epoch);
    } else {
        DLOG("Entered timer wheel with no session\n");
    }
}

void ptm_timer_cb_bfd(cl_timer_t *timer, void *context)
{
    ptm_bfd_timer_wheel();
}
#endif
