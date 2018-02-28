/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * bfdd.c implements the BFD daemon
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bfd.h"

#define BFDD_DEFAULT_CONFIG "bfdd.json"

void usage(void);
void bg_init(void);

struct bfd_global bglobal;

void usage(void)
{
	extern const char *__progname;

	fprintf(stderr,
		"%s: [OPTIONS...]\n"
		"\t-c - select a configuration file\n"
		"\t-C unix-socket - configuration socket path\n"
		"\t-h - show this message\n",
		__progname);

	exit(1);
}

void bg_init(void)
{
	TAILQ_INIT(&bglobal.bg_bcslist);

	bglobal.bg_shop = bp_udp_shop();
	bglobal.bg_mhop = bp_udp_mhop();
	bglobal.bg_shop6 = bp_udp6_shop();
	bglobal.bg_mhop6 = bp_udp6_mhop();
	bglobal.bg_echo = ptm_bfd_echo_sock_init();
	bglobal.bg_vxlan = ptm_bfd_vxlan_sock_init();

	bglobal.bg_eb = event_base_new();
	event_assign(&bglobal.bg_ev[0], bglobal.bg_eb, bglobal.bg_shop,
		     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
	event_assign(&bglobal.bg_ev[1], bglobal.bg_eb, bglobal.bg_mhop,
		     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
	event_assign(&bglobal.bg_ev[2], bglobal.bg_eb, bglobal.bg_shop6,
		     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
	event_assign(&bglobal.bg_ev[3], bglobal.bg_eb, bglobal.bg_mhop6,
		     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
	event_add(&bglobal.bg_ev[0], NULL);
	event_add(&bglobal.bg_ev[1], NULL);
	event_add(&bglobal.bg_ev[2], NULL);
	event_add(&bglobal.bg_ev[3], NULL);

	if (bglobal.bg_echo != -1) {
		event_assign(&bglobal.bg_ev[4], bglobal.bg_eb, bglobal.bg_echo,
			     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
		event_add(&bglobal.bg_ev[4], NULL);
	}
	if (bglobal.bg_vxlan != -1) {
		event_assign(&bglobal.bg_ev[5], bglobal.bg_eb, bglobal.bg_vxlan,
			     EV_PERSIST | EV_READ, bfd_recv_cb, NULL);
		event_add(&bglobal.bg_ev[5], NULL);
	}
}

int main(int argc, char *argv[])
{
	const char *conf = BFDD_DEFAULT_CONFIG;
	const char *ctl_path = BFD_CONTROL_SOCK_PATH;
	int opt;

	/* Ignore SIGPIPE on write() failures. */
	signal(SIGPIPE, SIG_IGN);

	log_init(1, BLOG_DEBUG);
	bg_init();

	while ((opt = getopt(argc, argv, "c:C:")) != -1) {
		switch (opt) {
		case 'c':
			conf = optarg;
			break;

		case 'C':
			ctl_path = optarg;
			break;

		default:
			usage();
			break;
		}
	}

	/* Initialize control socket. */
	control_init(ctl_path);

	parse_config(conf);

	event_base_dispatch(bglobal.bg_eb);
	/* NOTREACHED */

	return 0;
}
