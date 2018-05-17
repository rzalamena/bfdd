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
 * util.c: miscelaneous functions that doesn't fit other files.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bfd.h"

size_t strxcpy(char *dst, const char *src, size_t len)
{
	size_t srclen, tlen;

	srclen = strlen(src);
	tlen = (srclen < len) ? srclen : len;

	memcpy(dst, src, tlen);
	dst[tlen] = 0;

	return srclen;
}

const char *satostr(struct sockaddr_any *sa)
{
#define INETSTR_BUFCOUNT 8
	static char buf[INETSTR_BUFCOUNT][INET6_ADDRSTRLEN];
	static int bufidx = 0;
	struct sockaddr_in *sin = &sa->sa_sin;
	struct sockaddr_in6 *sin6;

	bufidx += (bufidx + 1) % INETSTR_BUFCOUNT;
	strxcpy(buf[bufidx], "unknown", sizeof(buf[bufidx]));
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

time_t get_monotime(struct timeval *tv)
{
	struct timespec ts;
	int r;

	r = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (r != 0) {
		memset(tv, 0, sizeof(*tv));
		return 0;
	}

	if (tv) {
		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	}

	return ts.tv_sec;
}
