/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * util.c miscelaneous functions that doesn't fit other files.
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

	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;

	return tv->tv_sec;
}
