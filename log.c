/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * log.c implements an abstraction between loggers interface. Implement all log
 * backends in this file.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "bfd.h"

void log_msg(int level, const char *fmt, va_list vl);


static int log_fg = 0;
static int log_level = BLOG_DEBUG;

void log_init(int foreground, enum blog_level level)
{
	log_fg = foreground;
	log_level = level;
}

void log_msg(int level, const char *fmt, va_list vl)
{
	if (level < log_level)
		return;

	switch (level) {
	case BLOG_DEBUG:
	case BLOG_INFO:
		vfprintf(stdout, fmt, vl);
		break;

	case BLOG_WARNING:
	case BLOG_ERROR:
	case BLOG_FATAL:
		vfprintf(stderr, fmt, vl);
		break;

	default:
		vfprintf(stderr, fmt, vl);
		break;
	}
}

void log_info(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_INFO, fmt, vl);
	va_end(vl);
}

void log_debug(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_DEBUG, fmt, vl);
	va_end(vl);
}

void log_error(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_ERROR, fmt, vl);
	va_end(vl);
}

void log_warning(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_WARNING, fmt, vl);
	va_end(vl);
}

void log_fatal(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_FATAL, fmt, vl);
	va_end(vl);

	exit(1);
}
