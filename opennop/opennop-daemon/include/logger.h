/*

  logger.c

  This file is part of OpenNOP-SoloWAN distribution.
  No modifications made from the original file in OpenNOP distribution.

  Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

  References:

    OpenNOP: http://www.opennop.org

  License:

    OpenNOP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef LOGGER_H_
#define LOGGER_H_
#define _GNU_SOURCE

#include <syslog.h>
#include <stdio.h>

#include <stdbool.h>

#define LOGSZ     256

void logger(int LOG_TYPE, char *message);


#include "log4c.h"

extern log4c_category_t* lc_main;
extern log4c_category_t* lc_config;
extern log4c_category_t* lc_cli;
extern log4c_category_t* lc_fetcher;
extern log4c_category_t* lc_worker;
extern log4c_category_t* lc_worker_retx;
extern log4c_category_t* lc_worker_opt;
extern log4c_category_t* lc_worker_cli;
extern log4c_category_t* lc_worker_counters;
extern log4c_category_t* lc_comp;
extern log4c_category_t* lc_dedup;
extern log4c_category_t* lc_tcpopts;
extern log4c_category_t* lc_sesman;
extern log4c_category_t* lc_sesman_insert;
extern log4c_category_t* lc_sesman_get;
extern log4c_category_t* lc_sesman_remove;
extern log4c_category_t* lc_sesman_update;
extern log4c_category_t* lc_sesman_check;
extern log4c_category_t* lc_memman;
extern log4c_category_t* lc_counters;
extern log4c_category_t* lc_queman;

#define LOGINFO(lc, ...)   log4c_category_log(lc, LOG4C_PRIORITY_INFO, ## __VA_ARGS__);fflush(stdout);
#define LOGDEBUG(lc, ...)  log4c_category_log(lc, LOG4C_PRIORITY_DEBUG, ## __VA_ARGS__);fflush(stdout);
#define LOGERROR(lc, ...)  log4c_category_log(lc, LOG4C_PRIORITY_ERROR, ## __VA_ARGS__);fflush(stdout);
#define LOGTRACE(lc, ...)  log4c_category_log(lc, LOG4C_PRIORITY_TRACE, ## __VA_ARGS__);fflush(stdout);

struct timeval tval;
char message[LOGSZ];

//#define LOGINFO(lc, ...)   if (isdaemon == true) { gettimeofday(&tval,NULL); sprintf(message, ## __VA_ARGS__ ); syslog(LOG_INFO, "[%ld.%ld] %s",tval.tv_sec, tval.tv_usec, message ); } else { log4c_category_log(lc, LOG4C_PRIORITY_INFO, ## __VA_ARGS__); fflush(stdout); }

#endif
