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

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <syslog.h>
#include <netinet/in.h>
#include <linux/types.h>

#include "logger.h"
#include "opennopd.h"

log4c_category_t* lc_main    = NULL;
log4c_category_t* lc_config  = NULL;
log4c_category_t* lc_cli     = NULL;
log4c_category_t* lc_fetcher = NULL;
log4c_category_t* lc_worker  = NULL;
log4c_category_t* lc_worker_retx = NULL;
log4c_category_t* lc_worker_opt  = NULL;
log4c_category_t* lc_worker_cli  = NULL;
log4c_category_t* lc_worker_counters  = NULL;
log4c_category_t* lc_comp    = NULL;
log4c_category_t* lc_dedup   = NULL;
log4c_category_t* lc_tcpopts = NULL;
log4c_category_t* lc_sesman  = NULL;
log4c_category_t* lc_sesman_insert = NULL;
log4c_category_t* lc_sesman_get    = NULL;
log4c_category_t* lc_sesman_remove = NULL;
log4c_category_t* lc_sesman_update = NULL;
log4c_category_t* lc_sesman_check  = NULL;
log4c_category_t* lc_memman = NULL;
log4c_category_t* lc_counters = NULL;
log4c_category_t* lc_queman = NULL;

/*
 * Logs a message to either the screen or to syslog.
 */
void logger(int LOG_TYPE, char *message) {

    struct timeval tval;
    gettimeofday(&tval,NULL); /* get current cal time */

    if (isdaemon == true){
	    syslog(LOG_INFO, "[%ld.%ld] %s",tval.tv_sec, tval.tv_usec, message);
    } else{
	    printf("[%ld.%ld] %s",tval.tv_sec, tval.tv_usec, message);
    }	
}

