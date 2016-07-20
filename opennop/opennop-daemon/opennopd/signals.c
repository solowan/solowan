/*

  signals.c

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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>

#include "signals.h"
#include "opennopd.h"
#include "logger.h"
#include "fetcher.h"
#include "worker.h"

void signal_handler(int sig) 
{

	switch(sig){
		case SIGHUP:
			LOGINFO(lc_main, "Received SIGHUP signal.");
			break;
		case SIGTERM:
			LOGINFO(lc_main, "Received SIGTERM signal.");
			
			switch(servicestate){
				case RUNNING:
					servicestate = STOPPING;
					fetcher_graceful_exit();
					shutdown_workers();
					exit(0);
					break;
				case STOPPING:
					servicestate = STOPPED;
					exit(0);
					break;
				default:
					servicestate = STOPPED;
					exit(0);
					break;
			}
			
			break;
		case SIGQUIT:
			LOGINFO(lc_main, "Received SIGQUIT signal.");
			break;
                case SIGINT:
                        LOGINFO(lc_main, "Received SIGINT signal.");
                        exit(0);
                        break;
                case SIGPIPE:
                        LOGINFO(lc_main, "Received SIGPIPE signal.");
                        exit(0);
                        break;
		default:
			LOGINFO(lc_main, "Unhandled signal (%s)", strsignal(sig));
			break;
	}
}

