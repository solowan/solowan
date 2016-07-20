/*

  help.c

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

#include "help.h"
void PrintUsage(int argc, char * argv[]) {
	if (argc >=1) {
		printf("Usage: %s -h -n\n", argv[0]);
		printf("  Options:\n");
		printf("      -n Don't fork off as a daemon.\n");
		printf("      -d run as daemon (default).\n");
		printf("      -c <config_file>, load the configuration file specified (defaults to /etc/opennop/opennop.conf).\n");
		printf("      -p <pid_file>, save process id to the file specified (defaults to /var/run/solowan.pid).\n");
		printf("      -t Show this help screen.\n");
		printf("\n");
	}
}
