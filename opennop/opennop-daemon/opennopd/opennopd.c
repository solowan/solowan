/*

  opennopd.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: <mod_description>

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm.

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad
    Politecnica de Madrid which aims to experiment with open-source based WAN
    optimization solutions.

  References:

    OpenNOP: http://www.opennop.org
    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es

  License:

    OpenNOP and OpenNOP-SoloWAN are free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP and OpenNOP-SoloWAN are distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <pthread.h> // for multi-threading
#include <unistd.h> // for sleep function
#include <ifaddrs.h> // for getting ip addresses
#include <netdb.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h> // for getting local ip address
#include <linux/types.h>
#include <assert.h>

#include "opennopd.h"
#include "fetcher.h"
#include "logger.h"
#include "sessioncleanup.h"
#include "sessionmanager.h"
#include "help.h"
#include "signals.h"
#include "worker.h"
#include "healthagent.h"
#include "counters.h"
#include "memorymanager.h"
#include "climanager.h"
#include "compression.h"
#include "version.h"

#include "deduplication.h"
#include "configure.h"
#include "01dedup.h"
#include "solowan_rolling.h"
#include "debugd.h"

#define DEBUG 1
#define DAEMON_NAME "opennopd"
#define PID_FILE "/var/run/opennopd.pid"
#define LOOPBACKIP 16777343UL // Loopback IP address 127.0.0.1.
#define PACKET_SIZE 1500
#define PACKET_NUMBER 131072
#define DEF_THR_NUM 1
#define DEF_FP_PER_PKT 32
#define DEF_FPS_FACTOR 2

//#ifndef BASIC
//#define BASIC
//#endif

#ifndef ROLLING
#define ROLLING
#endif

/* Global Variables. */
int servicestate = RUNNING; // Current state of the service.
__u32 localID = 0; // Variable to store eth0 IP address used as the device ID.
int isdaemon = true; // Determines how to log the messages and errors.
hashtable ht;

int main(int argc, char *argv[]) {
	pthread_t t_cleanup; // thread for cleaning up dead sessions.
	pthread_t t_healthagent; // thread for health agent.
	pthread_t t_cli; // thread for cli.
	pthread_t t_counters; // thread for performance counters.
	pthread_t t_memorymanager; // thread for the memory manager.
	struct ifaddrs *ifaddr;//, *ifa;
	__u32 tempIP;
//	int s;
	int i;
	char message[LOGSZ];
	char strIP[20];
//	char host[NI_MAXHOST];
	char path[100] = "/etc/opennop/opennop.conf";
	int tmp;
	__u32 packet_size = PACKET_SIZE, packet_number = PACKET_NUMBER, thr_num = DEF_THR_NUM;
        __u32 fpPerPkt = DEF_FP_PER_PKT, fpsFactor = DEF_FPS_FACTOR;

#if defined(DEBUG)

	int daemonize = false;
#else

	int daemonize = true;
#endif

	/* Setup signal handling */
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGPIPE,SIG_IGN);

	int c;
	while ((c = getopt(argc, argv, "nh|help")) != -1) {
		switch (c) {
		case 'h':
			PrintUsage(argc, argv);
			exit(0);
			break;
		case 'n':
			daemonize = 0;
			isdaemon = false;
			break;
		default:
			PrintUsage(argc, argv);
			break;
		}
	}


	sprintf(message, "Initialization: %s daemon starting up.\n", DAEMON_NAME);
	logger(LOG_INFO, message);

	/*
	 * Configuration: read the configuration file
	 */
	sprintf(message, "Configuring: reading file %s.\n", path);
	logger(LOG_INFO, message);

	tmp = configure(path, &localID, &packet_number, &packet_size, &thr_num, &fpPerPkt, &fpsFactor);

	if(tmp == 1){
		sprintf(message, "Configuring error. EXIT\n");
		logger(LOG_INFO, message);
		exit(EXIT_FAILURE);
	}

	sprintf(message, "Initialization: Version %s.\n", VERSION);
	logger(LOG_INFO, message);

	/*
	 * Get the numerically highest local IP address.
	 * This will be used as the acceleratorID.
	 */
	if (getifaddrs(&ifaddr) == -1) {
		sprintf(message, "Initialization: Error opening interfaces.\n");
		logger(LOG_INFO, message);
		exit(EXIT_FAILURE);
	}

//	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) { // loop through all interfaces.
//
//		if (ifa->ifa_addr != NULL) {
//
//			if (ifa->ifa_addr->sa_family == AF_INET) { // get all IPv4 addresses.
//				s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
//						host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
//
//				if (s != 0) {
//					exit(EXIT_FAILURE);
//				}
//
//				inet_pton(AF_INET, (char *) &host, &tempIP); // convert string to decimal.
//
//				/*
//				 * Lets fine the largest local IP, and use that as accelleratorID
//				 * Lets also exclude 127.0.0.1 as a valid ID.
//				 */
//				if ((tempIP > localID) && (tempIP != LOOPBACKIP)) {
//					localID = tempIP;
//				}
//			} // end get all IPv4 addresses.
//		} // end ifa->ifa_addr NULL test.
//	} // end loop through all interfaces.

	if (localID == 0) { // fail if no usable IP found.
		inet_ntop(AF_INET, &tempIP, strIP, INET_ADDRSTRLEN);
		sprintf(message, "Initialization: No usable IP Address. %s\n", strIP);
		logger(LOG_INFO, message);
		exit(EXIT_FAILURE);
	}

#if defined(DEBUG)
	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
#else

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog(DAEMON_NAME, LOG_CONS, LOG_USER);
#endif

	/* Our process ID and Session ID */
	pid_t pid, sid;
	if (daemonize) {
		sprintf(message, "Initialization: Daemonizing the %s process.\n",
				DAEMON_NAME);
		logger(LOG_INFO, message);

		/* Fork off the parent process */
		pid = fork();
		if (pid < 0) {
			exit(EXIT_FAILURE);
		}

		/* If we got a good PID, then
		 we can exit the parent process. */
		if (pid > 0) {
			exit(EXIT_SUCCESS);
		}

		/* Change the file mode mask */
		umask(0);

		/* Create a new SID for the child process */
		sid = setsid();
		if (sid < 0) {
			/* Log the failure */
			exit(EXIT_FAILURE);
		}

		/* Change the current working directory */
		if ((chdir("/")) < 0) {
			/* Log the failure */
			exit(EXIT_FAILURE);
		}

		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/*
	 * Starting up the daemon.
	 */

	initialize_sessiontable();

	if (get_workers() == 0) {
		set_workers(thr_num);
		//set_workers(sysconf(_SC_NPROCESSORS_ONLN) * 2);
	}

#ifdef ROLLING
	init_common(packet_number,packet_size, fpPerPkt, fpsFactor, shareddict);
	init_debugd() ;
#endif

 	for (i = 0; i < get_workers(); i++) {
		create_worker(i);
	}

#ifdef BASIC
	create_hashmap(&ht); // Create hash table
#endif

	// Only one type of optimization can be active
//	assert(deduplication != compression);

	/*
	 * Create the fetcher thread that retrieves
	 * IP packets from the Netfilter Queue.
	 */
	create_fetcher();
	pthread_create(&t_cleanup, NULL, cleanup_function, (void *) NULL);
	pthread_create(&t_healthagent, NULL, healthagent_function, (void *) NULL);
	pthread_create(&t_cli, NULL, cli_manager_init, (void *) NULL);
	pthread_create(&t_counters, NULL, counters_function, (void *) NULL);
	pthread_create(&t_memorymanager, NULL, memorymanager_function, (void *) NULL);

	sprintf(message, "[OpenNOP]: Started all threads.\n");
	logger(LOG_INFO, message);

	/*
	 * All the threads have been created now commands should be registered.
	 */
	register_command("show traces mask", cli_show_traces_mask, false, false);
	register_command("traces mask orr", cli_traces_mask_orr, true, false);
	register_command("traces mask and", cli_traces_mask_and, true, false);
	register_command("traces mask nand", cli_traces_mask_nand, true, false);
	register_command("reset stats in_dedup", cli_reset_stats_in_dedup, false, false);
	register_command("reset stats in_dedup_thread", cli_reset_stats_in_dedup, false, false);
	register_command("show stats in_dedup", cli_show_stats_in_dedup, false, false);
	register_command("show stats in_dedup_thread", cli_show_stats_in_dedup_thread, false, false);
	register_command("reset stats out_dedup", cli_reset_stats_out_dedup, false, false);
	register_command("reset stats out_dedup_thread", cli_reset_stats_out_dedup, false, false);
	register_command("show stats out_dedup", cli_show_stats_out_dedup, false, false);
	register_command("show stats out_dedup_thread", cli_show_stats_out_dedup_thread, false, false);

	register_command("traces enable", cli_traces_enable, true, false);

	register_command("traces disable", cli_traces_disable, true, false);

	register_command("show version", cli_show_version, false, false);
	register_command("show compression", cli_show_compression, false, false);
	register_command("show workers", cli_show_workers, false, false);
	register_command("show fetcher", cli_show_fetcher, false, false);
	register_command("show sessions", cli_show_sessionss, false, false);
	register_command("show deduplication", cli_show_deduplication, false, false);
	register_command("compression enable", cli_compression_enable, false, false);
	register_command("compression disable", cli_compression_disable, false, false);
	register_command("deduplication enable", cli_deduplication_enable, false, false);
	register_command("deduplication disable", cli_deduplication_disable, false, false);

	/*
	 * Rejoin all threads before we exit!
	 */
	rejoin_fetcher();
	sprintf(message, "[OpenNOP] Fetcher joined\n");
	logger(LOG_INFO, message);
	pthread_join(t_cleanup, NULL);
	sprintf(message, "joined cleanup\n");
	logger(LOG_INFO, message);
	pthread_join(t_healthagent, NULL);
	sprintf(message, "joined health\n");
	logger(LOG_INFO, message);
	pthread_join(t_cli, NULL);
	sprintf(message, "joined cli\n");
	logger(LOG_INFO, message);
	pthread_join(t_counters, NULL);
	sprintf(message, "joined counters\n");
	logger(LOG_INFO, message);
	pthread_join(t_memorymanager, NULL);

	for (i = 0; i < get_workers(); i++) {
		rejoin_worker(i);
	}
#ifdef BASIC
	remove_hashmap(ht);
#endif
	clear_sessiontable();

	sprintf(message, "Exiting: %s daemon exiting", DAEMON_NAME);
	logger(LOG_INFO, message);

	exit(EXIT_SUCCESS);
}
