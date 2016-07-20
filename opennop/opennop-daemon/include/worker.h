/*

  worker.h

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: Some modifications done to include per worker dictionaries

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


#ifndef WORKER_H_
#define WORKER_H_
#define _GNU_SOURCE

#include <stdint.h>
#include <pthread.h>

#include <sys/types.h>

#include <linux/types.h>

#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options

#include "packet.h"
#include "lib/solowan_rolling.h"
#include "counters.h"

#define MAXWORKERS 255 // Maximum number of workers to process packets.
struct workercounters {
	// fruiz changed counters to __u64, cannot roll
	/*
	 * number of packets processed.
	 * used for pps calculation. can roll.
	 * should increment at end of main loop after each packet is finished processing.
	 */
	__u64 packets;
	__u64 packetsprevious;
	__u64 pps; // Where the calculated pps are stored.

	/*
	 * number of bytes entering process.
	 * used for bps calculation. can roll.
	 * should increment as beginning of main loop after packet is received from queue.
	 */
	__u64 bytesin;
	__u64 bytesinprevious;
	__u64 bpsin; // Where the calculated bps are stored.
	__u64 bytesout;
	__u64 bytesoutprevious;
	__u64 bpsout; // Where the calculated bps are stored.

	// fruiz new counters for storing information on different methods of redundancy elimination, and a count of sequence number gaps
	__u64 diffBytesCompression;
	__u64 diffBytesDeduplication;
	__u64 diffBytesIpTcpHeader;
	__u64 packetsWithOnlyCompression;
	__u64 packetsWithOnlyDeduplication;
	__u64 packetsWithBothCompressionAndDeduplication;

	__u64 sequenceGaps;

	/*
	 * Stores when the counters were last updated.
	 */
	struct timeval updated;

	/*
	 * When something reads/writes to this counter it should use the lock.
	 */
	pthread_mutex_t lock;
};

/*
 * This structure is a member of the worker structure.
 * It contains the thread for optimization or de-optimization of packets,
 * the counters for this thread, the threads packet queue
 * and the buffer used for QuickLZ.
 */
struct processor {
	pthread_t t_processor;
	struct workercounters metrics;
	struct packet_head queue;
	pDeduplicator dedupProcessor; // Pointer to dictionary processor
	__u8 *lzbuffer; // Buffer used for QuickLZ.
	__u8 *dedup_buffer; // Buffer used for deduplication
};

/* Structure contains the worker threads, queue, and status. */
struct worker {
	int workernum;
	struct processor optimization; //Thread that will do all optimizations(input).  Coming from LAN.
	struct processor deoptimization; //Thread that will undo optimizations(output).  Coming from WAN.
	u_int32_t sessions; // Number of sessions assigned to the worker.
	int state; // Marks this thread as active. 1=running, 0=stopping, -1=stopped.
	pthread_mutex_t lock; // Lock for this worker when adding sessions.
};

void *optimization_thread(void *dummyPtr);
void *deoptimization_thread(void *dummyPtr);
unsigned char get_workers(void);
void set_workers(unsigned char desirednumworkers);
u_int32_t get_worker_sessions(int i);
void create_worker(int i);
void rejoin_worker(int i);
void initialize_worker_processor(struct processor *thisprocessor);
void joining_worker_processor(struct processor *thisprocessor);
void set_worker_state_running(struct worker *thisworker);
void set_worker_state_stopped(struct worker *thisworker);
void increment_worker_sessions(int i);
void decrement_worker_sessions(int i);
int optimize_packet(__u8 queue, struct packet *thispacket);
int deoptimize_packet(__u8 queue, struct packet *thispacket);
void shutdown_workers();
int cli_show_workers(int client_fd, char **parameters, int numparameters);
void counter_updateworkermetrics(t_counterdata metric);
struct session *closingsession(struct iphdr *iph, struct tcphdr *tcph, struct session *thissession);

pDeduplicator get_worker_compressor(int i);
pDeduplicator get_worker_decompressor(int i);

#endif /*WORKER_H_*/
