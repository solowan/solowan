/*

  memorymanager.c

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
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h> // for multi-threading
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <linux/types.h>

#include "memorymanager.h"
#include "opennopd.h"
#include "logger.h"

u_int32_t allocatedpacketbuffers;
struct packet_head freepacketbuffers;
pthread_cond_t mysignal; // Condition signal used to wake-up thread.
pthread_mutex_t mylock; // Lock for the memorymanager.

int initialfreepacketbuffers = 1000;
int minfreepacketbuffers = 500;
int packetbufferstoallocate = 100;

void *memorymanager_function(void *dummyPtr) {
	struct packet_head packetbufferstaging;
	u_int32_t newpacketbuffers;

	LOGDEBUG(lc_memman, "Starting memory manager thread");

	/*
	 * Initialize the memory manager lock and signal.
	 */
	pthread_cond_init(&mysignal, NULL);
	pthread_mutex_init(&mylock, NULL);
	pthread_mutex_lock(&mylock);
	allocatedpacketbuffers = 0;
	pthread_mutex_unlock(&mylock);

	/*
	 * Initialize the free packet buffer pool lock and signal.
	 */
	pthread_cond_init(&freepacketbuffers.signal, NULL);
        pthread_mutex_init(&freepacketbuffers.lock, NULL);
	pthread_mutex_lock(&freepacketbuffers.lock);
	freepacketbuffers.qlen = 0;
	pthread_mutex_unlock(&freepacketbuffers.lock);

	/*
	 * Initialize the staging packet buffer queue lock and signal.
	 */
	pthread_cond_init(&packetbufferstaging.signal, NULL);
	pthread_mutex_init(&packetbufferstaging.lock, NULL);
	pthread_mutex_lock(&packetbufferstaging.lock);
	packetbufferstaging.qlen = 0;
	pthread_mutex_unlock(&packetbufferstaging.lock);

	/*
	 * I need to initialize some packet buffers here.
	 * and move them to the freepacketbuffers pool.
	 */
	allocatefreepacketbuffers(&packetbufferstaging, initialfreepacketbuffers);
	pthread_mutex_lock(&mylock);
	allocatedpacketbuffers += move_queued_packets(&packetbufferstaging,
			&freepacketbuffers);
	pthread_mutex_unlock(&mylock);

	while (servicestate >= STOPPING) {

		/*
		 * Check if there are enough buffers.  If so then sleep.
		 */
		pthread_mutex_lock(&freepacketbuffers.lock); // Grab the free packet buffer pool lock.

		if (freepacketbuffers.qlen >= minfreepacketbuffers) {
			pthread_mutex_unlock(&freepacketbuffers.lock); // Lose the free packet buffer pool lock.
			pthread_mutex_lock(&mylock); // Grab lock.
			pthread_cond_wait(&mysignal, &mylock); // If we have enough free buffers then wait.
		} else {
			pthread_mutex_unlock(&freepacketbuffers.lock); // Lose the free packet buffer pool lock.
		}

		/*
		 * Something woke me up.  We allocate packet buffers now!
		 * Then move them to the freepacketbuffers pool.
		 */
		pthread_mutex_unlock(&mylock); // Lose lock while staging new buffers.
		allocatefreepacketbuffers(&packetbufferstaging, packetbufferstoallocate);

		pthread_mutex_lock(&mylock); // Grab lock again before modifying free packet buffer pool.
		newpacketbuffers = move_queued_packets(&packetbufferstaging,
				&freepacketbuffers);
		allocatedpacketbuffers += newpacketbuffers;

		LOGDEBUG(lc_memman, "Allocating %u new packet buffers", newpacketbuffers);

		/*
		 * Ok finished allocating more packet buffers.  Lets do it again.
		 */
		pthread_mutex_unlock(&mylock); // Lose lock.

	}

	LOGDEBUG(lc_memman, "Stopping memory manager thread");
	/*
	 * We need to do memory cleanup here.
	 */

	/* Thread ending */
	return NULL;
}

/*
 * This function allocates a number of free packets
 * and stores them in the specified queue.
 */
int allocatefreepacketbuffers(struct packet_head *queue, int bufferstoallocate) {
	int i;

	for (i = 0; i < bufferstoallocate; i++) {
		queue_packet(queue, newpacket());
	}

	return 0;
}

struct packet *get_freepacket_buffer(void) {
	struct packet *thispacket = NULL;

	LOGDEBUG(lc_memman, "Requesting a packet buffer from pool");
	/*
	 * Check if any packet buffers are in the pool
	 * get one if there are or allocate a new buffer if not.
	 */
	pthread_mutex_lock(&freepacketbuffers.lock); // Grab packet buffer pool lock.

	if (freepacketbuffers.qlen > 0) {

		LOGDEBUG(lc_memman, "There are free packet buffers in the pool");

		if (freepacketbuffers.qlen < minfreepacketbuffers) {

			LOGDEBUG(lc_memman, "Packet buffer pool is low");
			pthread_cond_signal(&mysignal); // Free packet buffers are low!
		}
		pthread_mutex_unlock(&freepacketbuffers.lock); // Lose packet buffer pool lock.
		thispacket = dequeue_packet(&freepacketbuffers, false); // This uses its own lock.

		LOGDEBUG(lc_memman, "Allocated packet from packet buffer pool");

	} else {

			LOGDEBUG(lc_memman, "Packet buffer pool is empty!");
		pthread_mutex_unlock(&freepacketbuffers.lock); // Lose packet buffer pool lock.
		pthread_cond_signal(&mysignal); // Free packet buffers are low!
		thispacket = newpacket(); // Try to allocate a packet for the requester.
		pthread_mutex_lock(&mylock); // Grab lock.
		allocatedpacketbuffers++;
		pthread_mutex_unlock(&mylock); // Lose lock.
	}

	if (thispacket != NULL) {
		memset(thispacket, 0, sizeof(struct packet));
	} else {
		LOGERROR(lc_memman, "Failed to allocate packet! ");
	}

	LOGDEBUG(lc_memman, "Return packet to requester");

	return thispacket;
}

int put_freepacket_buffer(struct packet *thispacket) {
	int result;

	LOGDEBUG(lc_memman, "Returning a packet buffer to the pool");
	result = queue_packet(&freepacketbuffers, thispacket);

	if (result < 0) {
		LOGDEBUG(lc_memman, "Return packet buffer to the pool failed! ");
	} else {
		LOGDEBUG(lc_memman, "Returned packet buffer to the pool");
	}
	return result;
}

