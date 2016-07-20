/*

  queuemanager.c

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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h> // for multi-threading
#include <stdint.h> // Sharwan Joram:  uint32_t etc./ are defined in this
//#include <libnetfilter_queue/libnetfilter_queue.h> // for access to Netfilter Queue //Not used Justin Yaple: 3-28-2013
#include "queuemanager.h"
#include "packet.h"
#include "worker.h"
#include "logger.h"


int queue_packet(struct packet_head *queue, struct packet *thispacket) {
	/* Lets add the  packet to a queue. */

	if (thispacket != NULL) {
		pthread_mutex_lock(&queue->lock); // Grab lock on queue.

		if (queue->qlen == 0) { // Check if any packets are in the queue.
			queue->next = thispacket; // Queue next will point to the new packet.
			queue->prev = thispacket; // Queue prev will point to the new packet.
		} else {
			thispacket->prev = queue->prev; // Packet prev will point at the last packet in the queue.
			thispacket->prev->next = thispacket;
			queue->prev = thispacket; // Make this new packet the last packet in the queue.
		}

		queue->qlen += 1; // Need to increase the packet count in this queue.
		pthread_cond_signal(&queue->signal);
		pthread_mutex_unlock(&queue->lock); // Lose lock on queue.
		return 0;
	}
	return -1; // error packet was null
}

/*
 * Gets the next packet from a queue.
 * This can sleep if signal parameter is true = 1 not false = 0.
 */
struct packet *dequeue_packet(struct packet_head *queue, int signal) {
	struct packet *thispacket = NULL;

	/* Lets get the next packet from the queue. */
	pthread_mutex_lock(&queue->lock); // Grab lock on the queue.

	if ((queue->qlen == 0) && (signal == true)) { // If there is no work wait for some.
		pthread_cond_wait(&queue->signal, &queue->lock);
	}

	LOGDEBUG(lc_queman, "Queue Manager: Queue has %d packets!", queue->qlen);

	if (queue->next != NULL) { // Make sure there is work.

		thispacket = queue->next; // Get the next packet in the queue.
		queue->next = thispacket->next; // Move the next packet forward in the queue.
		queue->qlen -= 1; // Need to decrease the packet count on this queue.
		thispacket->next = NULL;
		thispacket->prev = NULL;
	} else {

		LOGDEBUG(lc_queman, "Queue Manager: Fatal - Queue missing packet!");
	}

	pthread_mutex_unlock(&queue->lock); // Lose lock on the queue.

	return thispacket;
}

/*
 * This function moves all packet buffers from one queue to another.
 * Returns how many were moved.
 */
u_int32_t move_queued_packets(struct packet_head *fromqueue,
		struct packet_head *toqueue) {
	struct packet *start; // Points to the first packet of the list.
	struct packet *end; // Points to the last packet of the list.
	u_int32_t qlen; // How many buffers are being moved.

	/*
	 * Get the first and last buffers in the source queue
	 * and remove all the packet buffers from the source queue.
	 */
	pthread_mutex_lock(&fromqueue->lock);
	start = fromqueue->next;
	end = fromqueue->prev;
	qlen = fromqueue->qlen;
	fromqueue->next = NULL;
	fromqueue->prev = NULL;
	fromqueue->qlen = 0;
	pthread_mutex_unlock(&fromqueue->lock);

	/*
	 * Add those buffers to the destination queue.
	 */
	pthread_mutex_lock(&toqueue->lock);
	if (toqueue->next == NULL) {
		toqueue->next = start;
		toqueue->prev = end;
		toqueue->qlen = qlen;
	} else {
		start->prev = toqueue->prev;
		toqueue->prev->next = start;
		toqueue->prev = end;
		toqueue->qlen += qlen;
	}
	pthread_mutex_unlock(&toqueue->lock);

	return qlen;
}
