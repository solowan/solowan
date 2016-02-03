/*

  sessionmanager.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description:  
	Some modifications to handle sessions depending on IP source-destination pair.
	This is done in order to make sure that the same flows always go to the same worker.
	In this version, dictionaries are associated to workers (threads), so in order to
	make better use of deduplication, we need to allocate flows to workers without regard to load.


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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h> // for multi-threading
#include <linux/types.h>

#include <arpa/inet.h>

#include "sessionmanager.h"
#include "opennopd.h"
#include "logger.h"
#include "worker.h"
#include "session.h"
#include "clicommands.h"

struct session_head sessiontable[SESSIONBUCKETS]; // Setup the session hashtable.

int DEBUG_SESSIONMANAGER_CHECK = false;
int DEBUG_SESSIONMANAGER_UPDATE = false;

int DEBUG_SESSIONMANAGER_INSERT = false;
int DEBUG_SESSIONMANAGER_GET = false;
int DEBUG_SESSIONMANAGER_REMOVE = false;

/*
 * Calculates the hash of a session provided the IP addresses, and ports.
 */
__u16 sessionhash(__u32 largerIP, __u16 largerIPPort, __u32 smallerIP,
		__u16 smallerIPPort) {
	__u16 hash1 = 0, hash2 = 0, hash3 = 0, hash4 = 0, hash = 0;

	hash1 = (largerIP ^ smallerIP) >> 16;
	hash2 = (largerIP ^ smallerIP);
	hash3 = hash1 ^ hash2;
	hash4 = largerIPPort ^ smallerIPPort;
	hash = hash3 ^ hash4;
	return hash;
}

/* 
 * This function frees all memory dynamically allocated for the session linked list. 
 */
void freemem(struct session_head *currentlist) {
	struct session *currentsession = NULL;

	if (currentlist->next != NULL) {
		currentsession = currentlist->next;

		while (currentlist->next != NULL) {

			printf("Freeing session!\n");
			if (currentsession->prev != NULL) { // Is there a previous session.
				free(currentsession->prev); // Free the previous session.
				currentsession->prev = NULL; // Assign the previous session NULL.
			}

			if (currentsession->next != NULL) { // Check if there are more sessions.
				currentsession = currentsession->next; // Advance to the next session.
			} else { // No more sessions.
				free(currentsession); // Free the last session.
				currentsession = NULL; // Set the current session as NULL.
				currentlist->next = NULL; // Assign the list as NULL.
				currentlist->prev = NULL; // Assign the list as NULL.
			}
		}
	}
	return;
}

/* 
 * Inserts a new sessio.n into the sessions linked list.
 * Will either use an empty slot, or create a new session in the list.
 */
struct session *insertsession(__u32 largerIP, __u16 largerIPPort,
		__u32 smallerIP, __u16 smallerIPPort) {
	struct session *newsession = NULL;
	int i;
	__u16 hash = 0;
	__u8 queuenum = 0;
	char message[LOGSZ];

	hash = sessionhash(largerIP, smallerIP, largerIPPort, smallerIPPort);

	/*
	 * What queue will the packets for this session go to?
	 */

	queuenum = 0;

	for (i = 0; i < get_workers(); i++) {

		if (DEBUG_SESSIONMANAGER_INSERT == true) {
			sprintf(message, "Session Manager: Queue #%d has %d sessions.\n",
					i, get_worker_sessions(i));
			logger(LOG_INFO, message);
		}

		if (get_worker_sessions(queuenum) > get_worker_sessions(i)) {

			if (i < get_workers()) {
				queuenum = i;
			}
		}
	}

// New behaviour: a hash depending on source and destination IP addresses is computed. The allocated queue depends on this hash.
//	unsigned char hashflow;
//	hashflow = (largerIP & 0xff) ^((largerIP >> 8) & 0xff) ^ ((largerIP >> 16) & 0xff) ^((largerIP >> 24) & 0xff) ; 
//	hashflow = hashflow ^(smallerIP & 0xff) ^((smallerIP >> 8) & 0xff) ^ ((smallerIP >> 16) & 0xff) ^((smallerIP >> 24) & 0xff) ; 
//	queuenum = hashflow % get_workers();
// End new behaviour

	if (DEBUG_SESSIONMANAGER_INSERT == true) {
		sprintf(message,
				"Session Manager: Assigning session to queue #: %d!\n",
				queuenum);
		logger(LOG_INFO, message);
	}

	newsession = calloc(1, sizeof(struct session)); // Allocate a new session.

	if (newsession != NULL) { // Write data to this new session.
		newsession->head = &sessiontable[hash]; // Pointer to the head of this list.
		newsession->next = NULL;
		newsession->prev = NULL;
		newsession->client = NULL;
		newsession->server = NULL;
		newsession->queue = queuenum;
		newsession->largerIP = largerIP; // Assign values and initialize this session.
		newsession->largerIPPort = largerIPPort;
		newsession->largerIPAccelerator = 0;
		newsession->largerIPseq = 0;
		newsession->smallerIP = smallerIP;
		newsession->smallerIPPort = smallerIPPort;
		newsession->smallerIPseq = 0;
		newsession->smallerIPAccelerator = 0;
		newsession->deadcounter = 0;
		newsession->state = 0;

		/*
		 * Increase the counter for number of sessions assigned to this worker.
		 */
		increment_worker_sessions(queuenum);

		/* 
		 * Lets add the new session to the session bucket.
		 */
		pthread_mutex_lock(&sessiontable[hash].lock); // Grab lock on the session bucket.

		if (DEBUG_SESSIONMANAGER_INSERT == true) {
			sprintf(message,
					"Session Manager: Assigning session to bucket #: %u!\n",
					hash);
			logger(LOG_INFO, message);
		}

		if (sessiontable[hash].qlen == 0) { // Check if any session are in this bucket.
			sessiontable[hash].next = newsession; // Session Head next will point to the new session.
			sessiontable[hash].prev = newsession; // Session Head prev will point to the new session.
		} else {
			newsession->prev = sessiontable[hash].prev; // Session prev will point at the last packet in the session bucket.
			newsession->prev->next = newsession;
			sessiontable[hash].prev = newsession; // Make this new session the last session in the session bucket.
		}

		sessiontable[hash].qlen += 1; // Need to increase the session count in this session bucket.	

		if (DEBUG_SESSIONMANAGER_INSERT == true) {
			sprintf(
					message,
					"Session Manager: There are %u sessions in this bucket now.\n",
					sessiontable[hash].qlen);
			logger(LOG_INFO, message);
		}

		pthread_mutex_unlock(&sessiontable[hash].lock); // Lose lock on session bucket.

		return newsession;
	} else {
		return NULL; // Failed to assign memory for newsession.
	}
}

/*
 * Gets the sessionindex for the TCP session.
 * Returns NULL if hits the end of the list without a match.
 */
struct session *getsession(__u32 largerIP, __u16 largerIPPort, __u32 smallerIP,
		__u16 smallerIPPort) {
	struct session *currentsession = NULL;
	__u16 hash = 0;
	char message[LOGSZ];

	hash = sessionhash(largerIP, smallerIP, largerIPPort, smallerIPPort);

	if (DEBUG_SESSIONMANAGER_GET == true) {
		sprintf(message,
				"Session Manager: Seaching for session in bucket #: %u!\n",
				hash);
		logger(LOG_INFO, message);
	}
	if (sessiontable[hash].next != NULL) { // Testing for sessions in the list.
		currentsession = sessiontable[hash].next; // There is at least one session in the list.
	} else { // No sessions were in this list.

		if (DEBUG_SESSIONMANAGER_GET == true) {
			sprintf(message, "Session Manager: No session was found.\n");
			logger(LOG_INFO, message);
		}
		return NULL;
	}

	while (currentsession != NULL) { // Looking for session.

		if ((currentsession->largerIP == largerIP) && // Check if session matches.
				(currentsession->largerIPPort == largerIPPort)
				&& (currentsession->smallerIP == smallerIP)
				&& (currentsession->smallerIPPort == smallerIPPort)) {

			if (DEBUG_SESSIONMANAGER_GET == true) {
				sprintf(message, "Session Manager: A session was found.\n");
				logger(LOG_INFO, message);
			}
			return currentsession; // Session matched so save session.
		} else {

			if (currentsession->next != NULL) { // Not a match move to next session.
				currentsession = currentsession->next;
			} else { // No more sessions so no session exists.

				if (DEBUG_SESSIONMANAGER_GET == true) {
					sprintf(message, "Session Manager: No session was found.\n");
					logger(LOG_INFO, message);
				}
				return NULL;
			}
		}
	}

	// Something went very bad if this runs.
	if (DEBUG_SESSIONMANAGER_GET == true) {
		sprintf(message, "Session Manager: FATAL! No session was found.\n");
		logger(LOG_INFO, message);
	}
	return NULL;
}

/*
 * Resets the sessionindex, and session. 
 */
void clearsession(struct session *currentsession) {
	__u16 hash = 0;
	char message[LOGSZ];

	if (currentsession != NULL) { // Make sure session is not NULL.

		if (DEBUG_SESSIONMANAGER_REMOVE == true) {
			hash = sessionhash(currentsession->largerIP,
					currentsession->smallerIP, currentsession->largerIPPort,
					currentsession->smallerIPPort);
			sprintf(message,
					"Session Manager: Removing session from bucket #: %u!\n",
					hash);
			logger(LOG_INFO, message);
		}

		pthread_mutex_lock(&currentsession->head->lock); // Grab lock on the session bucket.

		if ((currentsession->next == NULL) && (currentsession->prev == NULL)) { // This should be the only session.
			currentsession->head->next = NULL;
			currentsession->head->prev = NULL;
		}

		if ((currentsession->next != NULL) && (currentsession->prev == NULL)) { // This is the first session.
			currentsession->next->prev = NULL; // Set the previous session as the last.
			currentsession->head->next = currentsession->next; // Update the first session in head to the next.
		}

		if ((currentsession->next == NULL) && (currentsession->prev != NULL)) { // This is the last session.
			currentsession->prev->next = NULL; // Set the previous session as the last.
			currentsession->head->prev = currentsession->prev; // Update the last session in head to the previous.
		}

		if ((currentsession->next != NULL) && (currentsession->prev != NULL)) { // This is in the middle of the list.
			currentsession->prev->next = currentsession->next; // Sets the previous session next to the next session.
			currentsession->next->prev = currentsession->prev; // Sets the next session previous to the previous session.
		}

		currentsession->head->qlen -= 1; // Need to increase the session count in this session bucket.	

		pthread_mutex_unlock(&currentsession->head->lock); // Lose lock on session bucket.

		if (DEBUG_SESSIONMANAGER_REMOVE == true) {
			sprintf(
					message,
					"Session Manager: There are %u sessions in this bucket now.\n",
					currentsession->head->qlen);
			logger(LOG_INFO, message);
		}

		/*
		 * Decrease the counter for number of sessions assigned to this worker.
		 */
		decrement_worker_sessions(currentsession->queue);
		free(currentsession);
	}
	return;
}

/*
 * Puts sockets in order.
 */
void sort_sockets(__u32 *largerIP, __u16 *largerIPPort, __u32 *smallerIP,
		__u16 *smallerIPPort, __u32 saddr, __u16 source, __u32 daddr,
		__u16 dest) {
	if (saddr > daddr) { // Using source IP address as largerIP.
		*largerIP = saddr;
		*largerIPPort = source;
		*smallerIP = daddr;
		*smallerIPPort = dest;
	} else { // Using destination IP address as largerIP.
		*largerIP = daddr;
		*largerIPPort = dest;
		*smallerIP = saddr;
		*smallerIPPort = source;
	}
}

void initialize_sessiontable() {
	int i;
	for (i = 0; i < SESSIONBUCKETS; i++) { // Initialize all the slots in the hashtable to NULL.
		sessiontable[i].next = NULL;
		sessiontable[i].prev = NULL;
	}
}

void clear_sessiontable() {
	int i;
	char message[LOGSZ];

	for (i = 0; i < SESSIONBUCKETS; i++) { // ITCP_SEQ_NUMBERSnitialize all the slots in the hashtable to NULL.
		if (sessiontable[i].next != NULL) {
			freemem(&sessiontable[i]);
			sprintf(message, "Exiting: Freeing sessiontable %d!\n", i);
			logger(LOG_INFO, message);
		}

	}
}

struct session_head *getsessionhead(int i) {
	return &sessiontable[i];
}

int cli_show_sessionss(int client_fd, char **parameters, int numparameters) {
	struct session *currentsession = NULL;
	char msg[MAX_BUFFER_SIZE] = { 0 };
	int i;
	char temp[20];
	char col1[10];
	char col2[17];
	char col3[14];
	char col4[17];
	char col5[14];
	char col6[14];
	char end[3];

	sprintf(
			msg,
			"--------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  Index  |   Client IP    | Client Port |    Server IP   | Server Port | Optimizing |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"--------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	/*
	 * Check each index of the session table for any sessions.
	 */
	for (i = 0; i < SESSIONBUCKETS; i++) {

		/*
		 * Skip any index of the sessiontable that has no sessions.
		 */
		if (sessiontable[i].next != NULL) {
			currentsession = sessiontable[i].next;

			/*
			 * Work through all sessions in that index and print them out.
			 */
			while (currentsession != NULL) {

				/*
				 * TODO:
				 * This will only show the session if we know what IPs are client & server.
				 * Its possible we wont know that if a session opening is not witnessed
				 * by OpenNOP.  OpenNOP has a "recover" mechanism that allows the session
				 * to be optimized if it detects another OpenNOP appliance.
				 * https://sourceforge.net/p/opennop/bugs/16/
				 */
				if ((currentsession->client != NULL) && (currentsession->server
						!= NULL)) {
					strcpy(msg, "");
					sprintf(col1, "|  %-7i", i);
					strcat(msg, col1);
					inet_ntop(AF_INET, currentsession->client, temp,
							INET_ADDRSTRLEN);
					sprintf(col2, "| %-15s", temp);
					strcat(msg, col2);
					sprintf(col3, "|   %-10i", ntohs(
							currentsession->largerIPPort));
					strcat(msg, col3);
					inet_ntop(AF_INET, currentsession->server, temp,
							INET_ADDRSTRLEN);
					sprintf(col4, "| %-15s", temp);
					strcat(msg, col4);
					sprintf(col5, "|   %-10i", ntohs(
							currentsession->smallerIPPort));
					strcat(msg, col5);

					if ((((currentsession->largerIPAccelerator == localID)
							|| (currentsession->smallerIPAccelerator == localID))
							&& ((currentsession->largerIPAccelerator != 0)
									&& (currentsession->smallerIPAccelerator
											!= 0))
											&& (currentsession->largerIPAccelerator
													!= currentsession->smallerIPAccelerator))) {
						sprintf(col6, "|     Yes    ");
					} else {
						sprintf(col6, "|     No     ");
					}
					strcat(msg, col6);
					sprintf(end, "|\n");
					strcat(msg, end);
					cli_send_feedback(client_fd, msg);

					currentsession = currentsession->next;
				}
			}
		}

	}

	return 0;
}

int updateseq(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph,
		struct session *thissession) {

	if ((largerIP != 0) && (iph != NULL) && (tcph != NULL) && (thissession != NULL)) {

		if (iph->saddr == largerIP) { // See what IP this is coming from.

			if (ntohl(tcph->seq) != (thissession->largerIPseq - 1)) {
				thissession->largerIPStartSEQ = ntohl(tcph->seq);
			}
		} else {

			if (ntohl(tcph->seq) != (thissession->smallerIPseq - 1)) {
				thissession->smallerIPStartSEQ = ntohl(tcph->seq);
			}
		}
		return 0; // Everything OK.
	}

	return -1; // Had a problem!
}

int sourceisclient(__u32 largerIP, struct iphdr *iph, struct session *thissession) {

	if ((largerIP != 0) && (iph != NULL) && (thissession != NULL)) {

		if (iph->saddr == largerIP) { // See what IP this is coming from.
			thissession->client = &thissession->largerIP;
			thissession->server = &thissession->smallerIP;
		} else {
			thissession->client = &thissession->smallerIP;
			thissession->server = &thissession->largerIP;
		}
		return 0;// Everything  OK.
	}
	return -1;// Had a problem.
}

int saveacceleratorid(__u32 largerIP, __u32 acceleratorID, struct iphdr *iph, struct session *thissession) {

	if ((largerIP != 0) && (iph != NULL) && (thissession != NULL)){

		if (iph->saddr == largerIP)
		{ // Set the Accelerator for this source.
			thissession->largerIPAccelerator = acceleratorID;
		}
		else
		{
			thissession->smallerIPAccelerator = acceleratorID;
		}
		return 0;// Everything  OK.
	}
	return -1;// Had a problem.
}

int updateseqnumber(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph, struct session *thissession){
	char message[LOGSZ];

	if ((largerIP != 0) && (iph != NULL) && (tcph != NULL) && (thissession != NULL)) {

		if (iph->saddr == largerIP) { // See what IP this is coming from.

			if (DEBUG_SESSIONMANAGER_UPDATE == true) {
				sprintf(message, "[SESSION MANAGER] Update LargerIpSeq %u\n", ntohl(tcph->seq));
				logger(LOG_INFO, message);
			}
			thissession->largerIPseq = ntohl(tcph->seq);
			return 0;
		} else {

			if (DEBUG_SESSIONMANAGER_UPDATE == true) {
				sprintf(message, "[SESSION MANAGER] Update SmallerIPseq %u\n", ntohl(tcph->seq));
				logger(LOG_INFO, message);
			}
			thissession->smallerIPseq = ntohl(tcph->seq);
			return 0;
		}
	}

	if (DEBUG_SESSIONMANAGER_UPDATE == true) {
		sprintf(message, "[SESSION MANAGER] ERROR updating seq number!!!\n");
		logger(LOG_INFO, message);
	}
	return -1;
}

int checkseqnumber(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph, struct session *thissession){
	char message[LOGSZ];

	if ((largerIP != 0) && (iph != NULL) && (tcph != NULL) && (thissession != NULL)) {

		if (iph->saddr == largerIP) { // See what IP this is coming from.
//			if (((ntohl(tcph->seq) - thissession->largerIPseq) % TCP_SEQ_NUMBERS) < HALF_TCP_SEQ_NUMBER) {
			/*ToDo Change this condition: it will not work if the sequence
			 * number restarts from	the beginning inside the same connection*/
			if(ntohl(tcph->seq) < thissession->largerIPseq){
				if (DEBUG_SESSIONMANAGER_CHECK == true) {
					sprintf(message, "[SESSION MANAGER] Out of order - LargerIPseq: Rcv %u Stored %u\n", ntohl(tcph->seq), thissession->largerIPseq);
					logger(LOG_INFO, message);
				}
				return 0;
			}
			return 1;
		} else {
//			if (((ntohl(tcph->seq) - thissession->smallerIPseq) % TCP_SEQ_NUMBERS) < HALF_TCP_SEQ_NUMBER ) {
			if(ntohl(tcph->seq) < thissession->smallerIPseq ){
				if (DEBUG_SESSIONMANAGER_CHECK == true) {
					sprintf(message, "[SESSION MANAGER] SmallerIPseq: Received Seq %u Stored Seq%u\n", ntohl(tcph->seq), thissession->smallerIPseq);
					logger(LOG_INFO, message);
				}
				return 0;
			}
			return 1;
		}
	}
	if (DEBUG_SESSIONMANAGER_CHECK == true) {
		sprintf(message, "[SESSION MANAGER] ERROR!!!\n");
		logger(LOG_INFO, message);
	}
	return 0;
}
