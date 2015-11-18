/*

  deduplication.c

  This file is part of OpenNOP-SoloWAN distribution.

  Copyright (C) 2014 Center for Open Middleware (COM) 
                     Universidad Politecnica de Madrid, SPAIN

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization 
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm. 

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad 
    Politecnica de Madrid which aims to experiment with open-source based WAN 
    optimization solutions.

  References:

    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    OpenNOP: http://www.opennop.org
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es   

  License:

    OpenNOP-SoloWAN is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP-SoloWAN is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options
#include <ctype.h>
#include <inttypes.h>
#include "deduplication.h"
#include "solowan_rolling.h"
#include "tcpoptions.h"
#include "logger.h"
#include "climanager.h"
#include "debugd.h"
#include "worker.h"

//#ifndef BASIC
//#define BASIC
//#endif

#ifndef ROLLING
#define ROLLING
#endif

#ifdef BASIC
#include "solowan_basic.h"
#endif

#ifdef ROLLING
#include "solowan_rolling.h"
#endif

int deduplication = true; // Determines if opennop should deduplicate tcp data.
int shareddict = false; // Determines dictionary mode.
int DEBUG_DEDUPLICATION = false;
int DEBUG_DEDUPLICATION1 = false;

extern uint64_t debugword;
extern TRACECOMMAND trace_commands[];

int cli_reset_stats_in_dedup(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	int si;
	for (si=0;si<get_workers();si++) resetStatistics(get_worker_compressor(si));
	sprintf(msg,"Compressor statistics reset\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg,"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	return 0;
}

int cli_reset_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	int si;
	for (si=0;si<get_workers();si++) resetStatistics(get_worker_compressor(si));
	sprintf(msg,"Compressor statistics reset\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg,"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	return 0;
}

int cli_show_stats_in_dedup(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	Statistics cs, csAggregate;
	int si;
	memset(&csAggregate,0,sizeof(csAggregate));
	for (si = 0; si < get_workers(); si++) {
		getStatistics(get_worker_compressor(si),&cs);
		csAggregate.inputBytes += cs.inputBytes;		
		csAggregate.outputBytes += cs.outputBytes;		
		csAggregate.processedPackets += cs.processedPackets;		
		csAggregate.compressedPackets += cs.compressedPackets;		
		csAggregate.numOfFPEntries += cs.numOfFPEntries;		
		csAggregate.lastPktId += cs.lastPktId;		
		csAggregate.numberOfFPHashCollisions += cs.numberOfFPHashCollisions;		
		csAggregate.numberOfFPCollisions += cs.numberOfFPCollisions;		
		csAggregate.numberOfShortPkts += cs.numberOfShortPkts;		
	}
	memset(msg, 0, MAX_BUFFER_SIZE);
	sprintf(msg,"Compressor statistics\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", csAggregate.inputBytes);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", csAggregate.outputBytes);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"processed_packets.value %" PRIu64 "\n", csAggregate.processedPackets);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"compressed_packets.value %" PRIu64 "\n", csAggregate.compressedPackets);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"FP_entries.value %" PRIu64 "\n", csAggregate.numOfFPEntries);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"last_pktId.value %" PRIu64 "\n", csAggregate.lastPktId);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"FP_hash_collisions.value %" PRIu64 "\n", csAggregate.numberOfFPHashCollisions);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"FP_collisions.value %" PRIu64 "\n", csAggregate.numberOfFPCollisions);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"short_packets.value %" PRIu64 "\n", csAggregate.numberOfShortPkts);
	cli_send_feedback(client_fd, msg);
	sprintf	(msg,"------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
/*
                        Statistics cs;
			int si;
			for (si = 0; si < get_workers(); si++) {
	                        getStatistics(get_worker_compressor(si),&cs);
	                        memset(msg, 0, MAX_BUFFER_SIZE);
	                        sprintf(msg,"Compressor statistics (thread %d)\n",si);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", cs.inputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", cs.outputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"processed_packets.value %" PRIu64 "\n", cs.processedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"compressed_packets.value %" PRIu64 "\n", cs.compressedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_entries.value %" PRIu64 "\n", cs.numOfFPEntries);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"last_pktId.value %" PRIu64 "\n", cs.lastPktId);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_hash_collisions.value %" PRIu64 "\n", cs.numberOfFPHashCollisions);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_collisions.value %" PRIu64 "\n", cs.numberOfFPCollisions);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"short_packets.value %" PRIu64 "\n", cs.numberOfShortPkts);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"------------------------------------------------------------------\n");
	                        cli_send_feedback(client_fd, msg);
			}

*/
        return 0;
}

int cli_show_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

                        Statistics cs;
			int si;
			for (si = 0; si < get_workers(); si++) {
	                        getStatistics(get_worker_compressor(si),&cs);
	                        memset(msg, 0, MAX_BUFFER_SIZE);
	                        sprintf(msg,"Compressor statistics (thread %d)\n",si);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", cs.inputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", cs.outputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"processed_packets.value %" PRIu64 "\n", cs.processedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"compressed_packets.value %" PRIu64 "\n", cs.compressedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_entries.value %" PRIu64 "\n", cs.numOfFPEntries);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"last_pktId.value %" PRIu64 "\n", cs.lastPktId);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_hash_collisions.value %" PRIu64 "\n", cs.numberOfFPHashCollisions);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_collisions.value %" PRIu64 "\n", cs.numberOfFPCollisions);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"short_packets.value %" PRIu64 "\n", cs.numberOfShortPkts);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"------------------------------------------------------------------\n");
	                        cli_send_feedback(client_fd, msg);
			}


        return 0;
}

int cli_reset_stats_out_dedup(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	int si;
	for (si=0;si<get_workers();si++) resetStatistics(get_worker_decompressor(si));
	sprintf(msg,"Decompressor statistics reset\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg,"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	return 0;
}

int cli_reset_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	int si;
	for (si=0;si<get_workers();si++) resetStatistics(get_worker_decompressor(si));
	sprintf(msg,"Decompressor statistics reset\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg,"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	return 0;
}

int cli_show_stats_out_dedup(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	Statistics ds, dsAggregate;
        int si;
        memset(&dsAggregate,0,sizeof(dsAggregate));
        for (si=0;si<get_workers(); si++) {
		getStatistics(get_worker_decompressor(si),&ds);
		dsAggregate.inputBytes += ds.inputBytes;
		dsAggregate.outputBytes += ds.outputBytes;
		dsAggregate.processedPackets += ds.processedPackets;
		dsAggregate.uncompressedPackets += ds.uncompressedPackets;
		dsAggregate.errorsMissingFP += ds.errorsMissingFP;
		dsAggregate.errorsMissingPacket += ds.errorsMissingPacket;
		dsAggregate.errorsPacketFormat += ds.errorsPacketFormat;
		dsAggregate.errorsPacketHash += ds.errorsPacketHash;
         }
	memset(msg, 0, MAX_BUFFER_SIZE);
	sprintf(msg,"Decompressor statistics\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", dsAggregate.inputBytes);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", dsAggregate.outputBytes);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"processed_packets.value %" PRIu64 "\n", dsAggregate.processedPackets);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"uncompressed_packets.value %" PRIu64 "\n",dsAggregate.uncompressedPackets);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"FP_entries_not_found.value %" PRIu64 "\n",dsAggregate.errorsMissingFP);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"packet_hashes_not_found.value %" PRIu64 "\n",dsAggregate.errorsMissingPacket);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"bad_packet_format.value %" PRIu64 "\n", dsAggregate.errorsPacketFormat);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"bad_packet_hash.value %" PRIu64 "\n", dsAggregate.errorsPacketHash);
	cli_send_feedback(client_fd, msg);
	sprintf(msg,"------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
/***
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

                        Statistics ds;
			int si;
			for (si=0;si<get_workers();si++) {
	                        getStatistics(get_worker_decompressor(si),&ds);
	                        memset(msg, 0, MAX_BUFFER_SIZE);
	                        sprintf(msg,"Decompressor statistics (thread %d)\n",si);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", ds.inputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", ds.outputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"processed_packets.value %" PRIu64 "\n", ds.processedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"uncompressed_packets.value %" PRIu64 "\n", ds.uncompressedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_entries_not_found.value %" PRIu64 "\n", ds.errorsMissingFP);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"packet_hashes_not_found.value %" PRIu64 "\n", ds.errorsMissingPacket);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"bad_packet_format.value %" PRIu64 "\n", ds.errorsPacketFormat);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"------------------------------------------------------------------\n");
	                        cli_send_feedback(client_fd, msg);
	
			}
***/
        return 0;
}

int cli_show_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

                        Statistics ds;
			int si;
			for (si=0;si<get_workers();si++) {
	                        getStatistics(get_worker_decompressor(si),&ds);
	                        memset(msg, 0, MAX_BUFFER_SIZE);
	                        sprintf(msg,"Decompressor statistics (thread %d)\n",si);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_input_bytes.value %" PRIu64 " \n", ds.inputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"total_output_bytes.value %" PRIu64 "\n", ds.outputBytes);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"processed_packets.value %" PRIu64 "\n", ds.processedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"uncompressed_packets.value %" PRIu64 "\n", ds.uncompressedPackets);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"FP_entries_not_found.value %" PRIu64 "\n", ds.errorsMissingFP);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"packet_hashes_not_found.value %" PRIu64 "\n", ds.errorsMissingPacket);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"bad_packet_format.value %" PRIu64 "\n", ds.errorsPacketFormat);
	                        cli_send_feedback(client_fd, msg);
	                        sprintf(msg,"------------------------------------------------------------------\n");
	                        cli_send_feedback(client_fd, msg);
	
			}

        return 0;
}

int cli_show_deduplication(int client_fd, char **parameters, int numparameters) {
	char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	if (deduplication == true) {
		sprintf(msg, "Deduplication enabled\n");
	} else {
		sprintf(msg, "Deduplication disabled\n");
	}
	cli_send_feedback(client_fd, msg);

        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int cli_deduplication_enable(int client_fd, char **parameters, int numparameters) {
	deduplication = true;
	char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg, "Deduplication enabled\n");
	cli_send_feedback(client_fd, msg);
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int deduplication_enable(){
	deduplication = true;
	return 0;
}

int shareddict_enable() {
	shareddict = true;
	return 0;
}

int cli_deduplication_disable(int client_fd, char **parameters, int numparameters) {
	deduplication = false;
	char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg, "Deduplication disabled\n");
	cli_send_feedback(client_fd, msg);
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int deduplication_disable(){
	deduplication = false;
	return 0;
}

int shareddict_disable(){
	shareddict = false;
	return 0;
}
/*
 * Optimize the TCP data of an SKB.
 */
unsigned int tcp_optimize(pDeduplicator pd, __u8 *ippacket, __u8 *buffered_packet) {

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u16 oldsize = 0, newsize = 0; /* Store old, and new size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */
	char message[LOGSZ];
	int compressed;

	if (DEBUG_DEDUPLICATION == true) {
		sprintf(message, "[DEDUP]: Entering into TCP OPTIMIZATION \n");
		logger(LOG_INFO, message);
	}

	// If the skb or state_compress is NULL abort compression.
	if ((ippacket != NULL) && (deduplication == true)) {
		iph = (struct iphdr *) ippacket; // Access ip header.

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort deduplication.
			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl);
			oldsize = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;
			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.

			if (oldsize > 0) { // Only compress if there is any data.

				if (DEBUG_DEDUPLICATION == true) {
					sprintf(message,
							"[DEDUP]: IP packet ID: %u\n", ntohs(iph->id));
					logger(LOG_INFO, message);
				}

				newsize = (oldsize * 2);

				if (DEBUG_DEDUPLICATION1  == true) {
					sprintf(message, "[DEDUP]: Begin deduplication.\n");
					logger(LOG_INFO, message);
				}

#ifdef BASIC
				optimize(tcpdata, oldsize, buffered_packet, &newsize);
#endif

#ifdef ROLLING
				dedup(pd, tcpdata, oldsize, buffered_packet, &newsize);
#endif
				compressed = newsize < oldsize;

				if (DEBUG_DEDUPLICATION == true) {
					sprintf(message,
							"[DEDUP]: OLD SIZE: %u \t NEW SIZE: %u\n", oldsize, newsize);
					logger(LOG_INFO, message);
				}

				if(compressed){

					if (DEBUG_DEDUPLICATION == true) {
						sprintf(message,
								"[DEDUP]: IP packet %u COMPRESSED\n", ntohs(iph->id));
						logger(LOG_INFO, message);
					}

					memmove(tcpdata, buffered_packet, newsize);// Move compressed data to packet.
					// Set the ip packet and the TCP options
					iph->tot_len = htons(ntohs(iph->tot_len) - (oldsize - newsize));// Fix packet length.
					__set_tcp_option((__u8 *) iph, 31, 3, 1); // Set compression flag.
                    /* Bellido: change from increasing seq number to changing most significant bit
					tcph->seq = htonl(ntohl(tcph->seq) + 8000); // Increase SEQ number.
                    */
					tcph->seq = htonl(ntohl(tcph->seq) ^ 1 << 31 ); // Change most significant bit
				}

				if (DEBUG_DEDUPLICATION == true) {
					sprintf(message, "[DEDUP]: Leaving TCP OPTIMIZATION \n");
					logger(LOG_INFO, message);
				}
			}
		}
	}
	// fruiz return amount of redundancy elimination
	if (compressed) return oldsize-newsize; else return 0;
}

/*
 * Deoptimize the TCP data of an SKB.
 */
int tcp_deoptimize(pDeduplicator pd, __u8 *ippacket, __u8 *regenerated_packet) {

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u16 oldsize = 0, newsize = 0; /* Store old, and new size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */
	char message[LOGSZ];
	UncompReturnStatus status;
	

	if (DEBUG_DEDUPLICATION1 == true) {
		sprintf(message, "[SDEDUP]: Entering into TCP DEOPTIMIZATION \n");
		logger(LOG_INFO, message);
	}

	if ((ippacket != NULL)) { // If the skb or state_decompress is NULL abort compression.
		iph = (struct iphdr *) ippacket; // Access ip header.

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort compression.

			if (DEBUG_DEDUPLICATION == true) {
				sprintf(message, "[SDEDUP]: IP Packet ID %u\n", ntohs(iph->id));
				logger(LOG_INFO, message);
			}

			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl); // Access tcp header.
			oldsize = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff* 4;
			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.

			if ((oldsize > 0) && (regenerated_packet != NULL)) {

#ifdef BASIC
				if(deoptimize(tcpdata, oldsize, regenerated_packet, &newsize) == 2)
					return HASH_NOT_FOUND;
#endif

#ifdef ROLLING
				uncomp(pd,regenerated_packet, &newsize, tcpdata, oldsize, &status);
				if(status.code == UNCOMP_FP_NOT_FOUND)
					return HASH_NOT_FOUND;
#endif

				memmove(tcpdata, regenerated_packet, newsize); // Move decompressed data to packet.
				iph->tot_len = htons(ntohs(iph->tot_len) + (newsize - oldsize));// Fix packet length.
				__set_tcp_option((__u8 *) iph, 31, 3, 0); // Set compression flag to 0.
                    /* Bellido: change from decreasing seq number to changing most significant bit
				tcph->seq = htonl(ntohl(tcph->seq) - 8000); // Decrease SEQ number.
                */
                tcph->seq = htonl(ntohl(tcph->seq) ^ 1 << 31 ); // Change most significant bit

				if (DEBUG_DEDUPLICATION == true) {
					sprintf( message,
							"[SDEDUP]: Decompressing [%d] size of data to [%d] \n",
							oldsize, newsize);
					logger(LOG_INFO, message);
				}
				// return OK;
				// fruiz return amount of expanded data
				if (newsize >= oldsize) return newsize-oldsize; else return ERROR;
			}
		}
	}

	if (DEBUG_DEDUPLICATION == true) {
		sprintf( message, "[SDEDUP]: Packet NULL\n");
		logger(LOG_INFO, message);
	}
	return ERROR;
}


/*
 * Cache the TCP data of an SKB.
 */
unsigned int tcp_cache_deoptim(pDeduplicator pd, __u8 *ippacket) {
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u16 datasize = 0; /* Store the size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */
	char message[LOGSZ];

	if (DEBUG_DEDUPLICATION == true) {
		sprintf(message, "[CACHE DEOPTIM]: Entering into TCP CACHING \n");
		logger(LOG_INFO, message);
	}

	if ((ippacket != NULL)) { // If the skb or state_decompress is NULL abort compression.
		iph = (struct iphdr *) ippacket; // Access ip header.

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort compression.
			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl); // Access tcp header.
			datasize = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff* 4;
			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.

			if (datasize > 0) {

				if (DEBUG_DEDUPLICATION == true) {
					sprintf(message, "[CACHE DEOPTIM]: IP Packet ID %u\n", ntohs(iph->id));
					logger(LOG_INFO, message);
				}
				// Cache the packet content
#ifdef BASIC
				cache(tcpdata, datasize);
#endif

#ifdef ROLLING
				update_caches(pd, tcpdata, datasize);
#endif


				if (DEBUG_DEDUPLICATION == true) {
					sprintf( message, "[CACHE DEOPTIM] Cached packet \n");
					logger(LOG_INFO, message);
				}
				return OK;
			}
		}
	}
	return ERROR;
}


unsigned int tcp_cache_optim(pDeduplicator pd, __u8 *ippacket) {
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u16 datasize = 0; /* Store the size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */
	char message[LOGSZ];

	if (DEBUG_DEDUPLICATION == true) {
		sprintf(message, "[CACHE OPTIM]: Entering into TCP CACHING \n");
		logger(LOG_INFO, message);
	}

	if ((ippacket != NULL)) { // If the skb or state_decompress is NULL abort compression.
		iph = (struct iphdr *) ippacket; // Access ip header.

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort compression.
			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl); // Access tcp header.
			datasize = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff* 4;
			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.

			if (datasize > 0) {

				if (DEBUG_DEDUPLICATION == true) {
					sprintf(message, "[CACHE OPTIM]: IP Packet ID %u\n", ntohs(iph->id));
					logger(LOG_INFO, message);
				}

#ifdef BASIC
				cache(tcpdata, datasize);
#endif

#ifdef ROLLING
				put_in_cache(pd, tcpdata, datasize);
#endif


				if (DEBUG_DEDUPLICATION == true) {
					sprintf( message, "[CACHE OPTIM] Cached packet \n");
					logger(LOG_INFO, message);
				}
				return OK;
			}
		}
	}
	return ERROR;
}
