/*

  worker.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: Some modifications done to include and handle per worker dictionaries

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
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h> // for multi-threading
#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options
#include <linux/types.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h> // for access to Netfilter Queue
#include "queuemanager.h"
#include "worker.h"
#include "opennopd.h"
#include "packet.h"
#include "compression.h"
#include "csum.h"
#include "sessionmanager.h"
#include "tcpoptions.h"
#include "logger.h"
#include "quicklz.h"
#include "memorymanager.h"
#include "counters.h"
#include "climanager.h"

#include "deduplication.h"

struct worker workers[MAXWORKERS]; // setup slots for the max number of workers.
unsigned char numworkers = 0; // sets number of worker threads. 0 = auto detect.

void *optimization_thread(void *dummyPtr) {


	struct worker *me = NULL;
	struct packet *thispacket = NULL;
	struct session *thissession = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u32 largerIP, smallerIP, remoteID;
	__u16 largerIPPort, smallerIPPort;
	__u32 seqNo = 0; 
	qlz_state_compress *state_compress = (qlz_state_compress *) malloc(sizeof(qlz_state_compress));
	unsigned int redEl, redElComp, redElDedup;
	me = dummyPtr;

	me->optimization.lzbuffer = calloc(1, BUFSIZE + 400);
	/* Sharwan J: QuickLZ buffer needs (original data size + 400 bytes) buffer */
	if (me->optimization.lzbuffer == NULL) {
		LOGERROR(lc_worker, "Worker optimization: Couldn't allocate buffer lzbuffer");
		exit(1);
	}

	me->optimization.dedup_buffer = calloc(1, 2*BUFSIZE + 400);
	/* Solowan deduplication needs (original size + 400) buffer */
	if (me->optimization.dedup_buffer == NULL) {
		LOGERROR(lc_worker, "Worker optimization: Couldn't allocate buffer dedup");
		exit(1);
	}

	/*
	 * Register the worker threads metrics so they get updated.
	 */
	register_counter(counter_updateworkermetrics, (t_counterdata) & me->optimization.metrics);

	if (me->optimization.dedup_buffer != NULL) {

		while (me->state >= STOPPING) {

			thispacket = dequeue_packet(&me->optimization.queue, true);

			if(compression || deduplication || packetPipeline){

				if (thispacket != NULL) { // If a packet was taken from the queue.
					iph = (struct iphdr *) thispacket->data;
					tcph = (struct tcphdr *) (((u_int32_t *) iph) + iph->ihl);
					unsigned int headersBefore = getIPPlusTCPHeaderLength((__u8 *) iph);

					LOGTRACE(lc_worker, "Worker: IP Packet length is: %u", ntohs(iph->tot_len));
					me->optimization.metrics.bytesin += ntohs(iph->tot_len);
					
					if (__get_tcp_option((__u8 *)iph,32))  {/* Check what IP address is larger. */
						// Can this really happen???? According to fetcher code, it should not. Trace.
                        LOGERROR(lc_worker, "Worker: option 32 found in optimizer!!!");
                        unsigned char *tcpdata =  (unsigned char *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
                        pOpennopHeader oh = (pOpennopHeader) tcpdata;
                        remoteID = oh->opennopID;
						put_freepacket_buffer(thispacket);
						thispacket = NULL;
                        nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
						LOGERROR(lc_worker, "Worker: received packet with unexpected option 32, remote ID %x", remoteID);
						return NULL;
/*
						LOGDEBUG(lc_worker, "Worker: received packet with option 32, remote ID %x", remoteID);
   						unsigned int incLen   = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;
                                		if (incLen < sizeof(OpennopHeader)) {
                                        		sprintf(message, "Worker: detected opennop option but incoming TCP data length less than opennop header length!!!!\n");
                                        		logger(LOG_INFO, message);
							put_freepacket_buffer(thispacket);
							thispacket = NULL;
                                        		nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
							return NULL;
                                		}

                                		if (oh->pattern != OPENNOP_PATTERN) {
                                        		sprintf(message, "Worker: option 32 found but bad pattern!!!\n");
                                        		logger(LOG_INFO, message);
							put_freepacket_buffer(thispacket);
							thispacket = NULL;
                                        		nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
							return NULL;
                                		}
*/
					} else { 
						remoteID = 0; 
						LOGTRACE(lc_worker, "Worker: received packet without option 32, remote ID %x", remoteID);
					}

					sort_sockets(&largerIP, &largerIPPort, &smallerIP, &smallerIPPort, iph->saddr,tcph->source,iph->daddr,tcph->dest);

					//LOGDEBUG(lc_worker, "Worker: Searching for session.");

					thissession = getsession(largerIP, largerIPPort, smallerIP,smallerIPPort);

					if (thissession != NULL) {

						LOGTRACE(lc_worker, "Worker: Found a session.");

						unsigned int addedOpennopHeader = false;
						if ((tcph->syn == 0) && (tcph->ack == 1) && (tcph->fin == 0)) {

							if (remoteID == 0) { // Accelerator ID was not found.

								saveacceleratorid(largerIP, localID, iph, thissession);

								if (__set_tcp_option((__u8 *)iph,32,3,1) == -1) { // Add the opennop id to this packet
									LOGDEBUG(lc_worker, "Cannot add opennop option, worker.c, src addr %x dst addr %x src port %d dst port %d IP datagram ID %x, current value of TCP doff %d",ntohl(iph->saddr), ntohl(iph->daddr),ntohs(tcph->source), ntohs(tcph->dest), ntohs(iph->id), tcph->doff);
								} else {

									unsigned int cause = NOT_RELEVANT;
									if ((((iph->saddr == largerIP) &&
										(thissession->largerIPAccelerator == localID) &&
										(thissession->smallerIPAccelerator != 0) &&
										(thissession->smallerIPAccelerator != localID)) ||

										((iph->saddr == smallerIP) &&
										(thissession->smallerIPAccelerator == localID) &&
										(thissession->largerIPAccelerator != 0) &&
										(thissession->largerIPAccelerator != localID))) &&
										(thissession->state == TCP_ESTABLISHED))
									{
										redEl = redElComp = redElDedup = 0;


										/*
										 * Do some acceleration!
										 */
	
										LOGTRACE(lc_worker, "Worker: Processing packet...");
	
										if((compression == true) && (deduplication == false)){
											redEl = tcp_compress((__u8 *)iph, me->optimization.lzbuffer,state_compress);
											if (redEl > 0) {
												tcph->seq = htonl(ntohl(tcph->seq) + 8000); // Increase SEQ number.
												me->optimization.metrics.diffBytesCompression += redEl;
												me->optimization.metrics.packetsWithOnlyCompression++;
											}
										}
	
										if(deduplication == true){
											// Check Sequence Number to detect retransmission (or out of order segment)
											if(checkseqnumber(largerIP, iph, tcph, thissession)){
												updateseqnumber(largerIP, iph, tcph, thissession);
												redElDedup = tcp_optimize(me->optimization.dedupProcessor,(__u8 *)iph, me->optimization.dedup_buffer);
												if (redElDedup > 0) me->optimization.metrics.diffBytesDeduplication += redElDedup;
												// BEGIN Combine algorithms 
												if (compression == true) {
													redElComp = tcp_compress((__u8 *)iph, me->optimization.lzbuffer,state_compress);
													if (redElComp > 0) {
														me->optimization.metrics.diffBytesCompression += redElComp;
														if (redElDedup > 0) me->optimization.metrics.packetsWithBothCompressionAndDeduplication++;
														else me->optimization.metrics.packetsWithOnlyCompression++;
													} else if (redElDedup > 0) me->optimization.metrics.packetsWithOnlyDeduplication++;
												} else if (redElDedup > 0) me->optimization.metrics.packetsWithOnlyDeduplication++;
												if ((redElDedup > 0) || ((compression == true)&&(redElComp > 0)))
													tcph->seq = htonl(ntohl(tcph->seq) + 8000); // Increase SEQ number.
												// END Combine algorithms 
												if (redEl || redElComp || redElDedup) cause = NOT_RELEVANT;
												else cause = NO_OPT_GAIN;
												
											}else{
												cause = IS_A_RTX;
												//LOGDEBUG(lc_fetcher, "Worker: ReTX detected, packet not optimized.");
												LOGDEBUG(lc_worker_retx, "ReTX detected, packet not optimized: %x:%d->%x:%d, IP_Id=%x, Total_len=%d",
                                                         ntohl(iph->saddr), ntohs(tcph->source), ntohl(iph->daddr), ntohs(tcph->dest), ntohs(iph->id), ntohs(iph->tot_len));
												// printf("Before tcp_cache_optim worker %d\n",me->workernum);
												tcp_cache_optim(me->optimization.dedupProcessor,(__u8 *)iph);
											}
										}
									} else {
										cause = SESSION_CHECK;
										LOGTRACE(lc_worker, "Worker: Not compressing packet.");
										if(deduplication == true){
											updateseqnumber(largerIP, iph, tcph, thissession);
											// printf("Before tcp_cache_optim worker %d\n",me->workernum);
											tcp_cache_optim(me->optimization.dedupProcessor,(__u8 *)iph); // We cache it anyway
										}
									}
                                    unsigned char *tcpdata =  (unsigned char *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
									uint16_t tcplen = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;
									memmove(tcpdata+sizeof(OpennopHeader),tcpdata,tcplen);
                                    pOpennopHeader oh = (pOpennopHeader) tcpdata;
                                    oh->opennopID = localID;
                                    oh->seqNo = seqNo++;
                                    if (redEl || redElComp) oh->compression = 1; else oh->compression = 0;
                                    if (redElDedup) oh->deduplication = 1; else oh->deduplication = 0;
                                    oh->queuenum = thissession->queue;
                                    oh->reasonForNoOptimization = cause;
                                    oh->pattern = OPENNOP_PATTERN;
                                    iph->tot_len = htons(ntohs(iph->tot_len)+sizeof(OpennopHeader));
									addedOpennopHeader = true;
									LOGTRACE(lc_worker, "Worker: adding opennop header (IP total length=%d)",ntohs(iph->tot_len));
							
								}
							}
						}

						if (tcph->rst == 1) { // Session was reset.

							LOGDEBUG(lc_worker, "Worker: Session was reset.");
							clearsession(thissession);
							thissession = NULL;
						}

						closingsession(iph, tcph, thissession);

						if (thispacket != NULL) {
							/*
							 * Changing anything requires the IP and TCP
							 * checksum to need recalculated.
							 */

							checksum(thispacket->data);
							me->optimization.metrics.bytesout += ntohs(iph->tot_len);
							me->optimization.metrics.diffBytesIpTcpHeader += getIPPlusTCPHeaderLength((__u8 *) iph) - headersBefore;
							if (addedOpennopHeader) me->optimization.metrics.diffBytesIpTcpHeader += sizeof(OpennopHeader);
							nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)thispacket->data);
							put_freepacket_buffer(thispacket);
							thispacket = NULL;
						}

					} /* End NULL session check. */
					else
					{ /* Session was NULL. */
						me->optimization.metrics.bytesout += ntohs(iph->tot_len);
						me->optimization.metrics.diffBytesIpTcpHeader += getIPPlusTCPHeaderLength((__u8 *) iph) - headersBefore;
						nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
						put_freepacket_buffer(thispacket);
						thispacket = NULL;
					}
					me->optimization.metrics.packets++;
				} /* End NULL packet check. */
			} /* End compression enabled check. */
			else
			{  /* Compression is disabled */
				nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
				put_freepacket_buffer(thispacket);
				thispacket = NULL;
			}
		} /* End working loop. */
		free(me->optimization.lzbuffer);
		free(me->optimization.dedup_buffer);
		free(state_compress);
		me->optimization.lzbuffer = NULL;
		me->optimization.dedup_buffer = NULL;
	}
	return NULL;
}

void *deoptimization_thread(void *dummyPtr) {
	struct worker *me = NULL;
	struct packet *thispacket = NULL;
	struct session *thissession = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u32 largerIP, smallerIP, remoteID;
	__u16 largerIPPort, smallerIPPort;
	qlz_state_decompress *state_decompress = (qlz_state_decompress *) malloc(
			sizeof(qlz_state_decompress));
	me = dummyPtr;
	//int result = 0;
	uint32_t expectedSeqNo = 0, rxSeqNo;
	unsigned int dedupPresent, compressPresent;

	me->deoptimization.lzbuffer = calloc(1, BUFSIZE + 400);
	/* Sharwan J: QuickLZ buffer needs (original data size + 400 bytes) buffer */
	if (me->deoptimization.lzbuffer == NULL) {
		LOGERROR(lc_worker, "Worker:deoptimization Couldn't allocate buffer lzbuffer");
		exit(1);
	}

	me->deoptimization.dedup_buffer = calloc(1, 2*BUFSIZE + 400);
	/* Solowan deduplication needs a utility buffer */
	if (me->deoptimization.dedup_buffer == NULL) {
		LOGERROR(lc_worker, "Worker deoptimization: Couldn't allocate buffer dedup");
		exit(1);
	}

	/*
	 * Register the worker threads metrics so they get updated.
	 */
	register_counter(counter_updateworkermetrics, (t_counterdata)
			& me->deoptimization.metrics);

	if (me->deoptimization.dedup_buffer != NULL && me->deoptimization.lzbuffer != NULL) {

		while (me->state >= STOPPING) {

			thispacket = dequeue_packet(&me->deoptimization.queue, true);

			if (thispacket != NULL) { // If a packet was taken from the queue.
				iph = (struct iphdr *) thispacket->data;
				tcph = (struct tcphdr *) (((u_int32_t *) iph) + iph->ihl);
				unsigned int headersBefore = getIPPlusTCPHeaderLength((__u8 *) iph);

				LOGTRACE(lc_worker, "Worker: IP Packet length is: %u", ntohs(iph->tot_len));
				me->deoptimization.metrics.bytesin += ntohs(iph->tot_len);

				unsigned OpennopHeaderPresent = false;
				if (__get_tcp_option((__u8 *)iph,32) ) {/* Check what IP address is larger. */
          				unsigned char *tcpdata =  (unsigned char *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
					OpennopHeaderPresent = true;
                    pOpennopHeader oh = (pOpennopHeader) tcpdata;
                    remoteID = oh->opennopID;
					rxSeqNo = oh->seqNo;
					dedupPresent = oh->deduplication;
					compressPresent = oh->compression;
					unsigned int incomingLen = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff* 4;
                    if (incomingLen < sizeof(OpennopHeader)) {
                        LOGERROR(lc_worker, "Worker: detected opennop option but incoming TCP data length less than opennop header length!!!!");
                        nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
                        put_freepacket_buffer(thispacket);
                        thispacket = NULL;
                        return NULL;
                    }

                    if (oh->pattern != OPENNOP_PATTERN) {
                        LOGERROR(lc_worker, "Worker: option 32 found but bad pattern!!!");
                        nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
                        put_freepacket_buffer(thispacket);
                        thispacket = NULL;
                        return NULL;
                    }
					

                    LOGTRACE(lc_worker, "Worker: removing opennop header incomingLen %d header size %ld, IP total length before %d",incomingLen, sizeof(OpennopHeader), ntohs(iph->tot_len));

					memmove(tcpdata,tcpdata+sizeof(OpennopHeader),incomingLen-sizeof(OpennopHeader));
					__set_tcp_option((__u8 *)iph,32,3,0);
					iph->tot_len = htons(ntohs(iph->tot_len)-sizeof(OpennopHeader));
					checksum(thispacket->data);
                    LOGTRACE(lc_worker, "Worker: after removing opennop header (IP total length=%d)",ntohs(iph->tot_len));

				} else { // Can this really happen??? According to fetcher code, it should not.
					remoteID = 0;
					rxSeqNo = 0;
					compressPresent = 0;
					dedupPresent = 0;
                    LOGERROR(lc_worker, "Worker, option 32 not found when deoptimizing packet!!!");
                    nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);
                    put_freepacket_buffer(thispacket);
                    thispacket = NULL;
                    return NULL;
				}

				if (rxSeqNo != expectedSeqNo) {
					me->deoptimization.metrics.sequenceGaps++;
					LOGTRACE(lc_worker_retx, "Deoptimization: unexpected sequence number. Received %u, expected %u, src addr %x, dst addr %x, src port %d, dst port %d, IP datagram ID %x, total IP datagram length %d", 
						rxSeqNo, expectedSeqNo, ntohl(iph->saddr), ntohl(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest), ntohs(iph->id), ntohs(iph->tot_len));
					expectedSeqNo = rxSeqNo + 1;
				} else expectedSeqNo++;
				sort_sockets(&largerIP, &largerIPPort, &smallerIP, &smallerIPPort, iph->saddr,tcph->source,iph->daddr,tcph->dest);

				//LOGDEBUG(lc_worker, "Worker: Searching for session.");

				thissession = getsession(largerIP, largerIPPort, smallerIP,smallerIPPort);

				if (thissession != NULL) {

					LOGTRACE(lc_worker, "Worker: Found a session.");

					if ((tcph->syn == 0) && (tcph->ack == 1) && (tcph->fin == 0))
					{

						if (remoteID != 0){

							saveacceleratorid(largerIP, remoteID, iph, thissession);

							if (compressPresent || dedupPresent) { // Packet is flagged as compressed and/or deduplicated.

								LOGTRACE(lc_worker, "Worker: Packet is deduplicated.");

								if (((iph->saddr == largerIP) &&
									(thissession->smallerIPAccelerator == localID)) ||
									((iph->saddr == smallerIP) &&
    								(thissession->largerIPAccelerator == localID)))
								{

									/*
									 * Decompress this packet!
									 */
									if((compression == true) && (deduplication == false) && compressPresent){
										int redComp = tcp_decompress((__u8 *)iph, me->deoptimization.lzbuffer, state_decompress);
										if (redComp < 0) { // Decompression failed if < 0.
											nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP, 0, NULL); // Decompression failed drop.
											put_freepacket_buffer(thispacket);
											thispacket = NULL;
										} else {
											tcph->seq = htonl(ntohl(tcph->seq) - 8000); // Decrease SEQ number.
											me->deoptimization.metrics.diffBytesCompression += redComp;
											me->deoptimization.metrics.packetsWithOnlyCompression++;
										}
									}

									if (deduplication == true){
										int redComp = 0;
										int redDedup = 0;
										if ((compression == true) && compressPresent) {
											redComp = tcp_decompress((__u8 *)iph, me->deoptimization.lzbuffer, state_decompress);
											if (redComp < 0) { // Decompression failed if < 0.
											     nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP, 0, NULL); // Decompression failed drop.
											     put_freepacket_buffer(thispacket);
											     thispacket = NULL;
										        } else {
												me->deoptimization.metrics.diffBytesCompression += redComp;
												if (!dedupPresent) {
													tcph->seq = htonl(ntohl(tcph->seq) - 8000); // Decrease SEQ number.
													me->deoptimization.metrics.packetsWithOnlyCompression++;
												}
											}
										}
										if (dedupPresent) {
											updateseqnumber(largerIP, iph, tcph, thissession);
											// printf("Before tcp_deoptimize worker %d\n",me->workernum);
											redDedup = tcp_deoptimize(me->deoptimization.dedupProcessor,(__u8 *)iph, me->deoptimization.dedup_buffer);
											if (redDedup == ERROR)
											{ // Decompression failed if 0.
												if (thispacket !=NULL) {
													nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);// Decompression failed drop.
													put_freepacket_buffer(thispacket);
													thispacket = NULL;
												}
											}else if(redDedup == HASH_NOT_FOUND){
												if (thispacket !=NULL) {
													nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP,0,NULL);// Decompression failed drop.
													put_freepacket_buffer(thispacket);
													thispacket = NULL;
												}
											} else {
												tcph->seq = htonl(ntohl(tcph->seq) - 8000); // Decrease SEQ number.
												me->deoptimization.metrics.diffBytesDeduplication += redDedup;
												if (redComp > 0) me->deoptimization.metrics.packetsWithBothCompressionAndDeduplication++;
												else me->deoptimization.metrics.packetsWithOnlyDeduplication++;

											}
										} else {
											//We must cache packets even if they are not compressed
											// printf("Before tcp_cache_deoptim worker %d\n",me->workernum);
											tcp_cache_deoptim(me->deoptimization.dedupProcessor,(__u8 *)iph);
										}
									}

								}
							}else{
								if (deduplication == true){
									//We must cache packets even if they are not compressed
									// printf("Before tcp_cache_deoptim worker %d\n",me->workernum);
									tcp_cache_deoptim(me->deoptimization.dedupProcessor,(__u8 *)iph);
								}
							}
						}
					}

					if (tcph->rst == 1) { // Session was reset.

						LOGDEBUG(lc_worker, "Worker: Session was reset.");
						clearsession(thissession);
						thissession = NULL;
					}

					closingsession(iph, tcph, thissession);

					if (thispacket != NULL)
					{
						/*
						 * Changing anything requires the IP and TCP
						 * checksum to need recalculated.
						 */
						checksum(thispacket->data);
						me->deoptimization.metrics.bytesout += ntohs(iph->tot_len);
						me->deoptimization.metrics.diffBytesIpTcpHeader += headersBefore-getIPPlusTCPHeaderLength((__u8 *) iph);
						if (OpennopHeaderPresent) me->deoptimization.metrics.diffBytesIpTcpHeader += sizeof(OpennopHeader);
						nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)thispacket->data);
						put_freepacket_buffer(thispacket);
						thispacket = NULL;
					}

				} /* End NULL session check. */
				else
				{ /* Session was NULL. */
					me->deoptimization.metrics.bytesout += ntohs(iph->tot_len);
					me->deoptimization.metrics.diffBytesIpTcpHeader += getIPPlusTCPHeaderLength((__u8 *) iph) - headersBefore;
					if (OpennopHeaderPresent) me->deoptimization.metrics.diffBytesIpTcpHeader -= sizeof(OpennopHeader);
					nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
					put_freepacket_buffer(thispacket);
					thispacket = NULL;
				}
				me->deoptimization.metrics.packets++;
			} /* End NULL packet check. */
		} /* End working loop. */
		free(me->deoptimization.lzbuffer);
		free(me->deoptimization.dedup_buffer);
		free(state_decompress);
		me->deoptimization.lzbuffer = NULL;
		me->deoptimization.dedup_buffer = NULL;
	}
	return NULL;
}

/*
 * Returns how many workers should be running.
 */
unsigned char get_workers(void) {
	return numworkers;
}

/*
 * Sets how many workers should be running.
 */
void set_workers(unsigned char desirednumworkers) {
	numworkers = desirednumworkers;
}

u_int32_t get_worker_sessions(int i) {
	u_int32_t sessions;
	pthread_mutex_lock(&workers[i].lock);
	sessions = workers[i].sessions;
	pthread_mutex_unlock(&workers[i].lock);
	return sessions;
}

void increment_worker_sessions(int i) {

	pthread_mutex_lock(&workers[i].lock); // Grab lock on worker.
	workers[i].sessions += 1;
	pthread_mutex_unlock(&workers[i].lock); // Lose lock on worker.
}
void decrement_worker_sessions(int i) {
	pthread_mutex_lock(&workers[i].lock); // Grab lock on worker.
	workers[i].sessions -= 1;
	pthread_mutex_unlock(&workers[i].lock); // Lose lock on worker.
}

void create_worker(int i) {
	initialize_worker_processor(&workers[i].optimization);
	initialize_worker_processor(&workers[i].deoptimization);
	workers[i].workernum = i;
	workers[i].optimization.dedupProcessor = newDeduplicator();
	workers[i].deoptimization.dedupProcessor = newDeduplicator();
	workers[i].sessions = 0;
	pthread_mutex_init(&workers[i].lock, NULL); // Initialize the worker lock.
	pthread_create(&workers[i].optimization.t_processor, NULL,
			optimization_thread, (void *) &workers[i]);
	pthread_create(&workers[i].deoptimization.t_processor, NULL,
			deoptimization_thread, (void *) &workers[i]);
	set_worker_state_running(&workers[i]);
}

void set_worker_state_stopping(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = STOPPING;
	pthread_mutex_unlock(&thisworker->lock);
}

void shutdown_workers() {
	int i;
	for (i = 0; i < get_workers(); i++) {
		pthread_cond_signal(&workers[i].optimization.queue.signal);
		pthread_cond_signal(&workers[i].deoptimization.queue.signal);
		//		set_worker_state_stopping(i);
	}
}

void rejoin_worker(int i) {
	joining_worker_processor(&workers[i].optimization);
	joining_worker_processor(&workers[i].deoptimization);
	set_worker_state_stopped(&workers[i]);
}

void initialize_worker_processor(struct processor *thisprocessor) {
	pthread_cond_init(&thisprocessor->queue.signal, NULL); // Initialize the thread signal.
	thisprocessor->queue.next = NULL; // Initialize the queue.
	thisprocessor->queue.prev = NULL;
	thisprocessor->lzbuffer = NULL;
	thisprocessor->dedup_buffer = NULL;
	thisprocessor->queue.qlen = 0;
	pthread_mutex_init(&thisprocessor->queue.lock, NULL); // Initialize the queue lock.
}

void joining_worker_processor(struct processor *thisprocessor) {
	pthread_mutex_lock(&thisprocessor->queue.lock);
	pthread_cond_signal(&thisprocessor->queue.signal);
	pthread_mutex_unlock(&thisprocessor->queue.lock);
	pthread_join(thisprocessor->t_processor, NULL);
}

void set_worker_state_running(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = RUNNING;
	pthread_mutex_unlock(&thisworker->lock);
}

void set_worker_state_stopped(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = STOPPED;
	pthread_mutex_unlock(&thisworker->lock);
}

int optimize_packet(__u8 queue, struct packet *thispacket) {
	return queue_packet(&workers[queue].optimization.queue, thispacket);
}

int deoptimize_packet(__u8 queue, struct packet *thispacket) {
	return queue_packet(&workers[queue].deoptimization.queue, thispacket);
}

int cli_show_workers(int client_fd, char **parameters, int numparameters) {
	int i;
	__u64 ppsbps64;
	__u32 ppsbps32;
	__u32 total_optimization_pps = 0;
	__u64 total_optimization_bpsin = 0, total_optimization_bpsout = 0;
	__u32 total_deoptimization_pps = 0;
	__u64 total_deoptimization_bpsin = 0, total_deoptimization_bpsout = 0;
        __u64 total_bytesin, total_bytesout, total_diffbytescomp, total_diffbytesdedup, total_packets, total_packetscomp, total_packetsdedup, total_packetsboth, total_diffbytesheader, total_sequence_gaps;
	char msg[MAX_BUFFER_SIZE] = { 0 };
	char bps[255];
        char colagr[255];
        char optimizationbpsin[255];
        char optimizationbpsout[255];
        char deoptimizationbpsin[255];
        char deoptimizationbpsout[255];

	LOGDEBUG(lc_worker_cli, "Counters: Showing counters");

	sprintf(
			msg,
			"---------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  5 sec  |          optimization               |          deoptimization             |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  worker |  pps  |     in       |     out      |  pps  |     in       |     out      |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	for (i = 0; i < get_workers(); i++) {

		strcpy(msg, "");

		sprintf(colagr, "|    %-5i", i);
		strcat(msg, colagr);

		ppsbps32 = workers[i].optimization.metrics.pps;
		total_optimization_pps += ppsbps32;
		sprintf(colagr, "| %-6u", ppsbps32);
		strcat(msg, colagr);

		ppsbps64 = workers[i].optimization.metrics.bpsin;
		total_optimization_bpsin += ppsbps64;
		bytestostringbps(bps, ppsbps64);
		sprintf(colagr, "| %-13s", bps);
		strcat(msg, colagr);

		ppsbps64 = workers[i].optimization.metrics.bpsout;
		total_optimization_bpsout += ppsbps64;
		bytestostringbps(bps, ppsbps64);
		sprintf(colagr, "| %-13s", bps);
		strcat(msg, colagr);

		ppsbps32 = workers[i].deoptimization.metrics.pps;
		total_deoptimization_pps += ppsbps32;
		sprintf(colagr, "| %-6u", ppsbps32);
		strcat(msg, colagr);

		ppsbps64 = workers[i].deoptimization.metrics.bpsin;
		total_deoptimization_bpsin += ppsbps64;
		bytestostringbps(bps, ppsbps64);
		sprintf(colagr, "| %-13s", bps);
		strcat(msg, colagr);

		ppsbps64 = workers[i].deoptimization.metrics.bpsout;
		total_deoptimization_bpsout += ppsbps64;
		bytestostringbps(bps, ppsbps64);
		sprintf(colagr, "| %-13s", bps);
		strcat(msg, colagr);

		sprintf(colagr, "|\n");
		strcat(msg, colagr);
		cli_send_feedback(client_fd, msg);
	}
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	bytestostringbps(optimizationbpsin, total_optimization_bpsin);
	bytestostringbps(optimizationbpsout, total_optimization_bpsout);
	bytestostringbps(deoptimizationbpsin, total_deoptimization_bpsin);
	bytestostringbps(deoptimizationbpsout, total_deoptimization_bpsout);
	sprintf(msg, "|  total  | %-6u| %-13s| %-13s| %-6u| %-13s| %-13s|\n",
			total_optimization_pps, optimizationbpsin, optimizationbpsout,
			total_deoptimization_pps, deoptimizationbpsin, deoptimizationbpsout);
	cli_send_feedback(client_fd, msg);

	sprintf(
			msg,
			"---------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
        sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"| accmltd.|                                                     optimization                                              |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  worker |  bytes in   |  bytes out  |   bcomp     |  bdedup    | bhead  | pkts      |   cpkts   |  dpkts    | c&dpkts   |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

        total_sequence_gaps = total_bytesin = total_bytesout = total_diffbytescomp = total_diffbytesdedup = total_diffbytesheader = total_packets = total_packetscomp = total_packetsdedup = total_packetsboth = 0;
	for (i = 0; i < get_workers(); i++) {
		strcpy(msg, "");

		sprintf(colagr, "|    %-5i", i);
		strcat(msg, colagr);

		ppsbps64 = workers[i].optimization.metrics.bytesin;
		total_bytesin += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);

                ppsbps64 = workers[i].optimization.metrics.bytesout;
		total_bytesout += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);
                
                ppsbps64 = workers[i].optimization.metrics.diffBytesCompression;
		total_diffbytescomp += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);
                
		ppsbps64 = workers[i].optimization.metrics.diffBytesDeduplication;
		total_diffbytesdedup += ppsbps64;
		//sprintf(colagr, "| %-11" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-11lld", ppsbps64);
		strcat(msg, colagr);
                
		ppsbps64 = workers[i].optimization.metrics.diffBytesIpTcpHeader;
		total_diffbytesheader += ppsbps64;
		//sprintf(colagr, "| %-7" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-7lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].optimization.metrics.packets;
		total_packets += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].optimization.metrics.packetsWithOnlyCompression;
		total_packetscomp += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].optimization.metrics.packetsWithOnlyDeduplication;
		total_packetsdedup += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].optimization.metrics.packetsWithBothCompressionAndDeduplication;
		total_packetsboth += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].optimization.metrics.sequenceGaps;
		total_sequence_gaps += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
		sprintf(colagr, "|\n");
		strcat(msg, colagr);

		cli_send_feedback(client_fd, msg);
	}
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

        //sprintf(msg, "|  total  | %-12" PRId64 "| %-12" PRId64 "| %-12" PRId64 "| %-11" PRId64 "| %-7" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "|\n", 
        sprintf(msg, "|  total  | %-12lld| %-12lld| %-12lld| %-11lld| %-7lld| %-10lld| %-10lld| %-10lld| %-10lld| %-10lld|\n", 
		total_bytesin, total_bytesout, total_diffbytescomp, total_diffbytesdedup, total_diffbytesheader,total_packets, total_packetscomp, total_packetsdedup, total_packetsboth, total_sequence_gaps ); 
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);


        sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"| accmltd.|                                                   deoptimization                                                          |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  worker |  bytes in   |  bytes out  |   bcomp     |  bdedup    | bhead  | pkts      |   cpkts   |  dpkts    | c&dpkts   | seqGaps   |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

        total_sequence_gaps = total_bytesin = total_bytesout = total_diffbytescomp = total_diffbytesdedup = total_diffbytesheader = total_packets = total_packetscomp = total_packetsdedup = total_packetsboth = 0;
	for (i = 0; i < get_workers(); i++) {
		strcpy(msg, "");

		sprintf(colagr, "|    %-5i", i);
		strcat(msg, colagr);

		ppsbps64 = workers[i].deoptimization.metrics.bytesin;
		total_bytesin += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);

                ppsbps64 = workers[i].deoptimization.metrics.bytesout;
		total_bytesout += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);
                
                ppsbps64 = workers[i].deoptimization.metrics.diffBytesCompression;
		total_diffbytescomp += ppsbps64;
		//sprintf(colagr, "| %-12" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-12lld", ppsbps64);
		strcat(msg, colagr);
                
		ppsbps64 = workers[i].deoptimization.metrics.diffBytesDeduplication;
		total_diffbytesdedup += ppsbps64;
		//sprintf(colagr, "| %-11" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-11lld", ppsbps64);
		strcat(msg, colagr);
                
		ppsbps64 = workers[i].deoptimization.metrics.diffBytesIpTcpHeader;
		total_diffbytesheader += ppsbps64;
		//sprintf(colagr, "| %-7" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-7lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].deoptimization.metrics.packets;
		total_packets += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].deoptimization.metrics.packetsWithOnlyCompression;
		total_packetscomp += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].deoptimization.metrics.packetsWithOnlyDeduplication;
		total_packetsdedup += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].deoptimization.metrics.packetsWithBothCompressionAndDeduplication;
		total_packetsboth += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
        ppsbps64 = workers[i].deoptimization.metrics.sequenceGaps;
		total_sequence_gaps += ppsbps64;
		//sprintf(colagr, "| %-10" PRId64 "", ppsbps64);
		sprintf(colagr, "| %-10lld", ppsbps64);
		strcat(msg, colagr);
                
                
		sprintf(colagr, "|\n");
		strcat(msg, colagr);

		cli_send_feedback(client_fd, msg);
	}
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

    //sprintf(msg, "|  total  | %-12" PRId64 "| %-12" PRId64 "| %-12" PRId64 "| %-11" PRId64 "| %-7" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "| %-10" PRId64 "|\n", 
    sprintf(msg, "|  total  | %-12lld| %-12lld| %-12lld| %-11lld| %-7lld| %-10lld| %-10lld| %-10lld| %-10lld| %-10lld|\n", 
		total_bytesin, total_bytesout, total_diffbytescomp, total_diffbytesdedup, total_diffbytesheader,total_packets, total_packetscomp, total_packetsdedup, total_packetsboth,total_sequence_gaps ); 
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"---------------------------------------------------------------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	return 0;
}

void counter_updateworkermetrics(t_counterdata data) {
	struct workercounters *metrics;
	__u32 counter;

	LOGDEBUG(lc_worker_counters, "Worker: Updating metrics!");

	metrics = (struct workercounters*) data;
	counter = metrics->packets;
	metrics->pps = calculate_ppsbps(metrics->packetsprevious, counter);
	metrics->packetsprevious = counter;

	counter = metrics->bytesin;
	metrics->bpsin = calculate_ppsbps(metrics->bytesinprevious, counter);
	metrics->bytesinprevious = counter;

	counter = metrics->bytesout;
	metrics->bpsout = calculate_ppsbps(metrics->bytesoutprevious, counter);
	metrics->bytesoutprevious = counter;

}

struct session *closingsession(struct iphdr *iph, struct tcphdr *tcph, struct session *thissession) {

    // for debugging purposes
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &iph->saddr, saddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, daddr, INET_ADDRSTRLEN);

	if ((tcph != NULL) && (thissession != NULL)) {

		/* Normal session closing sequence. */
		if (tcph->fin == 1) {

			switch (thissession->state) {
			case TCP_ESTABLISHED:
				thissession->state = TCP_CLOSING;
			    LOGDEBUG(lc_worker, "Session half closed: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
				return thissession;

			case TCP_CLOSING:
				clearsession(thissession);
				thissession = NULL;
			    LOGDEBUG(lc_worker, "Session full closed: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
				return thissession;
			}
			return thissession; //Session not in good state!
		}
		return thissession; //Not a fin packet.
	}
	return thissession; // Something went very wrong!
}

pDeduplicator get_worker_compressor(int i) {
	return workers[i].optimization.dedupProcessor;
}

pDeduplicator get_worker_decompressor(int i) {
	return workers[i].deoptimization.dedupProcessor;
}

