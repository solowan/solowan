/*

  fetcher.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: Changed TCP option value for Accelerator Id

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
#include <unistd.h>
#include <string.h>

#include <sys/time.h>

#include <arpa/inet.h> // for getting local ip address
#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h> // for access to Netfilter Queue
#include "fetcher.h"
#include "queuemanager.h"
#include "sessionmanager.h"
#include "logger.h"
#include "tcpoptions.h"
#include "csum.h"
#include "packet.h"
#include "opennopd.h"
#include "worker.h"
#include "memorymanager.h"
#include "counters.h"
#include "climanager.h"
#include "tcpoptions.h"

#include <errno.h> //For error results

struct fetcher thefetcher;

int G_SCALEWINDOW = 7;

struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;

int fetcher_callback(struct nfq_q_handle *hq, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data) {
	u_int32_t id = 0;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct session *thissession = NULL;
	struct packet *thispacket = NULL;
	struct nfqnl_msg_packet_hdr *ph;
	struct timeval tv;
	__u32 largerIP, smallerIP, remoteID;
	__u16 largerIPPort, smallerIPPort, mms;
	int ret;
	int incomingQueueNum;
	unsigned char *originalpacket = NULL;
	char strIP[20];

    // for debugging purposes
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

	ph = nfq_get_msg_packet_hdr(nfa);

	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &originalpacket);

	if (servicestate >= RUNNING) {

		iph = (struct iphdr *) originalpacket;

		thefetcher.metrics.bytesin += ntohs(iph->tot_len);

		/* We need to double check that only TCP packets get accelerated. */
		/* This is because we are working from the Netfilter QUEUE. */
		/* User could QUEUE UDP traffic, and we cannot accelerate UDP. */
		if ((iph->protocol == IPPROTO_TCP) && (id != 0)) {

			tcph = (struct tcphdr *) (((u_int32_t *) originalpacket) + iph->ihl);

            // for debugging purpose
			inet_ntop(AF_INET, &iph->saddr, saddr, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &iph->daddr, daddr, INET_ADDRSTRLEN);

			/* Check what IP address is larger. */
			sort_sockets(&largerIP, &largerIPPort, &smallerIP, &smallerIPPort,
					iph->saddr, tcph->source, iph->daddr, tcph->dest);

			// remoteID = (__u32) __get_tcp_option((__u8 *)originalpacket,32);
			if (__get_tcp_option((__u8 *)originalpacket,32) ) {
				unsigned char *tcpdata =  (unsigned char *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
				unsigned int incLen   = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;
				if (incLen < sizeof(OpennopHeader)) {
					LOGERROR(lc_fetcher, "detected opennop option but incoming TCP data length less than opennop header length!!!!");
					return nfq_set_verdict(hq, id, NF_DROP,0,NULL);
				}

				pOpennopHeader oh = (pOpennopHeader) tcpdata;
				remoteID = oh->opennopID;
				incomingQueueNum = oh->queuenum;
				if (oh->pattern != OPENNOP_PATTERN) {
					LOGERROR(lc_fetcher, "option 32 found but bad pattern!!!");
					return nfq_set_verdict(hq, id, NF_DROP,0,NULL);
				}
			} else remoteID = 0;

			inet_ntop(AF_INET, &remoteID, strIP, INET_ADDRSTRLEN);
			//LOGDEBUG(lc_fetcher, "The accellerator ID is:%s", strIP);

			if (remoteID == 0) { 
			    LOGTRACE(lc_fetcher, "Packet from CLIENT: SYN=%d/FIN=%d/ACK=%d/RST=%d, %s:%d->%s:%d, IP_Id=%d, NFQ_Id=%d, TCP_seq=%u, ACK_seq=%u, Total_len=%d, TCP_hlen=%d, IP_hlen=%d, Data_len=%d", 
                  tcph->syn, tcph->fin, tcph->ack, tcph->rst, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest), ntohs(iph->id), id, ntohl(tcph->seq), ntohl(tcph->ack_seq),
                  ntohs(iph->tot_len), tcph->doff * 4, iph->ihl * 4, ntohs(iph->tot_len) - tcph->doff * 4 - iph->ihl * 4);
            } else {
			    LOGTRACE(lc_fetcher, "Packet from %s: SYN=%d/FIN=%d/ACK=%d/RST=%d, %s:%d->%s:%d, IP_Id=%d, NFQ_Id=%d, TCP_seq=%u, ACK_seq=%u, Total_len=%d, TCP_hlen=%d, IP_hlen=%d, Data_len=%d", 
                  strIP, tcph->syn, tcph->fin, tcph->ack, tcph->rst, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest), ntohs(iph->id), id, ntohl(tcph->seq), ntohl(tcph->ack_seq),
                  ntohs(iph->tot_len), tcph->doff * 4, iph->ihl * 4, ntohs(iph->tot_len) - tcph->doff * 4 - iph->ihl * 4);
            }    

			thissession = getsession(largerIP, largerIPPort, smallerIP, smallerIPPort); // Check for an outstanding syn.

				// if (thissession != NULL) {
                //     LOGDEBUG(lc_sesman_check, "****** [SESSION MANAGER] LargerIPseq: %u SmallerIPseq %u, TCP_seq=%u", thissession->largerIPseq, thissession->smallerIPseq, ntohl(tcph->seq));
                // }

			/* Check if this a SYN packet to identify a new session. */
			/* This packet will not be placed in a work queue, but  */
			/* will be accepted here because it does not have any data. */
			//if ((tcph->syn == 1) && (tcph->ack == 0)) {
            
			if (tcph->syn == 1) {
                
                //
                // SYN segment
                //
                if (tcph->ack == 0) {
					if (remoteID == 0) { LOGDEBUG(lc_fetcher, "SYN from CLIENT: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ); }
        	        else               { LOGDEBUG(lc_fetcher, "SYN from %s: %s:%d->%s:%d", strIP, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ); }
				} else {
					if (remoteID == 0) { LOGDEBUG(lc_fetcher, "SYN+ACK from CLIENT: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ); } 
					else               { LOGDEBUG(lc_fetcher, "SYN+ACK from %s: %s:%d->%s:%d", strIP, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ); }
				}

				if (thissession == NULL) {
					if (remoteID != 0) thissession = insertsession(largerIP, largerIPPort, smallerIP, smallerIPPort, incomingQueueNum); // Insert into sessions list.
					else thissession = insertsession(largerIP, largerIPPort, smallerIP, smallerIPPort, -1); // Insert into sessions list.
					if (remoteID == 0) { LOGDEBUG(lc_fetcher, "New session from CLIENT created: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ) }
                    else               { LOGDEBUG(lc_fetcher, "New session from %s created: %s:%d->%s:%d", strIP, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) ) };
				}

				/* We need to check for NULL to make sure */
				/* that a record for the session was created */
				if (thissession != NULL) {

					gettimeofday(&tv,NULL); // Get the time from hardware.
					thissession->lastactive = tv.tv_sec; // Update the session timestamp.

					sourceisclient(largerIP, iph, thissession, tcph->ack == 0);
					updateseq(largerIP, iph, tcph, thissession);
					updateseqnumber(largerIP, iph, tcph, thissession);

					if (remoteID == 0) { // Accelerator ID was not found.

						mms = __get_tcp_option((__u8 *)originalpacket,2);

						if (mms > 68) {

							if (__set_tcp_option((__u8 *)originalpacket,2,4,mms - 68) == -1) {// Reduce the MSS.
								LOGERROR(lc_fetcher, "Cannot reduce MSS in 68, fetcher.c, packet is a SYN, IP datagram ID %x, current value of TCP doff %d",ntohs(iph->id), tcph->doff);
							} 
							if (__set_tcp_option((__u8 *)originalpacket,32,3,1) == -1) { // Add the Accelerator ID to this packet.
								LOGERROR(lc_fetcher, "Cannot set opennop option to 1, fetcher.c, packet is a SYN, IP datagram ID %x, current value of TCP doff %d",ntohs(iph->id), tcph->doff);
							} else {
								unsigned char *tcpdata =  (unsigned char *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
								pOpennopHeader oh = (pOpennopHeader) tcpdata;
								oh->opennopID = localID;
								oh->seqNo = 0;
								oh->compression = 0;
								oh->deduplication = 0;
								oh->reasonForNoOptimization = NOT_RELEVANT;
								oh->pattern = OPENNOP_PATTERN;
								oh->queuenum = thissession->queue;
								iph->tot_len = htons(ntohs(iph->tot_len)+sizeof(OpennopHeader));
								LOGTRACE(lc_fetcher, "Adding opennop header to SYN packet: IP total length=%d",ntohs(iph->tot_len));
							}

							saveacceleratorid(largerIP, localID, iph, thissession);

							/*
							 * Changing anything requires the IP and TCP
							 * checksum to need recalculated.
							 */
							checksum(originalpacket);
						}
					} else { // Accelerator ID was found.

					    //LOGDEBUG(lc_fetcher, "New session from %s created: %s:%d->%s:%d", strIP, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) );

						if (__set_tcp_option((__u8 *)originalpacket,32,3,0) == -1) { 
							LOGERROR(lc_fetcher, "Cannot set opennop option to 0, fetcher.c, packet is a SYN, IP datagram ID %x, current value of TCP doff %d",ntohs(iph->id), tcph->doff);
						} else iph->tot_len = htons(ntohs(iph->tot_len)-sizeof(OpennopHeader));
						checksum(originalpacket);
						saveacceleratorid(largerIP, remoteID, iph, thissession);

					}

                    if (tcph->ack == 0) {
					    thissession->state = TCP_SYN_SENT;
                        LOGDEBUG(lc_fetcher, "Session state set to TCP_SYN_SENT");
                    } else {
						thissession->state = TCP_ESTABLISHED;
                        LOGDEBUG(lc_fetcher, "Session state set to TCP_ESTABLISHED");
                    }
				}

				/* Before we return let increment the packets counter. */
				thefetcher.metrics.packets++;

				/* This is the last step for a SYN packet. */
				/* accept all SYN packets. */
				return nfq_set_verdict(hq, id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)originalpacket);

			// } else if (tcph->rst == 1) { 
                
                //
                // RESET segment
                //
                // LOGDEBUG(lc_fetcher, "Session RESET %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
                // clearsession(thissession);
		// fruiz // 
		// thissession = NULL;

                /* Before we return let increment the packets counter. */
				// thefetcher.metrics.packets++;
			    // return nfq_set_verdict(hq, id, NF_ACCEPT, 0, NULL);


//			} else if (tcph->fin == 1) {  
//                
//                //
//                // FIN segment
//                //
//                LOGDEBUG(lc_fetcher, "FIN packet: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
//				if (thissession != NULL) {
//                    switch (thissession->state) {
//                        case TCP_ESTABLISHED:
//                                thissession->state = TCP_CLOSING;
//                                LOGDEBUG(lc_fetcher, "Session half closed: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
//                                break;
//                        case TCP_CLOSING:
//                                clearsession(thissession);
//                                LOGDEBUG(lc_fetcher, "Session full closed: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest));
//                                break;
//                    }
//                }
//
//                /* Before we return let increment the packets counter. */
//				thefetcher.metrics.packets++;
//	LOGDEBUG(lc_fetcher, "hq=%d, id=%d", hq, id);
//                int res = nfq_set_verdict(hq, id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)originalpacket);
//                LOGDEBUG(lc_fetcher, "Returning FIN packet %d", res);
//			    //return nfq_set_verdict(hq, id, NF_ACCEPT, 0, NULL);
//				//return nfq_set_verdict(hq, id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)originalpacket);
//				return res;


			} else { 

                //
                // DATA or FIN segment
                //
				if (thissession != NULL) { // DATA segment in an active session

                    //LOGDEBUG(lc_sesman_check, "[SESSION MANAGER] LargerIPseq: %u SmallerIPseq %u", thissession->largerIPseq, thissession->smallerIPseq);

					gettimeofday(&tv,NULL); // Get the time from hardware.
					thissession->lastactive = tv.tv_sec; // Update the active timer.
					thissession->deadcounter = 0; // Reset the dead counter.

					if (__get_tcp_option((__u8 *)originalpacket,32) == 2) { // Keepalive, can drop
						LOGDEBUG(lc_fetcher, "Received keepalive: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) );
						return nfq_set_verdict(hq, id, NF_DROP,0,NULL);
					}

					thispacket = get_freepacket_buffer();

					if (thispacket != NULL){
						save_packet(thispacket,hq, id, ret, (__u8 *)originalpacket, thissession);

						if (remoteID == 0){
						    LOGTRACE(lc_fetcher, "Packet sent to optimize");
							optimize_packet(thissession->queue, thispacket);
						} else {
						    LOGTRACE(lc_fetcher, "Packet sent to deoptimize");
							deoptimize_packet(thissession->queue, thispacket);
						}

					} else {
						LOGERROR(lc_fetcher, "Failed getting packet buffer for processing");
					}
					/* Before we return let increment the packets counter. */
					thefetcher.metrics.packets++;
					return 0;

				} else { // DATA segment and no active session exists


                    int data_len = ntohs(iph->tot_len) - tcph->doff * 4 - iph->ihl * 4;
                    if (data_len > 0) {
                        LOGDEBUG(lc_fetcher, "No session found for: SYN=%d/FIN=%d/ACK=%d/RST=%d, %s:%d->%s:%d, Opt_ID=%s, IP_Id=%d, NFQ_Id=%d, Total_len=%d, TCP_hlen=%d, IP_hlen=%d, Data_len=%d", 
                                tcph->syn, tcph->fin, tcph->ack, tcph->rst, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest), strIP, ntohs(iph->id), id, 
                                ntohs(iph->tot_len), tcph->doff * 4, iph->ihl * 4, ntohs(iph->tot_len) - tcph->doff * 4 - iph->ihl * 4);
                    }

    				/* We only want to create new sessions for active sessions. */
    				/* This means we exclude anything accept ACK packets. */

    				if (tcph->ack == 1) {

    					if (remoteID != 0) { // Detected remote Accelerator so it is safe to add this session.
    						thissession = insertsession(largerIP, largerIPPort, smallerIP, smallerIPPort, incomingQueueNum); // Insert into sessions list.

   							if (thissession != NULL) { // Test to make sure the session was added.
					            
                                LOGDEBUG(lc_fetcher, "Created NEW session for: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) );

							    thissession->state = TCP_ESTABLISHED;

							    saveacceleratorid(largerIP, remoteID, iph, thissession);

							    thispacket = get_freepacket_buffer();

							    if (thispacket != NULL){
								    save_packet(thispacket,hq, id, ret, (__u8 *)originalpacket, thissession);
								    updateseqnumber(largerIP, iph, tcph, thissession); //Update the stored TCP sequence number
								    deoptimize_packet(thissession->queue, thispacket);
							    } else {
								    LOGERROR(lc_fetcher, "Failed getting packet buffer for deoptimization.");
							    }
							    /* Before we return let increment the packets counter. */
							    thefetcher.metrics.packets++;
							    return 0;
                            } else {
                                LOGERROR(lc_fetcher, "Failed to create session for: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) );
                            }
                        }
				    }
					/* Before we return let increment the packets counter. */
					thefetcher.metrics.packets++;
                    //LOGERROR(lc_fetcher, "Unknown packet: %s:%d->%s:%d", saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest) );
					return nfq_set_verdict(hq, id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)originalpacket);
			    }
			}
		} else { /* Packet was not a TCP Packet or ID was 0. */
			/* Before we return let increment the packets counter. */
			thefetcher.metrics.packets++;
			return nfq_set_verdict(hq, id, NF_ACCEPT, 0, NULL);
		}
	} else { /* Daemon is not in a running state so return packets. */

		LOGTRACE(lc_fetcher, "The service is not running.");
		/* Before we return let increment the packets counter. */
		thefetcher.metrics.packets++;
		return nfq_set_verdict(hq, id, NF_ACCEPT, 0, NULL);
	}
	/*
	 * If we get here there was a major problem.
	 */
	/* Before we return let increment the packets counter. */
	thefetcher.metrics.packets++;
	return 0;
}

void *fetcher_function(void *dummyPtr) {
	long sys_pagesofmem = 0; // The pages of memory in this system.
	long sys_pagesize = 0; // The size of each page in bytes.
	//long sys_bytesofmem = 0; // The total bytes of memory in the system.
	//long nfqneededbuffer = 0; // Store how much memory the NFQ needs.
	long nfqlength = 0;
	int rv = 0;
	char buf[BUFSIZE]
	         __attribute__ ((aligned));

	LOGTRACE(lc_fetcher, "Initializing NFQ: getting library handle");

	h = nfq_open();

	if (!h) {

		LOGERROR(lc_fetcher, "NFQ init error getting library handle.");
		exit(EXIT_FAILURE);
	}

	LOGTRACE(lc_fetcher, "Initializing NFQ: unbinding existing nf_queue for AF_INET.");

	if (nfq_unbind_pf(h, AF_INET) < 0) {

		LOGERROR(lc_fetcher, "NFQ init error when unbinding nf_queue.");
		exit(EXIT_FAILURE);
	}

	LOGTRACE(lc_fetcher, "Initializing NFQ: binding to nf_queue.");

	if (nfq_bind_pf(h, AF_INET) < 0) {

		LOGERROR(lc_fetcher, "NFQ init error when binding to nf_queue.");
		exit(EXIT_FAILURE);
	}

	LOGTRACE(lc_fetcher, "Initializing NFQ: binding to queue '0'");
	qh = nfq_create_queue(h, 0, &fetcher_callback, NULL);

	if (!qh) {

		LOGDEBUG(lc_fetcher, "NFQ init error when binding to queue '0'");
		exit(EXIT_FAILURE);
	}

	LOGDEBUG(lc_fetcher, "Initializing NFQ: setting copy mode");

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, BUFSIZE) < 0) { // range/BUFSIZE was 0xffff

		LOGDEBUG(lc_fetcher, "NFQ init error when setting copy mode");
		exit(EXIT_FAILURE);
	}

	LOGDEBUG(lc_fetcher, "Initialzing NFQ: setting queue length.");

	sys_pagesofmem = sysconf(_SC_PHYS_PAGES);
	sys_pagesize = sysconf(_SC_PAGESIZE);

	LOGDEBUG(lc_fetcher, "There are %li pages of memory and %li bytes/page", sys_pagesofmem, sys_pagesize);

	if ((sys_pagesofmem <= 0) || (sys_pagesize <= 0)) {

		LOGDEBUG(lc_fetcher, "NFQ init error when checking system memory");
		exit(EXIT_FAILURE);
	}

	//sys_bytesofmem = (sys_pagesofmem * sys_pagesize);
	//nfqneededbuffer = (sys_bytesofmem / 100) * 10;

	//LOGDEBUG(lc_fetcher, "NFQ needs %li bytes of memory (%li MB)", nfqneededbuffer, (nfqneededbuffer / 1024) / 1024);
	//nfqlength = nfqneededbuffer / BUFSIZE;
	// nfqlength = 4096;
	nfqlength = 16384;

	LOGDEBUG(lc_fetcher, "NFQ length will be %li", nfqlength);

	LOGDEBUG(lc_fetcher, "NFQ cache  will be %ld MB", ((nfqlength * 2048) / 1024) / 1024);

	if (nfq_set_queue_maxlen(qh, nfqlength) < 0) {

		LOGDEBUG(lc_fetcher, "NFQ init error when setting queue length.");
		exit(EXIT_FAILURE);
	}
	nfnl_rcvbufsiz(nfq_nfnlh(h), nfqlength * BUFSIZE);
	fd = nfq_fd(h);

	register_counter(counter_updatefetchermetrics, (t_counterdata)
			& thefetcher.metrics);

	while ((servicestate >= RUNNING) && ((rv = recv(fd, buf, sizeof(buf), 0))
			&& rv >= 0)) {

		//LOGTRACE(lc_fetcher, "Packet received a packet");

		/*
		 * This will execute the callback_function for each ip packet
		 * that is received into the Netfilter QUEUE.
		 */
		nfq_handle_packet(h, buf, rv);
	}

	/*
	 * At this point the system is down.
	 * If this is due to rv = -1 we need to change the state
	 * of the service to STOPPING to alert the other components
	 * to begin shutting down because of the queue failure.
	 */
	if (rv == -1) {
		LOGERROR(lc_fetcher, "ERROR FETCHER: error code %d", errno);
		servicestate = STOPPING;
		LOGERROR(lc_fetcher, "Stopping last rv value: %i.", rv);
	}

	LOGDEBUG(lc_fetcher, "Unbinding from queue '0'");

	nfq_destroy_queue(qh);

#ifdef INSANE

	LOGDEBUG(lc_fetcher, "Fatal unbinding from queue '0'.");
	nfa_unbind_pf(h, AF_INET);
#endif

	LOGERROR(lc_fetcher, "NFQ release: closing library handle.");
	nfq_close(h);
	return NULL;
}

void fetcher_graceful_exit() {
	nfq_destroy_queue(qh);
	nfq_close(h);
	close(fd);
}

void create_fetcher() {
	pthread_create(&thefetcher.t_fetcher, NULL, fetcher_function, (void *) NULL);
}

void rejoin_fetcher() {
	pthread_join(thefetcher.t_fetcher, NULL);
}

int cli_show_fetcher(int client_fd, char **parameters, int numparameters) {
	char msg[MAX_BUFFER_SIZE] = { 0 };
	__u32 ppsbps;
	char bps[11];
	char col1[11];
	char col2[14];
	char col3[3];

	sprintf(msg, "------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg, "|  5 sec  |  fetcher   |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg, "------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg, "|   pps   |     in     |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(msg, "------------------------\n");
	cli_send_feedback(client_fd, msg);

	strcpy(msg, "");
	ppsbps = thefetcher.metrics.pps;
	bytestostringbps(bps, ppsbps);
	sprintf(col1, "| %-8u", ppsbps);
	strcat(msg, col1);

	ppsbps = thefetcher.metrics.bpsin;
	bytestostringbps(bps, ppsbps);
	sprintf(col2, "| %-11s", bps);
	strcat(msg, col2);

	sprintf(col3, "|\n");
	strcat(msg, col3);
	cli_send_feedback(client_fd, msg);

	sprintf(msg, "------------------------\n");
	cli_send_feedback(client_fd, msg);

	return 0;
}

void counter_updatefetchermetrics(t_counterdata data) {
	struct fetchercounters *metrics;
	__u32 counter;

	//LOGTRACE(lc_fetcher, "Updating metrics!");

	metrics = (struct fetchercounters*) data;
	counter = metrics->packets;
	metrics->pps = calculate_ppsbps(metrics->packetsprevious, counter);
	metrics->packetsprevious = counter;

	counter = metrics->bytesin;
	metrics->bpsin = calculate_ppsbps(metrics->bytesinprevious, counter);
	metrics->bytesinprevious = counter;
}
