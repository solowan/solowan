/*

  compression.c

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
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options
#include "compression.h"
#include "quicklz.h"
#include "tcpoptions.h"
#include "logger.h"
#include "climanager.h"

// int compression = false; // Determines if opennop should compress tcp data.
int compression = true; // Determines if opennop should compress tcp data.

int cli_show_compression(int client_fd, char **parameters, int numparameters) {
	char msg[MAX_BUFFER_SIZE] = { 0 };

        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	if (compression == true) {
		sprintf(msg, "compression enabled\n");
	} else {
		sprintf(msg, "compression disabled\n");
	}
	cli_send_feedback(client_fd, msg);

        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int cli_compression_enable(int client_fd, char **parameters, int numparameters) {
	compression = true;
	char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg, "Compression enabled\n");
	cli_send_feedback(client_fd, msg);
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int compression_enable(){
	compression = true;
	return 0;
}

int cli_compression_disable(int client_fd, char **parameters, int numparameters) {
	compression = false;
	char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
	sprintf(msg, "Compression disabled\n");
	cli_send_feedback(client_fd, msg);
        sprintf(msg,"------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

	return 0;
}

int compression_disable(){
	compression = false;
	return 0;
}

/*
 * Compresses the TCP data of an SKB.
 */
unsigned int tcp_compress(__u8 *ippacket, __u8 *lzbuffer,
		qlz_state_compress *state_compress) {
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u16 oldsize = 0, newsize = 0; /* Store old, and new size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */

	LOGDEBUG(lc_comp, "Entering into TCP COMPRESS ");

	// If the skb or state_compress is NULL abort compession.
	// if ((ippacket != NULL) && (NULL != state_compress) && (compression == true)) {
	if ((ippacket != NULL) && (NULL != state_compress)) {
		iph = (struct iphdr *) ippacket; // Access ip header.
		memset(state_compress, 0, sizeof(qlz_state_compress));

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort compression.
			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl);
			oldsize = (__u16)(ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;
			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.

			LOGDEBUG(lc_comp, "Compression: Original TCP data length is: %u", oldsize);

			if (oldsize > 0) { // Only compress if there is any data.
				newsize = (oldsize * 2);

				if (lzbuffer != NULL) {

					LOGDEBUG(lc_comp, "Compression: Begin compression.");

					newsize = qlz_compress((char *) tcpdata, (char *) lzbuffer,
							oldsize, state_compress);
				} else {

					LOGDEBUG(lc_comp, "Compression: lzbuffer was NULL!");
				}

				LOGDEBUG(lc_comp, "Compression: New TCP data length is: %u", newsize);

				if (newsize < oldsize) {
					memmove(tcpdata, lzbuffer, newsize); // Move compressed data to packet.
					//pskb_trim(skb,skb->len - (oldsize - newsize)); // Remove extra space from skb.
					iph->tot_len = htons(ntohs(iph->tot_len) - (oldsize - newsize));// Fix packet length.
                                        /* Bellido: this code is now in workers
					tcph->seq = htonl(ntohl(tcph->seq) + 8000); // Increase SEQ number.
                                        */

					LOGDEBUG(lc_comp, "Compressing [%d] size of data to [%d] ", oldsize, newsize);
				}

				LOGDEBUG(lc_comp, "Leaving TCP COMPRESS ");
			}
		}
	}
	// return 1;
	// fruiz return amount of removed redundancy
	if (newsize<oldsize) return oldsize-newsize; else return 0;
}

/*
 * Decompress the TCP data of an SKB.
 */
int tcp_decompress(__u8 *ippacket, __u8 *lzbuffer, qlz_state_decompress *state_decompress) {
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int oldsize = 0, newsize = 0; /* Store old, and new size of the TCP data. */
	__u8 *tcpdata = NULL; /* Starting location for the TCP data. */

	LOGDEBUG(lc_comp, "Entering into TCP DECOMPRESS ");

	if ((ippacket != NULL) && (NULL != state_decompress)) { // If the skb or state_decompress is NULL abort compression.
		iph = (struct iphdr *) ippacket; // Access ip header.
		memset(state_decompress, 0, sizeof(qlz_state_decompress));

	LOGDEBUG(lc_comp, "************************* 1 ");

		if ((iph->protocol == IPPROTO_TCP)) { // If this is not a TCP segment abort compression.
			tcph = (struct tcphdr *) (((u_int32_t *) ippacket) + iph->ihl); // Access tcp header.
			oldsize = (ntohs(iph->tot_len) - iph->ihl * 4) - tcph->doff * 4;

			tcpdata = (__u8 *) tcph + tcph->doff * 4; // Find starting location of the TCP data.
	LOGDEBUG(lc_comp, "************************* 2 ");

			if ((oldsize > 0) && (lzbuffer != NULL)) {

				newsize = qlz_decompress((char *) tcpdata, (char *) lzbuffer, state_decompress);
	LOGDEBUG(lc_comp, "************************* 3 ");
				if (newsize < 0) return -1;
				memmove(tcpdata, lzbuffer, newsize); // Move decompressed data to packet.
				iph->tot_len = htons(ntohs(iph->tot_len) + (newsize - oldsize));// Fix packet length.
				/* Bellido: this code is now in workers
				tcph->seq = htonl(ntohl(tcph->seq) - 8000); // Decrease SEQ number.
                                */

				LOGDEBUG(lc_comp, "Decompressing [%d] size of data to [%d] ", oldsize, newsize);
				// return 1;
				// fruiz return amount of data expansion
				return newsize-oldsize;
			}
		}
	}
	LOGDEBUG(lc_comp, "**************************");
	return -1;
}
