/*

  solowan_rolling.c

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
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include "solowan_rolling.h"
#include "MurmurHash3.h"
#include "logger.h"
#include "debugd.h"

inline static void cacheAndCompressIfNeeded(pDeduplicator pd, unsigned char *packet, uint16_t pktlen, unsigned char *optpkt, uint16_t *optlen, unsigned int compress) {

	FPEntryB pktFps[MAX_FP_PER_PKT];
	int i;
	FPEntryB *fpp;
	struct timeval tiempo;
	uint32_t computedPacketHash;
	int orig, dest;
	void *poffsetFPD, *pliml, *plimr;
	void *poffsetFP, *poffsetPktHash;
	uint16_t firstoffs;
	int ofs1 = 0;
	int ofs2 = 0;
	unsigned int fpNum;
	FPEntryB fptopkt[MAX_FP_PER_PKT];
	DictElement detectedRedundancy[MAX_FP_PER_PKT];
	  
	// Calculate FPs and packet hash
	// These functions may be placed outside locks, as they don't involve access to any shared state	
	if (pktlen >= BETA) {
		if (shared_dictionary_mode) fpNum = calculateRelevantFPs(fptopkt, packet, pktlen);
		else fpNum = calculateRelevantFPs(pktFps, packet, pktlen);
		MurmurHash3_x86_32  (packet, pktlen, SEED, (void *) &computedPacketHash );
	}	
	pthread_mutex_lock(&pd->cerrojo);
	pd->compStats.processedPackets++;
	pd->compStats.inputBytes += pktlen;

	if (debugword & DEDUP_MASK) {
		gettimeofday(&tiempo,NULL);
		LOGDEBUG(lc_dedup, "DEDUP processing at %ld.%ld hash %x len %d",tiempo.tv_sec,tiempo.tv_usec, computedPacketHash, pktlen);
	}

	// Default return values, no changes
	if (compress) *optlen = pktlen;

	// Do not optimize packets shorter than length of fingerprinted strings
	if (pktlen < BETA) {
		pd->compStats.numberOfShortPkts++;
		pd->compStats.outputBytes += pktlen;
		pthread_mutex_unlock(&pd->cerrojo);
		if (debugword & DEDUP_MASK) {
			LOGDEBUG(lc_dedup, "DEDUP returning, short %d", pktlen);
		}
		return;
	}
	if (shared_dictionary_mode) {
		pthread_mutex_unlock(&pd->cerrojo);
		if (compress) {
	  		// Compressed packet format:
	  		//     32 bit int (network order) original packet hash
	  		//     Short int (network order) offset from end of this header to first FP descriptor
	  		// Compressed data: byte sequence of uncompressed chunks (variable length) and interleaved FP descriptors
	  		// FP descriptors pointed by the header, fixed format and length:
	  		//     64 bit FP (network order)
	  		//     32 bit packet hash (network order)
	  		//     16 bit left limit (network order)
	  		//     16 bit right limit (network order)
	  		//     16 bit offset from end of this header to next FP descriptor (if all ones, no more descriptors)
	  		// Check fingerprints in FPStore
	
			getPktsByFPsAndContent(packet, pktlen, computedPacketHash, fptopkt, fpNum, detectedRedundancy);
	 	 
	  		poffsetFPD = (void *) optpkt+ sizeof(uint32_t);
	  		orig = dest= 0;
	  		for (i=0; i<fpNum; i++) {
				DictElement *fpt = &detectedRedundancy[i];
	  			if (fpt->pktLen != 0) {
	  				ofs1 = fptopkt[i].offset;
	 	 
	  				// If already covered, skip
	  				if (orig > ofs1) {
	  					continue;
	  				}
	
	  				// Contents match, dedup content
	  				// Explore full matching string
					ofs2 = fpt->offset;
	
	  				int liml = (ofs1-orig < ofs2) ? ofs1-orig : ofs2;
	  				int deltal = 1;
	  				while ((deltal <= liml) && (packet[ofs1-deltal] == fpt->pkt[ofs2-deltal])) deltal++;
	  				deltal--;
					assert (deltal >= 0);
	  				int limr = (pktlen - ofs1 < fpt->pktLen - ofs2) ? pktlen - ofs1 - BETA : fpt->pktLen - ofs2 - BETA;
	  				int deltar = 0;
	  				while ((deltar < limr) && (packet[ofs1+deltar+BETA] == fpt->pkt[ofs2+deltar+BETA])) deltar++;
					assert (deltar >= 0);
	
	  				// Copy uncompressed chunk before matching bytes
	  				assert (ofs1 >= deltal+orig);
					if (dest == 0) {
						hton32((void *) optpkt, computedPacketHash);
						dest = sizeof(uint32_t) + sizeof(uint16_t);
						firstoffs = ofs1-deltal-orig;
					}
	  				memcpy(optpkt+dest,packet+orig,ofs1-deltal-orig);
	
	  				hton16(poffsetFPD,ofs1-deltal-orig);
	  				dest += ofs1-deltal-orig;
	
	  				poffsetFP = (void *) optpkt+dest;
	  				hton64(poffsetFP, fptopkt[i].fp);
	  				dest += sizeof(uint64_t);
	 	 
	  				poffsetPktHash = (void *) optpkt+dest;
	  				hton32(poffsetPktHash, fpt->pktHash);
	  				dest += sizeof(uint32_t);
	 	 
	  				pliml = (void *) optpkt+dest;
	  				hton16(pliml,ofs2-deltal);
	  				dest += sizeof(uint16_t);
	 	 
	  				plimr = (void *) optpkt+dest;
	  				assert(ofs2+deltar+BETA-1 < MAX_PKT_SIZE());
	  				hton16(plimr,ofs2+deltar+BETA-1);
	  				dest += sizeof(uint16_t);
	
	  				poffsetFPD = (void *) optpkt+dest;
	  				hton16(poffsetFPD,0xffff);
	  				orig = ofs1+deltar+BETA;
	  				dest += sizeof(uint16_t);
	  				*optlen = dest;
	 	 
					if (pktlen == orig) break;
	  				else if (orig + BETA > pktlen) {
	  					memcpy(optpkt+dest,packet+orig,pktlen-orig);
	  					*optlen += pktlen-orig;
	  					orig = pktlen;
	  					break;
	  				}
	 	 
	  			}
	  		}
	  
	  		if (orig < pktlen) {
	  			memcpy(optpkt+dest,packet+orig,pktlen-orig);
				*optlen = dest+pktlen-orig;
	  		} 

			if (*optlen < pktlen) {
				assert(ntoh16(optpkt+ sizeof(uint32_t)) == firstoffs);
				assert(ntoh16(optpkt+ sizeof(uint32_t)) < MAX_PKT_SIZE());
			}
	 	 
	  		if (debugword & DEDUP_MASK) {
	  			gettimeofday(&tiempo,NULL);
	  			LOGDEBUG(lc_dedup, "[DEDUP] storing at %ld.%ld",tiempo.tv_sec,tiempo.tv_usec);
	  		}
		}

		putPktAndFPsComp(packet,pktlen,computedPacketHash, fptopkt, fpNum);
	
		if (compress) {
			pd->compStats.outputBytes += *optlen;
			if (*optlen < pktlen) pd->compStats.compressedPackets++;
			assert (*optlen <= MAX_PKT_SIZE());
			assert (orig <= MAX_PKT_SIZE());
		} else {
			pd->compStats.outputBytes += pktlen;
		}

	} else { // Not shared dictionary
		// Store packet in PS
		int64_t currPktId;
		currPktId = putPkt(&pd->ps, packet, pktlen, computedPacketHash);
	
		if (compress) {
	  		// Compressed packet format:
	  		//     32 bit int (network order) original packet hash
	  		//     Short int (network order) offset from end of this header to first FP descriptor
	  		// Compressed data: byte sequence of uncompressed chunks (variable length) and interleaved FP descriptors
	  		// FP descriptors pointed by the header, fixed format and length:
	  		//     64 bit FP (network order)
	  		//     32 bit packet hash (network order)
	  		//     16 bit left limit (network order)
	  		//     16 bit right limit (network order)
	  		//     16 bit offset from end of this header to next FP descriptor (if all ones, no more descriptors)
	  		// Check fingerprints in FPStore
	 	 
	  		poffsetFPD = (void *) optpkt+ sizeof(uint32_t);
	  		orig = dest= 0;
	  		for (i=0; i<fpNum; i++) {
	  			ofs1 = pktFps[i].offset;
				fpp = getFPcontent(pd->fps,&pd->ps,pktFps[i].fp,packet+ofs1);
	  			if (fpp != NULL)  {
	 	 
	  				// If already covered, skip
	  				if (orig > ofs1) {
	  					continue;
	  				}
	
	  				// Contents match, dedup content
	  				// Explore full matching string
					PktEntry *storedPacket;
					storedPacket = getPkt(&pd->ps,fpp->pktId);
					ofs2 = fpp->offset;
	
	  				int liml = (ofs1-orig < ofs2) ? ofs1-orig : ofs2;
	  				int deltal = 1;
	  				while ((deltal <= liml) && (packet[ofs1-deltal] == storedPacket->pkt[ofs2-deltal])) deltal++;
	  				deltal--;
					assert (deltal >= 0);
	  				int limr = (pktlen - ofs1 < storedPacket->len - ofs2) ? pktlen - ofs1 - BETA : storedPacket->len - ofs2 - BETA;
	  				int deltar = 0;
	  				while ((deltar < limr) && (packet[ofs1+deltar+BETA] == storedPacket->pkt[ofs2+deltar+BETA])) deltar++;
					assert (deltar >= 0);
	
	 	 
	  				// Copy uncompressed chunk before matching bytes
	  				assert (ofs1 >= deltal+orig);
					if (dest == 0) {
						hton32((void *) optpkt, computedPacketHash);
						dest = sizeof(uint32_t) + sizeof(uint16_t);
						firstoffs = ofs1-deltal-orig;
					}
	  				memcpy(optpkt+dest,packet+orig,ofs1-deltal-orig);

	  				hton16(poffsetFPD,ofs1-deltal-orig);
	  				dest += ofs1-deltal-orig;
	
	  				poffsetFP = (void *) optpkt+dest;
	  				hton64(poffsetFP, fpp->fp);
	  				dest += sizeof(uint64_t);
	 		 
	  				poffsetPktHash = (void *) optpkt+dest;
	  				hton32(poffsetPktHash, storedPacket->hash);
	  				dest += sizeof(uint32_t);
	  
	  				pliml = (void *) optpkt+dest;
	  				hton16(pliml,ofs2-deltal);
	  				dest += sizeof(uint16_t);
	 	 
	  				plimr = (void *) optpkt+dest;
	  				assert(ofs2+deltar+BETA-1 < MAX_PKT_SIZE());
	  				hton16(plimr,ofs2+deltar+BETA-1);
	  				dest += sizeof(uint16_t);
	
	  				poffsetFPD = (void *) optpkt+dest;
	  				hton16(poffsetFPD,0xffff);
	  				orig = ofs1+deltar+BETA;
	  				dest += sizeof(uint16_t);
	  				*optlen = dest;
	 	 
					if (pktlen == orig) break;
	  				else if (orig + BETA > pktlen) {
	  					memcpy(optpkt+dest,packet+orig,pktlen-orig);
	  					*optlen += pktlen-orig;
	  					orig = pktlen;
	  					break;
	  				}
	 	 
	  			}
	  		}
	  
	  		if (orig < pktlen) {
	  			memcpy(optpkt+dest,packet+orig,pktlen-orig);
				*optlen = dest+pktlen-orig;
	  		} 

			if (*optlen < pktlen) {
				assert(ntoh16(optpkt+ sizeof(uint32_t)) == firstoffs);
				assert(ntoh16(optpkt+ sizeof(uint32_t)) < MAX_PKT_SIZE());
			}
	 	 
	  		if (debugword & DEDUP_MASK) {
	  			gettimeofday(&tiempo,NULL);
	  			LOGDEBUG(lc_dedup, "[DEDUP] storing at %ld.%ld",tiempo.tv_sec,tiempo.tv_usec);
	  		}
		}

		for (i=fpNum-1; i >=0; i--) {
			putFP(pd->fps, &pd->ps, pktFps[i].fp, currPktId, pktFps[i].offset, &pd->compStats);
			if (debugword & DEDUP_MASK) {
				LOGDEBUG(lc_dedup, "[DEDUP] storing (empty) FP %" PRIx64 " for hash %x",pktFps[i].fp,computedPacketHash);
			}
		}
		pd->compStats.lastPktId = currPktId;
		if (compress) {
			pd->compStats.outputBytes += *optlen;
			if (*optlen < pktlen) pd->compStats.compressedPackets++;
			assert (*optlen <= MAX_PKT_SIZE());
			assert (orig <= MAX_PKT_SIZE());
		}
		pthread_mutex_unlock(&pd->cerrojo);
        }
}

// dedup takes an incoming packet (packet, pktlen), processes it and, if some compression is possible,
// outputs the compressed packet (optpkt -- must be allocated by the caller, optlen). If no compression is possible, 
// optlen is the same as pktlen
void dedup(pDeduplicator pd, unsigned char *packet, uint16_t pktlen, unsigned char *optpkt, uint16_t *optlen) {
	cacheAndCompressIfNeeded(pd, packet, pktlen, optpkt, optlen, 1);
}

void put_in_cache(pDeduplicator pd, unsigned char *packet, uint16_t pktlen) {
	cacheAndCompressIfNeeded(pd, packet, pktlen, NULL, NULL, 0);
}



