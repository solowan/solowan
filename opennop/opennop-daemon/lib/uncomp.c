/*

  uncomp.c

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
#include <time.h>
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

inline static void local_update_caches(pDeduplicator pd, unsigned char *packet, uint16_t pktlen, uint32_t computedPacketHash) {

   if (shared_dictionary_mode) {

	FPStruct fptopkt[MAX_FP_PER_PKT];
	int i;
	unsigned char message[LOGSZ];
	struct timeval tiempo;
	unsigned int fpNum;

	if (pktlen < BETA) return; // Short packets are never optimized
	fpNum = calculateRelevantFPs(fptopkt, packet, pktlen);


	if (debugword & LOCAL_UPDATE_CACHE_MASK) {
		gettimeofday(&tiempo,NULL);
		sprintf(message, "[LOCAL UPDATE CACHE]: at %d.%d computedPacketHash %x len %d\n", tiempo.tv_sec, tiempo.tv_usec, computedPacketHash, pktlen);
		logger(LOG_INFO, message);
	}


	putPktAndFPsDesc(packet,pktlen,computedPacketHash,fptopkt,fpNum);	

   } else {

	FPEntryB pktFps[MAX_FP_PER_PKT];
	int i;
	unsigned char message[LOGSZ];
	struct timeval tiempo;
	unsigned int fpNum;

	if (pktlen < BETA) return; // Short packets are never optimized
	fpNum = calculateRelevantFPs(pktFps, packet, pktlen);
	pthread_mutex_lock(&pd->cerrojo);

	// Store packet in PS
	int64_t currPktId;
	currPktId = putPkt(&pd->ps,packet,pktlen,computedPacketHash);

	if (debugword & LOCAL_UPDATE_CACHE_MASK) {
		gettimeofday(&tiempo,NULL);
		sprintf(message, "[LOCAL UPDATE CACHE]: at %d.%d computedPacketHash %x len %d\n", tiempo.tv_sec, tiempo.tv_usec, computedPacketHash, pktlen);
		logger(LOG_INFO, message);
	}

	for (i=fpNum-1; i >= 0; i--) {
		putFP(pd->fps, &pd->ps, pktFps[i].fp, currPktId, pktFps[i].offset, &pd->compStats);
		if (debugword & LOCAL_UPDATE_CACHE_MASK) {
				sprintf(message, "[LOCAL UPDATE CACHE]: store FP %" PRIx64 " for hash %x pktId %" PRIu64 "\n",pktFps[i].fp, computedPacketHash, currPktId);
				logger(LOG_INFO, message);
		}
	}
	pthread_mutex_unlock(&pd->cerrojo);
   }
}

// update_caches takes an incoming uncompressed packet (packet, pktlen) and updates fingerprint pointers and packet cache
// PENDING: behaviour when a compressed packet includes uncached fingerprints
// PENDING: think of handling the same cache on both sides (merge with dedup.c)

void update_caches(pDeduplicator pd, unsigned char *packet, uint16_t pktlen) {

	unsigned char message[LOGSZ];
	struct timeval tiempo;
	uint32_t computedPacketHash;

	if (pktlen < BETA) return; // Short packets are never optimized

	if (debugword & UPDATE_CACHE_MASK) {
		gettimeofday(&tiempo,NULL);
		sprintf(message, "[UPDATE CACHE]: entering at %d.%d\n", tiempo.tv_sec, tiempo.tv_usec);
		logger(LOG_INFO, message);
	}
        MurmurHash3_x86_32  (packet, pktlen, SEED, (void *) &computedPacketHash);
	local_update_caches(pd, packet, pktlen, computedPacketHash);
	pd->compStats.inputBytes += pktlen;
	pd->compStats.outputBytes += pktlen;
	pd->compStats.processedPackets++;
	if (debugword & UPDATE_CACHE_MASK) {
		gettimeofday(&tiempo,NULL);
		sprintf(message, "[UPDATE CACHE]: exiting at %d.%d\n", tiempo.tv_sec, tiempo.tv_usec);
		logger(LOG_INFO, message);
	}
}

// Uncompress received optimized packet
// Input parameter: optpkt (pointer to an array of unsigned char holding an optimized packet).
// Input parameter: optlen (actual length of optimized packet -- 16 bit unsigned integer).
// Output parameter: packet (pointer to an array of unsigned char holding the uncompressed packet). VERY IMPORTANT: THE CALLER MUST ALLOCATE THIS ARRAY
// Output parameter: pktlen (actual length of uncompressed packet -- pointer to a 16 bit unsigned integer)
// Output parameter: status (pointer to UncompReturnStatus, holding the return status of the call. Must be allocated by caller.)
//                      status.code == UNCOMP_OK                packet successfully uncompressed, packet and pktlen output parameters updated
//                      status.code == UNCOMP_FP_NOT_FOUND      packet unsuccessfully uncompressed due to a fingerprint not found or not matching stored hash
//                                                              packet and pktlen not modified
//                                                              status.fp and status.hash hold the missed values
// This function also calls update_caches when the packet is successfully uncompressed, no need to call update_caches externally

extern void uncomp(pDeduplicator pd, unsigned char *packet, uint16_t *pktlen, unsigned char *optpkt, uint16_t optlen, UncompReturnStatus *status) {

   if (shared_dictionary_mode) {
	uint32_t hash;
	uint32_t computedPacketHash, sentPktHash;
	uint16_t offset;
	uint16_t orig = 0;
	uint16_t firstPassPktLen;
	unsigned int curr;
	uint16_t orig_optlen;
	unsigned char *orig_pkt;
        unsigned char message[LOGSZ];
	PktChunk fptopkt[MAX_FP_PER_PKT];
	PktFrag  pktfr[MAX_FP_PER_PKT];
	uint16_t fpNum;

	int failed;

	orig_optlen = optlen;
	orig_pkt = optpkt;

	// pthread_mutex_lock(&pd->cerrojo);

	optlen = orig_optlen;
	optpkt = orig_pkt;
	*pktlen=0;
	pd->compStats.inputBytes += optlen;
	pd->compStats.processedPackets++;


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

	sentPktHash = ntoh32(optpkt);
	optpkt += sizeof(uint32_t);
	optlen -= sizeof(uint32_t);
	offset = ntoh16(optpkt);
	optpkt += sizeof(uint16_t);
	optlen -= sizeof(uint16_t);

	if (offset > 0) {
        	if (offset > MAX_PKT_SIZE()) {
			pd->compStats.errorsPacketFormat++;
                        *pktlen = 0;
                        status->code = UNCOMP_BAD_PACKET_FORMAT;
                        // pthread_mutex_unlock(&pd->cerrojo);
                        return;
        	}
		// memcpy(packet+orig,optpkt,offset);
		orig += offset;
		*pktlen += offset;
		optpkt += offset;
		optlen -= offset;
	}

	failed = 0;
	fpNum = 0;
	while (optlen >= sizeof(uint64_t) + sizeof(uint32_t)+3*sizeof(uint16_t)) {
		PktChunk *fpt = &fptopkt[fpNum];

		fpt->fp = ntoh64(optpkt);

		optpkt += sizeof(uint64_t);
		optlen -= sizeof(uint64_t);

		fpt->hash = ntoh32(optpkt);
		optpkt += sizeof(uint32_t);
		optlen -= sizeof(uint32_t);


		fpt->left = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);

		fpt->right = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);

		if ((fpt->left > fpt->right) || (orig+fpt->right-fpt->left> MAX_PKT_SIZE())) {
			pd->compStats.errorsPacketFormat++;
			*pktlen = 0;
			status->code = UNCOMP_BAD_PACKET_FORMAT;
			// pthread_mutex_unlock(&pd->cerrojo);
			return;
		}

		orig += fpt->right-fpt->left+1;
		*pktlen += fpt->right-fpt->left+1;

		fpNum++;

		offset = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);
		if (offset == 0xffff) {
			if (orig+optlen> MAX_PKT_SIZE()) {
				pd->compStats.errorsPacketFormat++;
				*pktlen = 0;
				status->code = UNCOMP_BAD_PACKET_FORMAT;
				// pthread_mutex_unlock(&pd->cerrojo);
				return;
			}
			orig += optlen;
			*pktlen += optlen;
			optlen = 0;
		} else {
			if (orig+offset> MAX_PKT_SIZE()) {
				pd->compStats.errorsPacketFormat++;				
				*pktlen = 0;
				status->code = UNCOMP_BAD_PACKET_FORMAT;
				// pthread_mutex_unlock(&pd->cerrojo);
				return;
			}
			orig += offset;
			*pktlen += offset;
			optpkt += offset;
			optlen -= offset;
		}
	}

	if ((*pktlen> MAX_PKT_SIZE())|| (orig > MAX_PKT_SIZE())) {
		pd->compStats.errorsPacketFormat++;				
		*pktlen = 0;
		status->code = UNCOMP_BAD_PACKET_FORMAT;
		// pthread_mutex_unlock(&pd->cerrojo);
		return;
	}

	if ((curr=getPktsByFPsAndHash(fptopkt,fpNum,pktfr)) != fpNum) {
		*pktlen = 0;
		status->code = UNCOMP_FP_NOT_FOUND;
		pd->compStats.errorsMissingFP++;				
		PktChunk *fpt = &fptopkt[curr];
		status->fp = fpt->fp;
		status->hash = fpt->hash;
		// pthread_mutex_unlock(&pd->cerrojo);
		return;
	}

	orig = curr = 0;
	optlen = orig_optlen;
	optpkt = orig_pkt;
	firstPassPktLen = *pktlen;
	*pktlen=0;

	sentPktHash = ntoh32(optpkt);
	optpkt += sizeof(uint32_t);
	optlen -= sizeof(uint32_t);
	offset = ntoh16(optpkt);
	optpkt += sizeof(uint16_t);
	optlen -= sizeof(uint16_t);

	if (offset > 0) {
		memcpy(packet,optpkt,offset);
		orig += offset;
		*pktlen += offset;
		optpkt += offset;
		optlen -= offset;
	}

	while (optlen >= sizeof(uint64_t) + sizeof(uint32_t)+3*sizeof(uint16_t)) {

		PktFrag *fpt = &pktfr[curr];
		uint16_t left, right;
		failed = (fpt->pktFragLen == 0);
		if (failed) break;

		optpkt += sizeof(uint64_t);
		optlen -= sizeof(uint64_t);

		optpkt += sizeof(uint32_t);
		optlen -= sizeof(uint32_t);

		left = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);

		right = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);

		memcpy(packet+orig,fpt->pktFrag,right-left+1);

		orig += right-left+1;
		*pktlen += right-left+1;

		curr++;

		offset = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);
		if (offset == 0xffff) {
			memcpy(packet+orig,optpkt,optlen);
			orig += optlen;
			*pktlen += optlen;
			optlen = 0;
		} else {
			memcpy(packet+orig,optpkt,offset);
			orig += offset;
			*pktlen += offset;
			optpkt += offset;
			optlen -= offset;
		}
	}

	if (failed) {
		*pktlen = 0;
		status->code = UNCOMP_FP_NOT_FOUND;
		pd->compStats.errorsMissingFP++;				
		PktChunk *fpt = &fptopkt[curr];
		status->fp = fpt->fp;
		status->hash = fpt->hash;
		// pthread_mutex_unlock(&pd->cerrojo);
		return;
	}

	if (*pktlen > orig_optlen) pd->compStats.uncompressedPackets++;
	// pthread_mutex_unlock(&pd->cerrojo);
        MurmurHash3_x86_32  (packet, *pktlen, SEED, (void *) &computedPacketHash);
	if (computedPacketHash == sentPktHash) {
		pd->compStats.outputBytes += *pktlen;
		local_update_caches(pd,packet,*pktlen, computedPacketHash); 
		status->code = UNCOMP_OK;
	} else {
		// abort();
		pd->compStats.errorsPacketHash++;				
		*pktlen = 0;
		status->code = UNCOMP_BAD_PACKET_HASH;
	}

   } else {
	uint64_t tentativeFP;
	uint32_t hash;
	uint32_t tentativePktHash, computedPacketHash, sentPktHash;
	uint16_t offset;
	uint16_t orig = 0;
	FPEntryB *fpp;
	uint16_t left, right;
	unsigned char curr;
	uint16_t orig_optlen;
	unsigned char *orig_pkt;
        unsigned char message[LOGSZ];

	int failed;

	orig_optlen = optlen;
	orig_pkt = optpkt;

	pthread_mutex_lock(&pd->cerrojo);

		optlen = orig_optlen;
		optpkt = orig_pkt;
		pd->compStats.inputBytes += optlen;
		pd->compStats.processedPackets++;

		*pktlen=0;

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

		sentPktHash = ntoh32(optpkt);
		optpkt += sizeof(uint32_t);
		optlen -= sizeof(uint32_t);

		offset = ntoh16(optpkt);
		optpkt += sizeof(uint16_t);
		optlen -= sizeof(uint16_t);
		if (offset > 0) {
        		if (offset > MAX_PKT_SIZE()) {
				pd->compStats.errorsPacketFormat++;
                        *pktlen = 0;
                        status->code = UNCOMP_BAD_PACKET_FORMAT;
                        pthread_mutex_unlock(&pd->cerrojo);
                        return;
        		}
			memcpy(packet+orig,optpkt,offset);
			orig += offset;
			*pktlen += offset;
			optpkt += offset;
			optlen -= offset;
		}

		failed = 0;

		while (optlen >= sizeof(uint64_t) + sizeof(uint32_t)+3*sizeof(uint16_t)) {
			tentativeFP = ntoh64(optpkt);
			optpkt += sizeof(uint64_t);
			optlen -= sizeof(uint64_t);

			tentativePktHash = ntoh32(optpkt);
			optpkt += sizeof(uint32_t);
			optlen -= sizeof(uint32_t);


			fpp = getFPhash(pd->fps,&pd->ps,tentativeFP,tentativePktHash);

			if (fpp == NULL) {
				if (debugword & UNCOMP_MASK) {
					sprintf(message, "[UNCOMP]: cannot find FP/PktHash pair tentativeFP %" PRIx64 " tentativePktHash %x\n",tentativeFP,tentativePktHash);
					logger(LOG_INFO, message);
				}
				// *pktlen = 0;
				// status->code = UNCOMP_FP_NOT_FOUND;
				// decompStats.errorsMissingFP++;				
				// status->fp = tentativeFP;
				// status->hash = tentativePktHash;
				// pthread_mutex_unlock(&cerrojo);
				// return;
				failed = 1;
				break;
			}

			left = ntoh16(optpkt);
			optpkt += sizeof(uint16_t);
			optlen -= sizeof(uint16_t);

			right = ntoh16(optpkt);
			optpkt += sizeof(uint16_t);
			optlen -= sizeof(uint16_t);

			PktEntry *storedPkt;
			storedPkt = getPkt(&pd->ps,fpp->pktId);
			if ((left > right) || (right >= storedPkt->len) || (orig+right-left> MAX_PKT_SIZE())) {
				pd->compStats.errorsPacketFormat++;
				*pktlen = 0;
				status->code = UNCOMP_BAD_PACKET_FORMAT;
				pthread_mutex_unlock(&pd->cerrojo);
				return;
			}
			memcpy(packet+orig,storedPkt->pkt+left,right-left+1);
			orig += right-left+1;
			*pktlen += right-left+1;

			offset = ntoh16(optpkt);
			optpkt += sizeof(uint16_t);
			optlen -= sizeof(uint16_t);
			if (offset == 0xffff) {
				if (orig+optlen> MAX_PKT_SIZE()) {
					pd->compStats.errorsPacketFormat++;
					*pktlen = 0;
					status->code = UNCOMP_BAD_PACKET_FORMAT;
					pthread_mutex_unlock(&pd->cerrojo);
					return;
				}
				memcpy(packet+orig,optpkt,optlen);
				orig += optlen;
				*pktlen += optlen;
				optlen = 0;
			} else {
				if (orig+offset> MAX_PKT_SIZE()) {
					pd->compStats.errorsPacketFormat++;				
					*pktlen = 0;
					status->code = UNCOMP_BAD_PACKET_FORMAT;
					pthread_mutex_unlock(&pd->cerrojo);
					return;
				}
				memcpy(packet+orig,optpkt,offset);
				orig += offset;
				*pktlen += offset;
				optpkt += offset;
				optlen -= offset;
			}
		}

	if (failed) {
		*pktlen = 0;
		status->code = UNCOMP_FP_NOT_FOUND;
		pd->compStats.errorsMissingFP++;				
		status->fp = tentativeFP;
		status->hash = tentativePktHash;
		pthread_mutex_unlock(&pd->cerrojo);
		return;
	}

	assert(*pktlen <= MAX_PKT_SIZE());
	assert(orig <= MAX_PKT_SIZE());
	if (*pktlen > orig_optlen) pd->compStats.uncompressedPackets++;
	pthread_mutex_unlock(&pd->cerrojo);
        MurmurHash3_x86_32  (packet, *pktlen, SEED, (void *) &computedPacketHash);
	if (computedPacketHash == sentPktHash) {
		pd->compStats.outputBytes += *pktlen;
		local_update_caches(pd,packet,*pktlen, computedPacketHash); 
		status->code = UNCOMP_OK;
	} else {
		pd->compStats.errorsPacketHash++;				
		*pktlen = 0;
		status->code = UNCOMP_BAD_PACKET_HASH;
	}
   }
}

