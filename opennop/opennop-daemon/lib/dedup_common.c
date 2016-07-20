/*

  dedup_common.c

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
#include <sys/mman.h>
#include "solowan_rolling.h"
#include "MurmurHash3.h"
#include "logger.h"
#include "debugd.h"

static uint64_t fpfactors[BYTE_RANGE][BETA];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cerrojoComp = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cerrojoDesc = PTHREAD_MUTEX_INITIALIZER;
static unsigned int MAXPKTSIZE;
static unsigned int PKTSTORESIZE;
static unsigned int FPSTORESIZE;
static unsigned int FPPERPKT;
static unsigned int FPSFACTOR;

static PktStore psComp, psDesc;
static Statistics compSt, descSt;
static FPEntry *fpStoreComp, *fpStoreDesc;

unsigned int shared_dictionary_mode=false;

inline void hton16(unsigned char *p, uint16_t n) {
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline void hton32(unsigned char *p, uint32_t n) {
	*p++ = (n >> 24) & 0xff;
	*p++ = (n >> 16) & 0xff;
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline void hton64(unsigned char *p, uint64_t n) {
	*p++ = (n >> 56) & 0xff;
	*p++ = (n >> 48) & 0xff;
	*p++ = (n >> 40) & 0xff;
	*p++ = (n >> 32) & 0xff;
	*p++ = (n >> 24) & 0xff;
	*p++ = (n >> 16) & 0xff;
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline uint16_t ntoh16(unsigned char *p) {
        uint16_t res = *p++;
        return (res << 8) + *p;
}

inline uint32_t ntoh32(unsigned char *p) {
        uint32_t res = *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        return res;
}

inline uint64_t ntoh64(unsigned char *p) {
        uint64_t res = *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        return res;
}

inline uint32_t hashFPStore(uint64_t fp) {

    uint32_t h1, h2, h3, h4 ;
    fp = fp >> GAMMA;
    h1 = (uint32_t) (fp & 0xffffffff);
    h2 = (uint32_t) ((fp >> 32) & 0xffffffff);
    h3 = h1 ^ h2;
    h4 = h3 & (FPSTORESIZE-1);
    return h4 ^ (h3 >> 24);

}

// Full calculation of the initial Rabin fingerprint
inline static uint64_t full_rfp(unsigned char *p) {
	int i;
	uint64_t fp = 0;
	for (i=0;i<BETA;i++) {
		fp = (fp + fpfactors[p[i]][BETA-i-1]) & MOD_MASK;
	}
	return fp;
}

// Incremental calculation of a Rabin fingerprint
inline static uint64_t inc_rfp(uint64_t prev_fp, unsigned char new, unsigned char dropped) {
	uint64_t fp;
	fp = ((prev_fp - fpfactors[dropped][BETA-1])*P + new) & MOD_MASK;
	return fp;

}

// Auxiliary table for calculating fingerprints
static uint64_t fpfactors[BYTE_RANGE][BETA];

static void initDictionary(void) {
	int i,j;

 	// Packet Counter
        psComp.pktId = 1; // 0 means empty FPEntry
        // Packet store
        psComp.pkts = malloc(PKT_STORE_SIZE()*sizeof(PktEntry));

        if (psComp.pkts == NULL) {
                printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                abort();
        }

        for (i = 0; i < PKT_STORE_SIZE(); i++) {
                psComp.pkts[i].pkt = malloc(MAX_PKT_SIZE());
                if (psComp.pkts[i].pkt == NULL) {
                        printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                        abort();
                }
        }
        fpStoreComp = malloc(FP_STORE_SIZE()*sizeof(FPEntry));
        if (fpStoreComp == NULL) {
                printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                abort();
        }

        // Initialize FPStore
        for (i=0; i<FP_STORE_SIZE(); i++) {
                fpStoreComp[i].pkts = malloc(PKTS_PER_FP*sizeof(FPEntryB));
                if (fpStoreComp[i].pkts == NULL) {
                        printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                        abort();
                }
                for (j=0; j<PKTS_PER_FP; j++) {
                        fpStoreComp[i].pkts[j].pktId = 0;
                        fpStoreComp[i].pkts[j].fp = UINT64_MAX;
                }
        }
	memset(&compSt,0,sizeof(compSt));

 	// Packet Counter
        psDesc.pktId = 1; // 0 means empty FPEntry
        // Packet store
        psDesc.pkts = malloc(PKT_STORE_SIZE()*sizeof(PktEntry));

        if (psDesc.pkts == NULL) {
                printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                abort();
        }

        for (i = 0; i < PKT_STORE_SIZE(); i++) {
                psDesc.pkts[i].pkt = malloc(MAX_PKT_SIZE());
                if (psDesc.pkts[i].pkt == NULL) {
                        printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                        abort();
                }
        }
        fpStoreDesc = malloc(FP_STORE_SIZE()*sizeof(FPEntry));
        if (fpStoreDesc == NULL) {
                printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                abort();
        }

        // Initialize FPStore
        for (i=0; i<FP_STORE_SIZE(); i++) {
                fpStoreDesc[i].pkts = malloc(PKTS_PER_FP*sizeof(FPEntryB));
                if (fpStoreDesc[i].pkts == NULL) {
                        printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
                        abort();
                }
                for (j=0; j<PKTS_PER_FP; j++) {
                        fpStoreDesc[i].pkts[j].pktId = 0;
                        fpStoreDesc[i].pkts[j].fp = UINT64_MAX;
                }
        }
	memset(&descSt,0,sizeof(descSt));
}
void init_common(unsigned int pktStoreSize, unsigned int pktSize, unsigned int fpPerPkt, unsigned int fpsFactor, unsigned int shareddict) {

	int i,j;
	
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
                printf("Unable to lock all current and future pages in RAM memory\n");
                abort();
        }

	pthread_mutex_lock(&mutex);
	shared_dictionary_mode = shareddict;
        MAXPKTSIZE = pktSize;
        PKTSTORESIZE = pktStoreSize;
	FPPERPKT = (fpPerPkt <= MAX_FP_PER_PKT) ? fpPerPkt : MAX_FP_PER_PKT;
	FPSFACTOR = (fpsFactor <= MAX_FPS_FACTOR) ? fpsFactor : MAX_FPS_FACTOR;
        FPSTORESIZE = (fpPerPkt*PKTSTORESIZE*fpsFactor);

        // Initialize auxiliary table for calculating fingerprints
        for (i=0; i<BYTE_RANGE; i++) {
                fpfactors[i][0] = i;
                for (j=1; j<BETA; j++) {
                        fpfactors[i][j] = (fpfactors[i][j-1]*P) & MOD_MASK;
                }
        }
	if (shared_dictionary_mode) initDictionary();
	pthread_mutex_unlock(&mutex);

}

unsigned int MAX_PKT_SIZE(void) {return MAXPKTSIZE;}
unsigned int PKT_STORE_SIZE(void) {return PKTSTORESIZE;}
unsigned int FP_STORE_SIZE(void) {return FPSTORESIZE;}
unsigned int FP_PER_PKT(void) {return FPPERPKT;}
unsigned int FPS_FACTOR(void) {return FPSFACTOR;}

unsigned int calculateRelevantFPs(FPEntryB *fpma, unsigned char *packet, uint16_t pktlen) {

        uint64_t selectFPmask;
        uint64_t tentativeFP;
        int exploring, previous;
        int endLoop;
        unsigned int fpNum = 1;
        int iter = 0;

        // Calculate initial fingerprint
        fpma[0].fp = full_rfp(packet);
        fpma[0].offset = 0;
	
        selectFPmask = SELECT_FP_MASK;

        // Calculate other relevant fingerprints
        tentativeFP = fpma[0].fp;
        previous = exploring = BETA;
        endLoop = (exploring >= pktlen);
        while (!endLoop) {
                tentativeFP = inc_rfp(tentativeFP, packet[exploring], packet[exploring-BETA]);
                if (((tentativeFP & selectFPmask) == 0) && (exploring - previous >= BETA/2)) {
                       previous = exploring;
                       fpma[fpNum].fp = tentativeFP;
                       fpma[fpNum].offset = exploring-BETA+1;
                       fpNum++;
                }
                if (++exploring >= pktlen) {
                        if ((fpNum < FPPERPKT) && (iter < MAX_ITER)) {
                                tentativeFP = fpma[0].fp;
                                previous = exploring = BETA;
                                selectFPmask = selectFPmask << 1;
                                iter++;
                        } else endLoop = 1;
                } else endLoop = (fpNum == FPPERPKT);
        }
        return fpNum;
}

// UNSAFE FUNCTION, must be called inside code with locks
// getFPhash returns the FPEntryB given the FPStore, the PStore, the FP and the packet hash (returns NULL if not found) 
FPEntryB *getFPhash(FPStore fpStore, PktStore *pktStore, uint64_t fp, uint32_t pktHash) {
	uint32_t fpHash;
	FPEntry *fpp;
	int bkt;
	PktEntry *pkt;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];
	for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
		if (fpp->pkts[bkt].fp == fp) {
			pkt = getPkt(pktStore, fpp->pkts[bkt].pktId);
			if ((pkt != NULL) && (pkt->hash == pktHash)) break;
		}
	}
	if (bkt == PKTS_PER_FP) return (FPEntryB *) NULL; // Not found
	else return &fpp->pkts[bkt];
}

// UNSAFE FUNCTION, must be called inside code with locks
// getFPcontent returns the FPEntryB given the FPStore, the PStore, the FP and the packet chunk (returns NULL if not found) 
FPEntryB *getFPcontent(FPStore fpStore, PktStore *pktStore, uint64_t fp, unsigned char *chunk) {
	FPEntry *fpp;
	uint32_t fpHash;
	int bkt;
	PktEntry *pkt;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];
	for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
		if ((fpp->pkts[bkt].pktId > 0) && (fpp->pkts[bkt].fp == fp)) {
			pkt = getPkt(pktStore, fpp->pkts[bkt].pktId);
			if ((pkt != NULL) && !memcmp(chunk,pkt->pkt+fpp->pkts[bkt].offset,BETA)) break;
		}
	}
	if (bkt == PKTS_PER_FP) return (FPEntryB *) NULL; // Not found
	else return &fpp->pkts[bkt];
}

// UNSAFE FUNCTION, must be called inside code with locks
PktEntry *getPkt(PktStore *pktStore, int64_t pktId) {
	if (pktStore->pktId < pktId) return NULL;
	if (pktId < pktStore->pktId - PKTSTORESIZE) return NULL;
	// return &pktStore->pkts[pktId % PKTSTORESIZE];
	return &pktStore->pkts[pktId & (PKTSTORESIZE-1)];
}

// UNSAFE FUNCTION, must be called inside code with locks
int64_t putPkt(PktStore *pktStore, unsigned char *pkt, uint16_t pktlen, uint32_t pktHash) {
	// int32_t pktIdx = (int32_t) (pktStore->pktId % PKTSTORESIZE);
	int32_t pktIdx = (int32_t) (pktStore->pktId & (PKTSTORESIZE-1));
	memcpy(pktStore->pkts[pktIdx].pkt, pkt, pktlen);
	pktStore->pkts[pktIdx].len = pktlen;
	pktStore->pkts[pktIdx].hash = pktHash;
	return pktStore->pktId++;
}

// UNSAFE FUNCTION, must be called inside code with locks
void putFP(FPStore fpStore, PktStore *pktStore, uint64_t fp, int64_t pktId, uint16_t offset, Statistics *st) {
	int fpidx;
	int emptyPos = PKTS_PER_FP;
	PktEntry *pktE, *pktEbis;
	uint32_t fpHash;
	FPEntry *fpp;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];

	for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
 		if (fpp->pkts[fpidx].pktId < pktId - PKTSTORESIZE) fpp->pkts[fpidx].pktId = 0;
		if (fpp->pkts[fpidx].pktId == 0) emptyPos = fpidx;
	}

	// Search FP value
	for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
		if (fpp->pkts[fpidx].fp == fp) break;
	}
	if (fpidx == PKTS_PER_FP) { // FP value not present in database, store if possible
		if (emptyPos < PKTS_PER_FP) {
			fpp->pkts[emptyPos].fp = fp;
			fpp->pkts[emptyPos].pktId = pktId;
			fpp->pkts[emptyPos].offset = offset;
			st->numOfFPEntries++;
		} else  { // All bucket filled, we call this FP Hash collisions
			st->numberOfFPHashCollisions++;
		}
	} else { // FP value present in database. Update if not FP collision, else store if possible.
		pktE = getPkt(pktStore,pktId);
		pktEbis = getPkt(pktStore,fpp->pkts[fpidx].pktId);
		if ((pktE != NULL) && (pktEbis != NULL) && !memcmp(pktEbis->pkt+fpp->pkts[fpidx].offset,pktE->pkt+offset,BETA)) { // Not FP collision, update
			fpp->pkts[fpidx].fp = fp;
			fpp->pkts[fpidx].pktId = pktId;
			fpp->pkts[fpidx].offset = offset;
		} else { // FP collision, store if possible
			if (emptyPos < PKTS_PER_FP) {
				fpp->pkts[emptyPos].fp = fp;
				fpp->pkts[emptyPos].pktId = pktId;
				fpp->pkts[emptyPos].offset = offset;
				st->numOfFPEntries++;
			}
		}

	}

}

// Initialization tasks
pDeduplicator newDeduplicator(void) {
        


        int i, j;
	
	pDeduplicator pd;
	
	pd = malloc(sizeof(Deduplicator));
	if (pd == NULL) {
		printf("Unable to allocate memory");
		abort();
	}

        if (shared_dictionary_mode) pd->fps = NULL;
	else {
		// Packet Counter
		pd->ps.pktId = 1; // 0 means empty FPEntry
		// Packet store
 		pd->ps.pkts = malloc(PKT_STORE_SIZE()*sizeof(PktEntry));
	
        	if (pd->ps.pkts == NULL) {
			printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
			abort();
		}
		
        	for (i = 0; i < PKT_STORE_SIZE(); i++) {
                	pd->ps.pkts[i].pkt = malloc(MAX_PKT_SIZE());
                	if (pd->ps.pkts[i].pkt == NULL) {
				printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
				abort();
			}
        	}
        	pd->fps = malloc(FP_STORE_SIZE()*sizeof(FPEntry));
        	if (pd->fps == NULL) {
			printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
			abort();
		}
	
        	// Initialize FPStore
        	for (i=0; i<FP_STORE_SIZE(); i++) {
                	pd->fps[i].pkts = malloc(PKTS_PER_FP*sizeof(FPEntryB));
                	if (pd->fps[i].pkts == NULL) {
				printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
				abort();
			}
                	for (j=0; j<PKTS_PER_FP; j++) {
				pd->fps[i].pkts[j].pktId = 0;
				pd->fps[i].pkts[j].fp = UINT64_MAX;
                	}
        	}
	}

	pthread_mutex_init(&pd->cerrojo, NULL);

	// Initialize statistics
	memset((void *) &pd->compStats, 0, sizeof(pd->compStats));
	return pd;

}

void getStatistics(pDeduplicator pd, Statistics *cs) {
	pthread_mutex_lock(&pd->cerrojo);
	*cs = pd->compStats;
	pthread_mutex_unlock(&pd->cerrojo);
}
void resetStatistics(pDeduplicator pd) {
	pthread_mutex_lock(&pd->cerrojo);
	memset(&pd->compStats,0,sizeof(pd->compStats));
	pthread_mutex_unlock(&pd->cerrojo);
}
void getCompDictStatistics(Statistics *cs) {
	pthread_mutex_lock(&cerrojoComp);
	*cs = compSt;
	pthread_mutex_unlock(&cerrojoComp);
}
void getDescDictStatistics(Statistics *cs) {
	pthread_mutex_lock(&cerrojoDesc);
	*cs = descSt;
	pthread_mutex_unlock(&cerrojoDesc);
}

// Dictionary API

// Get all packets in the dictionary that match the set of fingerprints in a processed packet, 
//  verifying its associated data pattern to avoid collisions.
// Parameters:
// * unsigned char *pkt. Pointer to the packet the passed fingerprints belong to.
// * FPEntryB *fpa. Pointer to an array of FPEntryB structures, cointaining the computed fingerprints in the
//   passed packet (pkt). This structure must have been previously filled by a call to calculateRelevantFPs(), so
//   each entry have the following significant fields: fp, offset.
// * uint16_t fpNum. Number of entries of the array pointed by fpa.
// Results:
// * Returns an array of DictElement entries. Each entry has the following modified fields:
//   - pkt: pointer to a packet in the dictionary with a match to the fingerprint in the passed packet at offset field.
//   - pktLen: length of packet pointed in the pkt field or 0 if no match could be found.
//   - pktHash: hash of the packet in the dictionary.
//   - offset: where the packet in the dictionary has a match to the fingerprint in the passed packet.
void getPktsByFPsAndContent(unsigned char *pkt, uint16_t pktLen, uint32_t pktHash, FPEntryB *fpa, uint16_t fpNum, DictElement *returnParam) {
	int i;
        uint32_t fpHash;
        FPEntry *fpp;
        int bkt;
        PktEntry *pktE;

	pthread_mutex_lock(&cerrojoComp);
	for (i=0; i<fpNum; i++) {
        	fpHash = hashFPStore(fpa->fp);
        	fpp = &fpStoreComp[fpHash];
        	for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
                	if ((fpp->pkts[bkt].pktId > 0) && (fpp->pkts[bkt].fp == fpa->fp)) {
                        	pktE = getPkt(&psComp,fpp->pkts[bkt].pktId);
                        	if ((pktE != NULL) && !memcmp(pkt+fpa->offset,pktE->pkt+fpp->pkts[bkt].offset,BETA)) break;
                	}
        	}
        	if (bkt == PKTS_PER_FP) { // Packet not found
			returnParam->pktLen = 0;
		} else {
			returnParam->pktLen = pktE->len;
			memcpy(returnParam->pkt,pktE->pkt,pktE->len);
			returnParam->pktHash = pktE->hash;
			returnParam->offset = fpp->pkts[bkt].offset;

		}
		fpa++;
		returnParam++;
	}
	pthread_mutex_unlock(&cerrojoComp);
}


// Get all packets in the dictionary that match the set of fingerprints in a processed packet, 
//  verifying its associated packet hash.
// Parameters:
// * PktChunk *fpa. Pointer to an array of PktChunk structures, cointaining the received fingerprint references 
//   in a compressed packet. The relevant fields in each structure are:
//   - fp. The fingerprint.
//   - hash. Hash of the packet the fingerprint fp is associated to.
//   - left. Left limit of the matched packet content.
//   - right. Right limit of the matched packet content.
// * uint16_t fpNum. Number of entries of the array pointed by fpa.
// Results:
// * Returns fpNum if all the references have been found in the dictionary. Else, the index in the array of
//   structures fpa of the failed match.
// * Returns the pa array of PktFrag structures. Each entry has the following modified fields:
//   - pktFrag: pointer to a packet fragment in the dictionary with a match to the fingerprint in the passed packet.
//   - pktFragLen: length of returned packet fragment (must be right - left + 1 if OK)
int getPktsByFPsAndHash(PktChunk *fpa, uint16_t fpNum, PktFrag *pf) {
	uint32_t fpHash;
	FPEntry *fpp;
	int bkt, i;
	PktEntry *pkt;

	pthread_mutex_lock(&cerrojoDesc);
	for (i=0; i<fpNum; i++) {
		fpHash = hashFPStore(fpa->fp);
		fpp = &fpStoreDesc[fpHash];
		for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
			if (fpp->pkts[bkt].fp == fpa->fp) {
				pkt = getPkt(&psDesc,fpp->pkts[bkt].pktId);
				if ((pkt != NULL) && (pkt->hash == fpa->hash)) break;
			}
		}
		if ((bkt == PKTS_PER_FP) || (fpa->right > pkt->len)) { // Not found or right limit greater than stored packet length
			pf->pktFragLen = 0;
			break;
		} else {
			pf->pktFragLen = fpa->right - fpa->left + 1;
			memcpy(pf->pktFrag,pkt->pkt+fpa->left,pf->pktFragLen);
		}
		fpa++;
		pf++;
	}
	pthread_mutex_unlock(&cerrojoDesc);
	return i;
}

// Store a packet and its associated fingerprints in the dictionary.
// Parameters:
// * unsigned char *pkt. Pointer to the packet to be stored.
// * uint16_t pktlen. Length of the packet to be stored.
// * uint32_t computedPacketHash. Hash of the packet to be stored.
// * FPEntryB *fpa. Pointer to an array of structures with the fingerprints associated to the packet. This array must 
//   be filled with a call to calculateRelevantFPs().
// * uint16_t fpNum. Number of entries in array fpa. Caller must ensure that it is not greater than MAX_FP_PER_PKT.
void putPktAndFPsComp(unsigned char *pkt, uint16_t pktlen, uint32_t computedPacketHash, FPEntryB *fpa, uint16_t fpNum) {

	int fpidx;
	int emptyPos = PKTS_PER_FP;
	PktEntry *pktE, *pktEbis;
	uint32_t fpHash;
	FPEntry *fpp;
	int i;
	int32_t pktIdx;

	pthread_mutex_lock(&cerrojoComp);
	// pktIdx = (int32_t) (psComp.pktId % PKTSTORESIZE);
	pktIdx = (int32_t) (psComp.pktId & (PKTSTORESIZE-1));
	memcpy(psComp.pkts[pktIdx].pkt, pkt, pktlen);
	psComp.pkts[pktIdx].len = pktlen;
	psComp.pkts[pktIdx].hash = computedPacketHash;

	for (i=0;i<fpNum;i++) {
		fpHash = hashFPStore(fpa->fp);
		fpp = &fpStoreComp[fpHash];

		for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
 			if (fpp->pkts[fpidx].pktId < psComp.pktId - PKTSTORESIZE) fpp->pkts[fpidx].pktId = 0;
			if (fpp->pkts[fpidx].pktId == 0) {emptyPos = fpidx; break;}
		}

		// Search FP value
		for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
			if (fpp->pkts[fpidx].fp == fpa->fp) break;
		}
		if (fpidx == PKTS_PER_FP) { // FP value not present in database, store if possible
			if (emptyPos < PKTS_PER_FP) {
				fpp->pkts[emptyPos].fp = fpa->fp;
				fpp->pkts[emptyPos].pktId = psComp.pktId;
				fpp->pkts[emptyPos].offset = fpa->offset;
				compSt.numOfFPEntries++;
			} else  { // All bucket filled, we call this FP Hash collisions
				compSt.numberOfFPHashCollisions++;
			}
		} else { // FP value present in database. Update if not FP collision, else store if possible.
			pktE = getPkt(&psComp,psComp.pktId);
			pktEbis = getPkt(&psComp,fpp->pkts[fpidx].pktId);
			if ((pktE != NULL) && (pktEbis != NULL) && !memcmp(pktEbis->pkt+fpp->pkts[fpidx].offset,pktE->pkt+fpa->offset,BETA)) { // Not FP collision, update
				fpp->pkts[fpidx].fp = fpa->fp;
				fpp->pkts[fpidx].pktId = psComp.pktId;
				fpp->pkts[fpidx].offset = fpa->offset;
			} else { // FP collision, store if possible
				if (emptyPos < PKTS_PER_FP) {
					fpp->pkts[emptyPos].fp = fpa->fp;
					fpp->pkts[emptyPos].pktId = psComp.pktId;
					fpp->pkts[emptyPos].offset = fpa->offset;
					compSt.numOfFPEntries++;
				}
			}
	
		}
		fpa++;
	}

	compSt.lastPktId = psComp.pktId++;
	pthread_mutex_unlock(&cerrojoComp);

}

void putPktAndFPsDesc(unsigned char *pkt, uint16_t pktlen, uint32_t computedPacketHash, FPEntryB *fpa, uint16_t fpNum) {

	int fpidx;
	int emptyPos = PKTS_PER_FP;
	PktEntry *pktE, *pktEbis;
	uint32_t fpHash;
	FPEntry *fpp;
	int i;
	int32_t pktIdx;

	pthread_mutex_lock(&cerrojoDesc);
	// pktIdx = (int32_t) (psDesc.pktId % PKTSTORESIZE);
	pktIdx = (int32_t) (psDesc.pktId & (PKTSTORESIZE-1));
	memcpy(psDesc.pkts[pktIdx].pkt, pkt, pktlen);
	psDesc.pkts[pktIdx].len = pktlen;
	psDesc.pkts[pktIdx].hash = computedPacketHash;

	for (i=0;i<fpNum;i++) {
		fpHash = hashFPStore(fpa->fp);
		fpp = &fpStoreDesc[fpHash];

		for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
 			if (fpp->pkts[fpidx].pktId < psDesc.pktId - PKTSTORESIZE) fpp->pkts[fpidx].pktId = 0;
			if (fpp->pkts[fpidx].pktId == 0) {emptyPos = fpidx; break;}
		}

		// Search FP value
		for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
			if (fpp->pkts[fpidx].fp == fpa->fp) break;
		}
		if (fpidx == PKTS_PER_FP) { // FP value not present in database, store if possible
			if (emptyPos < PKTS_PER_FP) {
				fpp->pkts[emptyPos].fp = fpa->fp;
				fpp->pkts[emptyPos].pktId = psDesc.pktId;
				fpp->pkts[emptyPos].offset = fpa->offset;
				descSt.numOfFPEntries++;
			} else  { // All bucket filled, we call this FP Hash collisions
				descSt.numberOfFPHashCollisions++;
			}
		} else { // FP value present in database. Update if not FP collision, else store if possible.
			pktE = getPkt(&psDesc,psDesc.pktId);
			pktEbis = getPkt(&psDesc,fpp->pkts[fpidx].pktId);
			if ((pktE != NULL) && (pktEbis != NULL) && !memcmp(pktEbis->pkt+fpp->pkts[fpidx].offset,pktE->pkt+fpa->offset,BETA)) { // Not FP collision, update
				fpp->pkts[fpidx].fp = fpa->fp;
				fpp->pkts[fpidx].pktId = psDesc.pktId;
				fpp->pkts[fpidx].offset = fpa->offset;
			} else { // FP collision, store if possible
				if (emptyPos < PKTS_PER_FP) {
					fpp->pkts[emptyPos].fp = fpa->fp;
					fpp->pkts[emptyPos].pktId = psDesc.pktId;
					fpp->pkts[emptyPos].offset = fpa->offset;
					descSt.numOfFPEntries++;
				}
			}
	
		}
		fpa++;
	}

	descSt.lastPktId = psDesc.pktId++;
	pthread_mutex_unlock(&cerrojoDesc);

}
