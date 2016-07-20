/*

  configure.c

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
#include <arpa/inet.h>
#include "logger.h"
#include "compression.h"
#include "deduplication.h"

#define MAX_LINE_LEN 256

int packetPipeline = 0;

unsigned round_down_to_power_of_2(unsigned x) {
  return 0x80000000u >> __builtin_clz(x);
}

int configure(char *path, __u32 *localID, __u32 *packet_number, __u32 *packet_size, __u32 *thr_num, __u32 *fpPerPkt, __u32 *fpsFactor){

	FILE *config_fp ;
	char line[MAX_LINE_LEN + 1] ;
	char *token ;
	config_fp = fopen( path, "r" ) ;
	__u32 tempIP = 0;
	int i = -1;
	int checked = 0;
	__u32 num_pkts = 0;
	__u32 pkt_size = 0;

	LOGDEBUG(lc_config, "Opening File %s",path);

	if(config_fp != NULL){
		while( fgets( line, MAX_LINE_LEN, config_fp ) != NULL ){

			token = strtok( line, "\t =\n\r" ) ; // get the first token
			if( token != NULL && token[0] != '#' ){// Not a comment

				LOGDEBUG(lc_config, "Setting %s: ",token);

				if (strcmp(token, "optimization") == 0){ // Set compression
					token = strtok( NULL, "\t =\n\r" );
					if(strcmp(token, "compression") == 0){
						LOGDEBUG(lc_config, "compression enabled ");
						compression_enable();
						deduplication_disable();
					}else if(strcmp(token, "deduplication") == 0){
						LOGDEBUG(lc_config, "deduplication enabled ");
						deduplication_enable();
						compression_disable();
					}else if(strcmp(token, "combined") == 0){
						LOGDEBUG(lc_config, "deduplication and compression enabled ");
						deduplication_enable();
						compression_enable();
					}else {
						compression_disable();
						deduplication_disable();
						if(strcmp(token, "pipeline") == 0){
							LOGDEBUG(lc_config, "pipeline debug mode enabled ");
							packetPipeline = 1;
						}
					}
				}
				else if (strcmp(token, "dictionary") == 0){ // Set dedulpication
					token = strtok( NULL, "\t =\n\r" ) ;
					if(strcmp(token, "shared") == 0){
						LOGDEBUG(lc_config, "shared dictionary enabled ");
						shareddict_enable();
					}else if(strcmp(token, "thread") == 0){
						LOGDEBUG(lc_config, "shared dictionary disabled ");
						shareddict_disable();
					}
				}
				else if (strcmp(token, "localid") == 0){
					token = strtok( NULL, "\t =\n\r");
					i = inet_pton(AF_INET, token, &tempIP);
					if(i==0){
						LOGDEBUG(lc_config, "No usable IP Address. %s", token);
					}else if(tempIP != 16777343UL && i){
						LOGDEBUG(lc_config, "%u", tempIP);
						LOGDEBUG(lc_config, "localid (IP format): %s", token);
						*localID = tempIP;
						checked = 1;
					}
				}
				else if (strcmp(token, "thrnum") == 0){
					token = strtok( NULL, "\t =\n\r");
					sscanf(token, "%u", thr_num);
					if(*thr_num>0){
						LOGDEBUG(lc_config, "%u", *thr_num);
						LOGDEBUG(lc_config, "Number of threads %u", *thr_num);
					}else{
						LOGDEBUG(lc_config, "Initialization: wrong number of threads: %s %u", token, *thr_num);
					}

				}
				else if (strcmp(token, "fp_per_pkt") == 0){
					token = strtok( NULL, "\t =\n\r");
					sscanf(token, "%u", fpPerPkt);
					if(*fpPerPkt>0){
                         *fpPerPkt = round_down_to_power_of_2(*fpPerPkt);
						LOGDEBUG(lc_config, "%u", *fpPerPkt);
						LOGDEBUG(lc_config, "Number of FP per packet %u", *fpPerPkt);
					}else{
						LOGDEBUG(lc_config, "Initialization: wrong number of FP per packet: %s %u", token, *fpPerPkt);
					}

				}
				else if (strcmp(token, "fps_factor") == 0){
					token = strtok( NULL, "\t =\n\r");
					sscanf(token, "%u", fpsFactor);
					if(*fpsFactor>0){
                        *fpsFactor = round_down_to_power_of_2(*fpsFactor);
						LOGDEBUG(lc_config, "%u", *fpsFactor);
						LOGDEBUG(lc_config, "FP hash table factor %u", *fpsFactor);
					}else{
						LOGDEBUG(lc_config, "Initialization: wrong number of FP hash table factor: %s %u", token, *fpsFactor);
					}

				}
				else if (strcmp(token, "num_pkt_cache_size") == 0){
					token = strtok( NULL, "\t =\n\r");
					sscanf(token, "%u", &num_pkts);
					if(num_pkts>0){
						*packet_number = round_down_to_power_of_2(num_pkts);
						LOGDEBUG(lc_config, "%u", num_pkts);
						LOGDEBUG(lc_config, "Hash table max number of packets: %u", *packet_number);
					}else{
						LOGDEBUG(lc_config, "Initialization: wrong memory size: %s %u", token, num_pkts);
					}

				}else if (strcmp(token, "pkt_size") == 0){
					token = strtok( NULL, "\t =\n\r");
					sscanf(token, "%u", &pkt_size);
					if(pkt_size>0){
						*packet_size = pkt_size;
						LOGDEBUG(lc_config, "%u", *packet_size);
					}else{
						LOGDEBUG(lc_config, "Initialization: wrong memory size: %s %u", token, pkt_size);
					}

				}
			}
		}
		fclose(config_fp);
		if(!checked){
			LOGDEBUG(lc_config, "Not defined 'localid' in the configuration file");
			return 1;
		}
	}else{
		LOGDEBUG(lc_config, "ERROR: Open File %s failed",path);
		return 1;
	}
	return 0;
}

