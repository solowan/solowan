/*

  debugd.c

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


#include "debugd.h"
#include "solowan_rolling.h"
#include "clisocket.h"
#include "clicommands.h"
#include "climanager.h"
#include "worker.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<unistd.h>   
#include<ctype.h>   
#include<pthread.h>   

uint64_t debugword  = 0;
static int socket_desc , c;
static struct sockaddr_in server , client;
static pthread_t thread_id;

static int zero = 0;

TRACECOMMAND trace_commands[] = {
        { "update_cache", UPDATE_CACHE_MASK, "UPDATE_CACHE_MASK", 0 },
        { "local_update_cache", LOCAL_UPDATE_CACHE_MASK, "LOCAL_UPDATE_CACHE_MASK", 2 },
        { "update_cache_rtx", UPDATE_CACHE_RTX_MASK, "UPDATE_CACHE_RTX_MASK", 4 },
        { "dedup", DEDUP_MASK, "DEDUP_MASK", 6 },
        { "put_in_cache", PUT_IN_CACHE_MASK, "PUT_IN_CACHE_MASK", 8 },
        { "uncomp", UNCOMP_MASK, "UNCOMP_MASK", 12 },
        { (char *)NULL, 0, (char*) NULL, 0 }
};


void *debugd_conn_process(void *arg) {
	#define MAX_CMD_LEN 64
	#define CMD_LEN 4
	#define STATS_BUF 2000
	unsigned char buf[MAX_CMD_LEN];
	unsigned char statsbuf[STATS_BUF];
	int bread, i;
	uint64_t argument, result;
	int fd = (int) arg;

	while (1) {
		memset(buf,0, MAX_CMD_LEN);
		do {
			bread = recv(fd, buf, MAX_CMD_LEN-1, 0);
		}while ((bread < CMD_LEN) && (bread > 0)) ;		
		result = debugword;
		if (bread <= 0) {
			close (fd);
			pthread_exit(&zero);
		} 
		for (i=0; i<bread; i++) buf[i] = toupper(buf[i]);	
		if (!memcmp(SET_DCMD,buf,CMD_LEN)) {
			sscanf(buf+CMD_LEN,"%" SCNx64 "",&argument);
			debugword = argument;
			result = debugword ;
		} else if (!memcmp(GET_DCMD,buf,CMD_LEN)) {
			result = debugword;
		} else if (!memcmp(ORR_DCMD,buf,CMD_LEN)) {
			sscanf(buf+CMD_LEN,"%" SCNx64 "",&argument);
			debugword |= argument;
			result = debugword;
		} else if (!memcmp(AND_DCMD,buf,CMD_LEN)) {
			sscanf(buf+CMD_LEN,"%" SCNx64 "",&argument);
			debugword &= argument;
			result = debugword;
		} else if (!memcmp(NAND_DCMD,buf,CMD_LEN)) {
			sscanf(buf+CMD_LEN,"%" SCNx64 "",&argument);
			debugword &= ~argument;
			result = debugword;
		} else if (!memcmp(QUIT_DCMD,buf,CMD_LEN)) {
			close (fd);
			pthread_exit(&zero);
		} else if (!memcmp(RSTC_SCMD, buf, CMD_LEN)) {
			int si;
			for (si=0;si<get_workers();si++) resetStatistics(get_worker_compressor(si));
		} else if (!memcmp(GSTC_SCMD, buf, CMD_LEN)) {
			Statistics cs;
			int si;
			for (si=0;si<get_workers(); si++) {
				getStatistics(get_worker_compressor(si),&cs);
				memset(statsbuf, 0, STATS_BUF);
				sprintf(statsbuf,"Compressor statistics (thread %d) \n", si);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"total_input_bytes.value %" PRIu64 " \n", cs.inputBytes);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"total_output_bytes.value %" PRIu64 "\n", cs.outputBytes);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"processed_packets.value %" PRIu64 "\n", cs.processedPackets);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"compressed_packets.value %" PRIu64 "\n", cs.compressedPackets);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_entries.value %" PRIu64 "\n", cs.numOfFPEntries);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"last_pktId.value %" PRIu64 "\n", cs.lastPktId);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_hash_collisions.value %" PRIu64 "\n", cs.numberOfFPHashCollisions);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_collisions.value %" PRIu64 "\n", cs.numberOfFPCollisions);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"short_packets.value %" PRIu64 "\n", cs.numberOfShortPkts);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"------------------------------------------------------------------\n");
				write(fd,statsbuf,strlen(statsbuf));
			}
			if (shared_dictionary_mode) {
				getCompDictStatistics(&cs);
				sprintf(statsbuf,"lastPktId.value %" PRIu64 "\n", cs.lastPktId);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_hash_collisions.value %" PRIu64 "\n", cs.numberOfFPHashCollisions);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_collisions.value %" PRIu64 "\n", cs.numberOfFPCollisions);
				write(fd,statsbuf,strlen(statsbuf));
			}
		} else if (!memcmp(RSTD_SCMD, buf, CMD_LEN)) {
			int si;
			for (si=0;si<get_workers();si++) resetStatistics(get_worker_decompressor(si));
		} else if (!memcmp(GSTD_SCMD, buf, CMD_LEN)) {
			Statistics ds;
			int si;
			for (si=0;si<get_workers(); si++) {
				getStatistics(get_worker_decompressor(si),&ds);
				memset(statsbuf, 0, STATS_BUF);
				sprintf(statsbuf,"Decompressor statistics (thread %d)\n",si);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"total_input_bytes.value %" PRIu64 " \n", ds.inputBytes);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"total_output_bytes.value %" PRIu64 "\n", ds.outputBytes);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"processed_packets.value %" PRIu64 "\n", ds.processedPackets);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"uncompressed_packets.value %" PRIu64 "\n", ds.uncompressedPackets);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_entries_not_found.value %" PRIu64 "\n", ds.errorsMissingFP);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"packet_hashes_not_found.value %" PRIu64 "\n", ds.errorsMissingPacket);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"bad_packet_format.value %" PRIu64 "\n", ds.errorsPacketFormat);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"bad_packet_hash.value %" PRIu64 "\n", ds.errorsPacketHash);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"------------------------------------------------------------------\n");
				write(fd,statsbuf,strlen(statsbuf));
			}
			if (shared_dictionary_mode) {
				getDescDictStatistics(&ds);
				sprintf(statsbuf,"lastPktId.value %" PRIu64 "\n", ds.lastPktId);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_hash_collisions.value %" PRIu64 "\n", ds.numberOfFPHashCollisions);
				write(fd,statsbuf,strlen(statsbuf));
				sprintf(statsbuf,"FP_collisions.value %" PRIu64 "\n", ds.numberOfFPCollisions);
				write(fd,statsbuf,strlen(statsbuf));
			}	
		}	
		memset(buf,0, MAX_CMD_LEN);
		sprintf(buf,"Current debug mask %" PRIx64 "\n",result);
		write(fd,buf,strlen(buf));
	}
}

void *debugd_conn_server (void) {
	int fd;
	while ((fd=accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c)) >=0) {
		pthread_t th;
		if (pthread_create(&th, NULL, debugd_conn_process, (void *) fd) < 0) {
			printf("Could not start debug conn thread\n");
		}
	}
	printf("Could not start debug conn thread\n");
	abort();
}


void init_debugd(void) {

	debugword = 0;
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1) {
		printf("Could not create debug socket\n");
		abort();
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;	
	server.sin_port = htons(SOLOWAN_DEBUGD_PORT);
 	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
		printf("Could not bind debug socket\n");
		abort();
    	}
	listen(socket_desc, 3);
	if (pthread_create(&thread_id, NULL, debugd_conn_server, (void *) NULL) < 0) {
		printf("Could not start debug thread\n");
		abort();
	}
}

TRACECOMMAND * find_trace_command (char *name) {
  register int i;

  for (i = 0; trace_commands[i].name; i++)
    if (strcmp (name, trace_commands[i].name) == 0)
      return (&trace_commands[i]);

  return ((TRACECOMMAND *)NULL);
}

void print_traces_help(int client_fd, bool hasnumber) { //hasnumber true if the command allows a number as parameter
        char msg[MAX_BUFFER_SIZE] = { 0 };
        int i;

        if (hasnumber) {
                sprintf(msg,"[1]: [Number(1..3)]\n");
                cli_send_feedback(client_fd, msg);
                for (i=0; trace_commands[i].name; i++) {
                        sprintf(msg,"[%d]: %s\n", i+2, trace_commands[i].name);
                        cli_send_feedback(client_fd, msg);
                }
        } else {
                for (i=0; trace_commands[i].name; i++) {
                        sprintf(msg,"[%d]: %s\n", i+1, trace_commands[i].name);
                        cli_send_feedback(client_fd, msg);
                }

        }
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
}

int validate_traces_level (int client_fd, char *level)
{
        char msg[MAX_BUFFER_SIZE] = { 0 };
        int argument, result;
        argument = atoi(level);
        if (argument == 0 && level[0] != '0'){
                sprintf(msg,"Command needs a number.\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                return CLI_ERROR;
        } else {
                result = argument ;
                if  (result > 0 && result < 4) {
                        return argument;
                } else {
                        sprintf(msg,"Level traces between 1 and 3\n");
                        cli_send_feedback(client_fd, msg);
                        sprintf(msg,"-------------------------------------------------------------------------------\n");
                        cli_send_feedback(client_fd, msg);
                        return CLI_ERROR;
                }
        }
        return CLI_ERROR;
}


int cli_traces_enable(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
        int argument, result;
        uint64_t level, val ;
        TRACECOMMAND *mytracecommand;

        if (numparameters == 1) {
                argument = atoi(parameters[0]);
                if (argument == 0 && parameters[0][0] != '0'){
                        print_traces_help(client_fd, true);
                        return CLI_ERR_CMD;
                } else {
                        result = argument ;
                                switch (result) {
                                        case 1:
                                                debugword = 0x1555;
                                                cli_show_traces_mask(client_fd, NULL, 0);
                                                break;
                                        case 2:
                                                debugword = 0x2aaa;
                                                cli_show_traces_mask(client_fd, NULL, 0);
                                                break;
                                        case 3:
                                                debugword = 0xffff;
                                                cli_show_traces_mask(client_fd, NULL, 0);
                                                break;
                                        default:
                                                sprintf(msg,"Level traces between 1 and 3\n");
                                                cli_send_feedback(client_fd, msg);
                                                sprintf(msg,"-------------------------------------------------------------------------------\n");
                                                cli_send_feedback(client_fd, msg);
                                                break;
                                }
                        return CLI_SUCCESS;
                }

        } else if (numparameters == 2) {
                if (strcmp(parameters[0], "mask") == 0) {
                        sscanf(parameters[1], "%" SCNx64 "",&level);
                        debugword = level;
                        val = debugword ;
                        sprintf(msg,"Traces mask changed to %" PRIx64 "\n", val);
                        cli_send_feedback(client_fd, msg);
                        cli_show_traces_mask(client_fd, NULL, 0);
                        return CLI_SUCCESS;
                }
                if ((level = validate_traces_level(client_fd, parameters[1])) == CLI_ERROR)
                       return level;
                if ((mytracecommand = find_trace_command(parameters[0])) != NULL) {
                        sprintf(msg,"Traces '%s' changed to %d\n", mytracecommand->name, (int)level);
                        cli_send_feedback(client_fd, msg);
                        debugword = (debugword & ~mytracecommand->mask) + (level << mytracecommand->offset_bits);
                        cli_show_traces_mask(client_fd, NULL, 0);
                } else {
                        sprintf(msg,"Mask not found: %s\n",parameters[0]);
                        cli_send_feedback(client_fd, msg);
                        print_traces_help(client_fd, false);
			return CLI_ERR_CMD;
                }

                return 0;

        } else  {
                print_traces_help(client_fd, true);
                return CLI_ERR_CMD;
        }
}

int cli_traces_disable(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        TRACECOMMAND *mytracecommand;
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
        if (numparameters == 0) {
                debugword = 0;
                cli_show_traces_mask(client_fd, NULL, 0);
                return CLI_SUCCESS;

        } else if (numparameters == 1) {
                if ((mytracecommand = find_trace_command(parameters[0])) != NULL) {
                        sprintf(msg,"Traces '%s' disable\n", mytracecommand->name);
                        cli_send_feedback(client_fd, msg);
                        debugword = (debugword & ~mytracecommand->mask);
                        cli_show_traces_mask(client_fd, NULL, 0);
                	return CLI_SUCCESS;
                } else {
                        sprintf(msg,"Mask not found: %s\n",parameters[0]);
                        cli_send_feedback(client_fd, msg);
                        print_traces_help(client_fd, false);
                	return CLI_ERR_CMD;
                }
                return CLI_SUCCESS;

        } else  {
                print_traces_help(client_fd, false);
                return CLI_ERR_CMD;
        }
}

int cli_show_traces_mask (int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        uint64_t result;
        int i;

        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);
        result = debugword ;
        sprintf(msg,"Current debug mask %" PRIx64 "\n",result);
        cli_send_feedback(client_fd, msg);
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

        for (i = 0; trace_commands[i].name; i++){
                result = (debugword & trace_commands[i].mask) >> trace_commands[i].offset_bits ;
                sprintf(msg,"%-25s:%" PRIx64 "\n", trace_commands[i].doc, result);
                cli_send_feedback(client_fd, msg);
        }
        sprintf(msg,"-------------------------------------------------------------------------------\n");
        cli_send_feedback(client_fd, msg);

        return CLI_SUCCESS;
}
int cli_traces_mask_orr(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        uint64_t argument, result;
        if (numparameters == 1) {
                sscanf(*parameters, "%" SCNx64 "",&argument);
                debugword |= argument;
                result = debugword ;
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"Traces mask changed to %" PRIx64 "\n", result);
                cli_send_feedback(client_fd, msg);
                cli_show_traces_mask(client_fd, NULL, 0);
                return CLI_SUCCESS;

        } else {
                sprintf(msg,"Incorrect number of parameters. Command 'traces mask orr' needs 1 parameter.\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                return CLI_ERR_CMD;
        }

}
int cli_traces_mask_and(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        uint64_t argument, result;
        if (numparameters == 1) {
                sscanf(*parameters, "%" SCNx64 "",&argument);
                debugword &= argument;
                result = debugword ;
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"Traces mask changed to %" PRIx64 "\n", result);
                cli_send_feedback(client_fd, msg);
		cli_show_traces_mask(client_fd, NULL, 0);
                return CLI_SUCCESS;
        } else {
                sprintf(msg,"Incorrect number of parameters. Command 'traces mask and' needs 1 parameter.\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                return CLI_ERR_CMD;
        }

}

int cli_traces_mask_nand(int client_fd, char **parameters, int numparameters) {
        char msg[MAX_BUFFER_SIZE] = { 0 };
        uint64_t argument, result;
        if (numparameters == 1) {
                sscanf(*parameters, "%" SCNx64 "",&argument);
                debugword &= ~argument;
                result = debugword ;
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"Traces mask changed to %" PRIx64 "\n", result);
                cli_send_feedback(client_fd, msg);
                cli_show_traces_mask(client_fd, NULL, 0);
                return CLI_SUCCESS;

        } else {
                sprintf(msg,"Incorrect number of parameters. Command 'traces mask nand' needs 1 parameter.\n");
                cli_send_feedback(client_fd, msg);
                sprintf(msg,"-------------------------------------------------------------------------------\n");
                cli_send_feedback(client_fd, msg);
                return CLI_ERR_CMD;
        }

}



