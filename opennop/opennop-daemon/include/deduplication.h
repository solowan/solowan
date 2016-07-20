/*

  deduplication.h

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


#ifndef DEDUPLICATION_H_
#define DEDUPLICATION_H_

#include <linux/types.h>
#include <stdint.h>
#include "01dedup.h"
#include "solowan_rolling.h"

#define CHUNK 400
#define BUFFER_SIZE 1600

#define OK 1
#define ERROR -1
#define HASH_NOT_FOUND -2

typedef struct hashptr{
    uint16_t position;
    struct hashptr *next;
}hashptr;

extern hashtable ht;

int cli_reset_stats_in_dedup(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_show_stats_in_dedup(int client_fd, char **parameters, int numparameters);
int cli_show_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_out_dedup(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_show_stats_out_dedup(int client_fd, char **parameters, int numparameters);
int cli_show_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters);

int cli_show_deduplication(int client_fd, char **parameters, int numparameters);
int cli_deduplication_enable(int client_fd, char **parameters, int numparameters);
int cli_deduplication_disable(int client_fd, char **parameters, int numparameters);

unsigned int tcp_optimize(pDeduplicator pd, __u8 *ippacket, __u8 *buffered_packet);
int tcp_deoptimize(pDeduplicator pd, __u8 *ippacket, __u8 *buffered_packet);
unsigned int tcp_cache_deoptim(pDeduplicator pd, __u8 *ippacket);
unsigned int tcp_cache_optim(pDeduplicator pd, __u8 *ippacket);
int deduplication_enable();
int deduplication_disable();
int shareddict_enable();
int shareddict_disable();
extern int deduplication;
extern int shareddict;

extern int packetPipeline;

#endif /* DEDUPLICATION_H_ */
