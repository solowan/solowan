/*

  sessionmanager.h

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

#ifndef SESSIONMANAGER_H_
#define SESSIONMANAGER_H_
#define _GNU_SOURCE

#include <linux/types.h>

#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options

#include "session.h"

#define SESSIONBUCKETS 65536 // Number of buckets in the hash table for session.
#define TCP_SEQ_NUMBERS 4294967296
#define HALF_TCP_SEQ_NUMBER 2147483648
__u16 sessionhash(__u32 largerIP, __u16 largerIPPort, __u32 smallerIP,
		__u16 smallerIPPort);
void freemem(struct session_head *currentlist);
struct session *insertsession(__u32 largerIP, __u16 largerIPPort,
		__u32 smallerIP, __u16 smallerIPPort, int qnum);
struct session *getsession(__u32 largerIP, __u16 largerIPPort, __u32 smallerIP,
		__u16 smallerIPPort);
void clearsession(struct session *currentsession);
void sort_sockets(__u32 *largerIP, __u16 *largerIPPort, __u32 *smallerIP,
		__u16 *smallerIPPort, __u32 saddr, __u16 source, __u32 daddr,
		__u16 dest);
void initialize_sessiontable();
void clear_sessiontable();
struct session_head *getsessionhead(int i);
int cli_show_sessionss(int client_fd, char **parameters, int numparameters);
int updateseq(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph,
		struct session *thissession);
int sourceisclient(__u32 largerIP, struct iphdr *iph, struct session *thisession, int issyn);
int saveacceleratorid(__u32 largerIP, __u32 acceleratorID, struct iphdr *iph, struct session *thissession);
int checkseqnumber(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph, struct session *thissession);
int updateseqnumber(__u32 largerIP, struct iphdr *iph, struct tcphdr *tcph, struct session *thissession);

#endif /*SESSIONMANAGER_H_*/
