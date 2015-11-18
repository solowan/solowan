/*

  tcpoptions.h

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

#ifndef TCPOPTIONS_H_
#define TCPOPTIONS_H_
#define _GNU_SOURCE

#include <linux/types.h>

__u8 optlen(const __u8 *opt, __u8 offset);
__u64 __get_tcp_option(__u8 *ippacket, __u8 tcpoptnum);
int __set_tcp_option(__u8 *ippacket, unsigned int tcpoptnum, unsigned int tcpoptlen, u_int64_t tcpoptdata);
unsigned int getIPPlusTCPHeaderLength(__u8 *ippacket);
 
#endif /*TCPOPTIONS_H_*/
