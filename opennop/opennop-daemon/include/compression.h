/*

  compression.h

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

#ifndef COMPRESSION_H_
#define COMPRESSION_H_
#define _GNU_SOURCE

#include <linux/types.h>

#include "quicklz.h"

int cli_show_compression(int client_fd, char **parameters, int numparameters);
int cli_compression_enable(int client_fd, char **parameters, int numparameters);
int cli_compression_disable(int client_fd, char **parameters, int numparameters);
unsigned int tcp_compress(__u8 *ippacket, __u8 *lzbuffer, qlz_state_compress *state_compress);
int tcp_decompress(__u8 *ippacket, __u8 *lzbuffer, qlz_state_decompress *state_decompress);
int compression_enable();
int compression_disable();
extern int compression;

#endif /*COMPRESSION_H_*/
