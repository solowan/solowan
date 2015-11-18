/*

  clicommands.h

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: <mod_description>

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm.

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad
    Politecnica de Madrid which aims to experiment with open-source based WAN
    optimization solutions.

  References:

    OpenNOP: http://www.opennop.org
    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es

  License:

    OpenNOP and OpenNOP-SoloWAN are free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP and OpenNOP-SoloWAN are distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef	_CLI_COMMANDS_H_
#define	_CLI_COMMANDS_H_

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include <linux/types.h>

#include "clisocket.h"

typedef int (*t_commandfunction)(int, char **, int);

struct command_head
{
    struct command *next; // Points to the first command of the list.
    struct command *prev; // Points to the last command of the list.
    pthread_mutex_t lock; // Lock for this node.
};

struct command {
	char *command;
	t_commandfunction command_handler;
	struct command *next;
	struct command *prev;
	struct command_head child;
	bool hasparams;
	bool hidden;
};

int cli_help();
struct command* lookup_command(const char *command_name);
int execute_commands(int client_fd, const char *command_name, int d_len);
int register_command(const char *command_name, t_commandfunction handler_function,bool,bool);
struct command* find_command(struct command_head *node, char *command_name);
int cli_prompt(int client_fd);
int cli_node_help(int client_fd, struct command_head *currentnode);
int cli_show_param(int client_fd, char **parameters, int numparameters);
void bytestostringbps(char *output, __u64 count);
int cli_send_feedback(int client_fd, char *msg);

#endif
