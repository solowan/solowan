/*

  opennop.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: Improved shell with history and completion

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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h> // for multi-threading
#include <pty.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include "clisocket.h"
#include "climanager.h"
#include "debugd.h"

#define TERMINAL_NAME   "opennopd#"
#define HISTORY_FILE	"opennop_history"


static int masterfd = -1;
static int slavefd;
static int cli_client_fd;

/* The terminal attributes before calling tty_cbreak */
static struct termios save_termios;
static struct winsize win_size;
static enum
{ RESET, TCBREAK } ttystate = RESET;

/*functions for completion feature */
char *fun_traces();
char *fun_reset();
char *fun_show(); 
char *fun_comp_dedup();
char *fun_traces_enable();
char *fun_traces_disable();
char *fun_traces_mask(); 
char *fun_show_traces();
char *fun_show_reset_stats();

typedef char **CPPFunction ();

bool hasparam;
char *hist_file;


/* Commands and options for completion feature */
COMMAND commands[] = {
  { "show", fun_show, "Show" },
  { "traces", fun_traces, "Traces" },
  { "reset", fun_reset, "Reset" },
  { "compression", fun_comp_dedup, "Compression" },
  { "deduplication", fun_comp_dedup, "Deduplication" },
  { "quit", (Function *)NULL, "Quit" },
  { "?", (Function *)NULL, "Help" },
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

/* Parameters for trace command */
COMMAND traces_options[] = {
  { "enable", fun_traces_enable, "Enable" },
  { "disable", fun_traces_disable, "Disable"},
  { "mask", fun_traces_mask, "Mask"},
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

/* Parameters for show command */
COMMAND show_options[] = {
  { "traces", fun_show_traces, "Show traces"},
  { "stats", fun_show_reset_stats, "Show stats" },
  { "version", (Function *)NULL, "Show version" },
  { "compression", (Function *)NULL, "Show compression" },
  { "workers", (Function *)NULL, "Show workers" },
  { "fetcher", (Function *)NULL, "Show fetcher" },
  { "sessions", (Function *)NULL, "Show sessions" },
  { "deduplication", (Function *)NULL, "Show deduplication" },
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

/* Parameters for compression and deduplication commands */
COMMAND comp_dedup_options[] = {
  { "enable", (Function *)NULL, "Compression enable" },
  { "disable", (Function *)NULL, "Compression disable" },
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

/* Parameters for 'traces enable' command */
COMMAND traces_enable_options[] = {
        { "mask", (Function *)NULL, "MASK" },
        { "update_cache", (Function *)NULL, "UPDATE_CACHE_MASK" },
        { "local_update_cache", (Function *)NULL, "LOCAL_UPDATE_CACHE_MASK" },
        { "update_cache_rtx", (Function *)NULL, "UPDATE_CACHE_RTX_MASK" },
        { "dedup", (Function *)NULL, "DEDUP_MASK" },
        { "put_in_cache", (Function *)NULL, "PUT_IN_CACHE_MASK" },
        { "uncomp", (Function *)NULL, "UNCOMP_MASK" },
        { (char *)NULL, (Function *)NULL, (char*) NULL }
};

/* Parameters for 'traces disable' command */
COMMAND traces_disable_options[] = {
        { "update_cache", (Function *)NULL, "UPDATE_CACHE_MASK" },
        { "local_update_cache", (Function *)NULL, "LOCAL_UPDATE_CACHE_MASK" },
        { "update_cache_rtx", (Function *)NULL, "UPDATE_CACHE_RTX_MASK" },
        { "dedup", (Function *)NULL, "DEDUP_MASK" },
        { "put_in_cache", (Function *)NULL, "PUT_IN_CACHE_MASK" },
        { "uncomp", (Function *)NULL, "UNCOMP_MASK" },
        { (char *)NULL, (Function *)NULL, (char*) NULL }
};

/* Parameters for 'show traces' command */
COMMAND show_traces_options[] = {
        { "mask", (Function *)NULL, "MASK" },
        { (char *)NULL, (Function *)NULL, (char*) NULL }
};

/* Parameters for 'traces mask' command */
COMMAND traces_mask_options[] = {
        { "orr", (Function *)NULL, "traces mask orr" },
        { "and", (Function *)NULL, "traces mask and" },
        { "nand", (Function *)NULL, "traces mask nand" },
        { (char *)NULL, (Function *)NULL, (char*) NULL }
};

/* Parameters for reset command */
COMMAND reset_options[] = {
  { "stats", fun_show_reset_stats, "reset stats" },
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

/* Parameters for 'show stats' and 'reset stats' command */
COMMAND show_reset_stats_options[] = {
  { "in_dedup", (Function *)NULL, "reset stats in_dedup" },
  { "out_dedup", (Function *)NULL, "reset stats out_dedup" },
  { "in_dedup_thread", (Function *)NULL, "reset stats in_dedup_thread" },
  { "out_dedup_thread", (Function *)NULL, "reset stats out_dedup_thread" },
  { (char *)NULL, (Function *)NULL, (char *)NULL }
};

bool find_end_of_command(char *message) {
	if (strstr(message, END_OF_COMMAND) != NULL)
		return true;
	else
		return false;
}

void display_line(char* mensaje){
                 char *found;
                 char *attrVal;
                 char new_line = '\n';
                 size_t len = 0;
                 char *buffer = NULL;
                 char *temp_buffer = NULL;
                 buffer = malloc(MAX_BUFFER_SIZE);

                 memcpy(buffer, mensaje, MAX_BUFFER_SIZE);
		 buffer[strlen(mensaje)] = '\0';
		 temp_buffer =  buffer;

		 if ((found = strchr(temp_buffer, new_line)) == NULL) {
			if (find_end_of_command(temp_buffer)) {
				temp_buffer[strlen(temp_buffer)- strlen(END_OF_COMMAND) - 1] = '\0';
			}
			rl_message("%s \n", temp_buffer);
		 }
                 while((found = strchr(temp_buffer, new_line)) != NULL)
                 {
                            len = found - temp_buffer;
                            attrVal = malloc(len + 1);
                            memcpy(attrVal, temp_buffer, len);
                            attrVal[len] = '\0';
			    
			    if (find_end_of_command(attrVal)) {
				if (len > strlen(END_OF_COMMAND)) {
					attrVal[len - strlen(END_OF_COMMAND) - 1] = '\0';
                            		rl_message("%s \n", attrVal);
			 	        rl_clear_message ();
				}
			    } else {
                            	rl_message("%s \n", attrVal);
		 	    	rl_clear_message ();
			    }	
                            temp_buffer=temp_buffer+len+1;
                            free(attrVal);
                 }
        if (find_end_of_command(temp_buffer)) {
		if (strlen(temp_buffer) > strlen(END_OF_COMMAND) + 1) 
			rl_message("%s \n", temp_buffer);
	}
	if (buffer != NULL)
		free (buffer);
		
}

void *server_cmd_handler(void *dummyPtr) {
	int client_fd = *(int*)dummyPtr;
	int length;
	char server_reply[MAX_BUFFER_SIZE] = { 0 };

	if (hasparam)
	{
	   while (((length = recv(client_fd, server_reply, MAX_BUFFER_SIZE, 0)) >= 0)
                       && (client_fd != 0)) {
		if (length > 0) {
			server_reply[length]='\0';
			if (find_end_of_command(server_reply)) {
				server_reply[length - strlen(END_OF_COMMAND) -1] = '\0';
                                fprintf(stdout, "%s", server_reply);
                                fflush(stdout);
				break;
			}
                                fprintf(stdout, "%s", server_reply);
                                fflush(stdout);
		}
                else
                {
                        if (length < 0)
                                perror("[cli_client]: recv");
                        else
                                fprintf(stdout, "server closed connection\n");
                        exit(1);
                }

	   }
	} else { //Has no param
	   while (1) {
		rl_clear_message ();
		if (((length = recv(client_fd, server_reply, MAX_BUFFER_SIZE, 0)) >= 0)
				&& (client_fd != 0)) {
			if (length > 0) {
			 rl_clear_message();
                         server_reply[length] = '\0';
                         display_line(server_reply);
	//		 rl_clear_message ();
			} 
			else if (length < 0)
			{
				perror("[cli_client]: recv");
				return (void *)-1;
			}
		}
	   }
	}
	return 0;
}

/* tty_reset: Sets the terminal attributes back to their previous state.
 * PRE: tty_cbreak must have already been called.
 *
 * fd    - The file descrioptor of the terminal to reset.
 *
 * Returns: 0 on success, -1 on error
 */
int tty_reset (int fd) {
    if (ttystate != TCBREAK)
        return (0);

    if (tcsetattr (fd, TCSAFLUSH, &save_termios) < 0)
        return (-1);

    ttystate = RESET;

    return 0;
}

void sigint (int s) {
    tty_reset (STDIN_FILENO);
    close (masterfd);
    close (slavefd);
    printf ("\n");
    exit (0);
}

static void rlctx_send_user_command (char *line) {
    /* This happens when rl_callback_read_char gets EOF */
    if (line == NULL)
        return;


    if ((strcmp (line, "exit") == 0) || (strcmp (line, "quit") == 0) || (strcmp (line, "quit ") == 0))
    {
        tty_reset (STDIN_FILENO);
        close (masterfd);
        close (slavefd);
        printf ("\n");
        exit (0);
    }

    if (send (cli_client_fd, line, strlen (line), 0) == -1)
    {
        //sprintf(stdout,"%s", "Error in sending data ");
        printf("Error in sending data ");
        exit(1);
    }
    /* Don't add the enter command */
    if (line && *line != '\0')
    {
        add_history (line);
	if (hist_file != NULL)
	    write_history(hist_file);
    }
}

static void
custom_deprep_term_function ()
{
}

static int readline_input () {
    const int MAX = 1024;
    char *buf = (char *) malloc (MAX + 1);
    int size;

    size = read (masterfd, buf, MAX);
    if (size == -1)
    {
        free (buf);
        buf = NULL;
        return -1;
    }

    buf[size] = 0;

    /* Display output from readline */
    if (size > 0)
        fprintf (stderr, "%s", buf);

    free (buf);
    buf = NULL;
    return 0;
}

char * dupstr (s)
     char *s;
{
  char *r;

  r = malloc (strlen (s) + 1);
  strcpy (r, s);
  return (r);
}

COMMAND * find_cli_command (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; commands[i].name; i++)
    if (strcmp (name, commands[i].name) == 0)
      return (&commands[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_traces_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; traces_options[i].name; i++)
    if (strcmp (name, traces_options[i].name) == 0)
      return (&traces_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_show_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; show_options[i].name; i++)
    if (strcmp (name, show_options[i].name) == 0)
      return (&show_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_traces_enable_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; traces_enable_options[i].name; i++)
    if (strcmp (name, traces_enable_options[i].name) == 0)
      return (&traces_enable_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_traces_disable_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; traces_disable_options[i].name; i++)
    if (strcmp (name, traces_disable_options[i].name) == 0)
      return (&traces_disable_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_show_traces_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; show_traces_options[i].name; i++)
    if (strcmp (name, show_traces_options[i].name) == 0)
      return (&show_traces_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_traces_mask_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; traces_mask_options[i].name; i++)
    if (strcmp (name, traces_mask_options[i].name) == 0)
      return (&traces_mask_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_reset_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; reset_options[i].name; i++)
    if (strcmp (name, reset_options[i].name) == 0)
      return (&reset_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_show_reset_stats_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; show_reset_stats_options[i].name; i++)
    if (strcmp (name, show_reset_stats_options[i].name) == 0)
      return (&show_reset_stats_options[i]);

  return ((COMMAND *)NULL);
}

COMMAND * find_comp_dedup_options (char *name) {
  register int i;

  if (name == NULL)
	return ((COMMAND *)NULL);

  for (i = 0; comp_dedup_options[i].name; i++)
    if (strcmp (name, comp_dedup_options[i].name) == 0)
      return (&comp_dedup_options[i]);

  return ((COMMAND *)NULL);
}

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *
stripwhite (string)
     char *string;
{
  register char *s, *t;

  for (s = string; whitespace (*s); s++)
    ;

  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && whitespace (*t))
    t--;
  *++t = '\0';

  return s;
}


/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
char * command_generator (text, state)
     char *text;
     int state;
{
  static int list_index, len;
  char *name;
  COMMAND *mycommand = NULL;
  char *token, *token2, *saved_token;
  char *nombre;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */
  if (!state)
    {
      list_index = 0;
      len = strlen (text);
    }
	char *line_buffer_cp;
	line_buffer_cp = strdup(rl_line_buffer);

	token = strtok_r (line_buffer_cp, " ", &saved_token);
	if (token == NULL){
		/* Return the next name which partially matches from the command list. */
		while ((name = commands[list_index].name))
		{
			list_index++;
			if (strncmp (name, text, len) == 0) {
				if (line_buffer_cp != NULL)
					free (line_buffer_cp);
				return (dupstr(name));
			}
		}
		if (line_buffer_cp != NULL)
			free (line_buffer_cp);
		return ((char *) NULL);
	}
	if ((mycommand = find_cli_command(token)) !=NULL) {
		token2 = strtok_r(NULL, " ", &saved_token);
		if (mycommand->func == NULL) {
			if (line_buffer_cp != NULL)
				free (line_buffer_cp);
			return ((char *) NULL);
		}
		nombre = (*(mycommand->func))(token2, &list_index, len, text, saved_token);
		if (line_buffer_cp != NULL)
			free (line_buffer_cp);
		return nombre;
	}
	else
	{
		/* Return the next name which partially matches from the command list. */
		while ((name = commands[list_index].name))
		{
			list_index++;
			if (strncmp (name, text, len) == 0) {
				if (line_buffer_cp != NULL)
					free (line_buffer_cp);
				return (dupstr(name));
			}
		}
	}

  /* If no names matched, then return NULL. */
  if (line_buffer_cp != NULL)
    free (line_buffer_cp);
  return ((char *)NULL);
}


/* Attempt to complete on the contents of TEXT.  START and END show the
   region of TEXT that contains the word to complete.  We can use the
   entire line in case we want to do some simple parsing.  Return the
   array of matches, or NULL if there aren't any. */
char ** opennop_completion (text, start, end)
     char *text;
     int start, end;
{
  char **matches;

  matches = (char **)NULL;

  /* If this word is at the start of the line, then it is a command
     to complete.  Otherwise it is the name of a file in the current
     directory. */
//  if (start == 0)
    //matches = completion_matches (text, command_generator); DFC
    matches = rl_completion_matches (text, command_generator);

  return (matches);
}


static int init_readline (int inputfd, int outputfd) {
    FILE *inputFILE, *outputFILE;

    inputFILE = fdopen (inputfd, "r");
    if (!inputFILE)
        return -1;

    outputFILE = fdopen (outputfd, "w");
    if (!outputFILE)
        return -1;

    rl_instream = inputFILE;
    rl_outstream = outputFILE;
    /* Tell readline what the prompt is if it needs to put it back */
    rl_callback_handler_install ("opennopd#", rlctx_send_user_command);

    /* Set the terminal type to dumb so the output of readline can be
     * understood by tgdb */
    if (rl_reset_terminal ("dumb") == -1)
        return -1;

    /* For some reason, readline can not deprep the terminal.
     * However, it doesn't matter because no other application is working on
     * the terminal besides readline */

    rl_deprep_term_function = custom_deprep_term_function;

    //Function called on completion
    rl_attempted_completion_function = (CPPFunction *)opennop_completion;

    if (hist_file != NULL)
            read_history(hist_file);
    using_history ();
    return 0;
}

static int user_input (cli_fd) {
    int size;
    const int MAX = 1024;
    char *buf = NULL;
    buf = (char *) malloc (MAX + 1);

    size = read (STDIN_FILENO, buf, MAX);
    if (size == -1) {
	if (buf != NULL)
	    free (buf);
        return -1;
    }

    size = write (masterfd, buf, size);
    if (size == -1) {
	if (buf != NULL)
	    free (buf);
        return -1;
    }

    if (buf != NULL)
        free (buf);
    return 0;
}

static int main_loop (int cli_fd) {
    fd_set rset;
    int max;

    max = (masterfd > STDIN_FILENO) ? masterfd : STDIN_FILENO;
    max = (max > slavefd) ? max : slavefd;
    max = (max > cli_fd) ? max : cli_fd;

    for (;;)
    {
        /* Reset the fd_set, and watch for input from GDB or stdin */
        FD_ZERO (&rset);
        FD_SET (STDIN_FILENO, &rset);
        FD_SET (slavefd, &rset);
        FD_SET (masterfd, &rset);
        FD_SET (cli_fd, &rset);

        /* Wait for input */
        if (select (max + 1, &rset, NULL, NULL, NULL) == -1)
        {
            if (errno == EINTR)
                continue;
            else
                return -1;
        }

        /* Input received through the pty:  Handle it
         * Wrote to masterfd, slave fd has that input, alert readline to read it.
         */
        if (FD_ISSET (slavefd, &rset))
            rl_callback_read_char ();

        /* Input received through the pty.
         * Readline read from slavefd, and it wrote to the masterfd.
         */
        if (FD_ISSET (masterfd, &rset))
            if (readline_input () == -1)
                return -1;
        /* Input received:  Handle it, write to masterfd (input to readline) */
        if (FD_ISSET (STDIN_FILENO, &rset))
            if (user_input (cli_fd) == -1)
                return -1;
    }

    return 0;

}

/* tty_cbreak: Sets terminal to cbreak mode. Also known as noncanonical mode.
 *    1. Signal handling is still turned on, so the user can still type those.
 *    2. echo is off
 *    3. Read in one char at a time.
 *
 * fd    - The file descriptor of the terminal
 *
 * Returns: 0 on sucess, -1 on error
 */
int tty_cbreak (int fd) {
    struct termios buf;

    if (tcgetattr (fd, &save_termios) < 0)
        return -1;

    buf = save_termios;
    buf.c_lflag &= ~(ECHO | ICANON);
    buf.c_iflag &= ~(ICRNL | INLCR);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;

#if defined (VLNEXT) && defined (_POSIX_VDISABLE)
    buf.c_cc[VLNEXT] = _POSIX_VDISABLE;
#endif

#if defined (VDSUSP) && defined (_POSIX_VDISABLE)
    buf.c_cc[VDSUSP] = _POSIX_VDISABLE;
#endif

    /* enable flow control; only stty start char can restart output */
#if 0
    buf.c_iflag |= (IXON | IXOFF);
#ifdef IXANY
    buf.c_iflag &= ~IXANY;
#endif
#endif

    /* disable flow control; let ^S and ^Q through to pty */
    buf.c_iflag &= ~(IXON | IXOFF);
#ifdef IXANY
    buf.c_iflag &= ~IXANY;
#endif

    if (tcsetattr (fd, TCSAFLUSH, &buf) < 0)
        return -1;

    ttystate = TCBREAK;

    /* set size */
    if (ioctl (fd, TIOCGWINSZ, (char *) &win_size) < 0)
        return -1;

#ifdef DEBUG
    err_msg ("%d rows and %d cols\n", size.ws_row, size.ws_col);
#endif

    return (0);
}

int tty_off_xon_xoff (int fd) {
    struct termios buf;

    if (tcgetattr (fd, &buf) < 0)
        return -1;

    buf.c_iflag &= ~(IXON | IXOFF);

    if (tcsetattr (fd, TCSAFLUSH, &buf) < 0)
        return -1;

    return 0;
}

static int run_main_cli (int client_fd) {
    int val;

    val = openpty (&masterfd, &slavefd, NULL, NULL, NULL);
    if (val == -1)
        return -1;

    val = tty_off_xon_xoff (masterfd);
    if (val == -1)
        return -1;

    val = init_readline (slavefd, slavefd);
    if (val == -1)
        return -1;

    val = tty_cbreak (STDIN_FILENO);
    if (val == -1)
        return -1;

    signal (SIGINT, sigint);

    val = main_loop (client_fd);

    tty_reset (STDIN_FILENO);

    if (val == -1)
        return -1;

    return 0;
}

int main(int argc, char *argv[]) {
	int length;
	struct sockaddr_un server;
	pthread_t t_fromserver;

	//if ((cli_client_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	if ((cli_client_fd = socket(AF_UNIX, SOCK_STREAM, TCP_NODELAY)) == -1) {
		perror("[cli_client]: socket");
		exit(1);
	}

	//fprintf(stdout, "\n Connecting to OpenNOP CLI... \n");
	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, OPENNOP_SOCK);
	length = strlen(server.sun_path) + sizeof(server.sun_family);

	if (connect(cli_client_fd, (struct sockaddr *) &server, length) == -1) {
		perror("[cli_client]: Connect");
		exit(1);
	}

	//fprintf(stdout, " Connected.....\n");
	
	hasparam = argc >=2;

	char * home = getenv("HOME");
	if (home != NULL){
		hist_file = malloc(strlen(home) + strlen(HISTORY_FILE) + 3);
		sprintf(hist_file,"%s/.%s", home, HISTORY_FILE);
	}
	else
		hist_file = NULL;

	pthread_create(&t_fromserver, NULL, server_cmd_handler, (void *)&cli_client_fd);

	if (argc < 2)
	{
           hasparam = false;		
	   run_main_cli (cli_client_fd);
	} else {
		hasparam = true;
		char comando [400] = { 0 };
		strcpy(comando, "");
		int i = 0;
		for (i=1; i < argc; i++)
		{
			strcat(comando, argv[i]);
			strcat(comando, " ");
       	        }
                if (send(cli_client_fd, comando, strlen(comando), 0) == -1) {
                        perror("[cli_client]: send");
                        exit(1);
                }

        }

	pthread_join(t_fromserver, NULL);

	close(cli_client_fd);
	
	//shutdown(cli_client_fd,2);
	exit(0);
}

char *fun_show (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token)
{
	char *name, *nombre;
	COMMAND *mycommand = NULL;
	if (arg != NULL) {
			if ((mycommand = find_show_options(arg)) !=NULL) 
			{
				if (mycommand->func == NULL)
					return ((char *)NULL);
                		nombre = (*(mycommand->func))(arg_saved_token, arg_list_index, arg_len, arg_text, arg_saved_token);
                		return nombre;
			}
			while ((name = show_options[*arg_list_index].name))
			{
				*arg_list_index = *arg_list_index + 1;
				if (strncmp (name, arg_text, arg_len) == 0)
				return (dupstr(name));
			}
	} else {
		while ((name = show_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char *fun_traces (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	COMMAND *mycommand = NULL;
	if (arg != NULL) {
			if ((mycommand = find_traces_options(arg)) !=NULL) 
			{
				if (mycommand->func == NULL)
					return ((char *)NULL);
                		nombre = (*(mycommand->func))(arg_saved_token, arg_list_index, arg_len, arg_text, arg_saved_token);
                		return nombre;
			}
			while ((name = traces_options[*arg_list_index].name))
			{
				*arg_list_index = *arg_list_index + 1;
				if (strncmp (name, arg_text, arg_len) == 0)
				return (dupstr(name));
			}
	} else {
		while ((name = traces_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char *fun_reset (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	COMMAND *mycommand = NULL;
	if (arg != NULL) {
			if ((mycommand = find_reset_options(arg)) !=NULL) 
			{
				if (mycommand->func == NULL)
					return ((char *)NULL);
                		nombre = (*(mycommand->func))(arg_saved_token, arg_list_index, arg_len, arg_text, arg_saved_token);
                		return nombre;
			}
			while ((name = reset_options[*arg_list_index].name))
			{
				*arg_list_index = *arg_list_index + 1;
				if (strncmp (name, arg_text, arg_len) == 0)
				return (dupstr(name));
			}
	} else {
		while ((name = reset_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char *fun_comp_dedup (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_comp_dedup_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = comp_dedup_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = comp_dedup_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char* fun_traces_enable  (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_traces_enable_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = traces_enable_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = traces_enable_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char* fun_traces_disable  (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_traces_disable_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = traces_disable_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = traces_disable_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char* fun_traces_mask  (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_traces_mask_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = traces_mask_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = traces_mask_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char* fun_show_traces  (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_show_traces_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = show_traces_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = show_traces_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

char* fun_show_reset_stats  (char *arg, int *arg_list_index, int arg_len, char *arg_text, char *arg_saved_token) {
	char *name, *nombre;
	char *token3 = NULL;
	char *saved_token3;
	COMMAND *mycommand = NULL;

	if (arg != NULL) {
		token3 = strtok_r(arg, " ", &saved_token3);
                if ((mycommand = find_show_reset_stats_options(token3)) !=NULL)
                {
                	if (mycommand->func == NULL){
                		return ((char *)NULL);
			}
                        nombre = (*(mycommand->func))(token3, arg_list_index, arg_len, arg_text, arg_saved_token);
                        return nombre;
                }
		while ((name = show_reset_stats_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	} else {
		while ((name = show_reset_stats_options[*arg_list_index].name))
		{
			*arg_list_index = *arg_list_index + 1;
			if (strncmp (name, arg_text, arg_len) == 0)
			return (dupstr(name));
		}
	}

	return ((char *)NULL);
}

