/**** st-base.c **********************************************************\
 * Aristos Miliaressis                                         5/3/2015  *
 *                                                                       *
 *                                                                       *
 * ********************************************************************* *
 * *****************************  *********        ********************* *
 * *****************************  ************  ************************ *
 * *****************************  ************  ********************  ** *
 * **   ***  **  *  * ***    ***  ***   ******  ******   ***  *  **    * *
 * *  *  ******        **  *  **  **  *  *****  *****  *  **  *  ***  ** *
 * **  ****  **  *  *  **  *  **  **     *****  *****     ***   ****  ** *
 * ***  ***  **  *  *  **    ***  **  ********  *****  ******   ****  ** *
 * *  *  **  **  *  *  **  *****  **  *  *****  *****  *  **  *  ***  ** *
 * **   ***  **  *  *  **  *****  ***   ******  ******   ***  *  ***   * *
 * ********************************************************************* *
\*************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include "st-daemon.h"
#include "st-ui.h"
#include "st-http.h"

static int start_listen (unsigned short);

int main (int argc, char * argv[])
{
	int i, status, lsockfd, csockfd;  /* local/connection socket file descriptor */
	struct sockaddr_in raddr;      /* remote address object */
	socklen_t raddr_len = sizeof (struct sockaddr_in);
	pthread_t connThread;   /* thread identifier */
	User_Settings * o_stngs; /* user suplied settings struct (stores user settings)*/

	/* set global variables */
	server = "simpleText";
	version = 1.0f;

	/* allocate user suplied settings struct */
	o_stngs = malloc(sizeof(User_Settings));

	/* read configuration file */
	read_conf_file (o_stngs);

	/* parse and set cli options */
	parse_cli_opts (argc, (char **) &argv[0], o_stngs);

	/* make daemon and start logging */
	status = init_daemon (server, o_stngs);
  if (status == 1)
		return EXIT_SUCCESS; /* parent returns success */
	else if (status == -1)
		return EXIT_FAILURE; /* parent returns failure */

	syslog (LOG_NOTICE, "[PID: %u, SID: %u] > %s started..",
					getpid (), getsid (getpid ()), server);

	/* Read Hosts File */
	host_cnt = read_host_file (NULL, 1);
	for (i = 0; i < host_cnt; i++)
		read_host_file (&o_vhost[i], 0);

	/* start listening for TCP connections */
	lsockfd = start_listen (o_stngs->port);
	free(o_stngs);

	/* loop through accepting and handling connections */
	while (1)
	{
		/* accept connection or skip to next conection if accept fails */
		csockfd = accept (lsockfd, (struct sockaddr *) &raddr, &raddr_len);
		if (csockfd == -1) /* if connection fails ignore it and continue */
			continue;

		Connect_Args * o_args = malloc(sizeof(Connect_Args *));
		o_args->socket = csockfd;
		strcpy (o_args->client_addr, inet_ntoa (raddr.sin_addr));

		/* create thread to handle connection */
		pthread_create(&connThread, NULL, (void *) &attent_connection, o_args);

		/* wait for one second before accepting next connection */
		sleep (1);
	}
}

/***********************************************************\
 * static int start_listen (unsigned short)                *
 *                                                         *
 * Creates a TCP socket binds to user provided port other  *
 * default port 80 or dynamic port 0 if port 80 is already *
 * in use and starts listening for connections             *
 *                                                         *
 * returns socket descriptor on success or calls           *
 * `terminate()` on fail                                   *
\***********************************************************/
static int start_listen (unsigned short port)
{
	struct sockaddr_in laddr;
	socklen_t laddr_len = sizeof (struct sockaddr);
	unsigned short dflt_port = port;
	int lsockfd;

	/* create TCP socket */
	lsockfd = socket (PF_INET, SOCK_STREAM, 0);
	if (lsockfd == -1)
	{
		syslog (LOG_ERR, "[Error: %s] > Creating TCP socket", strerror(errno));
		terminate (1);
	}
	syslog (LOG_DEBUG, "Created TCP socket for listening");

	/* set local address */
	memset (&laddr, 0, laddr_len);
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons (port);
	laddr.sin_addr.s_addr = htonl (INADDR_ANY);

	/* bind to port */
	do
	{
		bind (lsockfd, (struct sockaddr *) &laddr, laddr_len);
		if (errno == 0) /* Bind successfull */
		{
			break;
		}
		else if (errno != EADDRINUSE) /* Other error */
		{
			syslog (LOG_ERR, "[Error: %s] > Binding socket to TCP port %hu", strerror(errno), port);
			terminate (1);
		}

		/* Address already in use */
		if (ntohs (laddr.sin_port) == dflt_port)
			syslog (LOG_INFO, "Port %hu is already in use switching to dynamic port", dflt_port);

		/* Set dynamic port */
		laddr.sin_port = htons (0);
	errno = 0; /* Reset errno */
	}
	while (errno != EADDRINUSE)
	syslog (LOG_DEBUG, "Server socket binded to address localhost:%hu", ntohs(laddr.sin_port));

	/* listen for connections */
	if (listen (lsockfd, SOMAXCONN) == -1)
	{
		syslog (LOG_ERR, "[Error: %s] > Opening TCP socket for listening", strerror(errno));
		terminate (1);
	}
	syslog (LOG_INFO, "Started listening at localhost:%hu", ntohs (laddr.sin_port));

	return lsockfd;
}
