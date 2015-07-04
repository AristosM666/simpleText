/**** st-daemon.c *********************************\
 * Aristos Miliaressis                 11/3/2015  *
\**************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include "st-daemon.h"

#ifdef BSD
	#include <sys/ioctl.h>
#endif

/* global pid filename array (for `terminate()`) */
char pid_file[256];

/* static function declarations */
static void signal_callback_handler (int);
static int creat_lock_file (char *);
static int get_lock_file_status (char *);

/***************************************************************\
 * int init_daemon (const char *, User_Settings *)             *
 *                                                             *
 * Expects an identity tag for syslog, it forks daemon,        *
 * changes working directory, starts syslog connection,        *
 * redirects standard file handlers to `/dev/null`,            *
 * sets up signal handlers and creates a lock file.            *
 *                                                             *
 * parent returns 0 on success and -1 on fail, child           *
 * returns 0 on success or exits on fail                       *
\***************************************************************/
int init_daemon (const char * identity, User_Settings * o_stngs)
{
	pid_t pid;
	int fd;

	strncpy(pid_file, o_stngs->pid_file_name, sizeof(pid_file));

	/* Exit if other instance already running */
  if (get_lock_file_status (o_stngs->pid_file_name) == -1)
	{
		if (errno == EWOULDBLOCK)
			printf ("An instance of %s is already running..\n", identity);
		else
			printf ("[Error: %s] > Failed to test lockfile status.\n", strerror(errno));
		return -1;
	}

	/* Ignore terminal stop signals */
	#ifdef SIGTTOU
		signal (SIGTTOU, SIG_IGN);
	#endif
	#ifdef SIGTTIN
		signal (SIGTTIN, SIG_IGN);
	#endif
	#ifdef SIGTSTP
		signal (SIGTSTP, SIG_IGN);
	#endif

	/* fork parent process to daemon */
	pid = fork ();
	if (pid == -1) /* fork failed */
	  return -1;
	else if (pid != 0) /* fork succeeded */
		return 1; /* parent process returns */

	/* Disassociate from controlling terminal and process group. */
	#ifdef BSD
		setpgrp (0, getpid ()); /* change process group */

		if ((fd = open ("/dev/tty", O_RDWR)) >= 0)
		{
			ioctl (fd, TIOCNOTTY, 0); /* lose controlling terminal */
			close (fd);
		}
		else
		{
			exit (EXIT_FAILURE);
		}
	#else /* AT&T */
		setpgrp (); /* lose controlling terminal & change process group */

		/* ignore pgrp leader death signals */
		signal (SIGHUP, SIG_IGN);

		pid = fork();
		if (pid == -1) /* fork failed */
			exit (EXIT_FAILURE);
		else if (pid != 0) /* become non pgrp leader */
			exit (EXIT_SUCCESS); /* pgrp leader child */
	#endif

	/* change the processes umask */
	umask (o_stngs->umask);

	/* change the current working directory */
	if (chdir (o_stngs->work_dir) == -1)
		terminate (1);

	/* close all open file descriptors */
  for (fd = getdtablesize (); fd >= 0; --fd)
    close (fd);

	/* redirect stdin, stdout and stderr to /dev/null */
	open ("/dev/null", O_CREAT | O_RDONLY);
	open ("/dev/null", O_CREAT | O_WRONLY);
	open ("/dev/null", O_CREAT | O_RDWR);

	/* establishing signal handlers */
	signal (SIGINT, SIG_IGN);
	signal (SIGABRT, signal_callback_handler);
	signal (SIGILL, signal_callback_handler);
	signal (SIGFPE, signal_callback_handler);
	signal (SIGSEGV, signal_callback_handler);
	signal (SIGTERM, signal_callback_handler);

	/* start logging */
	setlogmask (LOG_UPTO (o_stngs->log_pri_mask));
	openlog (identity, LOG_NDELAY | LOG_PID, LOG_LOCAL0);
	syslog (LOG_INFO, "[LOG LEVEL: %d] > Syslog connection started..", o_stngs->log_pri_mask);

	/* create and lock PID file */
	if (creat_lock_file (o_stngs->pid_file_name) == -1)
		syslog (LOG_WARNING, "[Error: %s] Failed to create lock file \"%s\"",
						strerror(errno), o_stngs->pid_file_name);

	return 0;
}

/*************************************************\
 * static void signal_callback_handler (int)     *
 *                                               *
 * Catches signals and handles them accordingly  *
\*************************************************/
static void signal_callback_handler (int sig)
{
	switch (sig)
	{
		case SIGHUP:
			/* re-read config file */
			break;
		case SIGINT:
		case SIGTERM:
		case SIGSEGV:
		case SIGILL:
		case SIGFPE:
		case SIGABRT:
		case SIGQUIT:
			syslog (LOG_NOTICE, "[SIG: %s] > Recived signal..", strsignal(sig));
			terminate (0);
		default:
			syslog (LOG_WARNING, "[SIG: %s] > Unhandled signal..", strsignal(sig));
	}
}

/********************************************************\
 * static int create_lock_file (char *)                 *
 *                                                      *
 * Open/Create lock file, write PID to it and locks it  *
\*********************************************************/
static int creat_lock_file (char * pid_fn)
{
  /* Open and/or Create pid file */
	char pid_lock_buf[11];

	int pid_fd = open (pid_fn, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR);
	if (pid_fd < 0)
	{
		syslog (LOG_WARNING, "[Error: %s] > Failed to open lock file '%s'.", strerror(errno), pid_fn);
		return -1;
	}

	/* Lock pid file */
	if(flock (pid_fd, LOCK_EX | LOCK_NB))
	{
		syslog (LOG_WARNING, "[Error: %s] > Failed to lock PID file '%s'.", strerror(errno), pid_fn);
		close (pid_fd);
		return -1;
	}

	/* Write PID to lock file */
	sprintf (pid_lock_buf, "%ld\n", (long) getpid ());
	if (write (pid_fd, pid_lock_buf, strlen (pid_lock_buf) + 1) == -1)
	{
		syslog (LOG_WARNING, "[Error: %s] > Failed to write PID to lock file %s'.", strerror(errno), pid_fn);
		return -1;
	}

	return 0;
}

/********************************************\
 * static int get_lock_file_status (char *) *
 *                                          *
 * it returns 1 if file is locked or 0      *
 * if it's not                              *
\********************************************/
static int get_lock_file_status (char * pid_fn)
{
	/* Try opening file */
	int pid_fd = open (pid_fn, O_CREAT | O_WRONLY, S_IWUSR);
	if (pid_fd == -1)
		return -1; /* unhandeled error ocured while openning file, return FAILURE */

	/* Test file for lock */
	if (flock (pid_fd, LOCK_EX | LOCK_NB))
	{
		/* File is locked, close fd and retuen failure */
		close (pid_fd);
		return -1;
	}

	/* Close fd and return success */
	close (pid_fd);
	return 0;
}

/********************************************************\
 * void terminate (int)                                 *
 *                                                      *
 * Logs server shutdown, unlinks pid file, closes all   *
 * file descriptors, closes syslog connection and exits *
\********************************************************/
void terminate (int status)
{
	int fd;

	/* remove lock file */
	if (pid_file != NULL)
	{
		if (unlink (pid_file) == -1)
			syslog (LOG_WARNING, "[Error: %s] Failed to Unlink lock file.", strerror (errno));
		else
			syslog (LOG_DEBUG, "Unlinked lock file '%s'", pid_file);
	}

	/* Close all open file descriptors */
	for (fd = getdtablesize (); fd >= 0; --fd)
    close (fd);
	syslog (LOG_DEBUG, "Closing all open file/socket descriptors.");

	/* Close syslog connection */
	syslog (LOG_NOTICE, "Shutting down..");
	closelog ();

	/* Terminate process */
	if (status)
		exit (EXIT_FAILURE);
	else
		exit (EXIT_SUCCESS);
}
