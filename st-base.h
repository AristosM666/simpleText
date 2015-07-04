/**** st-base.h *********************************\
 * Aristos Miliaressis               5/3/2015   *
\************************************************/
#ifndef ST_STNGS_H
#define ST_STNGS_H

char * server;
float version;
short host_cnt;

#define MAX_VHOSTS 256

/* User settings struct */
typedef struct
{
	char pid_file_name[256]; /* lock file filename */
	char work_dir[256];      /* process working directory */
	int log_pri_mask;        /* syslog priority mask */
	mode_t umask;            /* Process file creation mask */
	unsigned short port;
} User_Settings;

typedef struct
{
	char name[256];     /* sub-domains authority field PS `www.`*/
	char web_root[256];
	char index[256];		/* index file */
} SubDomain;

typedef struct
{
	char name[256];         /* domains authority field PS `example.net`*/
	unsigned short count;

	char web_root[256];
	char index[256];
	SubDomain sub_domains[];  /* array of subdomains*/
} Domain;

Domain o_vhost[MAX_VHOSTS];

#endif
