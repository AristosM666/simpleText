/**** st-http.h *********************************\
 * Aristos Miliaressis                5/3/2015  *
\************************************************/
#ifndef ST_HTTP_H
#define ST_HTTP_H

/* define 'socklen_t' if it's not by default */
#if defined(__sgi)
typedef int socklen_t;
#endif


/* Connect_args struct stores connection specific information s*/
typedef struct
{
	int socket;
	char client_addr[16];
} Connect_Args;

/* function declarations */
void attent_connection (Connect_Args *);

#endif
