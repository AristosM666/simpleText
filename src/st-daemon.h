/**** st-daemon.h *******************************\
 * Aristos Miliaressis                11/3/2015 *
\************************************************/
#ifndef ST_DAEMON_H
#define ST_DAEMON_H

#include "st-base.h"

int init_daemon (const char *, User_Settings *);
void terminate (int);

#endif
