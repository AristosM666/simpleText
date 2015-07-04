/**** st-ui.h ***********************************\
 * Aristos Miliaressis                11/3/2015 *
\************************************************/
#ifndef ST_UI_H
#define ST_UI_H

#include "st-base.h"

int read_conf_file (User_Settings *);
void parse_cli_opts (int, char * args[], User_Settings *);
int read_host_file (Domain *, int just_count);

#endif
