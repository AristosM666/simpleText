/**** st-ui.c ***********************************\
 * Aristos Miliaressis                11/3/2015 *
\************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/file.h>
#include <syslog.h>
#include <errno.h>
#include <libconfig.h>
#include "st-ui.h"

const char * CONF_DIR = (const char *) "/etc/simpleText.d/"; /* simpleTexts program files */
const char * CONF_FILE = (const char *) "simpleText.cfg"; /* simpleTexts configuration file */
const char * HOST_FILE = (const char *) "vhost.cfg"; /* simpleTexts Virtual hosting configuration file*/

/* Default settings object */
static User_Settings o_dflt_stngs =
{
	"/var/run/simpleText.pid",
	"/srv/http/",
	LOG_INFO,
	0,
	80
};

/* static function declarations */
static void print_help (void);
static void print_ver_info (void);

/*********************************************************\
 * void parse_cli_opts (int, char **)                    *
 *                                                       *
 * parses command line arguments and sets global options *
 * calls `print_help()` if invalid arguments provided.   *
\*********************************************************/
void parse_cli_opts (int argc, char * args[], User_Settings * o_stngs)
{
	int tmp, count;

	/* looping through argument list */
	for (count = 1; count < argc; count++)
	{
		/* testing argument for command-line options */
		if (!(strcmp (args[count], "-h") && strcmp (args[count], "--help")))
		{
			print_help ();
		}
		else if (!(strcmp (args[count], "-v") && strcmp (args[count], "--version")))
		{
			print_ver_info ();
		}
		else if (!(strcmp (args[count], "-l") && strcmp (args[count], "--loglvl")))
		{
			count++;
			if (argc > count)
			{
				/* test for option values */
				sscanf (args[count], "%d", &tmp);

				/* if mask is invalid */
				if (tmp > 7 || tmp < 0)
				{
					printf ("invalid value `%s` for option `--loglvl`\n", args[count]);
					print_help ();
				}

				o_stngs->log_pri_mask = tmp;
			}
			else
			{
				printf ("no argument provided for option `--loglvl`\n");
				print_help ();
			}
		}
		else if (!(strcmp (args[count], "-i") && strcmp (args[count], "--pidfile")))
		{
			count++;
			if (argc > count)
			{
				strcpy (o_stngs->pid_file_name, args[count]);
				/* test validity */
			}
			else
			{
				printf ("no argument provided for option `--pidfile`\n");
				print_help ();
			}
		}
		else if (!(strcmp (args[count], "-w") && strcmp (args[count], "--workdir")))
		{
			count++;
			if (argc > count)
			{
				strcpy (o_stngs->work_dir, args[count]);
				/* test validity */
			}
			else
			{
				printf ("no argument provided for option `--workdir`\n");
				print_help ();
			}
		}
		else if (!(strcmp (args[count], "-m") && strcmp (args[count], "--mode")))
		{
			count++;
			if (argc > count)
			{
				if (strlen(args[count]) > 4 || strlen(args[count]) < 0)
				{
					printf ("invalid value `%s` for option `--mode`\n", args[count]);
					print_help ();
				}
				else
				{
					for (tmp = 0; tmp < strlen(args[count]); tmp++)
					{
						if ((args[count])[tmp] > '7' || (args[count])[tmp] < '0')
						{
							printf ("invalid value `%s` for option `--mode`\n", args[count]);
							print_help ();
						}
					}

					mode_t tmp_mask;
					sscanf (args[count], "%u", &tmp_mask);
					o_stngs->umask = tmp_mask;
				}
			}
			else
			{
				printf ("no value provided for option `--mode`\n");
				print_help ();
			}
		}
		else if (!(strcmp (args[count], "-p") && strcmp (args[count], "--port")))
		{
			count++;
			if (argc > count)
			{
				unsigned short tmp;
				sscanf (args[count], "%hu", &tmp);

				o_stngs->port = tmp;
			}
			else
			{
				printf ("no value provided for option `--port`\n");
				print_help ();
			}
		}
		else
		{
			printf ("invalid argument switch `%s`\n", args[count]);
			print_help ();
		}
	}
}

/*******************************************\
 * int read_conf_file (User_Settings *)    *
 *                                         *
 * Reads settings from 'simpleText.cfg'    *
 * and stires it in a User_Settings object *
 *                                         *
 * returns 0 on success or -1 on fail      *
\*******************************************/
int read_conf_file (User_Settings * o_stngs)
{
	const config_t cfg;
	config_t * cf;
	const char * str_value = NULL;
	char * filename = malloc(256);
	int num_value;

	strcpy(filename, CONF_DIR);
	strcat(filename, CONF_FILE);

	cf = (config_t *) &cfg;
	config_init(cf);

	if (!config_read_file(cf, filename))
	{
		printf("Unable to read configuration file, %s:%d - %s\n",
						filename,
						config_error_line(cf),
						config_error_text(cf));
		printf ("Using default settings.\n");
		config_destroy(cf);

		/* Setting default configuration */
		strcpy (o_stngs->work_dir, o_dflt_stngs.work_dir);
		strcpy (o_stngs->pid_file_name, o_dflt_stngs.pid_file_name);
		o_stngs->log_pri_mask = o_dflt_stngs.log_pri_mask;
		o_stngs->umask = o_dflt_stngs.umask;
		o_stngs->port = o_dflt_stngs.port;
		free(filename);
		return -1;
	}

	if (config_lookup_string(cf, "WORK_DIR", &str_value))
	{
		strcpy (o_stngs->work_dir, str_value);
	}
	else
	{
		strcpy (o_stngs->work_dir, o_dflt_stngs.work_dir);
		syslog (LOG_NOTICE, "Work Dir NOT configured, default Work Dir [%s] used.", o_stngs->work_dir);
	}

	if (config_lookup_string(cf, "PID_FILE", &str_value))
	{
		strcpy (o_stngs->pid_file_name, str_value);
	}
	else
	{
		strcpy (o_stngs->pid_file_name, o_dflt_stngs.pid_file_name);
		syslog (LOG_NOTICE, "PID File NOT configured, default PID File [%s] used.", o_stngs->pid_file_name);
	}

	if (config_lookup_int(cf, "LOG_MASK", &num_value))
	{
		/* if mask is invalid the default is used */
		if (num_value > 7 || num_value < 0)
		{
			num_value = o_dflt_stngs.log_pri_mask;
			syslog (LOG_NOTICE, "Log Mask incorrectly configured, default Log Mask [%d] used.", num_value);
		}

		o_stngs->log_pri_mask = num_value;
	}
	else
	{
		o_stngs->log_pri_mask = o_dflt_stngs.log_pri_mask;
		syslog (LOG_NOTICE, "Log Mask NOT configured, default Log Mask [%d] used.", o_stngs->log_pri_mask);
	}

	if (config_lookup_int(cf, "UMASK", &num_value))
	{
		mode_t tmp = num_value;

		if (tmp > 4096 || tmp < 0)
		{
			num_value = o_dflt_stngs.umask;
			syslog (LOG_NOTICE, "Umask incorrectly configured, default umask [%d] used.", num_value);
		}

		o_stngs->umask = tmp;
	}
	else
	{
		o_stngs->umask = o_dflt_stngs.umask;
		syslog (LOG_NOTICE, "Umask NOT configured, default Umask [%d] used.", o_stngs->umask);
	}

	if (config_lookup_int(cf, "PORT", &num_value))
	{
		o_stngs->port = num_value;
	}
	else
	{
		o_stngs->port = o_dflt_stngs.port;
		syslog (LOG_NOTICE, "Listen Port NOT configured, default Port [%d] used.", o_stngs->port);
	}

	config_destroy(cf);
	free(filename);
	return 0;
}

/*****************************************************\
 * int read_host_file(Domain *, int)                 *
 *                                                   *
 * Reads, parses and stores information about        *
 * one virtual domain in a Domain object             *
 *                                                   *
 * it returns 1 if more domains remain 0 in non      *
 * and -1 if domain information invalid or malformed *
\*****************************************************/
int read_host_file(Domain * o_domain, int just_count)
{
	const config_t cfg;
	config_t * cf;
	const char * str_value = NULL;
	char * filename = malloc(256), * cfg_entry = malloc(256);
	config_setting_t * domains, * subdomains;
	static int domains_read = 0;
	int i, c, domain_cnt;

	strcpy(filename, CONF_DIR);
	strcat(filename, HOST_FILE);

	/* Make sure no duplicates are entered */
	/* ... */

	cf = (config_t *) &cfg;
	config_init(cf);

	if (!config_read_file(cf, filename))
	{
		syslog(LOG_WARNING, "Unable to read host file, %s:%d - %s\n",
						filename,
						config_error_line(cf),
						config_error_text(cf));
		config_destroy(cf);
		free(cfg_entry);
		free(filename);
		return -1;
	}

	domains = config_lookup(cf, "vhosts");
	domain_cnt = config_setting_length(domains);
	if (just_count == 1)
	{
		free(cfg_entry);
		free(filename);
		return domain_cnt;
	}

	/* Read domains web root */
	strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
	strcat (cfg_entry, ".web_root");
	if (config_lookup_string(cf, cfg_entry, &str_value))
	{
		strcpy (o_domain->web_root, str_value);
		if (str_value[strlen(str_value)-1] != '/')
			strcat (o_domain->web_root, "/");
	}
	else
	{
		o_domain->name[0] = '\0';
		goto FINISH;
	}

	/* Read domains index filename */
	strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
	strcat (cfg_entry, ".index");
	if (config_lookup_string(cf, cfg_entry, &str_value))
		strcpy (o_domain->index, str_value);

	/* Read full domain name */
	strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
	strcat (cfg_entry, ".domain");
	if (config_lookup_string(cf, cfg_entry, &str_value))
	{
		strcpy (o_domain->name, str_value);
		syslog (LOG_INFO, "Domain '%s' created.", o_domain->name);
		for (i = 0; i < strlen(o_domain->name); i++)
			o_domain->name[i] = toupper(o_domain->name[i]);
	}
	else
	{
		o_domain->name[0] = '\0';
		goto FINISH;
	}

	/* Read Subdomain array */
	strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
	strcat (cfg_entry, ".sub_domains");
	if ((subdomains = config_lookup(cf, cfg_entry)))
	{
		o_domain->count = config_setting_length(subdomains);
		/* loop through sub-domains */
		for (c = 0; c < o_domain->count; c++)
		{
			strcpy (o_domain->sub_domains[c].name, config_setting_get_string_elem(subdomains, c));
			strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
			strcat (cfg_entry, ".");
			strcat (cfg_entry, o_domain->sub_domains[c].name);
			strcat (cfg_entry, ".web_root");
			if (config_lookup_string(cf, cfg_entry, &str_value))
			{
				strcpy (o_domain->sub_domains[c].web_root, str_value);
			}
			else
			{
				o_domain->sub_domains[c].name[0] = '\0';
				continue;
			}
			strcpy (cfg_entry, config_setting_get_string_elem(domains, domains_read));
			strcat (cfg_entry, ".");
			strcat (cfg_entry, o_domain->sub_domains[c].name);
			strcat (cfg_entry, ".index");
			if (config_lookup_string(cf, cfg_entry, &str_value))
			{
				strcpy (o_domain->sub_domains[c].index, str_value);
			}
			else
			{
				strcpy (o_domain->sub_domains[c].index, o_domain->index);
			}

			for (i = 0; i < strlen(o_domain->sub_domains[c].name); i++)
				o_domain->sub_domains[c].name[i] = toupper(o_domain->sub_domains[c].name[i]);
		}
	}

	FINISH:
	domains_read++;
	config_destroy(cf);
	free(cfg_entry);
	free(filename);
	return 0;
}

/***************************************\
 * static void print_help (void)       *
 *                                     *
 * Prints help page and exits          *
\***************************************/
static void print_help (void)
{
	printf ("Usage: simpleText [options]\n\n");

	printf ("OPTIONS:\n");
	printf ("\t-i, --pidfile <file path>            Set lock file (default: %s)\n",
					o_dflt_stngs.pid_file_name);
	printf ("\t-w, --workdir <directory path>       Set proccess working directory (default: %s)\n",
					o_dflt_stngs.work_dir);
	printf ("\t-m, --mode <umask>                   Set process umask (default: %d)\n",
					o_dflt_stngs.umask);
	printf ("\t-p, --port <port-num>                Set port for listening (default: %d)\n",
					o_dflt_stngs.port);
	printf ("\t-l, --loglvl <0-7>                   Set syslog log level (default: %d)\n",
					o_dflt_stngs.log_pri_mask+1);
	printf ("\t\t\t0 - Log only critical Massages\n");
	printf ("\t\t\t1 - Log Messages down to alert\n");
	printf ("\t\t\t2 - Log Messages down to emergency\n");
	printf ("\t\t\t3 - Log Messages down to error\n");
	printf ("\t\t\t4 - Log Messages down to warning\n");
	printf ("\t\t\t5 - Log Messages down to notice\n");
	printf ("\t\t\t6 - Log Messages down to info\n");
	printf ("\t\t\t7 - Log all Messages\n");
	printf ("\t-h, --help                           Display this help page\n");
	printf ("\t-v, --version                        Display version information\n");

	exit (EXIT_SUCCESS);
}

/*****************************************\
 * static void print_ver_info (void)     *
 *                                       *
 * Prints version informations and exits *
\*****************************************/
static void print_ver_info (void)
{
	printf ("Version Info.\n");
	exit (EXIT_SUCCESS);
}
