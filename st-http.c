/**** st-http.c *********************************\
 * Aristos Miliaressis                5/3/2015  *
\************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <magic.h>
#include "st-base.h"
#include "st-http.h"

/* Standard Error Pages. */
#define BAD_REQUEST "/etc/simpleText.d/std_err_page/bad_request.html"
#define HTTP_VER_NOT_SUPPORTED "/etc/simpleText.d/std_err_page/http_ver_not_supported.html"
#define NOT_IMPLEMENTED "/etc/simpleText.d/std_err_page/not_implemented.html"
#define RESOURCE_NOT_FOUND "/etc/simpleText.d/std_err_page/not_found.html"
#define INTERNAL_ERROR "/etc/simpleText.d/std_err_page/internal_error.html"
#define REQUESTED_URI_TOO_LONG "/etc/simpleText.d/std_err_page/uri_too_long.html"
#define REQUEST_TIMEOUT "/etc/simpleText.d/std_err_page/request_timeout.html"

/* Default simpleText Host (default vhost if no hosting configuration present) */
const char * ST_WEB_ROOT = "/etc/simpleText.d/example/";
const char * ST_INDEX = "index.html";
const char * ST_NAME = "simpleText";

#define MAX_URI_LEN 2048
const short MAX_REQ_LEN = 8192;
const short MAX_HEAD_LEN = 8192;
const short MAJOR_HTTP_VER = 1;
const short MINOR_HTTP_VER = 1;
const short TIMEOUT = 15;

/* HTTP General Header Fields */
struct General_Header
{
	char cache_control[128];
	char connection[128];
	char date[40];
	char pragma[128];
	char trailer;
	char transfer_encoding[128];
	char upgrade;
	char via;
	char warning;
};

/* HTTP Response Header Fields */
struct Response_Header
{
	char accept_ranges;
	unsigned int age;
	char etag;
	char location;
	char proxy_authendication;
	char proxy_authorization;
	char retry_after;
	char server[32];
	char vary;
	char www_authendicate;
};

/* HTTP Request Header Fields */
struct Request_Header
{
	char accept[256];
	char accept_charset[256];
	char accept_encoding[12]; /* gzip|x-gzip, compress|x-compress, deflate, identity */
	char accept_language[256];
	char authorization;
	char expect;
	char from;
	char host[96];
	char if_match;
	char if_modified_since;
	char if_none_match;
	char if_range;
	char if_unmodified_since;
	int max_forwards;
	char referer;
	char te;
	char user_agent;
};

/* HTTP Entity Header Fields */
struct Entity_Header
{
	char * allow;
	char * content_encoding; /* gzip, compress, deflate (x-gzip, x-compress) */
	char * content_language;
	unsigned int content_length;
	char * content_location;
	char * content_md5;
	char * content_range;
	char content_type[96];
	char * expires;
	char * last_modified;
};

/* Request Message Format */
typedef struct
{
	char method[8], uri[MAX_URI_LEN], query[MAX_URI_LEN];
	int major_http_ver, minor_http_ver;
	time_t timeout;

	struct General_Header o_gnrl_hdr;
	struct Request_Header o_rqst_hdr;
	struct Entity_Header o_ent_hdr;
	/* body */
} Request_Message;

/* Response Message Format */
typedef struct
{
	int major_http_ver, minor_http_ver, status;
	char status_description[192];

	struct General_Header o_gnrl_hdr;
	struct Response_Header o_resp_hdr;
	struct Entity_Header o_ent_hdr;

	char body[MAX_URI_LEN];
} Response_Message;

/* static function declarations */
static char * timestamp(void);
static int recv_rqst (Connect_Args *, Request_Message *);
static int read_line (int, char *, int, unsigned long);
static int parse_header_field (Request_Message *, char *);
static void generate_entity_headers (Response_Message *, Request_Message *);
static void send_respond (int, Response_Message *);

/******************************************\
 * static char * timestamp(void)          *
 *                                        *
 * returns an `RFC 1123` formated string  *
 * of the current GMT time.               *
\******************************************/
static char * timestamp(void)
{
	static char buffer[32];
	struct tm * o_time;
	time_t sec;

	time (&sec); /* get number of seconds since epoch */
	o_time = gmtime((const time_t *) &sec);
	strftime(buffer, 40, "%a, %d %b %Y %H:%M:%S GMT", o_time); /* format date as RFC 1123 defines */

	return buffer;
}

/***************************************************************\
 * void attent_connection (Connect_Args *)                     *
 *                                                             *
 * Excpects a Connect_Args object pointer it calls recv_rqst() *
 * to read the clients request processes the request and calls *
 * send_response to send a response to the client.             *
\***************************************************************/
void attent_connection (Connect_Args * o_args)
{
	Request_Message o_rqst_msg;
	Response_Message o_resp_msg;
	int j, domain_id, sub_domain_id;
	size_t len, i;

	/* set `server` header field */
	char * serv_buf = malloc(128);
	sprintf (serv_buf, "%s/%.1f", server, (float) version);

	/* Log start of connection */
	syslog (LOG_INFO, "Started connection with [%s]", o_args->client_addr);

	RECIVE_REQUEST:
	/* Zero out struct's */
	memset (&o_rqst_msg, 0, sizeof o_rqst_msg);
	memset (&o_resp_msg, 0, sizeof o_resp_msg);

	/* Set Default Values */
	strcpy (o_resp_msg.o_resp_hdr.server, serv_buf);
	o_resp_msg.major_http_ver = MAJOR_HTTP_VER;
	o_resp_msg.minor_http_ver = MINOR_HTTP_VER;
	time(&o_rqst_msg.timeout);
	o_rqst_msg.timeout += TIMEOUT;

	/* Read request */
	i = recv_rqst(o_args, &o_rqst_msg);

	switch (i)
	{
	case 400:
		o_resp_msg.status = 400;
		strcpy (o_resp_msg.status_description, "Bad Request");
		strcpy (o_resp_msg.body, BAD_REQUEST);
		goto SEND_RESPONSE;
	case 408:
		o_resp_msg.status = 408;
		strcpy (o_resp_msg.status_description, "Request Timeout");
		strcpy (o_resp_msg.body, REQUEST_TIMEOUT);
		strcpy(o_resp_msg.o_gnrl_hdr.connection, "close");
		goto SEND_RESPONSE;
	case 414:
		o_resp_msg.status = 414;
		strcpy (o_resp_msg.status_description, "Request-URI Too Long");
		strcpy (o_resp_msg.body, REQUESTED_URI_TOO_LONG);
		strcpy(o_resp_msg.o_gnrl_hdr.connection, "close");
		goto SEND_RESPONSE;
	case 501:
		o_resp_msg.status = 501;
		strcpy (o_resp_msg.status_description, "Not Implemented");
		strcpy (o_resp_msg.body, NOT_IMPLEMENTED);
		goto SEND_RESPONSE;
	case 505:
		o_resp_msg.status = 505;
		strcpy (o_resp_msg.status_description, "HTTP Version Not Supported");
		strcpy (o_resp_msg.body, HTTP_VER_NOT_SUPPORTED);
		strcpy(o_resp_msg.o_gnrl_hdr.connection, "close");
	}

	/* Test if host field recived */
	if (o_rqst_msg.o_rqst_hdr.host[0] != '\0' && host_cnt > 0)
	{
		for (i = 0; i < host_cnt; i++)
		{
			domain_id = -1;
			sub_domain_id = -1;
			if (strcmp(o_vhost[i].name, o_rqst_msg.o_rqst_hdr.host) == 0)
			{
				domain_id = i;
				break;
			}
			else if (o_vhost[i].count != 0)
			{
				for (j = 0; j < o_vhost[i].count; j++)
				{
					if (strncmp(o_vhost[i].sub_domains[j].name,
							o_rqst_msg.o_rqst_hdr.host,
							strlen(o_vhost[i].sub_domains[j].name)) == 0 &&
							strcmp(o_vhost[i].name,
							(char *) *(&o_rqst_msg.o_rqst_hdr.host + strlen(o_vhost[i].sub_domains[j].name))))
					{
						domain_id = i;
						sub_domain_id = j;
						break;
					}
				}
			}
		}

		if (domain_id == -1)
		{
			o_resp_msg.status = 400;
			strcpy (o_resp_msg.status_description, "Bad Request");
			strcpy (o_resp_msg.body, BAD_REQUEST);
			goto SEND_RESPONSE;
		}
	}
	else if (host_cnt == -1)
	{
		sub_domain_id = -1;
		domain_id = 0;
		strcpy(o_vhost[domain_id].index, ST_INDEX);
		strcpy(o_vhost[domain_id].web_root, ST_WEB_ROOT);
		strcpy(o_vhost[domain_id].name, ST_NAME);
	}
	else
	{
		o_resp_msg.status = 400;
		strcpy (o_resp_msg.status_description, "Bad Request");
		strcpy (o_resp_msg.body, BAD_REQUEST);
		goto SEND_RESPONSE;
	}

	/* if URI is '/' (root) use index */
	if (strlen (o_rqst_msg.uri) == 1 && o_rqst_msg.uri[0] == '/')
	{
		if (sub_domain_id != -1)
			strcpy(o_rqst_msg.uri, o_vhost[domain_id].sub_domains[sub_domain_id].index);
		else
			strcpy(o_rqst_msg.uri, o_vhost[domain_id].index);
	}

	/* prepend web-root to resource path and store it in request struct */
	if (sub_domain_id != -1)
	{
		len = strlen(o_vhost[domain_id].sub_domains[sub_domain_id].web_root);
		if (strlen(o_rqst_msg.uri) + len > MAX_URI_LEN)
		{
			o_resp_msg.status = 414;
			strcpy (o_resp_msg.status_description, "Request-URI Too Long");
			strcpy (o_resp_msg.body, REQUESTED_URI_TOO_LONG);
			strcpy(o_resp_msg.o_gnrl_hdr.connection, "close");
			goto SEND_RESPONSE;
		}

		memmove(o_rqst_msg.uri + len, o_rqst_msg.uri, strlen(o_rqst_msg.uri) + 1);

    for (i = 0; i < len; i++)
      o_rqst_msg.uri[i] = o_vhost[domain_id].sub_domains[sub_domain_id].web_root[i];
	}
	else
	{
		len = strlen(o_vhost[domain_id].web_root);
		if (strlen(o_rqst_msg.uri) + len > MAX_URI_LEN)
		{
			o_resp_msg.status = 414;
			strcpy (o_resp_msg.status_description, "Request-URI Too Long");
			strcpy (o_resp_msg.body, REQUESTED_URI_TOO_LONG);
			strcpy(o_resp_msg.o_gnrl_hdr.connection, "close");
			goto SEND_RESPONSE;
		}

		memmove(o_rqst_msg.uri + len, o_rqst_msg.uri, strlen(o_rqst_msg.uri) + 1);

    for (i = 0; i < len; i++)
       o_rqst_msg.uri[i] = o_vhost[domain_id].web_root[i];
	}

	/* Handle HTTP methods acordingly  (currently only GET and HEAD are implemented)*/
	if (strcmp(o_rqst_msg.method, "GET") && strcmp(o_rqst_msg.method, "HEAD"))
	{
		o_resp_msg.status = 501;
		strcpy (o_resp_msg.status_description, "Not Implemented");
		strcpy (o_resp_msg.body, NOT_IMPLEMENTED);
	}

	/* Send response to client */
	SEND_RESPONSE:
	generate_entity_headers (&o_resp_msg, &o_rqst_msg);

	/* Log respons status line */
	syslog (LOG_INFO, "Response to %s [HTTP/%d.%d %d %s]",
					o_args->client_addr,
					o_resp_msg.major_http_ver,
					o_resp_msg.minor_http_ver,
					o_resp_msg.status,
					o_resp_msg.status_description);

	send_respond (o_args->socket, &o_resp_msg);

	/* close connection (if connection header is set) */
	if (o_resp_msg.o_gnrl_hdr.connection[0] != '\0')
	{
		syslog (LOG_INFO, "Closed connection with [%s]", o_args->client_addr);
		close (o_args->socket);
		free(serv_buf);
		free(o_args);
		pthread_exit(0);
	}

	goto RECIVE_REQUEST;
}

/*************************************************************\
 * static int recv_rqst (Connect_Args *, Request_Message *)  *
 *                                                           *
 * Reads a request and stores it in a Request_message object *
 *                                                           *
 * it returns an HTTP status code if some error occurred     *
 * while reading the message else it returns 0               *
\*************************************************************/
static int recv_rqst (Connect_Args * o_args, Request_Message * o_rqst_msg)
{
	char start_line[MAX_REQ_LEN], header_field[MAX_HEAD_LEN], * method, * uri, * protocol, * tmp;
	int i, j, bad_request = 0, req_line_len;

	do {
		req_line_len = read_line (o_args->socket, (char *) &start_line, MAX_REQ_LEN, o_rqst_msg->timeout);
		if (req_line_len == MAX_REQ_LEN) /* end of request not read */
			return 400; /* Bad request */
		else if (req_line_len == -1)
			return 408; /* timeout occurred */
	} while (req_line_len == 0);

	/* Log request */
	syslog (LOG_INFO, "Request [%s] from %s to %s",
					start_line,
					o_args->client_addr,
					o_rqst_msg->o_rqst_hdr.host);

	/* Read request header fields */
	while ((i = read_line (o_args->socket, header_field, MAX_HEAD_LEN, o_rqst_msg->timeout)) != 0)
	{
		if (strlen (header_field) > 0 && parse_header_field (o_rqst_msg, header_field) == -1)
			return 400; /* Bad Request*/
		else if (i == -1)
			return 408; /* timeout occurred */
		header_field[0] = '\0';
	}

	/* Test if any recived header fields where malformed */
	if (bad_request == 1)
		return 400; /* Bad Request*/

	/* parse request line */
	method = strtok (start_line, " ");
	uri = strtok (NULL, " ");
  protocol = strtok (NULL, "\0");

	/* Test for Missing Start Line Field */
	if (method == NULL || uri == NULL || protocol == NULL)
		return 400; /* Bad Request*/

	/* Parse URI path and query */
	for (i = 0; i < strlen(uri); i++)
	{
		if (uri[i] == '?')
		{
			strcpy (o_rqst_msg->query, uri+i);
			uri[i] = '\0';
			break;
		}
	}
	/* Decode URI components */

	/* Remove special characters to prevent path traversal */
	for (i = 0; i < strlen(uri); i++)
	{
		if (uri[i] == '~')
		{
			for (j = i; j < strlen(uri)-1; j++)
				uri[j] = uri[j+1];
			i--;
		}
		else if (uri[i] == '.' && uri[i+1] == '.')
		{
			for (j = i; j < strlen(uri)-2; j++)
				uri[j] = uri[j+2];
			i--;
		}
	}

	/* Test if URI/Method too long */
	if (strlen (method) > 8)
		return 501; /* Method not implemented*/
	else if (strlen (uri) > MAX_URI_LEN)
		return 414; /* Request URI too long*/

	/* Uppercase method (case-insensitive) */
	for (i = 0; i < strlen (method); i++)
		method[i] = toupper(method[i]);

	/* store the method & uri in the request struct */
	strcpy (o_rqst_msg->method, method);
	strcat (o_rqst_msg->uri, uri);

	/* parse http version */
	if (strcmp(strtok (protocol, "/"), "HTTP") == 0)
	{
		char * str_end;

		tmp = strtok (NULL, ".");
		if (tmp == NULL)
			return 400; /* Bad request */

		o_rqst_msg->major_http_ver = (int) strtol (tmp, &str_end, 10);

		tmp = strtok (NULL, "\0");
		if (tmp == NULL)
			return 400; /* Bad request */
		o_rqst_msg->minor_http_ver = (int) strtol (tmp, &str_end, 10);

		if (o_rqst_msg->major_http_ver != 1)
			return 505; /* HTTP version not supported */
	}
	else
	{
		return 400; /* Bad request */
	}

	/* Read request body if defined */
	if (o_rqst_msg->o_ent_hdr.content_length != 0 || o_rqst_msg->o_ent_hdr.content_encoding != NULL)
	{
		/* Read requst body */
		/* ... */;
	}

	return 0;
}

/**********************************************************************\
 * static int parse_header_field (Request_Message *, char *)          *
 *                                                                    *
 * expects a pointer to a Request_Message struct object and a char    *
 * array containing an HTTP request header field, it parses the       *
 * header field and sets the apopriate struct member with the         *
 * field value.                                                       *
 *                                                                    *
 * returns 0 on success and -1 on fail                                *
\**********************************************************************/
static int parse_header_field (Request_Message * o_rqst_msg, char * req_field)
{
	static char * previous_field;
	char * field_name, * field_value;
	int i;

	/* check if line is continuation of the previous field */
	if ((req_field[0] == ' ' || req_field[0] == '\t') && previous_field != NULL)
	{
		field_name = previous_field;
	}
	else
	{
		field_name = strtok (req_field, ":");
		field_value = strtok (NULL, "\0");
		previous_field = field_name;

		if (field_name == NULL || field_value == NULL)
			return -1;
	}

	/* Make header field string uppercase (case-insensitive)*/
	for (i = 0; i < strlen (field_name); i++)
		field_name[i] = toupper(field_name[i]);

	/* Removing leading whitespace */
	while (field_value[0] == ' ' || field_value[0] == '\t')
		for (i = 0; i < strlen (field_value); i++)
			field_value[i] = field_value[i+1];

	/* Removing trailing whitespace */
	for (i = strlen (field_value); i > 0; i--)
	{
		if (field_value[i] == ' ' || field_value[i] == '\t')
			field_value[i] = '\0';
		else
			break;
	}

	//// Connection: header values are case insensitive

	/* Parse field value */
	if (strcmp(field_name, "CACHE-CONTROL") == 0)
	{
		if (o_rqst_msg->o_gnrl_hdr.cache_control[0] != '\0')
		  strncat (o_rqst_msg->o_gnrl_hdr.cache_control,
							field_value,
							sizeof(o_rqst_msg->o_gnrl_hdr.cache_control)-strlen(o_rqst_msg->o_gnrl_hdr.cache_control));
		else
			strncpy (o_rqst_msg->o_gnrl_hdr.cache_control,
							field_value,
							sizeof(o_rqst_msg->o_gnrl_hdr.cache_control));
	}
	else if (strcmp(field_name, "ACCEPT") == 0)
	{
		if (o_rqst_msg->o_rqst_hdr.accept[0] != '\0')
		  strncat (o_rqst_msg->o_rqst_hdr.accept,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept)-strlen(o_rqst_msg->o_rqst_hdr.accept));
		else
			strncpy (o_rqst_msg->o_rqst_hdr.accept,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept));
	}
	else if (strcmp(field_name, "ACCEPT-CHARSET") == 0)
	{
		if (o_rqst_msg->o_rqst_hdr.accept_charset[0] != '\0')
		  strncat (o_rqst_msg->o_rqst_hdr.accept_charset,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_charset)-strlen(o_rqst_msg->o_rqst_hdr.accept_charset));
		else
			strncpy (o_rqst_msg->o_rqst_hdr.accept_charset,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_charset));
	}
	else if (strcmp(field_name, "ACCEPT-ENCODING") == 0)
	{
		if (o_rqst_msg->o_rqst_hdr.accept_encoding[0] != '\0')
		  strncat (o_rqst_msg->o_rqst_hdr.accept_encoding,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_encoding)-strlen(o_rqst_msg->o_rqst_hdr.accept_encoding));
		else
			strncpy (o_rqst_msg->o_rqst_hdr.accept_encoding,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_encoding));
	}
	else if (strcmp(field_name, "ACCEPT-LANGUAGE") == 0)
	{
		if (o_rqst_msg->o_rqst_hdr.accept_language[0] != '\0')
		  strncat (o_rqst_msg->o_rqst_hdr.accept_language,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_language)-strlen(o_rqst_msg->o_rqst_hdr.accept_language));
		else
			strncpy (o_rqst_msg->o_rqst_hdr.accept_language,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.accept_language));
	}
	else if (strcmp(field_name, "HOST") == 0)
	{
		if (o_rqst_msg->o_rqst_hdr.host[0] != '\0')
		{
			return -1;
		}
		else
		{
			for (i = 0; i < strlen (field_value); i++)
				field_value[i] = toupper(field_value[i]);

			field_value = strtok(field_value, ":"); // ignore port
			strncpy (o_rqst_msg->o_rqst_hdr.host,
							field_value,
							sizeof(o_rqst_msg->o_rqst_hdr.host));
		}

	}
	else if (strcmp(field_name, "TRANSFER-ENCODING") == 0)
	{
		if (o_rqst_msg->o_gnrl_hdr.transfer_encoding[0] != '\0')
		  strncat (o_rqst_msg->o_gnrl_hdr.transfer_encoding,
							field_value,
							sizeof(o_rqst_msg->o_gnrl_hdr.transfer_encoding)-strlen(o_rqst_msg->o_gnrl_hdr.transfer_encoding));
		else
			strncpy (o_rqst_msg->o_gnrl_hdr.transfer_encoding,
							field_value,
							sizeof(o_rqst_msg->o_gnrl_hdr.transfer_encoding));
	}
	else if (strcmp(field_name, "CONTENT-LENGTH") == 0)
	{
		if (o_rqst_msg->o_gnrl_hdr.transfer_encoding != NULL)
			return -1;
		sscanf(field_value, "%ud", &o_rqst_msg->o_ent_hdr.content_length);
	}
	previous_field = field_name;

	return 0;
}

/*******************************************************************************\
 * static void generate_entity_headers (Response_Message *, Request_Message *) *
 *                                                                             *
 * Generates entity header fields for the response                             *
\*******************************************************************************/
static void generate_entity_headers (Response_Message * o_resp_msg, Request_Message * o_rqst_msg)
{
	struct stat file;

	if (o_resp_msg->body[0] == '\0')
		strcpy(o_resp_msg->body, o_rqst_msg->uri);

	/* check if file exists */
	if (access(o_resp_msg->body, F_OK | R_OK) == -1)
	{
		switch (errno)
		{
			case ENAMETOOLONG:
				o_resp_msg->status = 414;
				strcpy (o_resp_msg->status_description, "Request-URI Too Long");
				strcpy (o_resp_msg->body, REQUESTED_URI_TOO_LONG);
				strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
				break;
			case ENOENT:
			case ENOTDIR:
				o_resp_msg->status = 404;
				strcpy (o_resp_msg->status_description, "Not Found");
				strcpy (o_resp_msg->body, RESOURCE_NOT_FOUND);
				strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
				break;
			default:
				o_resp_msg->status = 500;
				strcpy (o_resp_msg->status_description, "Internal Server Error");
				strcpy (o_resp_msg->body, INTERNAL_ERROR);
				strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
		}
	}
	else if (o_resp_msg->status == 0)
	{
		o_resp_msg->status = 200;
		strcpy (o_resp_msg->status_description, "OK");
	}

	/* Analyze file */
	stat (o_resp_msg->body, &file); /* make uri _off_t */

	/* Get file size */
	o_resp_msg->o_ent_hdr.content_length = (unsigned int) file.st_size;

	/* Get file type */
	magic_t file_cookie; /* Used by libmagic to analyze file */
	file_cookie = magic_open (MAGIC_MIME_TYPE | MAGIC_SYMLINK);
	if (file_cookie == NULL)
	{
		o_resp_msg->status = 500;
		strcpy (o_resp_msg->status_description, "Internal Server Error");
		strcpy (o_resp_msg->body, INTERNAL_ERROR);
		strcpy(o_resp_msg->o_ent_hdr.content_type, "text/html");
		strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
		return;
	}

	if (magic_load (file_cookie, NULL) != 0)
	{
		o_resp_msg->status = 500;
		strcpy (o_resp_msg->status_description, "Internal Server Error");
		strcpy (o_resp_msg->body, INTERNAL_ERROR);
		strcpy(o_resp_msg->o_ent_hdr.content_type, "text/html");
		strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
		magic_close (file_cookie);
		return;
	}

	if (magic_setflags(file_cookie, MAGIC_MIME_TYPE | MAGIC_SYMLINK | MAGIC_MIME_ENCODING) == -1)
	{
		o_resp_msg->status = 500;
		strcpy (o_resp_msg->status_description, "Internal Server Error");
		strcpy (o_resp_msg->body, INTERNAL_ERROR);
		strcpy(o_resp_msg->o_ent_hdr.content_type, "text/html");
		strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
		magic_close (file_cookie);
		return;
	}

	if (magic_load (file_cookie, NULL) != 0)
	{
		o_resp_msg->status = 500;
		strcpy (o_resp_msg->status_description, "Internal Server Error");
		strcpy (o_resp_msg->body, INTERNAL_ERROR);
		strcpy(o_resp_msg->o_ent_hdr.content_type, "text/html");
		strcpy(o_resp_msg->o_gnrl_hdr.connection, "close");
		magic_close (file_cookie);
		return;
	}

	/* Check allow charset */
	strcpy (o_resp_msg->o_ent_hdr.content_type,
				(const char *) magic_file (file_cookie, o_resp_msg->body));

	/* last modified */
	/* content location */
	/* content md5 */
	/* Get encoding */
	/* content range */
	/* expires */
	/* allow (allowed methods on specified resource) */

	if (!strcmp(o_rqst_msg->method, "HEAD"))
		o_resp_msg->body[0] = '\0';

	magic_close (file_cookie);
}

/**************************************************************\
 * static void send_respond (int, Response_Message *)         *
 *                                                            *
 * Sends status line header fields and optional response body *
\**************************************************************/
static void send_respond (int csockfd, Response_Message * o_resp_msg)
{
	char * resp_buf = malloc(1024);

	/* send status line */
	sprintf (resp_buf, "HTTP/%d.%d %d %s\r\n",
					o_resp_msg->major_http_ver,
					o_resp_msg->minor_http_ver,
					o_resp_msg->status,
					o_resp_msg->status_description);
	send (csockfd, resp_buf, strlen (resp_buf), 0);

	/* send date header */
	sprintf (resp_buf, "Date: %s\r\n", timestamp());
	send (csockfd, resp_buf, strlen (resp_buf), 0);

	/* send server identity */
	sprintf (resp_buf, "Server: %s\r\n", o_resp_msg->o_resp_hdr.server);
	send (csockfd, resp_buf, strlen (resp_buf), 0);

	if (strcmp(o_resp_msg->o_gnrl_hdr.connection, "close") == 0)
		send (csockfd, "Connection: close\r\n", 19, 0);

	/* send headers */
	/* ... */
	if (o_resp_msg->o_ent_hdr.content_type != NULL)
	{
		sprintf (resp_buf, "Content-Type: %s\r\n", o_resp_msg->o_ent_hdr.content_type);
		send (csockfd, resp_buf, strlen (resp_buf), 0);
	}

	/* send resource size */
	if (o_resp_msg->o_gnrl_hdr.transfer_encoding != NULL)
	{
		sprintf (resp_buf, "Content-Length: %d\r\n", o_resp_msg->o_ent_hdr.content_length);
		send (csockfd, resp_buf, strlen (resp_buf), 0);
	}

	/* send empty line signaling end of headers */
	send (csockfd, "\r\n", 2, 0);

	if (o_resp_msg->body != NULL)
	{
		/* send body */
		int bytes_read, fd = open (o_resp_msg->body, O_RDONLY);
		bytes_read = (int) read (fd, resp_buf, sizeof resp_buf);
		while (bytes_read != 0 && bytes_read != -1)
		{
			send (csockfd, resp_buf, (unsigned int) bytes_read, 0);
			bytes_read = (int) read (fd, resp_buf, sizeof resp_buf);
		}

		if (resp_buf[strlen (resp_buf) - 1] != '\n')
			send (csockfd, "\n", 1, 0);
	}

	free(resp_buf);
}

/********************************************************************\
 * static int read_line (int sockfd, char * line_buf, int buf_size) *
 *                                                                  *
 * Reads a CRLF terminated string of buf_size - 1                   *
 * bytes from the provided stream `sockfd`, terminates              *
 * it with a NULL character and stores it in `line_buf`             *
 *                                                                  *
 * it returns the number of bytes read without                      *
 * CRLF terminator (0..buf_size-1), buf_size if                     *
 * CRLF not read or -1 if timeout occurred.                         *
\********************************************************************/
static int read_line (int sockfd, char * line_buf, int buf_size, unsigned long timeout)
{
	ssize_t n_byte_recv; /* num of recived chars (1|0), total count of caracters recived */
	time_t current_time;
	char recv_char; /* Recived character */
	int count = 0;

	do
	{
		n_byte_recv = recv (sockfd, &recv_char, 1, MSG_DONTWAIT);
		if (timeout < time (&current_time))
			return -1; /* timeout */

		if (n_byte_recv > 0)
		{
			if (recv_char == '\r')
			{
				n_byte_recv = recv (sockfd, &recv_char, 1, MSG_DONTWAIT);
				if (recv_char == '\n')
				{
					break; /* CRLF read */
				}
				else
				{
					line_buf[count] = '\r';
					count++;
				}
			}
			else if (recv_char == '\n')
			{
				break; /* LF can be considered a terminator mostly for parsing multi-line header fields */
			}
			line_buf[count] = recv_char; /* write recived byte to string */
			count++;
		}
	}
	while (count < buf_size - 1);
	line_buf[count] = '\0'; /* terminate string */

	/* Test if CRLF was read */
	if (count == buf_size - 1)
		return buf_size;

	return count;
}
