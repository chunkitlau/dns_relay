#ifndef _MAIN_H_
#define _MAIN_H_

#define VERSION "0.1.0"
#define DEFAULT_PORT 53
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_DNSSERVER_IP "114.114.114.114"
#define DEFAULT_CONFIG_FILE "dnsrelay.txt"
#define DEFAULT_LOG_FILE "log.txt"
#define DOMAIN_NAME_SIZE 256
#define STANDARD_QUERY 0
#define REVERSE_QUERY 1
#define QUERY_MESSAGE 0
#define RESPONSE_MESSAGE 1
#define HEADER_SIZE 12

#include <limits.h>
#include <math.h>
#include "message.h"
#include "client.h"
#include "protocol.h"

/***************************************************
 * RFC1035 4.1
 * +------------+
 * |   Header   |
 * +------------+
 * |  Question  |
 * +------------+
 * |   Answer   |
 * +------------+
 * | Authority  |
 * +------------+
 * | Additional |
 * +------------+
 */

static FILE *log_file = NULL;
static FILE *config_file = NULL;

static int debug_level = 1; 
static unsigned short port = DEFAULT_PORT;
static int server_sock;
static char server_ip[20];
static char dnsserver_ip[20];
static struct sockaddr_in dnsserver_addr;


#endif