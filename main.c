#ifdef _WIN32 /* for Windows Visual Studio */

#include <winsock.h>
#include <io.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include "getopt.h"

#define getopt_long getopt_int
#define stricmp _stricmp

static void socket_init(void) {
    WORD wVersionRequested;
    WSADATA WSAData;
	int status;

    wVersionRequested = MAKEWORD(1,1);
    status = WSAStartup(wVersionRequested, &WSAData);
    if (status != 0) {
        printf("Windows Socket DLL Error\n");
	    exit(0);
    }
}

#pragma comment(lib,"wsock32.lib")

#else /* for Linux */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#define stricmp strcasecmp
#define socket_init()

#endif

//#include ".h"

/* channel parameters */

#define VERSION "0.1.0"
#define DEFAULT_PORT 59144
#define DEFAULT_SERVER_IP "202.106.0.20"
#define DEFAULT_SERVER_PORT 53
#define DEFAULT_CONFIG_FILE "dnsrelay.txt"
#define DEFAULT_CACHE_SIZE 3000
#define DOMAIN_NAME_SIZE 256

/* End of channel parameters */

//datastruct

typedef struct Item {
    unsigned int ip;
    char domain_name[DOMAIN_NAME_SIZE];
    unsigned char valid;
    unsigned long ttl;
}Item;

static Item *new_item() {
    Item *item = (Item *)malloc(sizeof(Item));
    item->valid = 0;
    return item;
}

static void delete_item(Item *item) {
    free(item);
}

typedef struct Item_node {
    unsigned int ip;
    char domain_name[DOMAIN_NAME_SIZE];
    unsigned char valid;
    unsigned long ttl;
    Item_node* next_item;
}Item_node, *Item_link;

static Item_node *new_item_node() {
    Item_node *item_node = (Item_node *)malloc(sizeof(Item_node));
    item_node->valid = 0;
    item_node->next_item = NULL;
    return item_node;
}

static void *delete_item_node(Item_node *item_node) {
    free(item_node);
}

#define new_item_link new_item_node

static void *delete_item_link(Item_link item_link) {
    for (Item_node *p = item_link->next_item; p; p = item_link->next_item) {
        item_link->next_item = p->next_item;
        free(p);
    }
}

static Item *new_item_array(int size) {
    Item *item_p = (Item *)malloc(size * sizeof(Item));
    for (int k = 0; k < size; ++k) {
        item_p[k].valid = 0;
    }
    return item_p;
}

static void delete_item_array(Item *item_array) {
    free(item_array);
}

//end of datastruct

/* Parameters */

static int prime1 = 283;
static int server_sock;
static int client_sock;
static int debug_mask = 0; /* debug mask */
static unsigned short port = DEFAULT_PORT;
static int cache_size = DEFAULT_CACHE_SIZE;
static char server_ip[16];
static FILE *log_file = NULL;
static FILE *config_file = NULL;
static char **dnsmap_domain_name = NULL;
static char **dnsinvmap_domain_name = NULL;
static unsigned int *dnsmap_ip;
static unsigned int *dnsinvmap_ip;
static char *dnsinvmap_valid;
static Item *domain_name_map = NULL;

static struct option intopts[] = {
	{ "help",	no_argument, NULL, '?' },
	{ "nolog",  no_argument, NULL, 'n' },
	{ "debug",	required_argument, NULL, 'd' },
	{ "serverip",	required_argument, NULL, 's' },
	{ "configfile",	required_argument, NULL, 'c' },
	{ "port",	required_argument, NULL, 'p' },
	{ "log",	required_argument, NULL, 'l' },
	{ 0, 0, 0, 0 },
};

#define OPT_SHORT "?nd:p:l:"

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

/***************************************************
 *  Header Section Format (RFC1035 4.1.1)
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct HEADER {
    unsigned id: 16;      /* query identification number */
    unsigned rd: 1;       /* recursion desired */
    unsigned tc: 1;       /* truncated message */
    unsigned aa: 1;       /* authoritive answer */
    unsigned opcode: 4;   /* purpose of message */
    unsigned qr: 1;       /* response flag */
    unsigned rcode: 4;    /* response code */
    unsigned cd: 1;       /* checking disabled by resolver */
    unsigned ad: 1;       /* authentic data from named */
    unsigned z: 1;        /* unused bits, must be ZERO */
    unsigned ra: 1;       /* recursion available */
    unsigned qdcount: 16; /* number of question entries */
    unsigned ancount: 16; /* number of answer entries */
    unsigned nscount: 16; /* number of authority entries */
    unsigned arcount: 16; /* number of resource entries */
};

/***************************************************
 *  Question Section Format (RFC1035 4.1.2)
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

/* End of Parameters */

static void config(int argc, char *argv[]) {
	char log_fname[1024], config_fname[1024];
	int   i, opt;

    /*
	if (argc < 2) {
	usage:
		printf("\nUsage:\n  %s <options> <station-name>\n", argv[0]);
		printf(
			"\nOptions : \n"
			"    -?, --help : print this\n"
			"    -u, --utopia : utopia channel (an error-free channel)\n"
			"    -f, --flood : flood traffic\n"
			"    -i, --ibib  : set station B layer 3 sender mode as IDLE-BUSY-IDLE-BUSY-...\n"
			"    -n, --nolog : do not create log file\n"
			"    -d, --debug=<0-7>: debug mask (bit0:event, bit1:frame, bit2:warning)\n"
			"    -p, --port=<port#> : TCP port number (default: %u)\n"
			"    -b, --ber=<ber> : Bit Error Rate (received data only)\n"
			"    -l, --log=<filename> : using assigned file as log file\n"
			"    -t, --ttl=<seconds> : set time-to-live\n"
			"\n"
			"i.e.\n"
			"    %s -fd3 -b 1e-4 A\n"
			"    %s --flood --debug=3 --ber=1e-4 A\n"
			"\n",
			DEFAULT_PORT, argv[0], argv[0]);
		exit(0);
	}
    */

#ifdef _WIN32
	strcpy(log_fname, "log.txt");
	for (i = 0; i < argc; i++)
		sprintf(log_fname + strlen(log_fname), "%s ", argv[i]);
	SetConsoleTitle(log_fname);
#endif
	strcpy(log_fname, "log.txt");
    strcpy(config_fname, DEFAULT_CONFIG_FILE);
    strcpy(server_ip, DEFAULT_SERVER_IP);

	while ((opt = getopt_long(argc, argv, OPT_SHORT, intopts, NULL)) != -1) {
		switch (opt) {
        //help
		case '?':
			//goto usage;

        //nolog
		case 'n':
			strcpy(log_fname, "nul");
			break;

        //debug
		case 'd':
			debug_mask = atoi(optarg);
			break;

        //serverip
		case 's':
            strcpy(server_ip, optarg);
			break;

        //configfile
		case 'c':
			strcpy(config_fname, optarg);
			break;

        //port
		case 'p':
			port = (unsigned short)atoi(optarg);
			break;

        //log
		case 'l':
			strcpy(log_fname, optarg);
			break;

		default:
			printf("ERROR: Unsupported option\n");
			//goto usage;
		}
	}

	if (optind == argc) 
		//goto usage;

	if (stricmp(log_fname, "nul") == 0)
		log_file = NULL;
	else if ((log_file = fopen(log_fname, "w")) == NULL) 
		printf("WARNING: Failed to create log file \"%s\": %s\n", log_fname, strerror(errno));

    if ((config_file = fopen(config_fname, "r")) == NULL) 
		printf("WARNING: Failed to open config file \"%s\": %s\n", config_fname, strerror(errno));

	lprintf("src.c, version %s, chunkitlaucont@outlook.com\n", VERSION);
	lprintf("Log file \"%s\", Config file \"%s\"\n", log_fname, config_fname);
	lprintf("Server ip %s, TCP port %d, debug mask 0x%02x\n", server_ip, port, debug_mask);
}

static int hash_string(char *name_size) {
    int index = 0;
    for (int k = 0; (k < DOMAIN_NAME_SIZE) && name_size[k]; ++k) {
        index = (index * prime1 + name_size[k]) % cache_size;
    }
    int counter = 0;
    while ((counter < cache_size) && dnsmap_domain_name[index][0] && strncmp(name_size, dnsmap_domain_name[index], DOMAIN_NAME_SIZE)) {
        index = (index + 1 < cache_size) ? index + 1 : 0;
        ++counter;
    }
    if (counter >= cache_size) {
        lprintf("cache haven't enough memory\n");
        return -1;
    }
    return index;
}

static int dnsmap_insert(char *domain_name, unsigned int ip) {
    int index = hash_string(domain_name);
    if (index < 0) {
        return -1;
    }
    if (!dnsmap_domain_name[index][0]) {
        strncpy(dnsmap_domain_name[index], domain_name, DOMAIN_NAME_SIZE);
        dnsmap_ip[index] = ip;
    }
    else if (dnsmap_ip[index] != ip) {
        lprintf("replace the ip of domain name %s from %ux to %ux\n", dnsmap_domain_name[index], dnsmap_ip[index], ip);
        dnsmap_ip[index] = ip;
    }
    return 0;
}

static int hash_int(unsigned int ip) {
    int index = ip % cache_size;
    int counter = 0;
    while ((counter < cache_size) && dnsinvmap_valid[index] && (ip != dnsinvmap_ip[index])) {
        index = (index + 1 < cache_size) ? index + 1 : 0;
        ++counter;
    }
    if (counter >= cache_size) {
        lprintf("cache haven't enough memory\n");
        return -1;
    }
    return index;
}

static int dnsinvmap_insert(char *domain_name, unsigned int ip) {
    int index = hash_int(domain_name);
    if (index < 0) {
        return -1;
    }
    if (!dnsinvmap_ip[index]) {
        strncpy(dnsinvmap_domain_name[index], domain_name, DOMAIN_NAME_SIZE);
        dnsinvmap_ip[index] = ip;
        dnsinvmap_valid = 1;
    }
    else if (strncmp(domain_name, dnsmap_domain_name[index], DOMAIN_NAME_SIZE)) {
        lprintf("replace the domain name of ip %ux from %s to %s\n", ip, dnsinvmap_domain_name[index], domain_name);
        strncpy(dnsinvmap_domain_name[index], domain_name, DOMAIN_NAME_SIZE);
    }
    return 0;
}

static int server_init() {
    unsigned int ip_part1, ip_part2, ip_part3, ip_part4;
    char domain_name[DOMAIN_NAME_SIZE];

    domain_name_map = new_item_array(cache_size);

    dnsmap_domain_name = (char **)malloc(cache_size * sizeof(char *));
    for (int k = 0; k < cache_size; ++k) {
        dnsmap_domain_name[k] = (char *)malloc(DOMAIN_NAME_SIZE * sizeof(char));
        dnsmap_domain_name[k][0] = 0;
    }

    dnsmap_ip = (unsigned int *)malloc(cache_size * sizeof(unsigned int));
    dnsinvmap_valid = (char *)malloc(cache_size * sizeof(char));

    dnsinvmap_domain_name = (char **)malloc(cache_size * sizeof(char *));
    for (int k = 0; k < cache_size; ++k) {
        dnsinvmap_domain_name[k] = (char *)malloc(DOMAIN_NAME_SIZE * sizeof(char));
        dnsinvmap_domain_name[k][0] = 0;
        dnsinvmap_valid[k] = 0;
    }

    dnsinvmap_ip = (unsigned int *)malloc(cache_size * sizeof(unsigned int));

    while (fscanf(config_file,"%u.%u.%u.%u %s\n", ip_part1, ip_part2, ip_part3, ip_part4, domain_name)) {
        unsigned int ip = (ip_part1 << 24) + (ip_part2 << 16) + (ip_part3 << 8) + ip_part4;
        if (dnsmap_insert(domain_name, ip) < 0) {
            return -1;
        }
        if (dnsinvmap_insert(domain_name, ip) < 0) {
            return -1;
        }
    }
    int admin_sock, i;
    struct sockaddr_in server_name;
    struct sockaddr_in client_name;

    {
        server_name.sin_family = AF_INET;
        server_name.sin_addr.s_addr = INADDR_ANY;
        server_name.sin_port = htons(port);

        admin_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (admin_sock < 0) 
            ABORT("Create TCP socket");
        if (bind(admin_sock, (struct sockaddr *)&server_name, sizeof(server_name)) < 0) {
            lprintf("Station A: Failed to bind TCP port %u", port);
            ABORT("Station A failed to bind TCP port");
        }

        listen(admin_sock, 5);

        lprintf("Station A is waiting for station B on TCP port %u ... ", port);
        fflush(stdout);

        server_sock = accept(admin_sock, 0, 0);
        if (server_sock < 0) 
            ABORT("Station A failed to communicate with station B");
        lprintf("Done.\n");
    }
    {
        client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_sock < 0) 
            ABORT("Create TCP socket");

        client_name.sin_family = AF_INET;
        client_name.sin_addr.s_addr = inet_addr("127.0.0.1");
        client_name.sin_port = htons((short)port);

        for (i = 0; i < 60; i++) {
            lprintf("Station B is connecting station A (TCP port %u) ... ", port);
            fflush(stdout);

            if (connect(client_sock, (struct sockaddr *)&client_name, sizeof(struct sockaddr_in)) < 0) {
                lprintf("Failed!\n");
                Sleep(2000);
            } else {
                lprintf("Done.\n");
                break;
            }
        }
        if (i == 6)
            ABORT("Station B failed to connect station A");
    }

}

int main(int argc, char *argv[]) {
    config(argc, argv);
    if (server_init() < 0) {
        return 1;
    }
    lprintf("DNS Relay Server ---- Designed by Liu Junjie, build: 2021\n");
    unsigned char rcvbuf[4096];
    struct HEADER *p;
    int ret;
    //ret = recvfrom(client_sock, rcvbuf, sizeof(rcvbuf));
    //sendto();
    p = (struct HEADER *)rcvbuf;
    if (p->aa == 1) {

    }
    for (;;) {

    }
    return 0;
}