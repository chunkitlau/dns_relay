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
#include <sys/select.h>
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
#include <string.h>
#include <limits.h>
#include <math.h>

/* channel parameters */

#define VERSION "0.1.0"
#define DEFAULT_PORT 53
#define DEFAULT_SERVER_IP "202.106.0.20"
#define DEFAULT_DNSSERVER_IP "114.114.114.114"
#define DEFAULT_CONFIG_FILE "dnsrelay.txt"
#define DEFAULT_CACHE_SIZE 3000
#define DOMAIN_NAME_SIZE 256
#define WEBSITE_BLOCKING_OPTION 1
#define WEBSITE_BLOCKING_OPTION 1
#define STANDARD_QUERY 0
#define REVERSE_QUERY 1
#define QUERY_MESSAGE 0
#define RESPONSE_MESSAGE 1
#define HEADER_SIZE 12
#define BUFFER_SIZE 1024
#define DEFAULT_TTL 120
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
    struct Item_node *next_item_node;
}Item_node, *Item_link;

static Item_node *new_item_node() {
    Item_node *item_node = (Item_node *)malloc(sizeof(Item_node));
    item_node->valid = 0;
    item_node->next_item_node = NULL;
    return item_node;
}

static void *delete_item_node(Item_node *item_node) {
    free(item_node);
}

#define new_item_link new_item_node

static void delete_item_link(Item_link item_link) {
    if (!item_link) return;
    for (Item_node *p = item_link->next_item_node; p; p = item_link->next_item_node) {
        item_link->next_item_node = p->next_item_node;
        free(p);
    }
    free(item_link);
}

typedef struct Item_bucket_node {
    unsigned int ip;
    char domain_name[DOMAIN_NAME_SIZE];
    Item_link item_link;
    struct Item_bucket_node *next_bucket_node;
}Item_bucket_node, *Item_bucket_link;

static Item_bucket_node *new_item_bucket_node() {
    Item_bucket_node *item_bucket_node = (Item_bucket_node *)malloc(sizeof(Item_bucket_node));
    item_bucket_node->item_link = NULL;
    item_bucket_node->next_bucket_node = NULL;
    return item_bucket_node;
}

static void delete_item_bucket_node(Item_bucket_node *item_bucket_node) {
    free(item_bucket_node);
}

#define new_item_bucket_link new_item_bucket_node

static void delete_item_bucket_link(Item_bucket_link item_bucket_link) {
    if (!item_bucket_link) return;
    for (Item_bucket_node *p = item_bucket_link->next_bucket_node; p; p = item_bucket_link->next_bucket_node) {
        item_bucket_link->next_bucket_node = p->next_bucket_node;
        delete_item_link(p->item_link);
        free(p);
    }
    delete_item_link(item_bucket_link->item_link);
    free(item_bucket_link);
}

static Item_bucket_link *new_item_bucket_array(int size) {
    Item_bucket_link *item_bucket_array = (Item_bucket_link *)malloc(size * sizeof(Item_bucket_link));
    for (int k = 0; k < size; ++k) {
        item_bucket_array[k] = new_item_bucket_link();
        item_bucket_array[k]->next_bucket_node = NULL;
        item_bucket_array[k]->item_link = NULL;
    }
    return item_bucket_array;
}

static void delete_item_bucket_array(Item_bucket_link *item_bucket_array, int size) {
    for (int k = 0; k < size; ++k) {
        delete_item_link(item_bucket_array[k]->item_link);
        delete_item_bucket_link(item_bucket_array[k]->next_bucket_node);
    }
    free(item_bucket_array);
}

typedef struct Message{
    unsigned char *buffer;
    unsigned int buffer_size;
    unsigned int question_size;
    unsigned long ttl;
} Message;

static Message *new_message(unsigned char *buffer, unsigned int buffer_size, unsigned int question_size, unsigned long ttl) {
    Message* message = (Message *)malloc(sizeof(Message));
    message->buffer = (unsigned char *)malloc(message->buffer_size * sizeof(unsigned char));
    strncpy(message->buffer, buffer, message->buffer_size);
    message->buffer_size = buffer_size;
    message->question_size = question_size;
    message->ttl = ttl;
    return message;
}

static void delete_message(Message *message) {
    free(message->buffer);
    free(message);
}

typedef struct Client{
    unsigned id: 16;
    struct sockaddr_in client_addr;
} Client;

static Client *new_client(unsigned int id, struct sockaddr_in client_addr) {
    Client *client = (Client *)malloc(sizeof(Client));
    client->id = id;
    client->client_addr
    memset(&(client->client_addr), 0, sizeof(client->client_addr));
    client->client_addr.sin_family = client_addr.sin_family;
    client->client_addr.sin_addr.s_addr = client_addr.sin_addr.s_addr;
    client->client_addr.sin_port = client_addr.sin_port;
    return client;
}

static void delete_client(Client *client) {
    free(client);
}

//end of datastruct

/* Parameters */

static int prime1 = 283;
static int server_sock;
static int debug_mask = 0; /* debug mask */
static unsigned short port = DEFAULT_PORT;
static int cache_size = DEFAULT_CACHE_SIZE;
static char server_ip[20];
static char dnsserver_ip[20];
static FILE *log_file = NULL;
static FILE *config_file = NULL;
static char **dnsmap_domain_name = NULL;
static char **dnsinvmap_domain_name = NULL;
static unsigned int *dnsmap_ip;
static unsigned int *dnsinvmap_ip;
static char *dnsinvmap_valid;
static int sockaddr_in_size = sizeof(struct sockaddr_in);
static struct sockaddr_in dnsserver_addr;

static Item_bucket_link *domain_name_map = NULL;
static Item_bucket_link *ip_map = NULL;
static char ipdecstring[20];

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
typedef struct Header {
    unsigned int id;      /* query identification number */
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
} Header;

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
struct Question {
    char qname[DOMAIN_NAME_SIZE]; /* A domain name, i.e. www.bupt.edu.cn */
    unsigned qtype: 16;           /* A two octet code, type of the query, i.e. A(1),MX(15),CNAME(5),PTR(12),... */
    unsigned qclass: 16;          /* A two octet code, class of the query, i.e. IN(1) */
};

/* End of Parameters */

//map operation

static int hash_string(char *domain_name) {
    int index = 0;
    for (int k = 0; (k < DOMAIN_NAME_SIZE) && domain_name[k]; ++k) {
        index = (index * prime1 + domain_name[k]) % cache_size;
    }
    return index;
}

static void assign_item_node(Item_node *item_node_p, char *domain_name, unsigned int ip, unsigned long ttl) {
    item_node_p->valid = 1;
    strncpy(item_node_p->domain_name, domain_name, DOMAIN_NAME_SIZE);
    item_node_p->ip = ip;
    item_node_p->ttl = ttl;
}

static void insert_item_node(Item_bucket_node *item_bucket_node, char *domain_name, unsigned int ip, unsigned long ttl) {
    if (!item_bucket_node->next_bucket_node) {
        item_bucket_node->next_bucket_node = new_item_bucket_node();
        strncpy(item_bucket_node->next_bucket_node->domain_name, domain_name, DOMAIN_NAME_SIZE);
        item_bucket_node->next_bucket_node->ip = ip;
        item_bucket_node->next_bucket_node->item_link = new_item_link();
        item_bucket_node->next_bucket_node->item_link->next_item_node = new_item_node();
        assign_item_node(item_bucket_node->next_bucket_node->item_link->next_item_node, domain_name, ip, ttl);
        
    }
    else {
        int exist = 0;
        for (Item_node *p = item_bucket_node->next_bucket_node->item_link; p->next_item_node; p = p->next_item_node) {
            if (p->next_item_node->ip == ip && !strncmp(p->next_item_node->domain_name, domain_name, DOMAIN_NAME_SIZE)) {
                exist = 1;
                break;
            }
        }
        if (!exist) {
            Item_node *p = new_item_node();
            assign_item_node(p, domain_name, ip, ttl);
            p->next_item_node = item_bucket_node->next_bucket_node->item_link->next_item_node;
            item_bucket_node->next_bucket_node->item_link->next_item_node = p;
        }
    }
}

static Item_bucket_node *domain_name_map_find(char *domain_name) {
    int index = hash_string(domain_name);

    Item_bucket_node *item_bucket_node = domain_name_map[index];
    while (item_bucket_node->next_bucket_node && item_bucket_node->next_bucket_node->item_link 
        && strncmp(domain_name, item_bucket_node->next_bucket_node->domain_name, DOMAIN_NAME_SIZE)) {
            item_bucket_node = item_bucket_node->next_bucket_node;
    }

    return item_bucket_node;
}

static void domain_name_map_insert(char *domain_name, unsigned int ip, unsigned long ttl) {
    Item_bucket_node *item_bucket_node = domain_name_map_find(domain_name);

    insert_item_node(item_bucket_node, domain_name, ip, ttl);
}

static Item_bucket_node *ip_map_find(unsigned int ip) {
    int index = ip % cache_size;

    Item_bucket_node *item_bucket_node = ip_map[index];
    while (item_bucket_node->next_bucket_node && item_bucket_node->next_bucket_node->item_link 
        && (ip != item_bucket_node->next_bucket_node->ip)) {
            item_bucket_node = item_bucket_node->next_bucket_node;
    }

    return item_bucket_node;
}

static void ip_map_insert(char *domain_name, unsigned int ip, unsigned long ttl) {
    Item_bucket_node *item_bucket_node = ip_map_find(ip);

    insert_item_node(item_bucket_node, domain_name, ip, ttl);
}

//end map operation

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
	strncpy(log_fname, "log.txt", 10);
	for (i = 0; i < argc; i++)
		sprintf(log_fname + strlen(log_fname), "%s ", argv[i]);
	SetConsoleTitle(log_fname);
#endif
	strncpy(log_fname, "log.txt", 10);
    strncpy(config_fname, DEFAULT_CONFIG_FILE, 20);
    strncpy(server_ip, DEFAULT_SERVER_IP, 20);
    strncpy(dnsserver_ip, DEFAULT_DNSSERVER_IP, 20);

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

	if (strncmp(log_fname, "nul", 10) == 0)
		log_file = NULL;
	else if ((log_file = fopen(log_fname, "w")) == NULL) 
		printf("WARNING: Failed to create log file \"%s\": %s\n", log_fname, strerror(errno));

    if ((config_file = fopen(config_fname, "r")) == NULL) 
		printf("WARNING: Failed to open config file \"%s\": %s\n", config_fname, strerror(errno));

	printf("src.c, version %s, chunkitlaucont@outlook.com\n", VERSION);
	printf("Log file \"%s\", Config file \"%s\"\n", log_fname, config_fname);
	printf("Server ip %s, TCP port %d, debug mask 0x%02x\n", server_ip, port, debug_mask);
}

static char* iphexnum2decstring(unsigned int hex) {
    for (int k = 0, l = 0; l < 4; ++l) {
        for (int val = (hex >> ((3 - l) * 8)) & ((1 << 8) - 1), m = 100, flag = 0; m > 0; m = m / 10) {
            if (val >= m || m == 1 || flag) {
                ipdecstring[k++] = val / m + '0';
                val = val % m;
                flag = 1;
            }
        }
        if (l != 3) {
            ipdecstring[k++] = '.';
        }
        else {
            ipdecstring[k++] = 0;
        }
    }
    return ipdecstring;
}

static void server_test(int domain_name_to_ip, int use_file) {
    FILE *input_file = fopen("input.txt", "r");
    FILE *output_file = fopen("output.txt", "w");
    char domain_name[DOMAIN_NAME_SIZE];
    unsigned int ip_part1, ip_part2, ip_part3, ip_part4;

    while (1) {
        if (domain_name_to_ip) {
            if (!use_file) {
                printf("please input a domain name\n");
                scanf("%s", domain_name);
            }
            else {
                if (fscanf(input_file,"%s",domain_name) == EOF) {
                    break;
                }
                fscanf(input_file,"%s",domain_name);
            }
        }
        else {
            if (!use_file) {
                printf("please input an ip\n");
                scanf("%u.%u.%u.%u", &ip_part1, &ip_part2, &ip_part3, &ip_part4);
            }
            else {
                if (fscanf(input_file,"%u.%u.%u.%u", &ip_part1, &ip_part2, &ip_part3, &ip_part4) == EOF) {
                    break;
                }
                fscanf(input_file,"%s",domain_name);
            }
        }
        
        unsigned int ip = (ip_part1 << 24) + (ip_part2 << 16) + (ip_part3 << 8) + ip_part4;

        Item_bucket_node *item_bucket_node;

        if (domain_name_to_ip) {
            item_bucket_node = domain_name_map_find(domain_name);
        }
        else {
            item_bucket_node = ip_map_find(ip);
        }
        
        if (!item_bucket_node || !item_bucket_node->next_bucket_node || 
            !item_bucket_node->next_bucket_node->item_link || 
            !item_bucket_node->next_bucket_node->item_link->next_item_node ||
            (WEBSITE_BLOCKING_OPTION && domain_name_to_ip && !item_bucket_node->next_bucket_node->item_link->next_item_node->ip)) {
            if (domain_name_to_ip) {
                if (!use_file) {
                    printf("domain name %s does not exist\n", domain_name);
                }
                else {
                    fprintf(output_file, "domain name %s does not exist\n", domain_name);
                }
            }
            else {
                if (!use_file) {
                    printf("ip %s does not exist\n", iphexnum2decstring(ip));
                }
                else {
                    fprintf(output_file, "ip %s does not exist\n", iphexnum2decstring(ip));
                }
            }
        }
        else {
            if (domain_name_to_ip) {
                if (!use_file) {
                    printf("IP of resolved domain name %s:\n", domain_name);
                }
            }
            else {
                if (!use_file) {
                    printf("domain name of resolved ip %s:\n", iphexnum2decstring(ip));
                }
            }
            
            Item_node *item_node = item_bucket_node->next_bucket_node->item_link;
            while (item_node->next_item_node) {
                if (domain_name_to_ip) {
                    if (!use_file) {
                        printf("%s\n", iphexnum2decstring(item_node->next_item_node->ip));
                    }
                    else {
                        fprintf(output_file, "%s %s\n", iphexnum2decstring(item_node->next_item_node->ip), item_node->next_item_node->domain_name);
                    }
                }
                else {
                    if (!use_file) {
                        printf("%s\n", item_node->next_item_node->domain_name);
                    }
                    else {
                        fprintf(output_file, "%s %s\n", iphexnum2decstring(item_node->next_item_node->ip), item_node->next_item_node->domain_name);
                    }
                }
                
                item_node = item_node->next_item_node;
            }
        }
    }
}

static void decode_header(struct Header *header) {
    header->id = ntohs(header->id);
    header->qdcount = ntohs(header->qdcount);
    header->ancount = ntohs(header->ancount);
    header->nscount = ntohs(header->nscount);
    header->arcount = ntohs(header->arcount);
}

static void encode_header(struct Header *header) {
    header->id = htons(header->id);
    header->qdcount = htons(header->qdcount);
    header->ancount = htons(header->ancount);
    header->nscount = htons(header->nscount);
    header->arcount = htons(header->arcount);
}

static unsigned int form_standard_response(unsigned char *buffer, char *domain_name, unsigned int ip, unsigned int *question_size) {
    // Header
    Header *header = (Header *)buffer;
    header->id = 0;
    header->qr = 1;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 1;
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    if (ip) {
        header->opcode = 0;
        header->ancount = 1;
    }
    else {
        header->opcode = 3;
        header->ancount = 0;
    }
    header->qdcount = 1;
    header->nscount = 0;
    header->arcount = 0;
    encode_header(header);

    // Question
    unsigned int domain_name_size = strlen(domain_name);
    unsigned char *qname = (unsigned char *)(buffer + 12);
    *qname = 0;
    for (int k = 0; k <= domain_name_size; ++k) {
        if (domain_name[k] != '.' && !domain_name[k]) {
            *(qname + k + 1) = domain_name[k];
            ++(*qname);
        }
        else {
            qname += (*qname) + 1;
            *qname = 0;
        }
    }
    unsigned short *qtype = (unsigned short *)(qname + 1);
    *qtype = htons(1);
    unsigned short *qclass = qtype + 1;
    *qclass = htons(1);

    *question_size = (unsigned char *)(qclass + 1) - buffer;
    if (!ip) {
        return *question_size;
    }

    // Answer
    unsigned short *name = qclass + 1;
    *name = htons(0xc00c);
    unsigned short *type = name + 1;
    *type = htons(1);
    unsigned short *class = type + 1;
    *class = htons(1);
    unsigned short *ttl = class + 1;
    *ttl = htons(DEFAULT_TTL);
    unsigned short *rdlength = ttl + 1;
    *rdlength = htons(4);
    unsigned int *rdata = (unsigned int *)(rdlength + 1);
    *rdata = htonl(ip);

    return (unsigned char *)(rdata + 1) - buffer;
}

static void load_config_file() {
    unsigned int ip_part1, ip_part2, ip_part3, ip_part4;
    char domain_name[DOMAIN_NAME_SIZE];
    
    domain_name_map = new_item_bucket_array(cache_size);
    ip_map = new_item_bucket_array(cache_size);

    while (fscanf(config_file,"%u.%u.%u.%u %s\n", &ip_part1, &ip_part2, &ip_part3, &ip_part4, domain_name) != EOF) {
        unsigned int ip = (ip_part1 << 24) + (ip_part2 << 16) + (ip_part3 << 8) + ip_part4;

        unsigned char buffer[BUFFER_SIZE];
        unsigned int question_size;
        unsigned int buffer_size = form_standard_response(buffer, domain_name, ip, &question_size);
        Message *message = new_message(buffer, buffer_size, question_size, ULONG_MAX);
        message_map_insert(message);

        domain_name_map_insert(domain_name, ip, ULONG_MAX);
        ip_map_insert(domain_name, ip, ULONG_MAX);
    }

    printf("Config file loaded\n");
}

static void init_socket() {
    memset(&dnsserver_addr, 0, sizeof(dnsserver_addr));
    dnsserver_addr.sin_family = AF_INET;
    dnsserver_addr.sin_addr.s_addr = inet_addr(dnsserver_ip);
    dnsserver_addr.sin_port = htons(port);

    struct sockaddr_in server_addr;
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(port);

    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        printf("ERROR: Failed to create socket: %s\n", strerror(errno));
    }
    if (bind(server_sock, (struct sockaddr *)&server_addr, sockaddr_in_size) < 0) {
        printf("ERROR: Failed to bind port %u: %s\n", port, strerror(errno));
    }

    printf("DNS server IP: %s\n", server_ip);
    printf("Listening on port %u\n", port);    
}

static void message_map_insert(Message *message) {
    
}

static Message *message_map_find(char *domain_name) {
    return NULL;
}

static unsigned int client_map_insert(Client *client) {

    //return new_id;
}

static int client_map_find(unsigned int *id, struct sockaddr_in *client_addr) {

    //*id = new_id;
}

int main(int argc, char *argv[]) {
    printf("DNS Relay Server ---- Designed by Liu Junjie, build: 2021\n");
    
    config(argc, argv);
    load_config_file();
    init_socket();

    int n_bytes = 0;
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    struct Header *header;

    while (1) {
        //header->qr = 1;
        //header->ra = 1;
        //query ignore id flag = 0 expect rd=1 q=1
        n_bytes = recvfrom(server_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &sockaddr_in_size);
        if (n_bytes < HEADER_SIZE) {
            printf("receive a broken dns message\n");
            continue;
        }

        header = (struct Header *)buffer;
        decode_header(header);

        if (header->qr == QUERY_MESSAGE) {
            printf("receive a query message\n");
            if (!header->qdcount) {
                printf("receive an error query message\n");
                continue;
            }

            char qname[DOMAIN_NAME_SIZE];
            qname[0] = 0;
            unsigned int qtype = 0, qclass = 0;
            if (header->qdcount == 1) {
                resolve_question(qname, &qtype, &qclass, buffer);
            }
            else {
                Client *client = new_client(header->id, client_addr);
                header->id = client_map_insert(client);
                sendto(server_sock, buffer, n_bytes, 0, (struct sockaddr *)&dnsserver_addr, &sockaddr_in_size);
                continue;
            }

            if (header->opcode == STANDARD_QUERY) {
                printf("receive a standard query\n");
                Message *message = message_map_find(qname);
                if (message) {
                    sendto(server_sock, message->buffer, message->buffer_size, 0, (struct sockaddr *)&client_addr, &sockaddr_in_size);
                }
                else {
                    Client *client = new_client(header->id, client_addr);
                    header->id = client_map_insert(client);
                    sendto(server_sock, buffer, n_bytes, 0, (struct sockaddr *)&dnsserver_addr, &sockaddr_in_size);
                }
            }
            else if (header->opcode == REVERSE_QUERY) {
                printf("receive a reverse query\n");
                //to be done, now relay instead
                Client *client = new_client(header->id, client_addr);
                header->id = client_map_insert(client);
                sendto(server_sock, buffer, n_bytes, 0, (struct sockaddr *)&dnsserver_addr, &sockaddr_in_size);
            }
        }
        else if (header->qr == RESPONSE_MESSAGE) {
            printf("receive a response message\n");
            int error = client_map_find(&(header->id), &client_addr);
            if (!error) {
                sendto(server_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &sockaddr_in_size);
            }
            else {
                printf("can't find client ip of id %x\n", header->id);
            }
        }
    }
    
    close(server_sock);
    delete_item_bucket_array(domain_name_map, cache_size);
    delete_item_bucket_array(ip_map, cache_size);
    return 0;
}