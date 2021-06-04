#include "main.h"

#ifdef _WIN32

static void socket_init(void) {
    WORD wVersionRequested;
    WSADATA WSAData;
	int status;

    wVersionRequested = MAKEWORD(1,1);
    status = WSAStartup(wVersionRequested, &WSAData);
    if (status != 0) {
        printf("Windows Socket DLL ret\n");
	    exit(0);
    }
}

#endif

/////////////////////////////////////////////////////////////////////

/* Parameters */



static FILE *log_file = NULL;
static FILE *config_file = NULL;

/* End of Parameters */

/////////////////////////////////////////////////////////////////////
// component
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// message



// message

/////////////////////////////////////////////////////////////////////
// client queue
// check

typedef struct Client{
    unsigned id: 16;
    struct sockaddr_in client_addr;
    int question_size;
} Client;

static Client *new_client(unsigned short id, struct sockaddr_in client_addr, int question_size) {
    Client *client = (Client *)malloc(sizeof(Client));
    client->id = id;
    memset(&(client->client_addr), 0, sizeof(client->client_addr));
    client->client_addr.sin_family = client_addr.sin_family;
    client->client_addr.sin_addr.s_addr = client_addr.sin_addr.s_addr;
    client->client_addr.sin_port = client_addr.sin_port;
    client->question_size = question_size;
    return client;
}

static void delete_client(Client *client) {
    free(client);
}

static int client_queue_head = 0;
static int client_queue_tail = 0;
static Client *client_queue[CLIENT_QUEUE_SIZE];
static unsigned short client_queue_id[CLIENT_QUEUE_SIZE];
static unsigned short server_id_counter = 0;

static int client_queue_pre(int p) {
    return (p) ? (p - 1) : (CLIENT_QUEUE_SIZE - 1);
}

static int client_queue_next(int p) {
    return (p + 1 != CLIENT_QUEUE_SIZE) ? (p + 1) : 0;
}

static unsigned short client_queue_push(Client *client) {
    unsigned short id = server_id_counter++;
    client_queue[client_queue_tail] = client;
    client_queue_id[client_queue_tail] = id;
    client_queue_tail = client_queue_next(client_queue_tail);
    if (client_queue_tail == client_queue_head) {
        client_queue_head = client_queue_next(client_queue_head);
    }
    return id;
}

static int between(unsigned short a, unsigned short b, unsigned short c) {
    return ((a <= b) && (b < c)) || ((c < a) && (a <= b)) || ((b < c) && (c < a));
}

static Client *client_queue_find(unsigned short id) {
    if ((client_queue_head != client_queue_tail) && 
        between(client_queue_id[client_queue_head], id, client_queue_id[client_queue_pre(client_queue_tail)] + 1)) {
            int index = client_queue_head + (int)(id - client_queue_id[client_queue_head]);
            index = (index >= CLIENT_QUEUE_SIZE) ? index - CLIENT_QUEUE_SIZE : index;
            return client_queue[index];
    }
    else {
        return NULL;
    }
}

// client queue

static struct option intopts[] = {
	{ "help",	no_argument, NULL, '?' },
	{ "nolog",  no_argument, NULL, 'n' },
	{ "debug",	required_argument, NULL, 'd' },
	{ "serverip",	required_argument, NULL, 's' },
	{ "port",	required_argument, NULL, 'p' },
	{ "configfile",	required_argument, NULL, 'c' },
	{ "log",	required_argument, NULL, 'l' },
	{ 0, 0, 0, 0 },
};

#define OPT_SHORT "?nd:s:p:c:l:"

static void config(int argc, char *argv[]) {
	char log_fname[1024], config_fname[1024];
	int opt;

	if (argc < 1) {
	usage:
		printf("\nUsage:\n  %s <options>\n", argv[0]);
		printf(
			"\nOptions : \n"
			"    -?, --help : print this\n"
			"    -n, --nolog : nolog (default: log)\n"
			"    -d, --debug=<0-2>: debug level (0:basic, 1:info, 2:debug) (default: info)\n"
			"    -s, --serverip=<ip#> : DNS server ip number (default: %s)\n"
			"    -p, --port=<port#> : DNS server port number (default: %u)\n"
			"    -c, --configfile=<filename> : using assigned file as config file (default: %s)\n"
			"    -l, --log=<filename> : using assigned file as log file (default: %s)\n"
			"\n",
			DEFAULT_SERVER_IP, DEFAULT_PORT, DEFAULT_CONFIG_FILE, DEFAULT_LOG_FILE);
		//	"    -t, --ttl=<seconds> : set time-to-live\n"
		exit(0);
	}

	strncpy(log_fname, DEFAULT_LOG_FILE, 10);
    strncpy(config_fname, DEFAULT_CONFIG_FILE, 20);
    strncpy(server_ip, DEFAULT_SERVER_IP, 20);
    strncpy(dnsserver_ip, DEFAULT_DNSSERVER_IP, 20);

	while ((opt = getopt_long(argc, argv, OPT_SHORT, intopts, NULL)) != -1) {
		switch (opt) {
        //help
		case '?':
			goto usage;

        //nolog
		case 'n':
			strcpy(log_fname, "nul");
			break;

        //debug
		case 'd':
			debug_level = atoi(optarg);
			break;

        //serverip
		case 's':
            strcpy(server_ip, optarg);
			break;

        //port
		case 'p':
			port = (unsigned short)atoi(optarg);
			break;

        //configfile
		case 'c':
			strcpy(config_fname, optarg);
			break;

        //log
		case 'l':
			strcpy(log_fname, optarg);
			break;

		default:
            break;
		}
	}

	if (strncmp(log_fname, "nul", 10) == 0)
		log_file = NULL;
	else if ((log_file = fopen(log_fname, "w")) == NULL) 
		printf("WARNING: Failed to create log file \"%s\": %s\n", log_fname, strerror(errno));
    if ((config_file = fopen(config_fname, "r")) == NULL) 
		printf("WARNING: Failed to open config file \"%s\": %s\n", config_fname, strerror(errno));
	printf("main.c, version %s, chunkitlaucont@outlook.com\n", VERSION);
	printf("Log file \"%s\", Config file \"%s\"\n", log_fname, config_fname);
	printf("Server ip %s, port %d, debug level 0x%02x\n", server_ip, port, debug_level);
}

static void lprintf(char *string, unsigned char *buffer, int buffer_size) {
    fprintf(log_file, "%s", string);
    for (int k = 0; k < buffer_size; ++k) {
        fprintf(log_file, "%x ", buffer[k]);
    }
    fprintf(log_file, "\n");
}

static void network_init() {
    socket_init();

    memset(&dnsserver_addr, 0, sizeof(dnsserver_addr));
    dnsserver_addr.sin_family = AF_INET;
    dnsserver_addr.sin_addr.s_addr = inet_addr(dnsserver_ip);
    dnsserver_addr.sin_port = htons(port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    //server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    const char REUSE=1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &REUSE, sizeof(REUSE));

    if (server_sock < 0) printf("ret: Failed to create socket: %s\n", strerror(errno));
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        printf("ret: Failed to bind port %u: %s\n", port, strerror(errno));
    printf("DNS server IP: %s , Listening on port %u\n", server_ip, port);
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
    header->opcode = header->aa = header->tc = 0;
    header->rd = header->ra = 1;
    header->z = header->ad = header->cd = 0;
    if (ip) {
        header->rcode = 0;
        header->ancount = 1;
    }
    else {
        header->rcode = 3;
        header->ancount = 0;
    }
    header->qdcount = 1;
    header->nscount = header->arcount = 0;
    encode_header(header);

    // Question
    unsigned int domain_name_size = strlen(domain_name);
    unsigned char *qname = (unsigned char *)(buffer + 12);
    *qname = 0;
    for (int k = 0, l = 1; k <= domain_name_size; ++k, ++l) {
        if (domain_name[k] != '.' && domain_name[k]) {
            *(qname + l) = domain_name[k];
            ++(*qname);
        }
        else {
            qname += (*qname) + 1;
            *qname = l = 0;
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
    unsigned long *ttl = (unsigned long *)(class + 1);
    *ttl = htonl(DEFAULT_TTL);
    unsigned short *rdlength = (unsigned short *)(ttl + 1);
    *rdlength = htons(4);
    unsigned int *rdata = (unsigned int *)(rdlength + 1);
    *rdata = htonl(ip);

    return (unsigned char *)(rdata + 1) - buffer;
}

static void load_config_file() {
    unsigned int ip_part1, ip_part2, ip_part3, ip_part4;
    char domain_name[DOMAIN_NAME_SIZE];
    unsigned char buffer[BUFFER_SIZE];

    while (fscanf(config_file,"%u.%u.%u.%u %s\n", &ip_part1, &ip_part2, &ip_part3, &ip_part4, domain_name) != EOF) {
        unsigned int ip = (ip_part1 << 24) + (ip_part2 << 16) + (ip_part3 << 8) + ip_part4;

        unsigned int question_size, buffer_size = form_standard_response(buffer, domain_name, ip, &question_size);
        Message *message = new_message(buffer, buffer_size, question_size, ULONG_MAX);
        if (debug_level) fprintf(log_file, "Info: insert message {domain name: %s, ip: %u.%u.%u.%u} to hash map\n", domain_name, ip_part1, ip_part2, ip_part3, ip_part4);
        if (debug_level > 1) {
            fprintf(log_file, "Debug: insert message to hash map, hash is %d, at %x\n", message->hash, message);
            lprintf("Debug: message --- ", message->buffer, message->buffer_size);
        }
        message_map_insert(message);
    }

    printf("Static domain name - ip config file loaded\n");
}

int main(int argc, char *argv[]) {
    printf("DNS Relay Server ---- Designed by Liu Junjie, build: 2021\n");
    
    config(argc, argv);
    network_init();
    new_message_map();
    load_config_file();

    int n_bytes = 0, ret = 0;
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t sockaddr_in_size = sizeof(client_addr);
    struct Header *header;

    while (1) {
        n_bytes = recvfrom(server_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &sockaddr_in_size);
        if (n_bytes < HEADER_SIZE) {
            printf("ret: recvfrom ret with return %d, WSAGetLastError %d\n", n_bytes, WSAGetLastError());
            continue;
        }
        lprintf("\nInfo: received data --- ", buffer, n_bytes);

        header = (struct Header *)buffer;
        decode_header(header);
        unsigned qr = header->qr, id = header->id;
        encode_header(header);

        if (qr == QUERY_MESSAGE) {
            if (debug_level) fprintf(log_file, "Info: It's a query message\n");

            Message *message = new_message(buffer, n_bytes, n_bytes, ULONG_MAX);
            if (debug_level > 1) fprintf(log_file, "Debug: message hash value is %u\n", message->hash);
            Message_node *message_node = message_map_find(message)->next_message_node;

            if (message_node) {
                if (debug_level) fprintf(log_file, "Info: found local record\n");
                if (debug_level > 1) fprintf(log_file, "Debug: found local record message_node at %x, message at %x\n", message_node, message_node->message);
                
                header = (struct Header *)(message_node->message->buffer);
                decode_header(header);
                header->id = id;
                encode_header(header);

                if (debug_level) lprintf("Info: send local record to client --- ", message_node->message->buffer, message_node->message->buffer_size);
                ret = sendto(server_sock, message_node->message->buffer, message_node->message->buffer_size, 0, (struct sockaddr *)&client_addr, sockaddr_in_size);
            }
            else {
                if (debug_level) fprintf(log_file, "Info: can't found local record, ask remote dns server\n");

                Client *client = new_client(id, client_addr, n_bytes);
                decode_header(header);
                header->id = client_queue_push(client);
                if (debug_level > 1)  fprintf(log_file, "Debug: assign outsend id %u to {id: %d, ip: %s, port: %x }\n", 
                                            header->id, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                encode_header(header);

                if (debug_level) lprintf("Info: send request to remote dns server --- ", buffer, n_bytes);
                ret = sendto(server_sock, buffer, n_bytes, 0, (struct sockaddr *)&dnsserver_addr, sockaddr_in_size);
            }
        }
        else if (qr == RESPONSE_MESSAGE) {
            if (debug_level) fprintf(log_file, "Info: It's a response message\n");

            Client *client = client_queue_find(id);

            if (client) {
                if (debug_level) fprintf(log_file, "Info: message id is valid, found correspond client, cache this message\n");

                Message *message = new_message(buffer, n_bytes, client->question_size, ULONG_MAX);
                message_map_insert(message);
                if (debug_level > 1) {
                    fprintf(log_file, "Debug: found correspond record of id %u to {id: %d, ip: %s, port: %x }\n", 
                        id, inet_ntoa(client->client_addr.sin_addr), ntohs(client->client_addr.sin_port));
                    fprintf(log_file, "Debug: cache message hash is %u, message at %x\n", message->hash, message);
                }

                decode_header(header);
                header->id = client->id;
                encode_header(header);

                if (debug_level) lprintf("Info: send remote dns server record to client --- ", buffer, n_bytes);
                ret = sendto(server_sock, buffer, n_bytes, 0, (struct sockaddr *)&(client->client_addr), sockaddr_in_size);
            }
            else {
                if (debug_level) fprintf(log_file, "Info: message id is invalid, ignore this message\n");
                if (debug_level > 1) printf("message id %x\n", id);
            }
        }
        if (ret < 0) printf("ret: sendto ret with return %d, WSAGetLastError %d\n", ret, WSAGetLastError());
    }
    
    close(server_sock);
    delete_message_map();
    return 0;
}

// sudo vim /etc/resolv.conf
// gcc main.c -o main -g -lws2_32