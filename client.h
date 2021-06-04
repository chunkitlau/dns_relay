#ifndef _CLIENT_H_
#define _CLIENT_H_

#ifdef _WIN32 /* for Windows Visual Studio */

#include <winsock2.h>
#include <io.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <ws2tcpip.h>
#include <getopt.h>

//#define getopt_long getopt_int
#define stricmp _stricmp

static void socket_init(void);

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
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#define stricmp strcasecmp
#define socket_init()
#define WSAGetLastError() 0

#endif

#define CLIENT_QUEUE_SIZE 3000

typedef struct Client{
    unsigned id: 16;
    struct sockaddr_in client_addr;
    int question_size;
} Client;

static int client_queue_head = 0;
static int client_queue_tail = 0;
static Client *client_queue[CLIENT_QUEUE_SIZE];
static unsigned short client_queue_id[CLIENT_QUEUE_SIZE];
static unsigned short server_id_counter = 0;

extern Client *new_client(unsigned short id, struct sockaddr_in client_addr, int question_size);
extern unsigned short client_queue_push(Client *client);
extern Client *client_queue_find(unsigned short id);

#endif