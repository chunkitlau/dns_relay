#define VERSION "0.1.0"
#define DEFAULT_PORT 53
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_DNSSERVER_IP "114.114.114.114"
#define DEFAULT_CONFIG_FILE "dnsrelay.txt"
#define DEFAULT_LOG_FILE "log.txt"
#define DEFAULT_CACHE_SIZE 3000
#define DOMAIN_NAME_SIZE 256
#define STANDARD_QUERY 0
#define REVERSE_QUERY 1
#define QUERY_MESSAGE 0
#define RESPONSE_MESSAGE 1
#define HEADER_SIZE 12
#define BUFFER_SIZE 1024
#define DEFAULT_TTL 120
#define CLIENT_QUEUE_SIZE 3000
#define PRIME1 257

static int server_sock;
static int debug_level = 1; 
static unsigned short port = DEFAULT_PORT;
static int cache_size = DEFAULT_CACHE_SIZE;
static char server_ip[20];
static char dnsserver_ip[20];
static struct sockaddr_in dnsserver_addr;

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
} Header;