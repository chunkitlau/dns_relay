#include "client.h"

Client *new_client(unsigned short id, struct sockaddr_in client_addr, int question_size) {
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

static int client_queue_pre(int p) {
    return (p) ? (p - 1) : (CLIENT_QUEUE_SIZE - 1);
}

static int client_queue_next(int p) {
    return (p + 1 != CLIENT_QUEUE_SIZE) ? (p + 1) : 0;
}

unsigned short client_queue_push(Client *client) {
    unsigned short id = server_id_counter++;
    client_queue[client_queue_tail] = client;
    client_queue_id[client_queue_tail] = id;
    client_queue_tail = client_queue_next(client_queue_tail);
    if (client_queue_tail == client_queue_head) {
        delete_client(client_queue[client_queue_head]);
        client_queue_head = client_queue_next(client_queue_head);
    }
    return id;
}

static int between(unsigned short a, unsigned short b, unsigned short c) {
    return ((a <= b) && (b < c)) || ((c < a) && (a <= b)) || ((b < c) && (c < a));
}

Client *client_queue_find(unsigned short id) {
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