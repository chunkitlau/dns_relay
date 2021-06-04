#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define DEFAULT_CACHE_SIZE 3000
#define BUFFER_SIZE 1024
#define PRIME1 257

typedef struct Message{
    unsigned char *buffer;
    unsigned int buffer_size;
    unsigned int question_size;
    unsigned long ttl;
    unsigned int hash;
} Message;

typedef struct Message_node{
    Message *message;
    struct Message_node *next_message_node;
    unsigned int id;
} Message_node;

static int cache_size = DEFAULT_CACHE_SIZE;
static Message_node **message_map;
static unsigned char hash_ignore[BUFFER_SIZE];
static unsigned int message_map_dynamic_id = 0;
static unsigned int dynamic_size = 100000;

extern Message *new_message(unsigned char *buffer, unsigned int buffer_size, unsigned int question_size, unsigned long ttl);
extern void delete_message(Message *message);
extern void new_message_map();
extern void delete_message_map();
extern Message_node *message_map_find(Message *message);
extern void message_map_insert(Message *message);

#endif